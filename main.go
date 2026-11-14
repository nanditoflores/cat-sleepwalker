// cat-sleepwalker wakes computers on the local network when an approved person asks
// through a Telegram bot.
//
// Security model:
//   - Outbound connections only. The program never listens on any port; it asks
//     Telegram for new messages (long polling) and sends Wake-on-LAN packets.
//   - Only Telegram user IDs listed in the config are obeyed. Telegram sets the
//     sender ID itself, so it cannot be faked even by someone holding the token.
//   - Message text is never executed. Only the fixed computer IDs from the config
//     are accepted; anything else is ignored.
//   - The bot token is never written to logs.
//
// Standard library only, no third-party dependencies.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------------------------------------------------------------- config ---

type Machine struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	MAC  string `json:"mac"`
	IP   string `json:"ip,omitempty"` // optional: enables /status and "is it on?" checks

	hw net.HardwareAddr
}

type Config struct {
	TokenFile            string    `json:"token_file"`
	AllowedUserIDs       []int64   `json:"allowed_user_ids"`
	BroadcastAddr        string    `json:"broadcast_addr"`
	LongPollSeconds      int       `json:"long_poll_seconds"`
	PollIntervalSeconds  int       `json:"poll_interval_seconds"`
	MaxCommandAgeMinutes int       `json:"max_command_age_minutes"`
	WakeCooldownSeconds  int       `json:"wake_cooldown_seconds"`
	BootCheckSeconds     int       `json:"boot_check_seconds"`
	Machines             []Machine `json:"machines"`
}

var (
	idPattern    = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
	tokenPattern = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{30,}$`)
)

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		BroadcastAddr:        "255.255.255.255:9",
		LongPollSeconds:      50,
		MaxCommandAgeMinutes: 30,
		WakeCooldownSeconds:  30,
		BootCheckSeconds:     180,
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	if cfg.LongPollSeconds < 0 || cfg.LongPollSeconds > 50 {
		return nil, errors.New("long_poll_seconds must be between 0 and 50")
	}
	if cfg.PollIntervalSeconds < 0 || cfg.PollIntervalSeconds > 3600 {
		return nil, errors.New("poll_interval_seconds must be between 0 and 3600")
	}
	if cfg.LongPollSeconds == 0 && cfg.PollIntervalSeconds == 0 {
		return nil, errors.New("set long_poll_seconds or poll_interval_seconds (both 0 would poll nonstop)")
	}
	if _, err := net.ResolveUDPAddr("udp4", cfg.BroadcastAddr); err != nil {
		return nil, fmt.Errorf("broadcast_addr: %w", err)
	}
	if len(cfg.Machines) == 0 {
		return nil, errors.New("no machines configured")
	}
	seen := map[string]bool{}
	for i := range cfg.Machines {
		m := &cfg.Machines[i]
		m.ID = strings.ToLower(strings.TrimSpace(m.ID))
		if !idPattern.MatchString(m.ID) || m.ID == "all" {
			return nil, fmt.Errorf("machine %d: id %q must be 1-32 chars of a-z 0-9 _ - and not \"all\"", i+1, m.ID)
		}
		if seen[m.ID] {
			return nil, fmt.Errorf("duplicate machine id %q", m.ID)
		}
		seen[m.ID] = true
		hw, err := net.ParseMAC(m.MAC)
		if err != nil || len(hw) != 6 {
			return nil, fmt.Errorf("machine %q: invalid MAC %q", m.ID, m.MAC)
		}
		m.hw = hw
		if m.IP != "" && net.ParseIP(m.IP).To4() == nil {
			return nil, fmt.Errorf("machine %q: invalid IPv4 %q", m.ID, m.IP)
		}
		if m.Name == "" {
			m.Name = m.ID
		}
	}
	return cfg, nil
}

// readToken prefers the systemd credential (LoadCredential=bot_token:...),
// falling back to token_file for manual runs.
func readToken(cfg *Config) (string, error) {
	path := cfg.TokenFile
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		path = filepath.Join(dir, "bot_token")
	}
	if path == "" {
		return "", errors.New("no token: set token_file in the config")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read token: %w", err)
	}
	tok := strings.TrimSpace(string(raw))
	if !tokenPattern.MatchString(tok) {
		return "", errors.New("token file does not look like a Telegram bot token")
	}
	return tok, nil
}

// -------------------------------------------------------------- telegram ---

type User struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
}

type Chat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

type Message struct {
	MessageID int64  `json:"message_id"`
	From      *User  `json:"from"`
	Chat      Chat   `json:"chat"`
	Date      int64  `json:"date"`
	Text      string `json:"text"`
}

type CallbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message"`
	Data    string   `json:"data"`
}

type Update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *Message       `json:"message"`
	CallbackQuery *CallbackQuery `json:"callback_query"`
}

type Button struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type Keyboard struct {
	InlineKeyboard [][]Button `json:"inline_keyboard"`
}

type Bot struct {
	token string
	http  *http.Client
}

func (b *Bot) redact(s string) string { return strings.ReplaceAll(s, b.token, "<token>") }

func (b *Bot) call(ctx context.Context, method string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.telegram.org/bot"+b.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s: %s", method, b.redact(err.Error()))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %s", method, b.redact(err.Error()))
	}
	defer resp.Body.Close()

	var r struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&r); err != nil {
		return fmt.Errorf("%s: bad response (HTTP %d)", method, resp.StatusCode)
	}
	if !r.OK {
		return fmt.Errorf("%s: telegram error: %s", method, r.Description)
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

func (b *Bot) send(ctx context.Context, chatID int64, text string, kb *Keyboard) {
	p := map[string]any{"chat_id": chatID, "text": text}
	if kb != nil {
		p["reply_markup"] = kb
	}
	if err := b.call(ctx, "sendMessage", p, nil); err != nil {
		log.Printf("send failed: %v", err)
	}
}

// ------------------------------------------------------------------- app ---

type App struct {
	cfg      *Config
	bot      *Bot
	allowed  map[int64]bool
	byID     map[string]*Machine
	mu       sync.Mutex
	lastWake map[string]time.Time
}

func (a *App) run(ctx context.Context) {
	var offset int64
	backoff := time.Second
	for ctx.Err() == nil {
		var updates []Update
		err := a.bot.call(ctx, "getUpdates", map[string]any{
			"offset":          offset,
			"timeout":         a.cfg.LongPollSeconds,
			"allowed_updates": []string{"message", "callback_query"},
		}, &updates)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("poll error: %v (retrying in %s)", err, backoff)
			sleep(ctx, backoff)
			backoff = min(backoff*2, 5*time.Minute)
			continue
		}
		backoff = time.Second
		for _, u := range updates {
			offset = u.UpdateID + 1
			switch {
			case u.Message != nil:
				a.onMessage(ctx, u.Message)
			case u.CallbackQuery != nil:
				a.onButton(ctx, u.CallbackQuery)
			}
		}
		if a.cfg.PollIntervalSeconds > 0 {
			sleep(ctx, time.Duration(a.cfg.PollIntervalSeconds)*time.Second)
		}
	}
}

func (a *App) onMessage(ctx context.Context, m *Message) {
	if m.From == nil || m.Chat.Type != "private" {
		return
	}
	if !a.allowed[m.From.ID] {
		log.Printf("ignored message from unauthorized user id=%d name=%q username=%q",
			m.From.ID, m.From.FirstName, m.From.Username)
		return
	}
	sent := time.Unix(m.Date, 0)
	maxAge := time.Duration(a.cfg.MaxCommandAgeMinutes) * time.Minute
	if a.cfg.MaxCommandAgeMinutes > 0 && time.Since(sent) > maxAge {
		a.bot.send(ctx, m.Chat.ID, fmt.Sprintf(
			"Ignored your message from %s: it is older than %d minutes. Send it again if you still need it.",
			sent.Format("15:04"), a.cfg.MaxCommandAgeMinutes), nil)
		return
	}

	fields := strings.Fields(strings.ToLower(m.Text))
	if len(fields) == 0 {
		return
	}
	cmd := strings.TrimPrefix(fields[0], "/")
	if i := strings.IndexByte(cmd, '@'); i > 0 {
		cmd = cmd[:i] // "/wake@my_bot" -> "wake"
	}

	switch cmd {
	case "wake":
		if len(fields) > 1 {
			a.wake(ctx, m.Chat.ID, m.From, fields[1])
		} else {
			a.bot.send(ctx, m.Chat.ID, "Which computer?", a.keyboard())
		}
	case "status":
		a.status(ctx, m.Chat.ID)
	case "start", "help":
		a.bot.send(ctx, m.Chat.ID, a.help(), nil)
	default:
		a.bot.send(ctx, m.Chat.ID, "Unknown command. Use /wake or /status.", nil)
	}
}

func (a *App) onButton(ctx context.Context, q *CallbackQuery) {
	_ = a.bot.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": q.ID}, nil)
	if !a.allowed[q.From.ID] {
		log.Printf("ignored button from unauthorized user id=%d", q.From.ID)
		return
	}
	chatID := q.From.ID
	if q.Message != nil {
		chatID = q.Message.Chat.ID
	}
	if target, ok := strings.CutPrefix(q.Data, "wake:"); ok {
		a.wake(ctx, chatID, &q.From, target)
	}
}

func (a *App) wake(ctx context.Context, chatID int64, who *User, target string) {
	if target == "all" {
		for _, m := range a.cfg.Machines {
			a.wakeOne(ctx, chatID, who, a.byID[m.ID])
		}
		return
	}
	m, ok := a.byID[target]
	if !ok {
		a.bot.send(ctx, chatID, "Unknown computer. Options: "+strings.Join(a.ids(), ", ")+", all", nil)
		return
	}
	a.wakeOne(ctx, chatID, who, m)
}

func (a *App) wakeOne(ctx context.Context, chatID int64, who *User, m *Machine) {
	if m.IP != "" && ping(ctx, m.IP) {
		a.bot.send(ctx, chatID, "🟢 "+m.Name+" is already on.", nil)
		return
	}

	a.mu.Lock()
	since := time.Since(a.lastWake[m.ID])
	cooldown := time.Duration(a.cfg.WakeCooldownSeconds) * time.Second
	if since < cooldown {
		a.mu.Unlock()
		a.bot.send(ctx, chatID, fmt.Sprintf("%s was woken %ds ago, please wait a moment.", m.Name, int(since.Seconds())), nil)
		return
	}
	a.lastWake[m.ID] = time.Now()
	a.mu.Unlock()

	if err := sendMagicPacket(m.hw, a.cfg.BroadcastAddr); err != nil {
		log.Printf("wake %s failed: %v", m.ID, err)
		a.bot.send(ctx, chatID, "❌ Could not send the wake-up to "+m.Name+": "+err.Error(), nil)
		return
	}
	log.Printf("wake sent: machine=%s requested_by=%d (%s)", m.ID, who.ID, who.FirstName)

	if m.IP == "" {
		a.bot.send(ctx, chatID, "⏳ Wake-up sent to "+m.Name+". (Add its IP to the config to get an \"it's on\" confirmation.)", nil)
		return
	}
	a.bot.send(ctx, chatID, "⏳ Wake-up sent to "+m.Name+"…", nil)
	go a.confirmBoot(ctx, chatID, m)
}

func (a *App) confirmBoot(ctx context.Context, chatID int64, m *Machine) {
	start := time.Now()
	deadline := start.Add(time.Duration(a.cfg.BootCheckSeconds) * time.Second)
	for time.Now().Before(deadline) {
		if !sleep(ctx, 5*time.Second) {
			return
		}
		if ping(ctx, m.IP) {
			a.bot.send(ctx, chatID, fmt.Sprintf("✅ %s is on (took %ds).", m.Name, int(time.Since(start).Seconds())), nil)
			return
		}
	}
	a.bot.send(ctx, chatID, fmt.Sprintf(
		"⚠️ %s did not answer after %ds. It may still be starting, or its firewall may block ping.",
		m.Name, a.cfg.BootCheckSeconds), nil)
}

func (a *App) status(ctx context.Context, chatID int64) {
	lines := make([]string, len(a.cfg.Machines))
	var wg sync.WaitGroup
	for i, m := range a.cfg.Machines {
		wg.Add(1)
		go func(i int, m Machine) {
			defer wg.Done()
			switch {
			case m.IP == "":
				lines[i] = "❔ " + m.Name + " (no IP in config)"
			case ping(ctx, m.IP):
				lines[i] = "🟢 " + m.Name + " is on"
			default:
				lines[i] = "⚪ " + m.Name + " is off (or not answering ping)"
			}
		}(i, m)
	}
	wg.Wait()
	a.bot.send(ctx, chatID, strings.Join(lines, "\n"), nil)
}

func (a *App) keyboard() *Keyboard {
	kb := &Keyboard{}
	for _, m := range a.cfg.Machines {
		kb.InlineKeyboard = append(kb.InlineKeyboard, []Button{{Text: m.Name, CallbackData: "wake:" + m.ID}})
	}
	kb.InlineKeyboard = append(kb.InlineKeyboard, []Button{{Text: "All computers", CallbackData: "wake:all"}})
	return kb
}

func (a *App) help() string {
	var b strings.Builder
	b.WriteString("Commands:\n/wake: choose a computer to turn on\n/wake <id>: turn one on directly\n/wake all: turn all on\n/status: see which are on\n\nComputers:\n")
	for _, m := range a.cfg.Machines {
		fmt.Fprintf(&b, "• %s (%s)\n", m.ID, m.Name)
	}
	return b.String()
}

func (a *App) ids() []string {
	out := make([]string, 0, len(a.byID))
	for id := range a.byID {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ------------------------------------------------------------- network ---

// sendMagicPacket sends the standard Wake-on-LAN packet (6x 0xFF followed by
// the MAC address 16 times), three times for reliability. Same default
// destination as the `wakeonlan` command: 255.255.255.255 port 9.
func sendMagicPacket(mac net.HardwareAddr, addr string) error {
	pkt := bytes.Repeat([]byte{0xFF}, 6)
	for i := 0; i < 16; i++ {
		pkt = append(pkt, mac...)
	}
	dst, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", nil) // Go enables SO_BROADCAST on UDP sockets
	if err != nil {
		return err
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		if _, err := conn.WriteToUDP(pkt, dst); err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// ping runs the system ping once. The IP was validated at config load, and
// exec does not use a shell, so nothing from Telegram can reach this command.
func ping(ctx context.Context, ip string) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ip).Run() == nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ------------------------------------------------------------------ main ---

func main() {
	configPath := flag.String("config", "/etc/cat-sleepwalker/config.json", "path to config file")
	testWake := flag.String("test-wake", "", "send a wake-up to this machine id and exit (no Telegram)")
	flag.Parse()
	log.SetFlags(0) // journald adds timestamps

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if *testWake != "" {
		for _, m := range cfg.Machines {
			if m.ID == strings.ToLower(*testWake) {
				if err := sendMagicPacket(m.hw, cfg.BroadcastAddr); err != nil {
					log.Fatalf("wake failed: %v", err)
				}
				log.Printf("wake-up sent to %s (%s)", m.Name, m.MAC)
				return
			}
		}
		log.Fatalf("unknown machine id %q", *testWake)
	}

	token, err := readToken(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	app := &App{
		cfg: cfg,
		bot: &Bot{token: token, http: &http.Client{
			Timeout: time.Duration(cfg.LongPollSeconds+20) * time.Second,
		}},
		allowed:  map[int64]bool{},
		byID:     map[string]*Machine{},
		lastWake: map[string]time.Time{},
	}
	for _, id := range cfg.AllowedUserIDs {
		app.allowed[id] = true
	}
	for i := range cfg.Machines {
		app.byID[cfg.Machines[i].ID] = &cfg.Machines[i]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Verify the token and prepare the bot. Retry so a missing network at boot
	// does not crash the service.
	for {
		var me User
		err := app.bot.call(ctx, "getMe", map[string]any{}, &me)
		if err == nil {
			log.Printf("connected as @%s; %d machine(s), %d approved user(s)", me.Username, len(cfg.Machines), len(app.allowed))
			break
		}
		log.Printf("startup: %v (retrying in 15s)", err)
		if !sleep(ctx, 15*time.Second) {
			return
		}
	}
	if len(app.allowed) == 0 {
		log.Printf("WARNING: allowed_user_ids is empty, so every message is ignored. Send the bot a message and look for your id in this log.")
	}
	// getUpdates does not work while a webhook is set; make sure none is.
	_ = app.bot.call(ctx, "deleteWebhook", map[string]any{"drop_pending_updates": false}, nil)
	_ = app.bot.call(ctx, "setMyCommands", map[string]any{"commands": []map[string]string{
		{"command": "wake", "description": "Turn on a computer"},
		{"command": "status", "description": "See which computers are on"},
		{"command": "help", "description": "Show help"},
	}}, nil)

	app.run(ctx)
	log.Printf("stopped")
}
