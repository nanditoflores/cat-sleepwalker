# cat-sleepwalker: setup guide

Wake your computers from Telegram. The Ubuntu machine only makes **outgoing**
connections: nothing listens, no ports are opened, and nothing can connect in.

```
Phone (Telegram) ──► Telegram servers ◄── Ubuntu asks "anything new?" (outgoing only)
                                               │
                                               └─► Wake-on-LAN packet ──► PC
```

Files in this folder:

| File | What it is |
|---|---|
| `main.go`, `go.mod` | The program (Go, standard library only) |
| `config.json` | Your computers, approved Telegram users, timing |
| `cat-sleepwalker.service` | systemd service, runs locked down with no access to `/home` |

---

## 1. Create the bot (on your phone, about 2 minutes)

1. Open **https://t.me/BotFather** (the real one has a blue ✓ and the exact name `@BotFather`).
2. Type `/newbot` and send it.
3. Display name: e.g. `Home Wake`. Username: must end in `bot`, e.g. `gato_aparato_wake_bot`.
4. BotFather replies with a **token** like `123456789:AAH...`. Treat it like a password:
   don't send it to anyone, and don't paste it in chats or websites.
5. Still in BotFather: send `/setjoingroups`, pick your bot, choose **Disable**.

## 2. Build the program

The program needs **Go 1.22 or newer** to build. Running it needs nothing:
it is a single static file that works on any 64-bit Ubuntu (check with
`uname -m`, which should print `x86_64`).

**Easiest: build on another computer and copy the file over** (Ubuntu needs no Go at all):

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o cat-sleepwalker .
```

**Or build on the Ubuntu machine.** On Ubuntu 22.04, `apt install golang-go`
gives Go 1.18, which is **too old**. Use the snap instead:

```bash
sudo snap install go --classic
cd cat-sleepwalker
CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o cat-sleepwalker .
```

(On Ubuntu 24.04 or newer, `sudo apt install golang-go` is recent enough.)

## 3. Install

```bash
sudo install -m 755 cat-sleepwalker /usr/local/bin/cat-sleepwalker
sudo mkdir -p /etc/cat-sleepwalker
sudo install -m 644 config.json /etc/cat-sleepwalker/config.json
sudo install -m 644 cat-sleepwalker.service /etc/systemd/system/cat-sleepwalker.service
```

Save the token in a root-only file. The command below reads it without
showing it on screen or saving it in your shell history:

```bash
sudo bash -c 'umask 077; read -r -s -p "Paste bot token: " T; echo; printf "%s\n" "$T" > /etc/cat-sleepwalker/bot_token'
```

## 4. Quick test without Telegram

Check that the program can wake a PC (same as your `wakeonlan` command):

```bash
cat-sleepwalker -config /etc/cat-sleepwalker/config.json -test-wake sandra
```

## 5. Start the service and find your Telegram user IDs

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cat-sleepwalker
journalctl -u cat-sleepwalker -f
```

You should see `connected as @your_bot`. Now **you and your wife each send any
message to the bot**. The log shows a line for each:

```
ignored message from unauthorized user id=987654321 name="Fernando" ...
```

Put those numbers in `/etc/cat-sleepwalker/config.json`:

```json
"allowed_user_ids": [987654321, 123123123],
```

Then restart:

```bash
sudo systemctl restart cat-sleepwalker
```

## 6. Use it

In the bot chat:

- `/wake` shows buttons for each computer plus "All computers"
- `/wake sandra`, `/wake jose`, `/wake fernando`, `/wake all`
- `/status` shows which are on (needs IPs, see step 7)

Test once **from mobile data with Wi-Fi off** to be sure it works from outside.

## 7. Optional: "it's on" confirmation and /status

Add each PC's local IP to `config.json` (`"ip": "192.168.1.20"`). Give each PC a
fixed IP in your router (DHCP reservation) so it doesn't change.

- **Windows PCs block ping by default.** To allow it, open *Windows Defender
  Firewall → Advanced settings → Inbound Rules* and enable **"File and Printer
  Sharing (Echo Request - ICMPv4-In)"** for the Private profile.
- Check that the locked-down service is allowed to ping:
  ```bash
  sudo systemd-run --pipe --wait -p DynamicUser=yes -p NoNewPrivileges=yes ping -c1 192.168.1.20
  ```
  If that fails with "permission denied", run
  `echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee /etc/sysctl.d/60-cat-sleepwalker-ping.conf && sudo sysctl --system`.

## 8. Settings in config.json

| Setting | Default | Meaning |
|---|---|---|
| `long_poll_seconds` | 50 | Wait up to this long for a new message on each request. Replies come within about 1 second. Still outgoing only. |
| `poll_interval_seconds` | 0 | Extra pause between checks. For "check every 5 minutes", set `long_poll_seconds: 0` and `poll_interval_seconds: 300`. |
| `max_command_age_minutes` | 30 | Ignore old commands (e.g. sent while Ubuntu was off), so PCs don't turn on hours later. `0` = never ignore. |
| `wake_cooldown_seconds` | 30 | Ignore repeat taps on the same PC for this long. |
| `boot_check_seconds` | 180 | How long to wait for the PC to answer ping before warning. |
| `broadcast_addr` | `255.255.255.255:9` | Same as the `wakeonlan` command's default. |

## 9. Confirm nothing is listening

```bash
sudo ss -tulpn | grep cat-sleepwalker || echo "cat-sleepwalker is not listening on any port"
```

Recommended firewall (outgoing allowed, incoming blocked). **If you connect to
this machine remotely with SSH from your LAN, allow it first**, or you will lock
yourself out:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp   # only if you use SSH; adjust your subnet
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable
```

## 10. If a phone is lost, or the token leaks

- **Lost phone:** in Telegram on another device, go to *Settings → Devices* and end
  that session. Remove its user ID from `allowed_user_ids` if needed, then restart the service.
- **Token leaked:** in @BotFather send `/revoke`, then save the new token as in step 3
  and `sudo systemctl restart cat-sleepwalker`. Even with the old token, nobody could wake your PCs,
  because only your user IDs are obeyed.
- Turn on **Telegram Two-Step Verification** (Settings → Privacy and Security) on both phones.

## Logs

```bash
journalctl -u cat-sleepwalker --since today
```

Every wake is logged with who asked: `wake sent: machine=jose requested_by=987654321 (Fernando)`.
