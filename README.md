# 🛡️ SecNet-Auditor

Modular network audit, hardening and defensive monitoring suite for **Ubuntu/Debian** servers, with a local web dashboard (Flask). Educational project for the SMX course.

> ⚠️ **Read-only unless an admin password is set**: out of the box the tool only *audits* and never modifies the firewall, users or permissions; corrective actions are shown as suggestions. Once you set an admin password (`python app.py --set-password`) and run the server as root, a logged-in admin can apply a small, closed list of **guided fixes** from the dashboard (each with preview, backup and undo), and the raw **Logs** tab requires that login. Use it only on systems you own or are authorized to audit.

## Structure

```
SecNet-Auditor/
├── app.py                  # Flask server, JSON API, login/session wiring, --set-password
├── config.json             # Adjustable settings
├── modules/
│   ├── network_check.py    # Netplan, DNS (+ probes, DNSSEC), interfaces (ip link)
│   ├── services.py         # SSH, open ports, DHCP, NTP, HTTP(S)
│   ├── hardening.py        # UFW, UID 0, octal permissions
│   ├── log_monitor.py      # Lightweight SIEM (regex over auth.log)
│   ├── auth.py             # Admin password hash, CSRF token, login rate limit
│   ├── fixes.py            # Guided-fix catalogue and pipeline (plan/apply/verify/undo)
│   ├── fix_history.py      # Backups, record.json and the fixes.log audit trail
│   └── log_viewer.py       # Log sources, parsing, filtering, pagination
├── templates/index.html    # Dashboard (Bootstrap 5)
├── tests/                  # pytest suite (no real system changes)
├── backups/                # Created at runtime: one folder per applied fix (git-ignored)
├── instance/               # Created at runtime: secret.key for session cookies (git-ignored)
└── fixes.log               # Created at runtime: audit trail of fixes and undos (git-ignored)
```

## Requirements

- Ubuntu/Debian with Python 3.8+
- `iproute2` (`ip` command), optionally `ufw` and Netplan
- Flask

```bash
sudo apt update && sudo apt install -y python3 python3-venv ufw
cd SecNet-Auditor
python3 -m venv venv && source venv/bin/activate
pip install flask
```

## Running

```bash
# Limited privileges (some data will show as "no access"; fixes are unavailable)
python app.py

# Full audit (UFW, auth.log, /etc/netplan, /etc/shadow...) and, with a password set, fixes
sudo venv/bin/python app.py
```

Open `http://127.0.0.1:5000` and click **Run Full Audit**. The audit also runs when the page loads.

> Alternative without sudo: add your user to the `adm` group (`sudo usermod -aG adm $USER`) to read `/var/log/auth.log`. This is enough for the Logs tab, but fixes always need root.

## Setting the admin password

Fixes (and, once a password exists, the raw log viewer) are protected by one admin password:

```bash
python app.py --set-password
```

You are asked twice (nothing is echoed). It must be **at least 8 characters**. Only a salted hash is stored, in `config.json` under `auth.password_hash`; the password itself is never saved. Run the command again to change it. To go back to read-only, empty `auth.password_hash` in `config.json`.

Then open the dashboard and log in from the login dialog (the fix buttons say "Log in to fix" until you do).

Session behaviour:

- The login is a cookie session (`HttpOnly`, `SameSite=Strict`) lasting `auth.session_minutes` (default 30). The session-lifetime setting is read at server start, so restart after changing it.
- The cookie is signed with a random key created on first start in `instance/secret.key` (mode 600, git-ignored). Deleting that file logs everyone out.
- Every change request carries a per-session CSRF token.
- After **5 wrong passwords from one IP within 5 minutes** that IP is locked out for 5 minutes (kept in memory, so a restart clears it).

## Guided fixes

When an audit finding has a fix, a **Fix** button appears next to it (Hardening, Services/SSH, NTP, UFW and brute-force IPs). The browser only ever sends a fix id plus a few validated parameters; the server never runs text supplied by the client.

Every fix follows the same flow:

1. **Preview**: a dialog explains in one sentence what is wrong, shows exactly what will change (a diff or the command) and a risk note. Nothing has changed yet.
2. **Confirm**: you press Apply. High-risk fixes also require ticking "I understand the risk".
3. **Backup**: every file the fix may touch is copied to `backups/<timestamp>-<fix id>/` (mode 700) together with a `record.json`.
4. **Apply** the change.
5. **Verify**: the relevant check is run again. If it fails (or the command failed), the change is **rolled back automatically** and reported as "Reverted". If even the rollback fails, the record is marked as needing manual attention and the backup path is shown.
6. **Undo**: from the **Fix history** tab, press Undo on any of the 20 most recent applied fixes to put things back.

Every apply and undo is also appended as one JSON line to `fixes.log` (time, fix, parameters, result, client IP). Fixes are serialized, so two requests never change the system at once. A fix that is already in place is reported as "Already applied" and changes nothing.

Requirements: the server must run as **root** (`sudo`) and an admin password must be set and logged in. Otherwise the buttons are disabled with the reason ("Run the server with sudo" / "Fixes are disabled: set an admin password").

### Catalogue

| Fix id | What it does, in plain language | Risk |
|---|---|---|
| `perms.fix_file` | Restrict file permissions: `chmod` a file to the maximum mode expected in `hardening.critical_files` (or `600` for a `.yaml` in the Netplan directory). Nothing else is accepted. | low |
| `ntp.enable` | Turn on automatic time synchronization (`timedatectl set-ntp true`). | low |
| `ssh.disable_empty_passwords` | Refuse empty SSH passwords (`PermitEmptyPasswords no`). | low |
| `ssh.limit_auth_tries` | Limit SSH login attempts per connection (`MaxAuthTries` set to `services.max_auth_tries`). | low |
| `ssh.disable_root_login` | Disable root login over SSH (`PermitRootLogin no`). | medium |
| `ufw.enable` | Turn on the firewall: first allows your SSH port(s), then enables UFW. | medium |
| `ufw.block_ip` | Block an IP address (`ufw deny from <ip>`), from the Logs tab or the SSH alerts. | medium |
| `ssh.disable_password_auth` | Disable SSH password logins (keys only, `PasswordAuthentication no`). Refused unless a non-root user already has an `authorized_keys` file with a key. | high |

How the SSH fixes work: the main `sshd_config` is **never edited**. All four write one shared drop-in, `/etc/ssh/sshd_config.d/00-secnet.conf` (name chosen so it is read first and wins), then run `sshd -t` and only if that passes `systemctl reload ssh`. To remove a fix by hand, delete its line from that file (or the file) and reload ssh.

`ufw.block_ip` refuses your own address, loopback/link-local/multicast/reserved addresses and, unless `fixes.block_private_ips` is `false`, private-network addresses.

### Undoing a fix

Open the **Fix history** tab, find the entry and press **Undo**. Files are restored from `backups/`, SSH is re-validated and reloaded, and UFW rules the fix added are removed (the firewall is turned off again by undoing `ufw.enable`). Only the 20 most recent fixes can be undone from the dashboard; older backups stay on disk and you can restore them by hand (`record.json` lists each file and its original mode). Backups are never pruned automatically. Note that undo overwrites later manual changes to those same files.

### What is deliberately NOT fixable from the dashboard

- **Netplan and DNS edits**: a wrong value can cut the server off the network. (Only the file *permissions* of Netplan YAML can be tightened.)
- **Stopping or disabling services** (including insecure listening ports).
- **Non-root accounts with UID 0**: needs a human decision about the account.
- Anything else not in the table above: the catalogue is closed and there is no free-form command.

## Log viewer

The **Logs** tab is a friendlier way to read system logs than `grep`.

- **Sources** (a fixed allow-list in `logs.sources`; the browser sends only the source id, never a path): `auth` (`/var/log/auth.log`), `syslog` (`/var/log/syslog`), `ssh` (`journalctl -u ssh`), `ufw` (`/var/log/ufw.log`) and `fixes` (this app's own `fixes.log`). Relative paths resolve inside the repo folder.
- **Filters**: severity chips (All / Errors / Warnings / Info, inferred from keywords in the message), time range (any time, last hour, 24 hours, 7 days), **text search** (case-insensitive plain substring, not a regex) and an **IP filter**. IPs in the log are clickable and filter by that address; when fixes are available you also get a **Block IP** button.
- **Reading**: newest lines first, colour-coded by level, search matches highlighted. Files are read from the end in blocks, so large logs are not loaded into memory; use **Load older lines** to go further back (a single filtered query scans at most 50,000 lines). The limit is `logs.default_limit` (200 by default, 1000 at most).
- **Download filtered** saves exactly the lines currently matching the filters as a text file.
- **Auto-refresh**: the "Refresh every 5 s" switch re-queries while the tab is open.
- **Login behaviour**: with no admin password set the tab is open (read-only, same exposure as the SSH alerts). Once a password is set, `/api/logs/view` and `/api/logs/download` require login, because raw logs are more sensitive than the summary.
- Missing or unreadable logs give a plain message (for example "No permission to read auth.log - run with sudo or join the adm group").

## Configuration (`config.json`)

| Key | Description |
|---|---|
| `server.host` / `server.port` | Bind address and port (localhost only by default) |
| `ssh.failed_attempts_threshold` | Failed attempts from one IP before raising an alert |
| `ssh.auth_log_path` | Log path (`/var/log/auth.log`) |
| `ssh.lines_to_analyze` | Analyze the last N lines |
| `network.netplan_dir`, `network.resolv_conf`, `network.dns_test_host` | Paths and DNS test host |
| `services.ssh_config_path` · `services.max_auth_tries` | sshd_config path and maximum recommended `MaxAuthTries` (also the value `ssh.limit_auth_tries` applies) |
| `services.insecure_ports` | Extra port → description pairs to flag when exposed (added to the built-in list) |
| `services.web_check_urls` | URLs probed when a web server is active |
| `hardening.critical_files` | File → maximum expected octal permissions (also the allow-list for `perms.fix_file`) |
| `auth.password_hash` | Admin password hash; empty = read-only mode. Set with `python app.py --set-password`, do not edit by hand |
| `auth.session_minutes` | Login session length in minutes (default 30; read at server start) |
| `fixes.ssh_dropin_dir` | Directory for the SSH drop-in (`/etc/ssh/sshd_config.d`) |
| `fixes.backup_dir` | Where backups go; relative paths are inside the repo folder (`backups`) |
| `fixes.block_private_ips` | `true` (default) refuses to block private-network IPs |
| `logs.sources` | Log id → `{type: file, path}` or `{type: journal, unit}` |
| `logs.default_limit` | Lines returned per request (default 200, max 1000) |

Most settings are re-read on every request: no restart needed (except `server.*` and `auth.session_minutes`). `--set-password` rewrites `config.json` and re-indents it, so keep any comments elsewhere (JSON has none anyway).

## API

| Route | Content |
|---|---|
| `GET /` | Dashboard |
| `GET /api/audit` | Full audit |
| `GET /api/network` · `/api/services` · `/api/hardening` · `/api/logs` | Individual modules (`/api/logs` is the SSH brute-force summary) |
| `POST /login` | Body `{"password": "..."}`; starts a session and returns the CSRF token. 403 if no password is set, 401 wrong password, 429 locked out |
| `POST /logout` | Ends the session (CSRF header required) |
| `GET /api/session` | `{logged_in, fixes_enabled, is_root, csrf}` for the UI |
| `GET /api/logs/view` | Filtered log lines: `source, q, level, ip, since, limit, before` (cursor). Needs login once a password is set |
| `GET /api/logs/download` | Same filters, returned as a text file. Needs login once a password is set |
| `POST /api/fix/plan` | Body `{fix_id, params}`; preview only, changes nothing. Login + CSRF |
| `POST /api/fix/apply` | Body `{fix_id, params}`; runs the pipeline. Login + CSRF + root |
| `GET /api/fix/history` | The 20 most recent fix records. Login |
| `POST /api/fix/undo` | Body `{record_id}`; rolls a record back. Login + CSRF + root |

Every `POST` except `/login` needs the `X-CSRF-Token` header returned by `/login` or `/api/session`.

## Running the tests

```bash
pip install pytest
python -m pytest tests
```

The tests never touch the real system: fixes run against a temporary root directory and external commands (`ufw`, `sshd`, `timedatectl`, `journalctl`) go through an injectable fake runner.

## What it detects

- **Network**: Netplan YAML (DHCP, IPs, gateway, permissions, tabs), nameservers and a real resolution test, interfaces and their state.
- **DNS (advanced)**: each nameserver is queried directly over UDP 53 (reachability and latency), `systemd-resolved` is detected with its DNSSEC / DNS-over-TLS settings (`resolvectl`), and a single nameserver is flagged as no redundancy.
- **Services** (`modules/services.py`):
  - **SSH**: `sshd_config` + `sshd_config.d/*.conf` (`PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `Protocol`, `MaxAuthTries`, port).
  - **Ports**: listening sockets via `ss -tulnH`; flags those exposed on `0.0.0.0`/`::` and known-insecure services (telnet, FTP, rsh, VNC...).
  - **DHCP**: lease present when DHCP is in use (`networkctl`).
  - **NTP**: clock synchronization (`timedatectl`).
  - **HTTP(S)**: if nginx/apache2 are active, probes localhost for HTTPS and the basic security headers.
- **Hardening**: UFW active/inactive, non-root accounts with UID 0, permissions more permissive than expected.
- **Logs**: SSH brute force per IP (`Failed password`, `Invalid user`, `authentication failure`). Severity HIGH/CRITICAL; flagged if the IP ever authenticated successfully (`Accepted`).

## Dashboard security

- It listens on `127.0.0.1` only and uses plain HTTP. **Keep it that way.** Do not expose it to the network (`0.0.0.0`) without a reverse proxy with TLS in front, since the admin password and session cookie would otherwise travel in clear text.
- **Run as root only with an admin password set.** Root is needed for fixes, but a root server without a password cannot apply fixes and only widens exposure; set the password first, then use `sudo`.
- **Testing SSH fixes: keep a second SSH session open** until you have confirmed you can still log in. The same goes for `ufw.enable`.
- **UFW enable allows the SSH port first** (every `Port` in sshd_config, 22 if none), then turns the firewall on, so your session is not cut. Other services (web server, etc.) become unreachable until you allow them.
- **Backups contain copies of system files** (sshd config, Netplan, possibly more). Keep `backups/` and `fixes.log` private: they are git-ignored, the backup folders are mode 700, and you should not share or commit them. The same applies to `instance/secret.key`.
- Use a strong, unique admin password; `config.json` holds its hash, so do not publish a populated `config.json`.

## Troubleshooting

- *"No permission to read auth.log"* → use `sudo` or the `adm` group.
- *Missing log* → on pure-journald systems install `rsyslog`; the `ssh` source uses the journal directly and needs permission to run `journalctl` (root or the `systemd-journal` group).
- *UFW asks for root* → run with `sudo`.
- *Fix buttons are greyed out with "Fixes are disabled: set an admin password"* → run `python app.py --set-password` and reload the page (no restart needed).
- *Fix buttons say "Run the server with sudo"* → start the server with `sudo venv/bin/python app.py`.
- *"Too many failed attempts, try again in 5 minutes"* → wait 5 minutes or restart the server (the lockout is in memory).
- *Logged out unexpectedly* → the session lasts `auth.session_minutes`; also deleting `instance/secret.key` or restarting with a different key invalidates sessions.
- *"Add an SSH key for a non-root user first"* → `ssh.disable_password_auth` needs an `authorized_keys` file with at least one key for a non-root account; set up key login before disabling passwords.
- *"Reverted (...)"* → the change failed its check (for example `sshd -t` rejected the config) and was undone automatically; nothing was changed. Read the reason in the message and in the **Fixes made here** log.
- *"needs manual attention"* in Fix history → automatic restore also failed; restore the files by hand from the backup folder shown.
- *Reached the 20-fix undo limit* → older backups are still in `backups/` and can be copied back manually.

## Roadmap

Status: ✅ done · 🔜 next · 💡 idea.

**v0.1 – Audit (done)**
- ✅ Network (Netplan, interfaces), hardening (UFW, UID 0, permissions) and SSH brute-force detection
- ✅ Service audit: SSH, listening ports, DHCP, NTP, HTTP(S); advanced DNS (nameserver probes, DNSSEC, DoT)

**v0.2 – Guided fixes and logs (done, needs real-server validation)**
- ✅ Admin login, CSRF protection, login rate limiting
- ✅ Fix catalogue with preview, backup, verify, automatic rollback and undo
- ✅ Log viewer with filters, search, download and auto-refresh
- 🔜 Validate every fix on a real Ubuntu/Debian VM (SSH, UFW, NTP, `journalctl`) and fix what differs from the simulated tests

**v0.3 – Hardening of the tool itself**
- 🔜 Per-directive undo for SSH fixes (today an older SSH fix must be undone after newer ones)
- 🔜 Honour `AuthorizedKeysFile` and socket-activated SSH ports (Ubuntu 24.04) in the lock-out safeguards
- 🔜 Move the password hash out of the tracked `config.json` (e.g. into `instance/`)
- 🔜 Revoke sessions on logout / password change (server-side session store)
- 🔜 Rate limiting aware of a trusted reverse proxy, with bounded memory
- 💡 Automatic pruning of old backups

**v0.4 – More coverage**
- 💡 More catalogue entries (each is one small class in `modules/fixes.py`; see its docstring): `sysctl` network hardening, `fail2ban`, unattended upgrades, SSH port change
- 💡 Audit of more services (Samba/NFS, FTP, mail, databases) and open-port ↔ process mapping
- 💡 Scheduled audits with history and trend graphs

**v1.0 – Sharing and operations**
- 💡 Report export (PDF / HTML / JSON) and email or webhook alerts
- 💡 Multiple users and roles (viewer / operator / admin)
- 💡 Optional built-in HTTPS and multi-host auditing from one dashboard
- 💡 Packaging: `.deb` / systemd unit, CI with tests on every push

Ideas and exercises for the SMX course are welcome: pick any 💡 item and open an issue or a pull request.
