# Guided fixes and log viewer — design

Date: 2026-11-12 · Status: draft for review

## 1. Purpose

SecNet-Auditor currently only **reports** problems. Two additions make it useful to someone who is not a sysadmin:

1. **Guided fixes**: when a check fails, the user can correct it from the dashboard with a clear preview, confirmation, backup and undo.
2. **Log viewer**: a friendly interface to read system logs (filter, search, colour by severity) instead of reading raw files.

Audience: SMX students and small-server admins. Success means: a user can fix "root login over SSH is enabled" in three clicks without typing a command, can undo it, and can find "failed logins from IP X yesterday" without `grep`.

Out of scope: HTTPS in the app itself (stays on `127.0.0.1`; exposing it needs a reverse proxy with TLS), multiple users/roles, editing Netplan/DNS, stopping services, UID 0 remediation.

## 2. Principles

- **Read-only by default.** Without a configured admin password, the app behaves exactly as today: no fix endpoint accepts requests.
- **Closed catalogue, no free-form commands.** The browser sends only a `fix_id` plus validated parameters. The server never executes text supplied by the client.
- **Preview → confirm → backup → apply → verify → rollback on failure.**
- Everything reuses the existing pattern: `modules/*.py` + routes in `app.py` + panels in `templates/index.html`.

## 3. Architecture

```
app.py                 routes, session/CSRF wiring
modules/
  auth.py              password hash, login, CSRF token, rate limiting
  fixes.py             fix catalogue: plan() / apply() / rollback()
  fix_history.py       backups + fixes.log (audit trail), undo
  log_viewer.py        log sources, parsing, filtering, pagination
templates/index.html   "Fix" buttons + modal, "Logs" tab
tests/                 test_auth.py, test_fixes.py, test_log_viewer.py
```

Each unit has one purpose and talks through plain dicts: `fixes.py` knows nothing about Flask; `log_viewer.py` knows nothing about fixes.

## 4. Authentication and request safety (`auth.py`)

- Admin password hash (`werkzeug.security`) stored in `config.json` under `auth.password_hash`. Set with `python app.py --set-password` (prompts, never echoes, never stored in plain text).
- No hash configured → fix endpoints return 403 "Fixes are disabled: set an admin password"; log viewer stays available as read-only (same exposure as today's SSH alerts).
- Login: `POST /login`, Flask session cookie `HttpOnly`, `SameSite=Strict`, secret key generated at first start and stored outside the repo (`instance/secret.key`, mode 600, git-ignored).
- CSRF: per-session token required in header `X-CSRF-Token` on every POST.
- Rate limit: 5 failed logins per IP per 5 minutes, then a 5-minute lockout (in memory).
- Fixes need `os.geteuid() == 0`. Otherwise the button is disabled with the reason "Run the server with sudo".

## 5. Fix catalogue (`fixes.py`)

Each fix is a small class with `id`, `title` (plain language), `risk` (`low|medium|high`), and:

- `applicable(audit)` → whether the current audit shows the problem.
- `plan(params)` → `{summary, diff, risk_note}` without changing anything.
- `apply(params)` → performs the change, returns what was touched.
- `rollback(record)` → restores from the backup.

| Fix id | Plain-language title | Mechanism |
|---|---|---|
| `ssh.disable_root_login` | Disable direct root login over SSH | drop-in `sshd_config.d/00-secnet.conf`: `PermitRootLogin no` |
| `ssh.disable_password_auth` | Require SSH keys instead of passwords | drop-in `PasswordAuthentication no`; **blocked** unless `~/.ssh/authorized_keys` exists for at least one non-root user |
| `ssh.disable_empty_passwords` | Forbid empty passwords | drop-in `PermitEmptyPasswords no` |
| `ssh.limit_auth_tries` | Limit SSH login attempts | drop-in `MaxAuthTries <config value>` |
| `perms.fix_file` | Restrict permissions of `<file>` | `chmod <expected>`; path must be a key of `hardening.critical_files` or a file in `network.netplan_dir` |
| `ufw.enable` | Turn on the firewall | `ufw allow <ssh port>/tcp` first, then `ufw --force enable` |
| `ntp.enable` | Enable time synchronization | `timedatectl set-ntp true` |
| `ufw.block_ip` | Block IP `<ip>` | `ufw deny from <ip>`; IP validated with `ipaddress`; refuses the requester's own IP, loopback and private ranges unless explicitly allowed in config |

SSH fixes: after writing the drop-in, run `sshd -t`; only if it validates, `systemctl reload ssh`. If validation fails, remove the drop-in and report the error. The main `sshd_config` is never edited (first-value-wins is respected by writing the drop-in with a name that sorts first, `00-secnet.conf`, so it takes precedence).

Parameter validation is part of `plan()`: unknown ids, paths outside the allow-list, or malformed IPs raise a validation error before anything runs.

## 6. Backups, history and undo (`fix_history.py`)

- Before `apply()`, copy every file that will change to `backups/<timestamp>-<fix_id>/` (git-ignored, mode 700) with a `record.json` (fix id, params, files, previous modes, ufw state).
- Append one line to `fixes.log`: time, user, fix id, params, result.
- After `apply()`, re-run the relevant check. If the problem is still present or the command failed, call `rollback()` automatically and report "Reverted".
- Dashboard "History" list shows past fixes with an **Undo** button (calls `rollback(record)`, logged the same way). Undo is available for the 20 most recent records.

## 7. User interface — fixes

- Wherever a check is WARN/ERROR and a fix exists, show a **Fix** button next to the finding (SSH issues, permissions, UFW inactive, NTP, brute-force IPs).
- Click opens a modal:
  1. What is wrong, in one sentence.
  2. What will change (diff in a read-only code block).
  3. Risk note (e.g. "You will no longer be able to log in as root over SSH").
  4. **Apply** / **Cancel**. High-risk fixes require ticking "I understand".
- Result toast: success, reverted, or error with the reason. The audit refreshes automatically.
- Not logged in: the buttons show "Log in to fix" and open the login dialog.

## 8. Log viewer (`log_viewer.py`) and UI

**Sources** (allow-list in `config.json` → `logs.sources`; the client sends only a source id, never a path):

| Source id | Origin |
|---|---|
| `auth` | `/var/log/auth.log` (existing path setting) |
| `syslog` | `/var/log/syslog` |
| `ssh` | `journalctl -u ssh -o json` |
| `ufw` | `/var/log/ufw.log` (or kernel lines containing `UFW`) |
| `fixes` | the app's own `fixes.log` |

**Parsing**: each line becomes `{time, host, process, level, message, ip}`. Syslog and ISO timestamps are both handled; the level is inferred from keywords (`error|fail|denied|invalid` → ERROR/WARN, `accepted|opened` → INFO) or journald priority. IPs are extracted with a regex for the clickable-IP feature.

**API**: `GET /api/logs/view?source=&q=&level=&ip=&since=&limit=&before=`
- Returns the newest `limit` lines (default 200, max 1000) as JSON, newest first, plus a `cursor` for "load older".
- Reads from the end of the file in blocks, so large logs are not loaded into memory.
- Text search is a case-insensitive substring match (never user-supplied regex, to avoid ReDoS).
- `GET /api/logs/download?source=&...` returns the current filtered result as text.

**UI — new "Logs" tab**
- Source selector, search box, level chips (All / Errors / Warnings / Info), time range (last hour / 24 h / 7 days / custom), IP filter.
- Rows colour-coded by level; message text highlights search matches; IPs are clickable (filters by that IP and, when logged in, offers **Block IP**).
- Auto-refresh toggle (poll every 5 s), "Load older" button, "Download filtered" button, copy-line button.
- Empty and error states in plain language ("No permission to read auth.log — run with sudo or join the `adm` group").

Access: viewable without login only when no admin password is configured (same as today); once a password exists, `/api/logs/view` requires login because raw logs are more sensitive than the summary.

## 9. Configuration additions (`config.json`)

```json
"auth": { "password_hash": "", "session_minutes": 30 },
"fixes": { "ssh_dropin_dir": "/etc/ssh/sshd_config.d", "backup_dir": "backups",
           "block_private_ips": true },
"logs": { "sources": { "auth": {"type": "file", "path": "/var/log/auth.log"},
                       "syslog": {"type": "file", "path": "/var/log/syslog"},
                       "ssh": {"type": "journal", "unit": "ssh"},
                       "ufw": {"type": "file", "path": "/var/log/ufw.log"} },
          "default_limit": 200 }
```

## 10. Error handling

- Every endpoint is wrapped like `safe()` today: a failing module returns `{"status":"ERROR","message":...}` rather than a 500 page.
- A failed `apply()` always attempts rollback; if rollback also fails, the record is marked `needs_manual_attention` with the backup path shown to the user.
- Missing commands/files produce a clear message and disable only the affected fix or log source.

## 11. Testing

Tests never touch the real system: fixes operate on a configurable root directory (temp dir in tests) and external commands go through one injectable `_run`.

- `test_auth.py`: hash verify, CSRF rejection, rate limit, fixes disabled without hash.
- `test_fixes.py`: `plan()` diffs, parameter/path/IP validation, drop-in written and removed on rollback, automatic rollback when `sshd -t` fails, refusal to block own IP, key-auth precondition.
- `test_log_viewer.py`: syslog/ISO/journal parsing, level inference, filters, pagination cursor, tail reading on a large generated file, source allow-list (path traversal attempts rejected).
- Manual check on a real Ubuntu VM before release: apply and undo each SSH fix while keeping a second SSH session open.

## 12. Delivery order

1. `log_viewer.py` + Logs tab (read-only, independent, lowest risk).
2. `auth.py` + login UI.
3. `fixes.py` + `fix_history.py` + modal, one fix family at a time (permissions → NTP → SSH → UFW → block IP).
4. README: new "Fixes" and "Logs" sections, security warnings, `--set-password` usage.

## 13. Open assumptions to confirm during review

- Supported OS stays Ubuntu/Debian with systemd.
- A single admin account is enough.
- Backups are kept indefinitely until the user deletes them (no automatic pruning beyond the 20 undoable records).
