# Guided Fixes and Log Viewer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a friendly log viewer and a login-protected, previewable, undoable "Fix" workflow to the SecNet-Auditor dashboard.

**Architecture:** New focused modules (`log_viewer`, `auth`, `fix_history`, `fixes`) with plain-dict interfaces, wired into `app.py` routes and `templates/index.html`. Fixes come from a closed catalogue; the browser sends only a `fix_id` plus validated params. All system access goes through an injectable `FixContext` (root dir + command runner) so tests never touch the real system.

**Tech Stack:** Python 3.8+, Flask (sessions, `werkzeug.security`), Bootstrap 5 (CDN, already used), pytest.

**Spec:** `docs/superpowers/specs/2026-11-12-guided-fixes-and-log-viewer-design.md`

## Global Constraints

- Target OS: Ubuntu/Debian with systemd; Python 3.8+ (no `match`, no `X | Y` type unions at runtime).
- Server binds `127.0.0.1` only; no HTTPS in the app.
- Without `auth.password_hash`, every fix endpoint returns 403 `"Fixes are disabled: set an admin password"`; the app stays read-only.
- Fix endpoints require `os.geteuid() == 0`; otherwise the button is disabled with reason `"Run the server with sudo"`.
- Session cookie: `HttpOnly`, `SameSite=Strict`; CSRF token in header `X-CSRF-Token` on every POST.
- Login rate limit: 5 failed attempts per IP per 5 minutes, then 5-minute lockout.
- Drop-in file: `sshd_config.d/00-secnet.conf`; main `sshd_config` is never edited; run `sshd -t` before `systemctl reload ssh`.
- Backups in `backups/<timestamp>-<fix_id>/` (mode 700, git-ignored); audit trail in `fixes.log`; last 20 records are undoable.
- Log sources come only from the `logs.sources` allow-list; the client sends a source id, never a path. Search is substring match, never client regex. `limit` default 200, max 1000.
- Out of scope: Netplan/DNS edits, stopping services, UID 0 remediation, multi-user, TLS.
- Existing style: every module function wrapped by `safe()` in `app.py`; statuses are `OK|WARN|ERROR|INFO`.

## Review Focus

- Log file containing non-UTF-8 bytes or a single very long line: viewer must show replacement characters, not crash.
- Empty or missing log file / rotated log between two "load older" calls: return empty list with a message, not a 500.
- Applying the same fix twice (double click, already fixed): second call is a no-op reported as "Already applied", no duplicate backup.
- Two apply requests arriving concurrently: serialized by a lock; the second sees the first's result.
- IPv6 and IPv4-mapped IPs in logs and in `ufw.block_ip`: parsed, validated, and never block the requester's own address, loopback or (by default) private ranges.
- Session expiring while the confirm modal is open: apply returns 401 and the UI prompts for login instead of failing silently.

---

### Task 1: Log viewer backend

**Files:**
- Create: `modules/log_viewer.py`, `tests/test_log_viewer.py`
- Modify: `app.py` (routes), `config.json` (`logs.sources`, `logs.default_limit`)

**Interfaces:**
- Produces:
  - `parse_line(line: str, year: int = None) -> dict` → keys `time` (str), `host`, `process`, `level` (`ERROR|WARN|INFO`), `message`, `ip` (str or None).
  - `tail_lines(path: str, limit: int, before: int = None) -> tuple[list[str], int]` → newest-first lines and the byte offset cursor for older data (`0` when the start of file is reached).
  - `query_logs(cfg: dict, source: str, q: str = "", level: str = "", ip: str = "", since: str = "", limit: int = 200, before: int = None, runner=None) -> dict` → `{"status", "message", "entries": [dict], "cursor": int|None}`.
- Routes: `GET /api/logs/view`, `GET /api/logs/download` (same params as `query_logs`).

- [ ] **Step 1: Write failing tests in `tests/test_log_viewer.py`**: `test_parse_syslog_line` (`"Nov 12 10:01:02 srv sshd[12]: Failed password for root from 10.0.0.5 port 22"` → process `sshd`, level `WARN`, ip `10.0.0.5`), `test_parse_iso_line`, `test_parse_ipv6`, `test_level_inference` (`Accepted`→INFO, `error`→ERROR), `test_tail_lines_pagination` (generated 5000-line file: first call 200 newest, second call with returned cursor continues without overlap), `test_tail_non_utf8_and_long_line`, `test_tail_empty_file`, `test_query_unknown_source_rejected` (`source="../../etc/passwd"` → status `ERROR`), `test_query_filters` (q, level, ip combine with AND), `test_limit_clamped_to_1000`.
- [ ] **Step 2: Run** `python -m pytest tests/test_log_viewer.py -v` → Expected: FAIL (module missing).
- [ ] **Step 3: Implement `modules/log_viewer.py`** with the signatures above. `tail_lines` reads backwards in 8 KiB blocks and decodes with `errors="replace"`. Journal sources call `journalctl -u <unit> -n <limit> -o short-iso --no-pager` through `runner` (default `modules.network_check._run`). Source lookup is `cfg["logs"]["sources"].get(source)`; anything absent returns an error dict.
- [ ] **Step 4: Add `logs.sources` (`auth`, `syslog`, `ssh` journal unit `ssh`, `ufw`) and `logs.default_limit` to `config.json`.** Add both routes to `app.py` using `safe()`; download returns `text/plain` with `Content-Disposition: attachment`.
- [ ] **Step 5: Run** `python -m pytest tests -q` → Expected: all pass.
- [ ] **Step 6: Commit** `git add -A && git commit -m "feat: log viewer backend"`

### Task 2: Logs tab UI

**Files:**
- Modify: `templates/index.html`

**Interfaces:**
- Consumes: `GET /api/logs/view`, `GET /api/logs/download` from Task 1.
- Produces: JS function `setLogIp(ip: string)` (filters the viewer by IP) used later by Task 9.

- [ ] **Step 1: Add a "Logs" tab** with: source `<select>`, search box, level chips (All/Errors/Warnings/Info), time range select (1 h / 24 h / 7 d), IP filter, auto-refresh toggle (5 s), "Load older", "Download filtered", per-row copy button.
- [ ] **Step 2: Render rows** colour-coded by level (reuse `COLORS`), search matches wrapped in `<mark>` (escape with existing `esc()` before highlighting), IPs rendered as buttons calling `setLogIp`.
- [ ] **Step 3: Plain-language empty/error states** (e.g. "No permission to read auth.log — run with sudo or join the adm group") taken from the API `message`.
- [ ] **Step 4: Verify manually**: `python app.py`, open `http://127.0.0.1:5000`, Logs tab shows entries or a clear message on Windows/no-permission; toggling filters updates results; auto-refresh stops when the tab is hidden.
- [ ] **Step 5: Commit** `git commit -am "feat: logs tab"`

### Task 3: Authentication

**Files:**
- Create: `modules/auth.py`, `tests/test_auth.py`
- Modify: `app.py`, `config.json` (`auth`), `.gitignore` (`instance/`, `backups/`, `fixes.log`), `templates/index.html` (login dialog)

**Interfaces:**
- Produces:
  - `hash_password(password: str) -> str`; `verify_login(cfg: dict, password: str) -> bool` (False when no hash configured).
  - `fixes_enabled(cfg: dict) -> bool`.
  - `class RateLimiter(max_fail=5, window=300, lockout=300, clock=time.time)` with `allowed(key) -> bool`, `fail(key) -> None`, `reset(key) -> None`.
  - `get_or_create_secret(path: str) -> bytes` (creates 32 random bytes, mode 600).
  - `new_csrf_token(session) -> str`; `check_csrf(session, header_value) -> bool` (constant-time).
  - Decorator `login_required` (401 JSON when not logged in, 403 when fixes disabled) and `csrf_required` (403 on bad token), both usable on Flask views.
- Routes: `POST /login`, `POST /logout`, `GET /api/session` → `{logged_in, fixes_enabled, is_root, csrf}`.
- CLI: `python app.py --set-password` (uses `getpass`, writes hash to `config.json`).

- [ ] **Step 1: Write failing tests** `test_verify_login_ok_and_bad`, `test_no_hash_means_disabled`, `test_rate_limiter_locks_after_5_fails` (fake clock; unlocks after 300 s), `test_csrf_mismatch_rejected`, `test_secret_file_created_once`, `test_login_endpoint_sets_session` (Flask test client), `test_post_without_csrf_403`.
- [ ] **Step 2: Run** `python -m pytest tests/test_auth.py -v` → Expected: FAIL.
- [ ] **Step 3: Implement `modules/auth.py`** (werkzeug `generate_password_hash`/`check_password_hash`). In `app.py` set `app.secret_key` from `instance/secret.key`, `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE="Strict"`, session lifetime from `auth.session_minutes` (default 30); add the three routes and `--set-password` handling before `app.run`.
- [ ] **Step 4: Add login dialog and header status** (user badge, Log in/Log out) to `index.html`; store the CSRF token from `/api/session` and send it on every POST via a shared `postJson(url, body)` helper.
- [ ] **Step 5: Run** `python -m pytest tests -q` → Expected: all pass.
- [ ] **Step 6: Commit** `git commit -am "feat: admin login, csrf, rate limit"`

### Task 4: Log access control

**Files:**
- Modify: `app.py`, `tests/test_auth.py`

**Interfaces:**
- Consumes: `login_required`, `fixes_enabled` from Task 3; `/api/logs/view` from Task 1.

- [ ] **Step 1: Write failing tests** `test_logs_view_open_when_no_password`, `test_logs_view_401_when_password_set_and_anonymous`, `test_logs_view_ok_when_logged_in`.
- [ ] **Step 2: Run** `python -m pytest tests/test_auth.py -v` → Expected: the new tests FAIL.
- [ ] **Step 3: Apply a conditional guard** to `/api/logs/view` and `/api/logs/download`: require login only when `fixes_enabled(cfg)` is true. The UI shows the login dialog on 401.
- [ ] **Step 4: Run** `python -m pytest tests -q` → Expected: all pass.
- [ ] **Step 5: Commit** `git commit -am "feat: protect raw logs once a password is set"`

### Task 5: Fix history and undo

**Files:**
- Create: `modules/fix_history.py`, `tests/test_fix_history.py`

**Interfaces:**
- Produces:
  - `backup_files(paths: list, backup_root: str, fix_id: str, now=None) -> str` → backup dir path; stores each file with its mode in `record.json`-ready metadata, dir mode 700.
  - `create_record(fix_id: str, params: dict, backup_dir: str, files: list, extra: dict = None) -> dict` → record written to `<backup_dir>/record.json`.
  - `append_log(log_path: str, entry: dict) -> None` (one JSON line, includes ISO time).
  - `list_records(backup_root: str, limit: int = 20) -> list[dict]` newest first.
  - `restore_files(record: dict) -> None` (restores contents and modes; deletes files that did not exist before, listed in `record["created"]`).

- [ ] **Step 1: Write failing tests** `test_backup_and_restore_roundtrip`, `test_restore_removes_created_file`, `test_restore_preserves_mode`, `test_list_records_limited_and_ordered`, `test_append_log_one_json_line_each`.
- [ ] **Step 2: Run** `python -m pytest tests/test_fix_history.py -v` → Expected: FAIL.
- [ ] **Step 3: Implement** the four functions with `shutil.copy2` and `os.chmod(…, 0o700)` on the backup dir.
- [ ] **Step 4: Run** `python -m pytest tests -q` → Expected: pass.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: fix history, backups, undo primitives"`

### Task 6: Fix framework + permissions fix + modal UI

**Files:**
- Create: `modules/fixes.py`, `tests/test_fixes.py`
- Modify: `app.py`, `templates/index.html`, `config.json` (`fixes`)

**Interfaces:**
- Consumes: Task 3 decorators; Task 5 history functions.
- Produces:
  - `@dataclass FixContext(cfg: dict, root: str = "/", run: Callable = _run, is_root: bool = True, client_ip: str = "")`; `ctx.path(p) -> str` joins `root` and an absolute path.
  - `class Fix` base with `id`, `title`, `risk`, `plan(ctx, params) -> dict` (`{summary, diff, risk_note, files}`), `apply(ctx, params) -> dict`, `verify(ctx, params) -> bool`; raises `FixValidationError(str)` on bad params.
  - `CATALOGUE: Dict[str, Fix]`.
  - `get_plan(ctx, fix_id, params) -> dict`; `run_fix(ctx, fix_id, params) -> dict` → `{"result": "applied|already_applied|reverted|error", "message", "record"}` implementing backup → apply → verify → automatic rollback; guarded by a module-level `threading.Lock`; `undo(ctx, record_id) -> dict`.
  - Fix `perms.fix_file` with params `{"file": str}` valid only for keys of `hardening.critical_files` or `*.yaml` in `network.netplan_dir` (Netplan expected mode `600`).
- Routes: `POST /api/fix/plan`, `POST /api/fix/apply`, `GET /api/fix/history`, `POST /api/fix/undo` — all `login_required` + `csrf_required` (history needs login only).

- [ ] **Step 1: Write failing tests** with a temp `root`: `test_plan_shows_mode_diff`, `test_apply_chmods_and_records_backup`, `test_already_applied_is_noop_without_backup`, `test_path_outside_allowlist_rejected` (`/etc/passwd/../shadow`, `/tmp/x`), `test_undo_restores_mode`, `test_failed_verify_triggers_rollback` (stub `verify` to False), `test_concurrent_apply_serialized` (two threads, one record), `test_unknown_fix_id_rejected`, `test_apply_requires_root_flag`.
- [ ] **Step 2: Run** `python -m pytest tests/test_fixes.py -v` → Expected: FAIL.
- [ ] **Step 3: Implement `modules/fixes.py`**: base class, `FixContext`, `run_fix` pipeline (validate → plan → backup via `fix_history` → `apply` → `verify` → rollback via `restore_files` on failure → `append_log`), the lock, and `PermsFixFile`.
- [ ] **Step 4: Add the four routes to `app.py`**; build `FixContext` from request (`client_ip=request.remote_addr`, `is_root` from `os.geteuid`); add `fixes` block to `config.json` (`ssh_dropin_dir`, `backup_dir`, `block_private_ips`).
- [ ] **Step 5: Add UI**: "Fix" buttons beside permission findings (disabled with tooltip when not root or not logged in); confirm modal (problem sentence, diff in `<pre>`, risk note, "I understand" checkbox for high risk, Apply/Cancel); result toast; History panel with Undo; 401 from apply reopens the login dialog and keeps the modal content.
- [ ] **Step 6: Run** `python -m pytest tests -q` → Expected: pass. Manually verify on Ubuntu VM: fix `/etc/shadow` mode, then Undo.
- [ ] **Step 7: Commit** `git add -A && git commit -m "feat: fix framework, permissions fix, confirm modal, history"`

### Task 7: NTP fix

**Files:**
- Modify: `modules/fixes.py`, `tests/test_fixes.py`, `templates/index.html`

**Interfaces:**
- Consumes: `Fix`, `FixContext` from Task 6.
- Produces: fix `ntp.enable` (no params); `apply` runs `timedatectl set-ntp true`; `verify` checks `timedatectl show` reports `NTP=yes`; backup records previous `NTP` value so `rollback` runs `timedatectl set-ntp false` if it was off.

- [ ] **Step 1: Write failing tests** with a fake `ctx.run`: `test_ntp_plan_names_command`, `test_ntp_apply_calls_set_ntp`, `test_ntp_already_enabled_noop`, `test_ntp_undo_restores_previous_state`.
- [ ] **Step 2: Run** → Expected: FAIL.
- [ ] **Step 3: Implement `NtpEnable`** and register in `CATALOGUE`. Add Fix button on the NTP row in the Services tab.
- [ ] **Step 4: Run** `python -m pytest tests -q` → Expected: pass.
- [ ] **Step 5: Commit** `git commit -am "feat: ntp.enable fix"`

### Task 8: SSH fixes

**Files:**
- Modify: `modules/fixes.py`, `tests/test_fixes.py`, `templates/index.html`

**Interfaces:**
- Consumes: `Fix`, `FixContext`, `parse_sshd_config` from `modules/services.py`.
- Produces: fixes `ssh.disable_root_login`, `ssh.disable_password_auth`, `ssh.disable_empty_passwords`, `ssh.limit_auth_tries` (value from `services.max_auth_tries`). All edit **one drop-in** `<ssh_dropin_dir>/00-secnet.conf`, merging with directives already written by earlier SSH fixes. `apply` writes the drop-in, runs `sshd -t` then `systemctl reload ssh`; on `sshd -t` failure the drop-in is restored from backup and result is `reverted`.
- Precondition for `ssh.disable_password_auth`: at least one non-root user has a non-empty `authorized_keys` under `ctx.root`; otherwise `FixValidationError("Add an SSH key for a non-root user first")`.

- [ ] **Step 1: Write failing tests**: `test_dropin_created_with_directive`, `test_second_ssh_fix_merges_directives`, `test_sshd_test_failure_restores_and_reports_reverted`, `test_reload_only_after_validation`, `test_password_auth_blocked_without_keys`, `test_password_auth_allowed_with_key`, `test_main_sshd_config_untouched`, `test_undo_removes_dropin_when_it_did_not_exist`.
- [ ] **Step 2: Run** → Expected: FAIL.
- [ ] **Step 3: Implement** one parametrised `SshDirectiveFix` class and four registered instances; plan diff is the before/after of the drop-in.
- [ ] **Step 4: Add Fix buttons** on each SSH issue in the Services tab (map issue text → fix id by returning `fix_id` in `analyze_sshd` results through `check_ssh`'s `issues` entries: change issue items to `{"text", "fix_id"}` and update the existing renderer and `tests/test_services.py` accordingly).
- [ ] **Step 5: Run** `python -m pytest tests -q` → Expected: pass. Manually on an Ubuntu VM with a second SSH session open: apply and undo each.
- [ ] **Step 6: Commit** `git commit -am "feat: ssh hardening fixes via drop-in"`

### Task 9: Firewall fixes and Block IP

**Files:**
- Modify: `modules/fixes.py`, `tests/test_fixes.py`, `templates/index.html`

**Interfaces:**
- Consumes: `Fix`, `FixContext`; `setLogIp` from Task 2.
- Produces:
  - `ufw.enable` (no params): `ufw allow <ssh port>/tcp` (port from sshd config, default 22) then `ufw --force enable`; undo runs `ufw disable` and deletes the added allow rule.
  - `ufw.block_ip` params `{"ip": str}`: validated with `ipaddress.ip_address`; rejects `ctx.client_ip`, loopback, link-local, and private ranges when `fixes.block_private_ips` is true; `apply` runs `ufw deny from <ip>`; undo runs `ufw delete deny from <ip>`.

- [ ] **Step 1: Write failing tests** with a fake `ctx.run` recording calls: `test_enable_allows_ssh_before_enable` (call order), `test_enable_custom_ssh_port`, `test_block_ip_validates_format`, `test_block_ip_refuses_own_ip`, `test_block_ip_refuses_loopback_and_private`, `test_block_ip_accepts_ipv6`, `test_block_ip_ipv4_mapped_own_ip_refused`, `test_block_ip_undo_deletes_rule`, `test_block_ip_already_blocked_noop`.
- [ ] **Step 2: Run** → Expected: FAIL.
- [ ] **Step 3: Implement** both fixes and register them. Add a Fix button on UFW-inactive in the Hardening tab, and "Block IP" buttons on the SSH Alerts table rows and on IP buttons in the Logs tab (visible only when logged in).
- [ ] **Step 4: Run** `python -m pytest tests -q` → Expected: pass.
- [ ] **Step 5: Commit** `git commit -am "feat: ufw enable and block ip fixes"`

### Task 10: Documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README**: new "Guided fixes" and "Log viewer" sections, `--set-password` usage, security warnings (run as root only with password set; keep on 127.0.0.1; use SSH second session when testing SSH fixes), updated structure tree, config table rows (`auth.*`, `fixes.*`, `logs.*`), API table (new routes), and replace "Read-only" banner with "Read-only unless an admin password is set".
- [ ] **Step 2: Run** `python -m pytest tests -q` → Expected: pass; run the full manual checklist from the spec §11 on an Ubuntu VM.
- [ ] **Step 3: Commit** `git commit -am "docs: guided fixes and log viewer"`
