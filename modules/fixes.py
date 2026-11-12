"""Guided fixes: a closed catalogue of previewable, backed-up, undoable changes.

Pipeline (run_fix): validate -> plan -> no-op check -> backup -> apply -> verify
-> automatic rollback on failure -> audit log. Everything runs under one
module-level lock so concurrent requests are serialized.

How to add a fix (Tasks 7-9):
  1. Subclass `Fix`, set `id`, `title`, `risk` ('low'|'medium'|'high').
  2. Override what you need:
       validate(ctx, params) -> dict   normalise params; raise FixValidationError
       targets(ctx, params)  -> list   absolute system paths (e.g. "/etc/x") that
                                       apply() may touch; they are backed up
                                       through ctx.path() before apply()
       is_applied(ctx, params) -> bool True when nothing is left to do (no-op)
       plan(ctx, params) -> dict       {summary, diff, risk_note, files}
       apply(ctx, params) -> dict      do the change (use ctx.run for commands,
                                       ctx.path() for files); raise on failure
       verify(ctx, params) -> bool     re-check after apply
       rollback(ctx, record)           default restores backed-up files; override
                                       to also undo commands (ufw, timedatectl)
     Anything apply() needs to remember for rollback can be put in the dict it
     returns; run_fix stores it as record["details"].
  3. Register it: `register(MyFix())` (adds it to CATALOGUE).
Never touch the system except through ctx.path() and ctx.run so tests can use a
temp root and a fake runner.
"""
import difflib
import glob
import os
import posixpath
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from modules import fix_history
from modules.network_check import _run
from modules.services import parse_sshd_config

_LOCK = threading.Lock()
UNDO_LIMIT = 20
SUDO_MSG = "Run the server with sudo"


class FixValidationError(ValueError):
    """Bad fix id or parameters; reported to the client as HTTP 400."""


@dataclass
class FixContext:
    cfg: dict
    root: str = "/"
    run: Callable = _run
    is_root: bool = True
    client_ip: str = ""
    base: str = ""   # directory that holds backups/ and fixes.log (repo dir); defaults to root

    def path(self, p):
        """Map an absolute system path (/etc/x) under `root`."""
        return os.path.join(self.root, str(p).lstrip("/\\"))

    def _base(self):
        return self.base or self.root

    def backup_root(self):
        name = ((self.cfg or {}).get("fixes") or {}).get("backup_dir") or "backups"
        return name if os.path.isabs(name) else os.path.join(self._base(), name)

    def log_path(self):
        return os.path.join(self._base(), "fixes.log")


class Fix:
    id = ""
    title = ""
    risk = "low"

    def validate(self, ctx, params):
        return dict(params or {})

    def targets(self, ctx, params):
        return []

    def is_applied(self, ctx, params):
        return False

    def plan(self, ctx, params):
        return {"summary": self.title, "diff": "", "risk_note": "",
                "files": self.targets(ctx, params)}

    def apply(self, ctx, params):
        raise NotImplementedError

    def verify(self, ctx, params):
        return True

    def rollback(self, ctx, record):
        fix_history.restore_files(record)


CATALOGUE = {}  # type: dict  # fix id -> Fix instance


def register(fix):
    CATALOGUE[fix.id] = fix
    return fix


# --------------------------------------------------------------------------
# perms.fix_file
# --------------------------------------------------------------------------

def _mode_str(mode):
    return oct(mode & 0o777)[2:].zfill(3)


class PermsFixFile(Fix):
    id = "perms.fix_file"
    title = "Restrict file permissions"
    risk = "low"

    def _expected(self, ctx, params):
        """Validate params["file"] against the allow-list; return (path, mode_str)."""
        f = (params or {}).get("file")
        if not isinstance(f, str) or not f:
            raise FixValidationError("Missing file")
        if "\x00" in f or "\\" in f or posixpath.normpath(f) != f or not f.startswith("/"):
            raise FixValidationError("File is not allowed")
        crit = ((ctx.cfg or {}).get("hardening") or {}).get("critical_files") or {}
        if f in crit:
            expected = str(crit[f])
        else:
            nd = posixpath.normpath(
                ((ctx.cfg or {}).get("network") or {}).get("netplan_dir", "/etc/netplan"))
            if posixpath.dirname(f) == nd and f.endswith(".yaml"):
                expected = "600"
            else:
                raise FixValidationError("File is not allowed")
        try:
            int(expected, 8)
        except ValueError:
            raise FixValidationError("Invalid expected mode in config")
        real = ctx.path(f)
        if os.path.islink(real) or not os.path.isfile(real):
            raise FixValidationError("File does not exist or is not a regular file")
        return f, expected

    def validate(self, ctx, params):
        f, _ = self._expected(ctx, params)
        return {"file": f}

    def targets(self, ctx, params):
        # Only the mode changes, so the file is deliberately NOT backed up: restoring
        # a stale copy of /etc/shadow on undo could overwrite newer accounts/passwords.
        return []

    def _current(self, ctx, f):
        return _mode_str(os.stat(ctx.path(f)).st_mode)

    def is_applied(self, ctx, params):
        f, expected = self._expected(ctx, params)
        return not (int(self._current(ctx, f), 8) & ~int(expected, 8))

    def plan(self, ctx, params):
        f, expected = self._expected(ctx, params)
        cur = self._current(ctx, f)
        return {
            "summary": "{} is more open than it should be (mode {}). It will be set to {}."
                       .format(f, cur, expected),
            "diff": "--- {0}\n+++ {0}\n-mode {1}\n+mode {2}".format(f, cur, expected),
            "risk_note": "Only the permissions change, not the contents. Undo restores the old mode.",
            "files": [f],
        }

    def apply(self, ctx, params):
        f, expected = self._expected(ctx, params)
        previous = self._current(ctx, f)
        os.chmod(ctx.path(f), int(expected, 8))
        return {"file": f, "mode": expected, "previous_mode": previous}

    def verify(self, ctx, params):
        return self.is_applied(ctx, params)

    def rollback(self, ctx, record):
        d = record.get("details") or {}
        f, prev = d.get("file"), d.get("previous_mode")
        if not f or not prev:
            return  # apply() failed before changing anything
        f, _ = self._expected(ctx, {"file": f})   # re-validate: never chmod outside the allow-list
        os.chmod(ctx.path(f), int(prev, 8))


register(PermsFixFile())


# --------------------------------------------------------------------------
# pipeline
# --------------------------------------------------------------------------

def _get_fix(fix_id):
    fix = CATALOGUE.get(fix_id) if isinstance(fix_id, str) else None
    if fix is None:
        raise FixValidationError("Unknown fix")
    return fix


def _checked_params(params):
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise FixValidationError("params must be an object")
    return params


def _plan(ctx, fix, params):
    params = fix.validate(ctx, _checked_params(params))
    p = fix.plan(ctx, params)
    out = {
        "fix_id": fix.id, "title": fix.title, "risk": fix.risk,
        "summary": p.get("summary", ""), "diff": p.get("diff", ""),
        "risk_note": p.get("risk_note", ""),
        "files": list(p.get("files", [])),
        "already_applied": bool(fix.is_applied(ctx, params)),
    }
    return out, params


def get_plan(ctx, fix_id, params):
    """Preview only; changes nothing. Raises FixValidationError on bad input."""
    fix = _get_fix(fix_id)
    return _plan(ctx, fix, params)[0]


def _log(ctx, fix, action, params, result, message, record=None):
    entry = {"action": action, "fix_id": fix.id, "title": fix.title, "params": params,
             "result": result, "message": message, "user": "admin",
             "client_ip": ctx.client_ip}
    if record:
        entry["record_id"] = record.get("id")
    try:
        fix_history.append_log(ctx.log_path(), entry)
    except OSError:
        pass


def _out(result, message, record=None):
    return {"result": result, "message": message, "record": record}


def run_fix(ctx, fix_id, params):
    """validate -> plan -> backup -> apply -> verify -> rollback on failure -> log."""
    fix = _get_fix(fix_id)
    if not ctx.is_root:
        return _out("error", SUDO_MSG)
    with _LOCK:
        plan, params = _plan(ctx, fix, params)
        if plan["already_applied"]:
            msg = "Already applied: {}".format(fix.title)
            _log(ctx, fix, "apply", params, "already_applied", msg)
            return _out("already_applied", msg)

        real_paths = [ctx.path(p) for p in fix.targets(ctx, params)]
        backup_dir = fix_history.backup_files(real_paths, ctx.backup_root(), fix.id)
        record = fix_history.create_record(
            fix.id, params, backup_dir, fix_history.read_backup_meta(backup_dir),
            extra={"title": fix.title, "risk": fix.risk, "result": "pending",
                   "undone": False, "needs_manual_attention": False})

        failure = None
        try:
            details = fix.apply(ctx, params)
            if details:
                record["details"] = details
            if not fix.verify(ctx, params):
                failure = "Check after the change failed"
        except Exception as e:  # noqa: BLE001
            failure = "Could not apply: {}".format(e)

        if failure is None:
            record["result"] = "applied"
            message = "Applied: {}".format(fix.title)
            result = "applied"
        else:
            try:
                fix.rollback(ctx, record)
                record["result"] = result = "reverted"
                message = "Reverted ({}). Nothing was changed.".format(failure)
            except Exception as e:  # noqa: BLE001
                record["result"] = result = "error"
                record["needs_manual_attention"] = True
                message = ("{}; automatic rollback also failed ({}). "
                           "Restore manually from {}".format(failure, e, backup_dir))
        record["message"] = message
        fix_history.save_record(record)
        _log(ctx, fix, "apply", params, record["result"], message, record)
        return _out(result, message, record)


def history(ctx, limit=UNDO_LIMIT):
    """Most recent records, with the fields the UI relies on always present."""
    out = []
    for r in fix_history.list_records(ctx.backup_root(), limit):
        r = dict(r)
        fix = CATALOGUE.get(r.get("fix_id"))
        r.setdefault("title", fix.title if fix else r.get("fix_id", ""))
        r.setdefault("result", "applied")
        r.setdefault("undone", False)
        r.setdefault("needs_manual_attention", False)
        out.append(r)
    return out


def undo(ctx, record_id):
    """Roll back one of the 20 most recent applied records."""
    if not ctx.is_root:
        return _out("error", SUDO_MSG)
    with _LOCK:
        record = next((r for r in fix_history.list_records(ctx.backup_root(), UNDO_LIMIT)
                       if r.get("id") == record_id), None)
        if record is None:
            return _out("error", "Record not found (only the 20 most recent fixes can be undone)")
        fix = CATALOGUE.get(record.get("fix_id"))
        if fix is None:
            return _out("error", "Unknown fix in record", record)
        if record.get("undone"):
            return _out("error", "Already undone", record)
        if record.get("result", "applied") != "applied":
            return _out("error", "Nothing to undo: this fix was not applied", record)
        try:
            fix.rollback(ctx, record)
        except Exception as e:  # noqa: BLE001
            record["needs_manual_attention"] = True
            msg = "Undo failed ({}). Restore manually from {}".format(e, record["backup_dir"])
            fix_history.save_record(record)
            _log(ctx, fix, "undo", record.get("params"), "error", msg, record)
            return _out("error", msg, record)
        record["undone"] = True
        record["undone_time"] = datetime.now().isoformat()
        fix_history.save_record(record)
        msg = "Undone: {}".format(fix.title)
        _log(ctx, fix, "undo", record.get("params"), "applied", msg, record)
        return _out("applied", msg, record)


# --------------------------------------------------------------------------
# ntp.enable
# --------------------------------------------------------------------------

class NtpEnable(Fix):
    id = "ntp.enable"
    title = "Turn on automatic time synchronization"
    risk = "low"

    def _ntp_value(self, ctx):
        """Current `NTP=` value from `timedatectl show` ('yes'/'no'); raises if unreadable."""
        ok, out = ctx.run(["timedatectl", "show"])
        if not ok:
            raise RuntimeError("Cannot query timedatectl: {}".format(out))
        for line in out.splitlines():
            k, _, v = line.partition("=")
            if k.strip() == "NTP":
                return v.strip().lower()
        raise RuntimeError("timedatectl did not report NTP")

    def is_applied(self, ctx, params):
        return self._ntp_value(ctx) == "yes"

    def plan(self, ctx, params):
        return {
            "summary": "Automatic time synchronization (NTP) is off, so the clock may drift. "
                       "It will be turned on.",
            "diff": "$ timedatectl set-ntp true\n-NTP=no\n+NTP=yes",
            "risk_note": "The system clock may be adjusted slightly. "
                         "Undo runs timedatectl set-ntp false.",
            "files": [],
        }

    def apply(self, ctx, params):
        previous = self._ntp_value(ctx)
        ok, out = ctx.run(["timedatectl", "set-ntp", "true"])
        if not ok:
            raise RuntimeError("timedatectl set-ntp true failed: {}".format(out))
        return {"previous_ntp": previous}

    def verify(self, ctx, params):
        return self._ntp_value(ctx) == "yes"

    def rollback(self, ctx, record):
        details = record.get("details") or {}
        if details.get("previous_ntp") == "no":
            ok, out = ctx.run(["timedatectl", "set-ntp", "false"])
            if not ok:
                raise RuntimeError("timedatectl set-ntp false failed: {}".format(out))


register(NtpEnable())


# --------------------------------------------------------------------------
# ssh.* (one drop-in, merged across fixes)
# --------------------------------------------------------------------------

SSH_DROPIN_NAME = "00-secnet.conf"
SSH_HEADER = "# Managed by SecNet-Auditor guided fixes. Remove a line to undo it."


def _ssh_dropin_dir(ctx):
    return posixpath.normpath(
        ((ctx.cfg or {}).get("fixes") or {}).get("ssh_dropin_dir", "/etc/ssh/sshd_config.d"))


def _ssh_dropin_path(ctx):
    return posixpath.join(_ssh_dropin_dir(ctx), SSH_DROPIN_NAME)


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _ssh_effective_opts(ctx):
    """Effective sshd options: drop-ins (sorted) first, then the main config."""
    main = ((ctx.cfg or {}).get("services") or {}).get("ssh_config_path", "/etc/ssh/sshd_config")
    d = ctx.path(_ssh_dropin_dir(ctx))
    files = sorted(glob.glob(os.path.join(d, "*.conf"))) + [ctx.path(main)]
    return parse_sshd_config("\n".join(_read_text(f) for f in files))


def _parse_dropin(text):
    """Ordered [(keyword, value)] of directives in an existing drop-in."""
    items = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            items.append((parts[0], parts[1].strip()))
    return items


def _render_dropin(items):
    return SSH_HEADER + "\n" + "".join("{} {}\n".format(k, v) for k, v in items)


def _has_ssh_key_for_non_root(ctx):
    """True if some non-root user in <root>/etc/passwd has a non-empty authorized_keys."""
    for line in _read_text(ctx.path("/etc/passwd")).splitlines():
        f = line.split(":")
        if len(f) < 6 or f[0] == "root" or f[2] == "0" or not f[5].startswith("/"):
            continue
        keys = ctx.path(posixpath.join(f[5], ".ssh", "authorized_keys"))
        if _read_text(keys).strip():
            return True
    return False


class SshDirectiveFix(Fix):
    """Set one sshd directive in the shared drop-in <ssh_dropin_dir>/00-secnet.conf."""

    def __init__(self, id, title, risk, directive, value, summary, risk_note,
                 needs_key=False, value_cfg=None, default=None):
        self.id, self.title, self.risk = id, title, risk
        self.directive, self._value, self.summary = directive, value, summary
        self.risk_note, self.needs_key = risk_note, needs_key
        self.value_cfg, self.default = value_cfg, default

    def _target_value(self, ctx):
        if self.value_cfg:
            return str(((ctx.cfg or {}).get("services") or {}).get(self.value_cfg, self._value))
        return self._value

    def validate(self, ctx, params):
        if self.needs_key and not _has_ssh_key_for_non_root(ctx):
            raise FixValidationError("Add an SSH key for a non-root user first")
        return {}

    def targets(self, ctx, params):
        return [_ssh_dropin_path(ctx)]

    def is_applied(self, ctx, params):
        cur = _ssh_effective_opts(ctx).get(self.directive.lower(), self.default)
        want = self._target_value(ctx)
        if cur is None:
            return False
        if self.value_cfg:
            return cur.isdigit() and int(cur) <= int(want)
        return cur.lower() == want.lower()

    def _new_text(self, ctx):
        items = _parse_dropin(_read_text(ctx.path(_ssh_dropin_path(ctx))))
        want = self._target_value(ctx)
        items = [(k, v) for k, v in items if k.lower() != self.directive.lower()]
        items.append((self.directive, want))
        return _render_dropin(items)

    def plan(self, ctx, params):
        path = _ssh_dropin_path(ctx)
        old = _read_text(ctx.path(path))
        new = self._new_text(ctx)
        diff = "".join(difflib.unified_diff(
            old.splitlines(True), new.splitlines(True),
            fromfile=path + (" (new file)" if not old else ""), tofile=path))
        return {"summary": self.summary, "diff": diff, "risk_note": self.risk_note,
                "files": [path]}

    def apply(self, ctx, params):
        real = ctx.path(_ssh_dropin_path(ctx))
        new = self._new_text(ctx)
        os.makedirs(os.path.dirname(real), exist_ok=True)
        with open(real, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(new)
        os.chmod(real, 0o644)
        ok, out = ctx.run(["sshd", "-t"])
        if not ok:
            raise RuntimeError("sshd -t rejected the configuration: {}".format(out))
        ok, out = ctx.run(["systemctl", "reload", "ssh"])
        if not ok:
            raise RuntimeError("systemctl reload ssh failed: {}".format(out))
        return {"dropin": _ssh_dropin_path(ctx), "directive": self.directive,
                "value": self._target_value(ctx), "reloaded": True}

    def _live_ok(self, ctx):
        """Ask sshd for its effective config (`sshd -T`). True when it reports the wanted
        value, or when it cannot be queried / does not mention the directive. This catches
        a main sshd_config without an `Include sshd_config.d/*.conf` line, where the
        drop-in would be written but silently ignored."""
        ok, out = ctx.run(["sshd", "-T"])
        if not ok:
            return True
        key = self.directive.lower()
        for line in (out or "").splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == key:
                cur, want = parts[1].strip(), self._target_value(ctx)
                if self.value_cfg:
                    return cur.isdigit() and int(cur) <= int(want)
                return cur.lower() == want.lower()
        return True

    def verify(self, ctx, params):
        return self.is_applied(ctx, params) and self._live_ok(ctx)

    def rollback(self, ctx, record):
        fix_history.restore_files(record)
        if (record.get("details") or {}).get("reloaded"):
            ok, out = ctx.run(["sshd", "-t"])
            if not ok:
                raise RuntimeError("sshd -t failed after restoring: {}".format(out))
            ok, out = ctx.run(["systemctl", "reload", "ssh"])
            if not ok:
                raise RuntimeError("systemctl reload ssh failed: {}".format(out))


register(SshDirectiveFix(
    "ssh.disable_root_login", "Disable root login over SSH", "medium",
    "PermitRootLogin", "no",
    "SSH currently allows logging in directly as root. This will be turned off.",
    "You will no longer be able to log in as root over SSH. Make sure you can log in "
    "as another user (and use sudo) first, and keep a second SSH session open while testing.",
    default="prohibit-password"))
register(SshDirectiveFix(
    "ssh.disable_password_auth", "Disable SSH password logins", "high",
    "PasswordAuthentication", "no",
    "SSH currently accepts passwords. Only SSH keys will be accepted afterwards.",
    "Password logins stop working, so make sure your key works first. "
    "Keep a second SSH session open while testing.",
    needs_key=True, default="yes"))
register(SshDirectiveFix(
    "ssh.disable_empty_passwords", "Refuse empty SSH passwords", "low",
    "PermitEmptyPasswords", "no",
    "SSH allows accounts with an empty password to log in. This will be turned off.",
    "Accounts without a password can no longer log in over SSH. "
    "Keep a second SSH session open while testing.",
    default="no"))
register(SshDirectiveFix(
    "ssh.limit_auth_tries", "Limit SSH login attempts per connection", "low",
    "MaxAuthTries", "4",
    "SSH allows many login attempts per connection. The limit will be lowered.",
    "Connections are dropped after fewer failed attempts; people who mistype often "
    "may need to reconnect. Keep a second SSH session open while testing.",
    value_cfg="max_auth_tries", default="6"))


# --------------------------------------------------------------------------
# ufw.enable / ufw.block_ip
# --------------------------------------------------------------------------

import ipaddress  # noqa: E402

_UFW_EXISTS = "skipping adding existing rule"


def _ufw_status_text(ctx):
    """Text of `ufw status` or None when it cannot be read."""
    ok, out = ctx.run(["ufw", "status"])
    return out if ok else None


def _ufw_added_text(ctx):
    """Text of `ufw show added` (works while the firewall is inactive) or ''."""
    ok, out = ctx.run(["ufw", "show", "added"])
    return out if ok else ""


def _ssh_ports(ctx):
    """Every `Port` in the sshd config (+ drop-ins); [22] when none is set."""
    main = ((ctx.cfg or {}).get("services") or {}).get("ssh_config_path", "/etc/ssh/sshd_config")
    d = ctx.path(_ssh_dropin_dir(ctx))
    files = sorted(glob.glob(os.path.join(d, "*.conf"))) + [ctx.path(main)]
    ports = []
    for f in files:
        for line in _read_text(f).splitlines():
            parts = line.split("#", 1)[0].split()
            if len(parts) == 2 and parts[0].lower() == "port" and parts[1].isdigit():
                n = int(parts[1])
                if 1 <= n <= 65535 and n not in ports:
                    ports.append(n)
    return ports or [22]


def _port_rule_present(text, port):
    """True if `text` (ufw status / show added) already allows <port>/tcp."""
    for line in (text or "").splitlines():
        t = line.split()
        if t and "ALLOW" in t and t[0] in ("{}/tcp".format(port), str(port)):
            return True
        if t[:3] == ["ufw", "allow", "{}/tcp".format(port)]:
            return True
    return False


class UfwEnable(Fix):
    id = "ufw.enable"
    title = "Turn on the firewall"
    risk = "medium"

    def is_applied(self, ctx, params):
        text = _ufw_status_text(ctx)
        return text is not None and "Status: active" in text

    def plan(self, ctx, params):
        ports = _ssh_ports(ctx)
        cmds = ["$ ufw allow {}/tcp".format(p) for p in ports] + ["$ ufw --force enable"]
        return {
            "summary": "The firewall (UFW) is off. SSH (port {}) will be allowed first so you "
                       "are not locked out, then the firewall will be turned on.".format(
                           ", ".join(str(p) for p in ports)),
            "diff": "\n".join(cmds),
            "risk_note": "UFW blocks all other incoming connections by default, so other "
                         "services (web server, etc.) become unreachable until you allow them. "
                         "Undo turns the firewall off again and removes the SSH rule it added.",
            "files": [],
        }

    def apply(self, ctx, params):
        ports = _ssh_ports(ctx)
        existing = _ufw_status_text(ctx) or ""
        added_text = _ufw_added_text(ctx)
        added, pre_existing = [], []

        def cleanup():
            for p in added:
                ctx.run(["ufw", "delete", "allow", "{}/tcp".format(p)])

        for p in ports:
            rule = "{}/tcp".format(p)
            known = _port_rule_present(existing, p) or _port_rule_present(added_text, p)
            ok, out = ctx.run(["ufw", "allow", rule])
            if not ok:
                cleanup()
                raise RuntimeError("ufw allow {} failed: {}".format(rule, out))
            if known or _UFW_EXISTS in (out or "").lower():
                pre_existing.append(p)
            else:
                added.append(p)
        ok, out = ctx.run(["ufw", "--force", "enable"])
        if not ok:
            cleanup()
            raise RuntimeError("ufw --force enable failed: {}".format(out))
        return {"ssh_ports": ports, "allow_rules_added": added,
                "allow_rule_preexisted": bool(pre_existing) and not added,
                "allow_rules_preexisting": pre_existing}

    def verify(self, ctx, params):
        return self.is_applied(ctx, params)

    def rollback(self, ctx, record):
        details = record.get("details") or {}
        if not details:
            return  # apply() failed and cleaned up after itself
        ok, out = ctx.run(["ufw", "disable"])
        if not ok:
            raise RuntimeError("ufw disable failed: {}".format(out))
        errors = []
        for p in details.get("allow_rules_added") or []:
            ok, out = ctx.run(["ufw", "delete", "allow", "{}/tcp".format(p)])
            if not ok:
                errors.append("{}/tcp: {}".format(p, out))
        if errors:
            raise RuntimeError("ufw delete allow failed: " + "; ".join(errors))


def _normalize_ip(value):
    """ipaddress object for `value` with IPv4-mapped IPv6 collapsed to IPv4, or None."""
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or "%" in s or "/" in s:
        return None
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def _deny_rule_present(text, ip):
    """True if `text` (ufw status / show added) has a deny rule from exactly `ip`."""
    for line in (text or "").splitlines():
        t = line.split()
        if t[:3] == ["ufw", "deny", "from"] and len(t) > 3:
            cand = t[3]
        elif "DENY" in t:
            rest = [x for x in t[t.index("DENY") + 1:] if x not in ("IN", "OUT", "FWD")]
            cand = rest[0] if rest else ""
        else:
            continue
        if _normalize_ip(cand) == ip:
            return True
    return False


class UfwBlockIp(Fix):
    id = "ufw.block_ip"
    title = "Block IP"   # the plan summary / diff name the address
    risk = "medium"

    def validate(self, ctx, params):
        ip = _normalize_ip((params or {}).get("ip"))
        if ip is None:
            raise FixValidationError("Not a valid IP address")
        client = _normalize_ip(ctx.client_ip)
        if client is not None and client == ip:
            raise FixValidationError("Refusing to block your own IP address")
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified \
                or ip.is_reserved:
            raise FixValidationError("This address cannot be blocked (loopback, link-local, "
                                     "multicast, reserved or unspecified)")
        if ((ctx.cfg or {}).get("fixes") or {}).get("block_private_ips", True) and ip.is_private:
            raise FixValidationError("Refusing to block a private-network address")
        return {"ip": str(ip)}

    def _present(self, ctx, params):
        ip = _normalize_ip(params["ip"])
        return _deny_rule_present(_ufw_status_text(ctx), ip) or \
            _deny_rule_present(_ufw_added_text(ctx), ip)

    def is_applied(self, ctx, params):
        return self._present(ctx, params)

    def plan(self, ctx, params):
        ip = str(_normalize_ip(params["ip"]))
        text = _ufw_status_text(ctx)
        note = "Connections from this address are refused. Undo removes the rule."
        if text is not None and "Status: active" not in text:
            note += " The firewall is currently off, so the rule only takes effect once it is on."
        return {"summary": "Block all incoming connections from {}.".format(ip),
                "diff": "$ ufw deny from {}".format(ip), "risk_note": note, "files": []}

    def apply(self, ctx, params):
        ip = str(_normalize_ip(params["ip"]))
        ok, out = ctx.run(["ufw", "deny", "from", ip])
        if not ok:
            raise RuntimeError("ufw deny from {} failed: {}".format(ip, out))
        return {"ip": ip, "rule_preexisted": _UFW_EXISTS in (out or "").lower()}

    def verify(self, ctx, params):
        return self._present(ctx, params)

    def rollback(self, ctx, record):
        details = record.get("details") or {}
        if not details or details.get("rule_preexisted"):
            return
        ip = _normalize_ip(details.get("ip"))
        if ip is None:
            raise RuntimeError("Record has no valid IP")
        ok, out = ctx.run(["ufw", "delete", "deny", "from", str(ip)])
        if not ok:
            raise RuntimeError("ufw delete deny from {} failed: {}".format(ip, out))


register(UfwEnable())
register(UfwBlockIp())
