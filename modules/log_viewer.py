"""Log viewer backend: parse, tail, filter and paginate allow-listed logs."""
import ipaddress
import json
import os
import re
from datetime import datetime, timedelta

from modules.network_check import _run

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_LIMIT = 1000
DEFAULT_LIMIT = 200
BLOCK = 8192
MAX_SCAN_LINES = 50000   # cap on lines examined for one filtered query

_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$")
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$")
_PROC = re.compile(r"^(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")
_TOKEN = re.compile(r"[0-9A-Fa-f:.]{3,}")

_ERROR_WORDS = ("error", "critical", "fatal", "panic", "segfault")
_WARN_WORDS = ("fail", "denied", "invalid", "warn", "refused", "block", "reject", "timeout")


def infer_level(text):
    low = text.lower()
    if any(w in low for w in _ERROR_WORDS):
        return "ERROR"
    if any(w in low for w in _WARN_WORDS):
        return "WARN"
    return "INFO"


def extract_ips(text):
    """Return valid IPv4/IPv6 addresses found in text, in order, de-duplicated."""
    found = []
    for tok in _TOKEN.findall(text):
        tok = tok.rstrip(":.").lstrip(".")
        if "." not in tok and ":" not in tok:
            continue
        try:
            ipaddress.ip_address(tok)
            addr = tok.lower()
        except ValueError:
            continue
        if addr not in found:
            found.append(addr)
    return found


def _norm_ts(ts, year):
    ts = ts.strip()
    for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            d = datetime.strptime("%d %s" % (year, ts), "%Y " + fmt)
            return d.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return ts.replace("T", " ")


_FIX_LEVEL = {"applied": "INFO", "already_applied": "INFO", "reverted": "WARN", "error": "ERROR"}


def _parse_fix_entry(line):
    """Parse one fixes.log JSON line (written by modules.fixes); None if not one."""
    if not line.startswith("{"):
        return None
    try:
        d = json.loads(line)
    except ValueError:
        return None
    if not isinstance(d, dict) or "fix_id" not in d:
        return None
    result = str(d.get("result", ""))
    label = "Undo" if d.get("action") == "undo" else "Fix"
    msg = "{} {}: {}".format(label, result or "?", d.get("title") or d.get("fix_id"))
    if d.get("message"):
        msg += " - {}".format(d["message"])
    ip = d["params"].get("ip") if isinstance(d.get("params"), dict) else None
    ips = extract_ips(str(ip)) if ip else []
    return {"time": str(d.get("time", "")).replace("T", " ")[:19], "host": "",
            "process": str(d["fix_id"]), "level": _FIX_LEVEL.get(result, "INFO"),
            "message": msg, "ip": ips[0] if ips else None}


def parse_line(line, year=None):
    """Parse one syslog/ISO/journal line into a plain dict."""
    year = year or datetime.now().year
    line = line.rstrip("\r\n")
    fx = _parse_fix_entry(line)
    if fx is not None:
        return fx
    time_s, host, rest = "", "", line
    m = _SYSLOG.match(line)
    if m:
        time_s = _norm_ts(m.group("ts"), year)
        host, rest = m.group("host"), m.group("rest")
    else:
        m = _ISO.match(line)
        if m:
            time_s = m.group("ts").replace("T", " ")
            host, rest = m.group("host"), m.group("rest")
    process, message = "", rest
    pm = _PROC.match(rest)
    if pm:
        process, message = pm.group("proc"), pm.group("msg")
    ips = extract_ips(message)
    return {
        "time": time_s, "host": host, "process": process,
        "level": infer_level(message or line), "message": message,
        "ip": ips[0] if ips else None,
    }


def _tail_raw(path, limit, before=None):
    """Like tail_lines but returns undecoded byte lines (newest first)."""
    limit = max(1, int(limit))
    try:
        size = os.path.getsize(path)
        end = size if before is None else max(0, min(int(before), size))
        if end == 0:
            return [], 0
        with open(path, "rb") as fh:
            pos = end
            buf = b""
            while pos > 0 and buf.count(b"\n") <= limit:
                step = min(BLOCK, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
    except OSError:
        return [], 0

    parts = buf.split(b"\n")
    start = pos
    if pos > 0:  # first piece may be a partial line; drop it
        start = pos + len(parts[0]) + 1
        parts = parts[1:]
    if parts and parts[-1] == b"":
        parts.pop()
    if len(parts) > limit:
        drop = parts[:-limit]
        start += sum(len(p) + 1 for p in drop)
        parts = parts[-limit:]
    parts.reverse()
    return parts, start


def tail_lines(path, limit, before=None):
    """Read up to `limit` lines ending at byte offset `before` (default EOF).

    Returns (lines newest-first, cursor). cursor is the byte offset where the
    returned data starts; 0 means the beginning of the file was reached.
    Missing/empty files return ([], 0).
    """
    raw, start = _tail_raw(path, limit, before)
    return [b.decode("utf-8", errors="replace").rstrip("\r") for b in raw], start


def _parse_since(since, now=None):
    now = now or datetime.now()
    since = (since or "").strip()
    if not since:
        return None
    m = re.fullmatch(r"(\d+)\s*([hdm])", since.lower())
    if m:
        n = int(m.group(1))
        unit = {"h": "hours", "d": "days", "m": "minutes"}[m.group(2)]
        return now - timedelta(**{unit: n})
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(since, fmt)
        except ValueError:
            pass
    return None


def _entry_dt(entry, now):
    t = entry.get("time", "")
    try:
        d = datetime.strptime(t[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    if d > now + timedelta(days=1):  # syslog lines lack a year; assume last year
        d = d.replace(year=d.year - 1)
    return d


def _norm_ip(s):
    try:
        return str(ipaddress.ip_address(s.strip()))
    except ValueError:
        return s.strip().lower()


def _matcher(q, level, ip, since_dt, now):
    q = (q or "").lower()
    level = (level or "").strip().upper()
    if level in ("ALL", "*"):
        level = ""
    if level == "WARNING":
        level = "WARN"
    ip_n = _norm_ip(ip) if ip else ""

    def ok(entry):
        if level and entry["level"] != level:
            return False
        if q and q not in entry["raw"].lower():
            return False
        if ip_n and ip_n not in [_norm_ip(a) for a in extract_ips(entry["message"])]:
            return False
        if since_dt is not None:
            d = _entry_dt(entry, now)
            if d is not None and d < since_dt:
                return False
        return True
    return ok


def _clamp(limit, default=DEFAULT_LIMIT):
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = default
    return max(1, min(limit, MAX_LIMIT))


def _error(msg):
    return {"status": "ERROR", "message": msg, "entries": [], "cursor": None}


def _mk(line, year):
    e = parse_line(line, year)
    e["raw"] = line
    return e


def query_logs(cfg, source, q="", level="", ip="", since="", limit=DEFAULT_LIMIT,
               before=None, runner=None):
    """Return filtered entries (newest first) from an allow-listed source."""
    logs_cfg = (cfg or {}).get("logs", {}) or {}
    sources = logs_cfg.get("sources", {}) or {}
    src = sources.get(source) if isinstance(source, str) else None
    if not isinstance(src, dict):
        return _error("Unknown log source")
    default = _clamp(logs_cfg.get("default_limit", DEFAULT_LIMIT))
    limit = _clamp(limit, default)
    now = datetime.now()
    year = now.year
    ok = _matcher(q, level, ip, _parse_since(since, now), now)
    filtering = bool(q or level or ip or since)

    entries, cursor = [], None
    if src.get("type") == "journal":
        unit = str(src.get("unit", ""))
        if not re.fullmatch(r"[A-Za-z0-9_.@:-]+", unit):
            return _error("Invalid journal unit in config")
        run = runner or _run
        n = 5000 if filtering else limit
        good, out = run(["journalctl", "-u", unit, "-n", str(n), "-o", "short-iso", "--no-pager"])
        if not good:
            return _error("Cannot read journal for '%s': %s" % (unit, out or "no output"))
        lines = [ln for ln in out.splitlines() if ln.strip() and not ln.startswith("-- ")]
        for ln in reversed(lines):
            e = _mk(ln, year)
            if ok(e):
                entries.append(e)
                if len(entries) >= limit:
                    break
    elif src.get("type") == "file":
        path = src.get("path", "")
        if path and not os.path.isabs(path):
            path = os.path.join(REPO_DIR, path)   # relative paths resolve against the repo dir
        if not path or not os.path.isfile(path):
            return {"status": "WARN", "message": "Log file not found: %s" % (path or "(none)"),
                    "entries": [], "cursor": None}
        if not os.access(path, os.R_OK):
            return {"status": "ERROR",
                    "message": "No permission to read %s - run with sudo or join the adm group"
                               % os.path.basename(path),
                    "entries": [], "cursor": None}
        pos, scanned = before, 0
        chunk = max(limit, 1000) if filtering else limit
        while len(entries) < limit and scanned < MAX_SCAN_LINES:
            lines, start = _tail_raw(path, chunk, pos)
            scanned += len(lines)
            for i, rawb in enumerate(lines):
                e = _mk(rawb.decode("utf-8", errors="replace").rstrip("\r"), year)
                if ok(e):
                    entries.append(e)
                    if len(entries) >= limit:
                        # resume right after the last consumed line (older data)
                        rest = lines[i + 1:]
                        start = start + sum(len(r) + 1 for r in rest)
                        break
            cursor = start
            if start == 0 or not lines:
                break
            pos = start
        if cursor == 0:
            cursor = None
    else:
        return _error("Unsupported log source type")

    if not entries:
        msg = "No matching log entries" if filtering or before else "Log is empty"
        return {"status": "INFO", "message": msg, "entries": [], "cursor": cursor}
    return {"status": "OK", "message": "%d entries" % len(entries),
            "entries": entries, "cursor": cursor}


def format_text(result):
    """Plain-text rendering of a query result for download."""
    return "\n".join(e.get("raw", "") for e in result.get("entries", [])) + "\n"
