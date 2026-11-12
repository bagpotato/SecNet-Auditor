"""Service checks: SSH, listening ports, DHCP, NTP and web servers. Read-only."""
import glob
import os
import re
import ssl
import urllib.error
import urllib.request

from modules.network_check import _run

DEFAULT_INSECURE_PORTS = {
    21: "FTP (cleartext)", 23: "Telnet (cleartext)", 69: "TFTP",
    110: "POP3 (cleartext)", 143: "IMAP (cleartext)", 512: "rexec",
    513: "rlogin", 514: "rsh", 2049: "NFS", 5900: "VNC",
}
WEB_HEADERS = ("X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security")


def _worst(statuses):
    return "ERROR" if "ERROR" in statuses else "WARN" if "WARN" in statuses else "OK"


# ---------------------------------------------------------------- SSH
def parse_sshd_config(text):
    """Return {lowercase keyword: first value}. sshd uses the first occurrence."""
    opts = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            opts.setdefault(parts[0].lower(), parts[1].strip())
    return opts


def analyze_sshd_fixes(opts, max_tries=4):
    """Return issues as {"text", "fix_id"}; fix_id is None when no guided fix exists."""
    issues = []
    if opts.get("permitrootlogin", "prohibit-password").lower() == "yes":
        issues.append({"text": "PermitRootLogin yes: disable direct root login",
                       "fix_id": "ssh.disable_root_login"})
    if opts.get("passwordauthentication", "yes").lower() == "yes":
        issues.append({"text": "PasswordAuthentication yes: prefer key-based authentication",
                       "fix_id": "ssh.disable_password_auth"})
    if opts.get("permitemptypasswords", "no").lower() == "yes":
        issues.append({"text": "PermitEmptyPasswords yes: accounts without a password may log in",
                       "fix_id": "ssh.disable_empty_passwords"})
    if opts.get("protocol") == "1":
        issues.append({"text": "Protocol 1 is obsolete and insecure", "fix_id": None})
    tries = opts.get("maxauthtries", "6")
    if tries.isdigit() and int(tries) > max_tries:
        issues.append({"text": f"MaxAuthTries {tries}: recommended {max_tries} or less",
                       "fix_id": "ssh.limit_auth_tries"})
    return issues


def analyze_sshd(opts, max_tries=4):
    """Return a list of issue strings for the parsed options."""
    return [i["text"] for i in analyze_sshd_fixes(opts, max_tries)]


def check_ssh(cfg):
    sv = cfg.get("services", {})
    path = sv.get("ssh_config_path", "/etc/ssh/sshd_config")
    res = {"status": "OK", "port": "22", "issues": [], "message": ""}
    # Include files first: sshd keeps the first value it sees.
    files = sorted(glob.glob(os.path.join(os.path.dirname(path), "sshd_config.d", "*.conf"))) + [path]
    text, read_any = "", False
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                text += fh.read() + "\n"
            read_any = True
        except FileNotFoundError:
            continue
        except PermissionError:
            res.update(status="WARN", message=f"No read permission on {f} (run with sudo)")
            return res
    if not read_any:
        res.update(status="WARN", message=f"{path} not found (OpenSSH server not installed?)")
        return res
    opts = parse_sshd_config(text)
    res["port"] = opts.get("port", "22")
    res["issues"] = analyze_sshd_fixes(opts, sv.get("max_auth_tries", 4))
    if res["issues"]:
        res.update(status="WARN", message=f"{len(res['issues'])} issue(s) found")
    else:
        res["message"] = "sshd_config looks reasonable"
    return res


# -------------------------------------------------------------- Ports
def parse_ss(text):
    """Parse `ss -tulnH` output into [{proto, address, port}]."""
    rows = []
    for line in text.splitlines():
        p = line.split()
        if len(p) < 5 or p[0] not in ("tcp", "udp"):
            continue
        addr, _, port = p[4].rpartition(":")
        if port.isdigit():
            rows.append({"proto": p[0], "address": addr.strip("[]") or "*", "port": int(port)})
    return rows


def analyze_ports(rows, insecure):
    """Mark exposed listeners and known-insecure services."""
    out = []
    for r in rows:
        r = dict(r)
        r["exposed"] = r["address"] in ("0.0.0.0", "*", "::")
        r["insecure"] = insecure.get(r["port"])
        r["status"] = "WARN" if (r["insecure"] and r["exposed"]) else "OK"
        out.append(r)
    return out


def check_ports(cfg):
    insecure = dict(DEFAULT_INSECURE_PORTS)
    for k, v in cfg.get("services", {}).get("insecure_ports", {}).items():
        insecure[int(k)] = v
    ok, out = _run(["ss", "-tulnH"])
    if not ok:
        return {"status": "WARN", "listeners": [], "message": out}
    rows = analyze_ports(parse_ss(out), insecure)
    bad = [r for r in rows if r["status"] == "WARN"]
    return {"status": "WARN" if bad else "OK", "listeners": rows,
            "message": f"{len(bad)} insecure service(s) exposed" if bad
            else f"{len(rows)} listening socket(s), none insecure"}


# --------------------------------------------------------------- DHCP
def check_dhcp(cfg):
    res = {"status": "OK", "message": ""}
    ok, out = _run(["networkctl", "list", "--no-legend"])
    if not ok:
        res.update(status="WARN", message=f"Cannot query networkd: {out}")
        return res
    ok, st = _run(["networkctl", "status", "--no-pager"])
    uses_dhcp = bool(re.search(r"DHCP\w*:\s*(yes|ipv4|ipv6)", st, re.I)) or "DHCP4 Client" in st
    leases = glob.glob("/run/systemd/netif/leases/*") + glob.glob("/var/lib/dhcp/*.leases")
    if uses_dhcp and not leases:
        res.update(status="WARN", message="DHCP appears enabled but no lease file was found")
    else:
        res["message"] = "DHCP lease present" if leases else "No DHCP in use (static addressing)"
    return res


# ---------------------------------------------------------------- NTP
def parse_timedatectl(text):
    return dict(l.split("=", 1) for l in text.splitlines() if "=" in l)


def check_ntp(cfg):
    ok, out = _run(["timedatectl", "show"])
    if not ok:
        return {"status": "WARN", "message": f"Cannot query timedatectl: {out}"}
    d = parse_timedatectl(out)
    synced = d.get("NTPSynchronized") == "yes"
    enabled = d.get("NTP") == "yes"
    res = {"synchronized": synced, "ntp_enabled": enabled, "timezone": d.get("Timezone", "?")}
    if synced:
        res.update(status="OK", message="Clock synchronized")
    elif not enabled:
        res.update(status="WARN", message="NTP is disabled: the clock may drift",
                   fix_id="ntp.enable")
    else:
        res.update(status="WARN", message="NTP enabled but not yet synchronized")
    return res


# ---------------------------------------------------------- HTTP(S)
def _service_active(name):
    ok, out = _run(["systemctl", "is-active", name])
    return out.strip() == "active"


def missing_headers(headers):
    have = {k.lower() for k in headers}
    return [h for h in WEB_HEADERS if h.lower() not in have]


def check_web(cfg):
    active = [s for s in ("nginx", "apache2") if _service_active(s)]
    if not active:
        return {"status": "OK", "servers": [], "issues": [], "message": "No web server running"}
    urls = cfg.get("services", {}).get("web_check_urls", ["http://127.0.0.1", "https://127.0.0.1"])
    issues = []
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # local probe only
    reachable = {}
    for u in urls:
        try:
            with urllib.request.urlopen(u, timeout=4, context=ctx) as r:
                reachable[u] = r.headers
        except urllib.error.HTTPError as e:
            reachable[u] = e.headers
        except Exception:  # noqa: BLE001
            continue
    if not any(u.startswith("https") for u in reachable):
        issues.append("No HTTPS response on localhost: TLS not configured?")
    for u, h in reachable.items():
        miss = missing_headers(h)
        if miss:
            issues.append(f"{u}: missing headers {', '.join(miss)}")
    return {"status": "WARN" if issues else "OK", "servers": active, "issues": issues,
            "message": f"Active: {', '.join(active)}" + (f" · {len(issues)} issue(s)" if issues else "")}


def run_services_audit(cfg):
    data = {"ssh": check_ssh(cfg), "ports": check_ports(cfg), "dhcp": check_dhcp(cfg),
            "ntp": check_ntp(cfg), "web": check_web(cfg)}
    data["status"] = _worst([v["status"] for v in data.values()])
    return data
