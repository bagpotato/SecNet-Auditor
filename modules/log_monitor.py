"""SIEM ligero: detección de fuerza bruta SSH en auth.log mediante regex."""
import re
from collections import defaultdict, deque

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})"
PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from " + IP + r" port"),
    re.compile(r"Invalid user (?P<user>\S*) from " + IP),
    re.compile(r"authentication failure;.*rhost=" + IP + r"(?:\s+user=(?P<user>\S+))?"),
]
SUCCESS = re.compile(r"Accepted \w+ for (?P<user>\S+) from " + IP)


def tail(path, n):
    """Lee las últimas n líneas sin cargar todo el fichero en memoria."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return list(deque(fh, maxlen=n))


def run_log_audit(cfg):
    ssh = cfg.get("ssh", {})
    path = ssh.get("auth_log_path", "/var/log/auth.log")
    threshold = int(ssh.get("failed_attempts_threshold", 5))
    n = int(ssh.get("lines_to_analyze", 2000))
    res = {"status": "OK", "log_path": path, "threshold": threshold, "lines_analyzed": 0,
           "total_failed": 0, "alerts": [], "suspicious": [], "message": ""}
    try:
        lines = tail(path, n)
    except FileNotFoundError:
        res.update(status="WARN", message=f"{path} no existe (¿usa journald?)")
        return res
    except PermissionError:
        res.update(status="WARN", message=f"Sin permisos para leer {path}. Usa sudo o el grupo 'adm'.")
        return res
    res["lines_analyzed"] = len(lines)
    fails, users, last, success = defaultdict(int), defaultdict(set), {}, defaultdict(int)
    for line in lines:
        s = SUCCESS.search(line)
        if s:
            success[s.group("ip")] += 1
        for pat in PATTERNS:
            m = pat.search(line)
            if m:
                ip = m.group("ip")
                fails[ip] += 1
                if m.groupdict().get("user"):
                    users[ip].add(m.group("user"))
                last[ip] = " ".join(line.split()[:3])
                break
    res["total_failed"] = sum(fails.values())
    fw = "ufw"
    for ip, c in sorted(fails.items(), key=lambda x: -x[1]):
        row = {"ip": ip, "attempts": c, "users": sorted(users[ip])[:5], "last_seen": last.get(ip, "-"),
               "compromised": success.get(ip, 0) > 0}
        if c >= threshold:
            row["severity"] = "CRÍTICA" if row["compromised"] or c >= threshold * 3 else "ALTA"
            row["action"] = f"sudo {fw} deny from {ip}"  # solo sugerencia, nunca se ejecuta
            res["alerts"].append(row)
        else:
            row["severity"] = "BAJA"
            res["suspicious"].append(row)
    if res["alerts"]:
        res.update(status="ERROR", message=f"{len(res['alerts'])} IP(s) superan el umbral de {threshold} intentos")
    elif res["suspicious"]:
        res.update(status="WARN", message="Intentos fallidos por debajo del umbral")
    else:
        res["message"] = "Sin intentos fallidos detectados"
    return res
