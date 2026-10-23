"""Hardening checks: UFW, UID 0 users and critical file permissions."""
import os
import subprocess


def check_ufw():
    """Check UFW status (needs root for full results). Read-only."""
    res = {"status": "WARN", "active": None, "rules": [], "message": ""}
    try:
        r = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True, timeout=8)
    except FileNotFoundError:
        res.update(status="ERROR", message="UFW is not installed")
        return res
    except subprocess.TimeoutExpired:
        res["message"] = "Timed out"
        return res
    out = (r.stdout + r.stderr).strip()
    if r.returncode != 0 and "root" in out.lower():
        res["message"] = "Root privileges (sudo) are required to query the firewall"
        return res
    if "Status: active" in out:
        res.update(status="OK", active=True, message="Firewall active")
        res["rules"] = [l.strip() for l in out.splitlines()[3:] if l.strip() and not l.startswith("--")]
    elif "inactive" in out:
        res.update(status="ERROR", active=False, message="Firewall INACTIVE: enable it (see README)")
    else:
        res["message"] = out or "Unknown status"
    return res


def check_uid0():
    """Find accounts with UID 0 other than root."""
    res = {"status": "OK", "uid0_users": [], "suspicious": [], "message": ""}
    try:
        with open("/etc/passwd", "r", encoding="utf-8") as fh:
            for line in fh:
                p = line.strip().split(":")
                if len(p) >= 7 and p[2] == "0":
                    res["uid0_users"].append(p[0])
                    if p[0] != "root":
                        res["suspicious"].append(p[0])
    except (PermissionError, FileNotFoundError) as e:
        res.update(status="ERROR", message=str(e))
        return res
    if res["suspicious"]:
        res.update(status="ERROR", message="Hidden UID 0 users: " + ", ".join(res["suspicious"]))
    else:
        res["message"] = "Only root has UID 0"
    return res


def check_permissions(cfg):
    """Compare octal permissions against the expected ones (or stricter)."""
    files = cfg.get("hardening", {}).get("critical_files", {})
    rows, worst = [], "OK"
    for path, expected in files.items():
        row = {"file": path, "expected": expected, "actual": "-", "status": "OK", "note": ""}
        try:
            actual = oct(os.stat(path).st_mode & 0o777)[2:].zfill(3)
            row["actual"] = actual
            # Insecure if it grants any bit the expected mode does not
            if int(actual, 8) & ~int(expected, 8):
                row.update(status="ERROR", note=f"More permissive than expected: set to {expected}")
        except FileNotFoundError:
            row.update(status="INFO", note="Does not exist")
        except PermissionError:
            row.update(status="WARN", note="No access")
        if row["status"] == "ERROR":
            worst = "ERROR"
        elif row["status"] == "WARN" and worst == "OK":
            worst = "WARN"
        rows.append(row)
    return {"status": worst, "files": rows}


def run_hardening_audit(cfg):
    data = {"ufw": check_ufw(), "uid0": check_uid0(), "permissions": check_permissions(cfg)}
    sts = [v["status"] for v in data.values()]
    data["status"] = "ERROR" if "ERROR" in sts else "WARN" if "WARN" in sts else "OK"
    return data
