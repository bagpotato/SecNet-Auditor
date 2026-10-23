"""Módulo de hardening: UFW, usuarios UID 0 y permisos de archivos críticos."""
import os
import subprocess


def check_ufw():
    """Comprueba el estado de UFW (requiere root para resultado completo). Solo lectura."""
    res = {"status": "WARN", "active": None, "rules": [], "message": ""}
    try:
        r = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True, timeout=8)
    except FileNotFoundError:
        res.update(status="ERROR", message="UFW no está instalado")
        return res
    except subprocess.TimeoutExpired:
        res["message"] = "Tiempo de espera agotado"
        return res
    out = (r.stdout + r.stderr).strip()
    if r.returncode != 0 and "root" in out.lower():
        res["message"] = "Se requieren privilegios de root (sudo) para consultar el firewall"
        return res
    if "Status: active" in out:
        res.update(status="OK", active=True, message="Firewall activo")
        res["rules"] = [l.strip() for l in out.splitlines()[3:] if l.strip() and not l.startswith("--")]
    elif "inactive" in out:
        res.update(status="ERROR", active=False, message="Firewall INACTIVO: actívalo (ver README)")
    else:
        res["message"] = out or "Estado desconocido"
    return res


def check_uid0():
    """Busca cuentas con UID 0 distintas de root."""
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
        res.update(status="ERROR", message="Usuarios con UID 0 ocultos: " + ", ".join(res["suspicious"]))
    else:
        res["message"] = "Solo root tiene UID 0"
    return res


def check_permissions(cfg):
    """Compara los permisos octales con los esperados (o más restrictivos)."""
    files = cfg.get("hardening", {}).get("critical_files", {})
    rows, worst = [], "OK"
    for path, expected in files.items():
        row = {"file": path, "expected": expected, "actual": "-", "status": "OK", "note": ""}
        try:
            actual = oct(os.stat(path).st_mode & 0o777)[2:].zfill(3)
            row["actual"] = actual
            # Inseguro si concede algún bit que el esperado no concede
            if int(actual, 8) & ~int(expected, 8):
                row.update(status="ERROR", note=f"Más permisivo de lo esperado: ajustar a {expected}")
        except FileNotFoundError:
            row.update(status="INFO", note="No existe")
        except PermissionError:
            row.update(status="WARN", note="Sin acceso")
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
