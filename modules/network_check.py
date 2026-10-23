"""Módulo de verificación de red: Netplan, DNS e interfaces."""
import glob
import json
import os
import re
import subprocess


def _run(cmd, timeout=8):
    """Ejecuta un comando de forma segura; devuelve (ok, salida)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, (r.stdout or r.stderr).strip()
    except FileNotFoundError:
        return False, f"Comando no encontrado: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "Tiempo de espera agotado"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def check_netplan(cfg):
    """Lista los YAML de Netplan y comprueba sintaxis básica y permisos."""
    directory = cfg.get("network", {}).get("netplan_dir", "/etc/netplan")
    result = {"status": "OK", "files": [], "message": ""}
    if not os.path.isdir(directory):
        result.update(status="WARN", message=f"{directory} no existe (¿no es Ubuntu/Netplan?)")
        return result
    files = sorted(glob.glob(os.path.join(directory, "*.yaml")))
    if not files:
        result.update(status="WARN", message="No hay archivos .yaml de Netplan")
        return result
    for f in files:
        info = {"file": f, "dhcp": None, "addresses": [], "gateway": None,
                "perms": "?", "issues": []}
        try:
            info["perms"] = oct(os.stat(f).st_mode & 0o777)[2:]
            if int(info["perms"], 8) & 0o077:
                info["issues"].append("Permisos demasiado abiertos (recomendado 600)")
            with open(f, "r", encoding="utf-8") as fh:
                content = fh.read()
            if "\t" in content:
                info["issues"].append("Contiene tabuladores (YAML inválido)")
            m = re.search(r"dhcp4:\s*(true|false|yes|no)", content, re.I)
            if m:
                info["dhcp"] = m.group(1).lower() in ("true", "yes")
            info["addresses"] = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", content)
            g = re.search(r"(?:gateway4|via):\s*([\d.]+)", content)
            info["gateway"] = g.group(1) if g else None
        except PermissionError:
            info["issues"].append("Sin permisos de lectura (ejecuta con sudo)")
        except Exception as e:  # noqa: BLE001
            info["issues"].append(f"Error: {e}")
        if info["issues"]:
            result["status"] = "WARN"
        result["files"].append(info)
    return result


def check_dns(cfg):
    """Lee resolv.conf y prueba una resolución real."""
    net = cfg.get("network", {})
    path = net.get("resolv_conf", "/etc/resolv.conf")
    result = {"status": "OK", "nameservers": [], "search": [], "resolution_test": None, "message": ""}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("nameserver"):
                    result["nameservers"].append(line.split()[1])
                elif line.startswith("search"):
                    result["search"] = line.split()[1:]
    except (FileNotFoundError, PermissionError) as e:
        result.update(status="ERROR", message=str(e))
        return result
    if not result["nameservers"]:
        result.update(status="ERROR", message="No hay nameservers configurados")
    ok, _ = _run(["getent", "hosts", net.get("dns_test_host", "debian.org")])
    result["resolution_test"] = "OK" if ok else "FALLO"
    if not ok and result["status"] == "OK":
        result.update(status="WARN", message="La resolución de nombres falla")
    return result


def check_interfaces():
    """Estado de interfaces con `ip -j link` (JSON) o fallback textual."""
    result = {"status": "OK", "interfaces": [], "message": ""}
    ok, out = _run(["ip", "-j", "link"])
    if ok:
        try:
            for i in json.loads(out):
                result["interfaces"].append({
                    "name": i.get("ifname"), "state": i.get("operstate", "UNKNOWN"),
                    "mac": i.get("address", "-"), "mtu": i.get("mtu")})
        except json.JSONDecodeError:
            ok = False
    if not ok:
        ok, out = _run(["ip", "link"])
        if not ok:
            result.update(status="ERROR", message=out)
            return result
        for m in re.finditer(r"^\d+:\s+([^:@]+).*state\s+(\w+)", out, re.M):
            result["interfaces"].append({"name": m.group(1), "state": m.group(2), "mac": "-", "mtu": None})
    real = [i for i in result["interfaces"] if i["name"] != "lo"]
    if not any(i["state"] == "UP" for i in real):
        result.update(status="WARN", message="Ninguna interfaz física está UP")
    return result


def run_network_audit(cfg):
    """Ejecuta toda la auditoría de red y calcula estado global."""
    data = {"netplan": check_netplan(cfg), "dns": check_dns(cfg), "interfaces": check_interfaces()}
    sts = [v["status"] for v in data.values()]
    data["status"] = "ERROR" if "ERROR" in sts else "WARN" if "WARN" in sts else "OK"
    return data
