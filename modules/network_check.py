"""Network checks: Netplan, DNS and interfaces."""
import glob
import json
import os
import re
import socket
import struct
import subprocess
import time


def _run(cmd, timeout=8):
    """Run a command safely; returns (ok, output)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, (r.stdout or r.stderr).strip()
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "Timed out"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def check_netplan(cfg):
    """List Netplan YAML files and check basic syntax and permissions."""
    directory = cfg.get("network", {}).get("netplan_dir", "/etc/netplan")
    result = {"status": "OK", "files": [], "message": ""}
    if not os.path.isdir(directory):
        result.update(status="WARN", message=f"{directory} does not exist (not Ubuntu/Netplan?)")
        return result
    files = sorted(glob.glob(os.path.join(directory, "*.yaml")))
    if not files:
        result.update(status="WARN", message="No Netplan .yaml files found")
        return result
    for f in files:
        info = {"file": f, "dhcp": None, "addresses": [], "gateway": None,
                "perms": "?", "issues": []}
        try:
            info["perms"] = oct(os.stat(f).st_mode & 0o777)[2:]
            if int(info["perms"], 8) & 0o077:
                info["issues"].append("Permissions too open (600 recommended)")
            with open(f, "r", encoding="utf-8") as fh:
                content = fh.read()
            if "\t" in content:
                info["issues"].append("Contains tabs (invalid YAML)")
            m = re.search(r"dhcp4:\s*(true|false|yes|no)", content, re.I)
            if m:
                info["dhcp"] = m.group(1).lower() in ("true", "yes")
            info["addresses"] = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", content)
            g = re.search(r"(?:gateway4|via):\s*([\d.]+)", content)
            info["gateway"] = g.group(1) if g else None
        except PermissionError:
            info["issues"].append("No read permission (run with sudo)")
        except Exception as e:  # noqa: BLE001
            info["issues"].append(f"Error: {e}")
        if info["issues"]:
            result["status"] = "WARN"
        result["files"].append(info)
    return result


def build_dns_query(host, qid=0x1234):
    """Build a minimal UDP DNS A-record query packet."""
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in host.strip(".").split("."))
    return header + qname + b"\x00" + struct.pack(">HH", 1, 1)


def probe_nameserver(server, host, timeout=2.0):
    """Query one nameserver directly. Returns latency in ms, or None if unreachable."""
    try:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            start = time.monotonic()
            s.sendto(build_dns_query(host), (server, 53))
            data, _ = s.recvfrom(512)
            if len(data) >= 12 and data[:2] == b"\x12\x34":
                return round((time.monotonic() - start) * 1000, 1)
    except (OSError, UnicodeError):
        pass
    return None


def parse_resolvectl(text):
    """Extract DNSSEC / DNS-over-TLS settings from `resolvectl status` output."""
    out = {}
    for key, name in (("DNSSEC setting", "dnssec"), ("DNSOverTLS setting", "dns_over_tls")):
        m = re.search(rf"{key}:\s*(\S+)", text)
        if m:
            out[name] = m.group(1)
    return out


def check_dns(cfg):
    """Read resolv.conf, run a resolution test and probe each nameserver."""
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
        result.update(status="ERROR", message="No nameservers configured")
    ok, _ = _run(["getent", "hosts", net.get("dns_test_host", "debian.org")])
    result["resolution_test"] = "OK" if ok else "FAIL"
    if not ok and result["status"] == "OK":
        result.update(status="WARN", message="Name resolution is failing")

    # Advanced checks: direct nameserver probes, resolver details, redundancy.
    host = net.get("dns_test_host", "debian.org")
    result["probes"] = []
    for ns in result["nameservers"]:
        # 127.0.0.53 is the systemd-resolved stub: probing it is still valid.
        ms = probe_nameserver(ns, host)
        result["probes"].append({"server": ns, "latency_ms": ms})
    unreachable = [p["server"] for p in result["probes"] if p["latency_ms"] is None]
    result["systemd_resolved"] = "127.0.0.53" in result["nameservers"]
    result["dnssec"] = result["dns_over_tls"] = None
    if result["systemd_resolved"]:
        rok, rout = _run(["resolvectl", "status"])
        if rok:
            result.update(parse_resolvectl(rout))
    notes = []
    if unreachable:
        notes.append("Unreachable nameserver(s): " + ", ".join(unreachable))
    if len(result["nameservers"]) == 1 and not result["systemd_resolved"]:
        notes.append("Only one nameserver configured (no redundancy)")
    if notes and result["status"] == "OK":
        result.update(status="WARN", message="; ".join(notes))
    elif notes:
        result["message"] = (result["message"] + "; " if result["message"] else "") + "; ".join(notes)
    return result


def check_interfaces():
    """Interface status via `ip -j link` (JSON) with a text fallback."""
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
        result.update(status="WARN", message="No physical interface is UP")
    return result


def run_network_audit(cfg):
    """Run the full network audit and compute the overall status."""
    data = {"netplan": check_netplan(cfg), "dns": check_dns(cfg), "interfaces": check_interfaces()}
    sts = [v["status"] for v in data.values()]
    data["status"] = "ERROR" if "ERROR" in sts else "WARN" if "WARN" in sts else "OK"
    return data
