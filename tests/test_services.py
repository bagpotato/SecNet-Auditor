"""Tests for the pure parsing/analysis helpers (no root or Linux services needed)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.network_check import build_dns_query, parse_resolvectl  # noqa: E402
from modules.services import (analyze_ports, analyze_sshd, analyze_sshd_fixes,
                              check_ssh, missing_headers,  # noqa: E402
                              parse_sshd_config, parse_ss, parse_timedatectl,
                              DEFAULT_INSECURE_PORTS)

SSHD = """
# comment
Port 2222
PermitRootLogin yes
PasswordAuthentication yes
MaxAuthTries 10
PermitRootLogin no
"""

SS = """tcp   LISTEN 0 128 0.0.0.0:22     0.0.0.0:*
tcp   LISTEN 0 128 127.0.0.1:631  0.0.0.0:*
tcp   LISTEN 0 128 [::]:23        [::]:*
udp   UNCONN 0 0   127.0.0.53%lo:53 0.0.0.0:*
"""


def test_sshd_first_value_wins():
    opts = parse_sshd_config(SSHD)
    assert opts["port"] == "2222"
    assert opts["permitrootlogin"] == "yes"


def test_sshd_issues():
    issues = analyze_sshd(parse_sshd_config(SSHD), max_tries=4)
    text = " ".join(issues)
    assert "PermitRootLogin" in text and "PasswordAuthentication" in text and "MaxAuthTries 10" in text


def test_sshd_clean_config():
    assert analyze_sshd({"permitrootlogin": "no", "passwordauthentication": "no", "maxauthtries": "3"}) == []


def test_parse_ss_and_exposure():
    rows = analyze_ports(parse_ss(SS), DEFAULT_INSECURE_PORTS)
    by_port = {r["port"]: r for r in rows}
    assert by_port[22]["exposed"] and by_port[22]["status"] == "OK"
    assert not by_port[631]["exposed"]
    assert by_port[23]["status"] == "WARN" and "Telnet" in by_port[23]["insecure"]
    assert by_port[53]["address"].startswith("127.0.0.53")


def test_timedatectl():
    d = parse_timedatectl("Timezone=Europe/Madrid\nNTP=yes\nNTPSynchronized=no\n")
    assert d["NTP"] == "yes" and d["NTPSynchronized"] == "no"


def test_missing_headers():
    assert missing_headers({"x-frame-options": "DENY"}) == ["X-Content-Type-Options", "Strict-Transport-Security"]


def test_resolvectl():
    out = parse_resolvectl("Global\n  DNSSEC setting: allow-downgrade\n  DNSOverTLS setting: no\n")
    assert out == {"dnssec": "allow-downgrade", "dns_over_tls": "no"}


def test_dns_query_packet():
    pkt = build_dns_query("debian.org")
    assert pkt[:2] == b"\x12\x34" and pkt.endswith(b"\x00\x00\x01\x00\x01")
    assert b"\x06debian\x03org\x00" in pkt


def test_check_ntp_disabled_exposes_fix_id(monkeypatch):
    from modules import services
    monkeypatch.setattr(services, "_run",
                        lambda cmd, *a, **k: (True, "Timezone=UTC\nNTP=no\nNTPSynchronized=no"))
    r = services.check_ntp({})
    assert r["status"] == "WARN" and r["fix_id"] == "ntp.enable"
    monkeypatch.setattr(services, "_run",
                        lambda cmd, *a, **k: (True, "NTP=yes\nNTPSynchronized=yes"))
    assert "fix_id" not in services.check_ntp({})


def test_analyze_sshd_fixes_maps_fix_ids():
    issues = analyze_sshd_fixes(parse_sshd_config(SSHD + "PermitEmptyPasswords yes\nProtocol 1\n"), 4)
    by_fix = {i["fix_id"]: i["text"] for i in issues}
    assert set(by_fix) == {"ssh.disable_root_login", "ssh.disable_password_auth",
                           "ssh.disable_empty_passwords", "ssh.limit_auth_tries", None}
    assert by_fix["ssh.limit_auth_tries"].startswith("MaxAuthTries 10")


def test_check_ssh_issues_are_objects(tmp_path):
    cfg_file = tmp_path / "sshd_config"
    cfg_file.write_text("PermitRootLogin yes\nPasswordAuthentication no\nMaxAuthTries 3\n")
    res = check_ssh({"services": {"ssh_config_path": str(cfg_file), "max_auth_tries": 4}})
    assert res["status"] == "WARN"
    assert res["issues"] == [{"text": "PermitRootLogin yes: disable direct root login",
                              "fix_id": "ssh.disable_root_login"}]
