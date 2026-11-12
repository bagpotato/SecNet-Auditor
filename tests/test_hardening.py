import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import hardening  # noqa: E402


def _fake(stdout, rc=0):
    def run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr="")
    return run


def test_ufw_inactive_offers_fix(monkeypatch):
    monkeypatch.setattr(hardening.subprocess, "run", _fake("Status: inactive"))
    r = hardening.check_ufw()
    assert r["status"] == "ERROR" and r["active"] is False
    assert r["fix_id"] == "ufw.enable"


def test_ufw_active_has_no_fix(monkeypatch):
    out = "Status: active\nLogging: on\nDefault: deny\n\n22/tcp ALLOW IN Anywhere\n"
    monkeypatch.setattr(hardening.subprocess, "run", _fake(out))
    r = hardening.check_ufw()
    assert r["status"] == "OK" and "fix_id" not in r
