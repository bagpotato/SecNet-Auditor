import json
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import fixes, fix_history, auth  # noqa: E402
from modules.fixes import FixContext, FixValidationError  # noqa: E402

# Windows only knows read-only vs writable, so use modes it can represent.
BAD, GOOD = (0o666, "444") if sys.platform == "win32" else (0o644, "600")
SHADOW = "/etc/shadow"


def make_ctx(tmp_path, **kw):
    cfg = {"hardening": {"critical_files": {SHADOW: GOOD}},
           "network": {"netplan_dir": "/etc/netplan"},
           "fixes": {"backup_dir": "backups"}}
    f = tmp_path / "etc" / "shadow"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("root:x\n")
    os.chmod(str(f), BAD)
    return FixContext(cfg=cfg, root=str(tmp_path), base=str(tmp_path), **kw)


def mode(tmp_path, rel="etc/shadow"):
    return oct(os.stat(str(tmp_path / rel)).st_mode & 0o777)[2:].zfill(3)


def test_plan_shows_mode_diff(tmp_path):
    ctx = make_ctx(tmp_path)
    p = fixes.get_plan(ctx, "perms.fix_file", {"file": SHADOW})
    assert p["risk"] == "low" and p["title"] and p["summary"] and p["risk_note"]
    assert "+mode " + GOOD in p["diff"] and "-mode " + oct(BAD)[2:] in p["diff"]
    assert p["files"] == [SHADOW]
    assert mode(tmp_path) == oct(BAD)[2:]  # plan changes nothing


def test_apply_chmods_and_records_backup(tmp_path):
    ctx = make_ctx(tmp_path)
    r = fixes.run_fix(ctx, "perms.fix_file", {"file": SHADOW})
    assert r["result"] == "applied" and r["message"]
    assert mode(tmp_path) == GOOD
    rec = r["record"]
    assert rec["title"] and rec["result"] == "applied" and rec["undone"] is False
    assert os.path.isdir(rec["backup_dir"])
    assert str(tmp_path / "backups") in rec["backup_dir"]
    h = fixes.history(ctx)
    assert [x["id"] for x in h] == [rec["id"]]
    lines = (tmp_path / "fixes.log").read_text().splitlines()
    e = json.loads(lines[-1])
    assert e["fix_id"] == "perms.fix_file" and e["result"] == "applied" and e["title"]


def test_already_applied_is_noop_without_backup(tmp_path):
    ctx = make_ctx(tmp_path)
    assert fixes.run_fix(ctx, "perms.fix_file", {"file": SHADOW})["result"] == "applied"
    r = fixes.run_fix(ctx, "perms.fix_file", {"file": SHADOW})
    assert r["result"] == "already_applied" and r["record"] is None
    assert len(os.listdir(str(tmp_path / "backups"))) == 1


def test_path_outside_allowlist_rejected(tmp_path):
    ctx = make_ctx(tmp_path)
    for bad in ("/etc/passwd/../shadow", "/tmp/x", "", "etc/shadow", "/etc/../etc/shadow",
                None, 5, "/etc/netplan/../shadow.yaml"):
        with pytest.raises(FixValidationError):
            fixes.get_plan(ctx, "perms.fix_file", {"file": bad})
        with pytest.raises(FixValidationError):
            fixes.run_fix(ctx, "perms.fix_file", {"file": bad})
    assert not (tmp_path / "backups").exists()


def test_netplan_yaml_allowed(tmp_path):
    ctx = make_ctx(tmp_path)
    y = tmp_path / "etc" / "netplan" / "01-x.yaml"
    y.parent.mkdir()
    y.write_text("network: {}\n")
    os.chmod(str(y), BAD)
    ctx.cfg["hardening"]["critical_files"] = {}
    if sys.platform == "win32":
        pytest.skip("netplan expects 600, not representable on Windows")
    assert fixes.run_fix(ctx, "perms.fix_file", {"file": "/etc/netplan/01-x.yaml"})["result"] == "applied"
    assert mode(tmp_path, "etc/netplan/01-x.yaml") == "600"
    with pytest.raises(FixValidationError):
        fixes.get_plan(ctx, "perms.fix_file", {"file": "/etc/netplan/sub/x.yaml"})
    with pytest.raises(FixValidationError):
        fixes.get_plan(ctx, "perms.fix_file", {"file": "/etc/netplan/x.txt"})


def test_undo_restores_mode(tmp_path):
    ctx = make_ctx(tmp_path)
    rec = fixes.run_fix(ctx, "perms.fix_file", {"file": SHADOW})["record"]
    r = fixes.undo(ctx, rec["id"])
    assert r["result"] == "applied" and r["record"]["undone"] is True
    assert mode(tmp_path) == oct(BAD)[2:]
    assert fixes.history(ctx)[0]["undone"] is True
    assert json.loads((tmp_path / "fixes.log").read_text().splitlines()[-1])["action"] == "undo"
    assert fixes.undo(ctx, rec["id"])["result"] == "error"          # not twice
    assert fixes.undo(ctx, "nope")["result"] == "error"
    assert fixes.undo(ctx, "../..")["result"] == "error"


def test_failed_verify_triggers_rollback(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    monkeypatch.setattr(fixes.PermsFixFile, "verify", lambda self, c, p: False)
    r = fixes.run_fix(ctx, "perms.fix_file", {"file": SHADOW})
    assert r["result"] == "reverted"
    assert mode(tmp_path) == oct(BAD)[2:]
    assert r["record"]["result"] == "reverted"
    assert fixes.undo(ctx, r["record"]["id"])["result"] == "error"


def test_apply_exception_triggers_rollback(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)

    def boom(self, c, p):
        raise RuntimeError("boom")
    monkeypatch.setattr(fixes.PermsFixFile, "verify", boom)
    r = fixes.run_fix(ctx, "perms.fix_file", {"file": SHADOW})
    assert r["result"] == "reverted" and mode(tmp_path) == oct(BAD)[2:]


def test_perms_undo_does_not_restore_file_contents(tmp_path):
    """Undo of a chmod fix must only restore the mode, never stale file contents."""
    ctx = make_ctx(tmp_path)
    rec = fixes.run_fix(ctx, "perms.fix_file", {"file": SHADOW})["record"]
    shadow = tmp_path / "etc" / "shadow"
    assert rec["files"] == []
    os.chmod(str(shadow), 0o666)
    shadow.write_text("root:x\nnewuser:hash\n")
    os.chmod(str(shadow), 0o444 if sys.platform == "win32" else 0o600)
    assert fixes.undo(ctx, rec["id"])["result"] == "applied"
    assert shadow.read_text() == "root:x\nnewuser:hash\n"
    assert mode(tmp_path) == oct(BAD)[2:]


def test_rollback_failure_marks_manual_attention(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    monkeypatch.setattr(fixes.PermsFixFile, "verify", lambda self, c, p: False)
    monkeypatch.setattr(fixes.PermsFixFile, "rollback",
                        lambda self, c, r: (_ for _ in ()).throw(OSError("disk")))
    r = fixes.run_fix(ctx, "perms.fix_file", {"file": SHADOW})
    assert r["result"] == "error" and r["record"]["needs_manual_attention"] is True
    assert r["record"]["backup_dir"] in r["message"]


def test_concurrent_apply_serialized(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    orig = fixes.PermsFixFile.apply

    def slow(self, c, p):
        time.sleep(0.2)
        return orig(self, c, p)
    monkeypatch.setattr(fixes.PermsFixFile, "apply", slow)
    results = []
    ts = [threading.Thread(target=lambda: results.append(
        fixes.run_fix(ctx, "perms.fix_file", {"file": SHADOW})["result"])) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(results) == ["already_applied", "applied"]
    assert len(os.listdir(str(tmp_path / "backups"))) == 1


def test_unknown_fix_id_rejected(tmp_path):
    ctx = make_ctx(tmp_path)
    for bad in ("nope", "", None, "../x"):
        with pytest.raises(FixValidationError):
            fixes.get_plan(ctx, bad, {})
        with pytest.raises(FixValidationError):
            fixes.run_fix(ctx, bad, {})


def test_apply_requires_root_flag(tmp_path):
    ctx = make_ctx(tmp_path, is_root=False)
    r = fixes.run_fix(ctx, "perms.fix_file", {"file": SHADOW})
    assert r["result"] == "error" and "sudo" in r["message"]
    assert mode(tmp_path) == oct(BAD)[2:]
    assert not (tmp_path / "backups").exists()
    assert fixes.undo(ctx, "x")["result"] == "error"


# ---- routes ----

@pytest.fixture
def client(tmp_path, monkeypatch):
    import app as appmod
    ctx = make_ctx(tmp_path)
    cfg = dict(ctx.cfg)
    cfg["auth"] = {"password_hash": auth.hash_password("pw"), "session_minutes": 30}
    monkeypatch.setattr(appmod, "load_config", lambda: cfg)
    monkeypatch.setattr(appmod, "BASE", str(tmp_path))
    monkeypatch.setattr(appmod, "FIX_ROOT", str(tmp_path))
    monkeypatch.setattr(appmod, "_is_root", lambda: True)
    appmod.limiter.__init__()
    appmod.app.config["TESTING"] = True
    c = appmod.app.test_client()
    return c, appmod, tmp_path


def login(c):
    assert c.post("/login", json={"password": "pw"}).status_code == 200
    return {"X-CSRF-Token": c.get("/api/session").get_json()["csrf"]}


def test_routes_flow(client):
    c, _, tmp = client
    assert c.post("/api/fix/plan", json={}).status_code == 401
    assert c.get("/api/fix/history").status_code == 401
    h = login(c)
    assert c.post("/api/fix/plan", json={"fix_id": "perms.fix_file", "params": {"file": SHADOW}}).status_code == 403  # no csrf
    d = c.post("/api/fix/plan", json={"fix_id": "perms.fix_file", "params": {"file": SHADOW}}, headers=h).get_json()
    assert d["risk"] == "low" and d["diff"]
    r = c.post("/api/fix/apply", json={"fix_id": "perms.fix_file", "params": {"file": SHADOW}}, headers=h).get_json()
    assert r["result"] == "applied"
    hist = c.get("/api/fix/history").get_json()
    assert hist[0]["id"] == r["record"]["id"] and hist[0]["title"]
    u = c.post("/api/fix/undo", json={"record_id": r["record"]["id"]}, headers=h).get_json()
    assert u["result"] == "applied" and u["record"]["undone"] is True
    assert mode(tmp) == oct(BAD)[2:]


def test_routes_validation_and_root(client, monkeypatch):
    c, appmod, _ = client
    h = login(c)
    for url, body in (("/api/fix/plan", {"fix_id": "nope", "params": {}}),
                      ("/api/fix/apply", {"fix_id": "perms.fix_file", "params": {"file": "/tmp/x"}}),
                      ("/api/fix/apply", {"fix_id": 5}),
                      ("/api/fix/apply", {"fix_id": "perms.fix_file", "params": []}),
                      ("/api/fix/undo", {})):
        r = c.post(url, json=body, headers=h)
        assert r.status_code == 400, (url, body)
        assert r.get_json()["status"] == "ERROR" and r.get_json()["message"]
    monkeypatch.setattr(appmod, "_is_root", lambda: False)
    r = c.post("/api/fix/apply", json={"fix_id": "perms.fix_file", "params": {"file": SHADOW}}, headers=h)
    assert r.status_code == 403 and r.get_json()["message"] == "Run the server with sudo"
    assert c.post("/api/fix/undo", json={"record_id": "x"}, headers=h).status_code == 403


def test_routes_disabled_without_password(client, monkeypatch):
    c, appmod, _ = client
    monkeypatch.setattr(appmod, "load_config", lambda: {})
    assert c.get("/api/fix/history").status_code == 403


# ---------------------------------------------------------------- ntp.enable
class FakeTimedatectl:
    """Fake ctx.run emulating timedatectl; records every command."""

    def __init__(self, ntp="no", fail_set_true=False):
        self.ntp = ntp
        self.fail_set_true = fail_set_true
        self.calls = []

    def __call__(self, cmd, timeout=8):
        self.calls.append(list(cmd))
        if cmd[:2] == ["timedatectl", "show"]:
            return True, "Timezone=UTC\nNTP={}\nNTPSynchronized=no".format(self.ntp)
        if cmd == ["timedatectl", "set-ntp", "true"]:
            if self.fail_set_true:
                return False, "Failed to set ntp: Access denied"
            self.ntp = "yes"
            return True, ""
        if cmd == ["timedatectl", "set-ntp", "false"]:
            self.ntp = "no"
            return True, ""
        return False, "unexpected command"

    def sets(self):
        return [c for c in self.calls if c[:2] == ["timedatectl", "set-ntp"]]


def ntp_ctx(tmp_path, **kw):
    runner = FakeTimedatectl(**kw)
    ctx = FixContext(cfg={"fixes": {"backup_dir": "backups"}}, root=str(tmp_path),
                     base=str(tmp_path), run=runner)
    return ctx, runner


def test_ntp_plan_names_command(tmp_path):
    ctx, runner = ntp_ctx(tmp_path, ntp="no")
    p = fixes.get_plan(ctx, "ntp.enable", {})
    assert "timedatectl set-ntp true" in (p["summary"] + p["diff"] + p["risk_note"])
    assert p["risk"] == "low" and p["already_applied"] is False
    assert runner.sets() == []  # preview changes nothing


def test_ntp_apply_calls_set_ntp(tmp_path):
    ctx, runner = ntp_ctx(tmp_path, ntp="no")
    r = fixes.run_fix(ctx, "ntp.enable", {})
    assert r["result"] == "applied"
    assert runner.sets() == [["timedatectl", "set-ntp", "true"]]
    assert runner.ntp == "yes"
    assert r["record"]["details"]["previous_ntp"] == "no"


def test_ntp_already_enabled_noop(tmp_path):
    ctx, runner = ntp_ctx(tmp_path, ntp="yes")
    r = fixes.run_fix(ctx, "ntp.enable", {})
    assert r["result"] == "already_applied"
    assert runner.sets() == []


def test_ntp_undo_restores_previous_state(tmp_path):
    ctx, runner = ntp_ctx(tmp_path, ntp="no")
    rec = fixes.run_fix(ctx, "ntp.enable", {})["record"]
    assert runner.ntp == "yes"
    assert fixes.undo(ctx, rec["id"])["result"] == "applied"
    assert runner.ntp == "no"
    assert runner.sets()[-1] == ["timedatectl", "set-ntp", "false"]


def test_ntp_undo_leaves_enabled_if_previously_on(tmp_path):
    ctx, runner = ntp_ctx(tmp_path, ntp="no")
    rec = fixes.run_fix(ctx, "ntp.enable", {})["record"]
    rec["details"]["previous_ntp"] = "yes"
    fix = fixes.CATALOGUE["ntp.enable"]
    fix.rollback(ctx, rec)
    assert runner.ntp == "yes"


def test_ntp_set_ntp_failure_reverts_without_change(tmp_path):
    ctx, runner = ntp_ctx(tmp_path, ntp="no", fail_set_true=True)
    r = fixes.run_fix(ctx, "ntp.enable", {})
    assert r["result"] in ("error", "reverted")
    assert runner.ntp == "no"
    assert r["record"]["result"] == r["result"]
    assert runner.sets() == [["timedatectl", "set-ntp", "true"]]


# ---------------------------------------------------------------- ssh.*
DROPIN = "/etc/ssh/sshd_config.d/00-secnet.conf"
MAIN_SSHD = "PermitRootLogin yes\nPasswordAuthentication yes\nMaxAuthTries 10\n"


class FakeSshd:
    def __init__(self, fail_test=False, fail_reload=False):
        self.fail_test, self.fail_reload = fail_test, fail_reload
        self.calls = []

    def __call__(self, cmd, timeout=8):
        self.calls.append(list(cmd))
        if cmd == ["sshd", "-t"]:
            return (False, "bad config") if self.fail_test else (True, "")
        if cmd == ["systemctl", "reload", "ssh"]:
            return (False, "reload failed") if self.fail_reload else (True, "")
        return False, "unexpected command"


def ssh_ctx(tmp_path, with_key=False, **kw):
    etc = tmp_path / "etc" / "ssh"
    etc.mkdir(parents=True)
    (etc / "sshd_config").write_text(MAIN_SSHD)
    (tmp_path / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
    if with_key:
        ssh = tmp_path / "home" / "alice" / ".ssh"
        ssh.mkdir(parents=True)
        (ssh / "authorized_keys").write_text("ssh-ed25519 AAAA alice\n")
    runner = FakeSshd(**kw)
    cfg = {"fixes": {"backup_dir": "backups", "ssh_dropin_dir": "/etc/ssh/sshd_config.d"},
           "services": {"max_auth_tries": 4}}
    return FixContext(cfg=cfg, root=str(tmp_path), base=str(tmp_path), run=runner), runner


def dropin(tmp_path):
    p = tmp_path / "etc" / "ssh" / "sshd_config.d" / "00-secnet.conf"
    return p.read_text() if p.exists() else None


def test_dropin_created_with_directive(tmp_path):
    ctx, runner = ssh_ctx(tmp_path)
    r = fixes.run_fix(ctx, "ssh.disable_root_login", {})
    assert r["result"] == "applied"
    assert "PermitRootLogin no" in dropin(tmp_path)
    assert r["record"]["details"]["directive"] == "PermitRootLogin"
    assert fixes.CATALOGUE["ssh.disable_root_login"].risk == "medium"


def test_plan_has_diff_and_risk_note(tmp_path):
    ctx, _ = ssh_ctx(tmp_path)
    p = fixes.get_plan(ctx, "ssh.disable_root_login", {})
    assert "+PermitRootLogin no" in p["diff"] and "root" in p["risk_note"]
    assert p["already_applied"] is False and p["files"] == [DROPIN]


def test_second_ssh_fix_merges_directives(tmp_path):
    ctx, _ = ssh_ctx(tmp_path)
    fixes.run_fix(ctx, "ssh.disable_root_login", {})
    r = fixes.run_fix(ctx, "ssh.limit_auth_tries", {})
    assert r["result"] == "applied"
    text = dropin(tmp_path)
    assert "PermitRootLogin no" in text and "MaxAuthTries 4" in text
    assert text.count("PermitRootLogin") == 1


def test_sshd_test_failure_restores_and_reports_reverted(tmp_path):
    ctx, runner = ssh_ctx(tmp_path)
    fixes.run_fix(ctx, "ssh.disable_root_login", {})
    before = dropin(tmp_path)
    runner.fail_test = True
    r = fixes.run_fix(ctx, "ssh.limit_auth_tries", {})
    assert r["result"] == "reverted"
    assert dropin(tmp_path) == before


def test_sshd_test_failure_removes_new_dropin(tmp_path):
    ctx, runner = ssh_ctx(tmp_path, fail_test=True)
    r = fixes.run_fix(ctx, "ssh.disable_root_login", {})
    assert r["result"] == "reverted"
    assert dropin(tmp_path) is None
    assert ["systemctl", "reload", "ssh"] not in runner.calls


def test_reload_only_after_validation(tmp_path):
    ctx, runner = ssh_ctx(tmp_path)
    fixes.run_fix(ctx, "ssh.disable_root_login", {})
    assert runner.calls == [["sshd", "-t"], ["systemctl", "reload", "ssh"], ["sshd", "-T"]]


def test_password_auth_blocked_without_keys(tmp_path):
    ctx, runner = ssh_ctx(tmp_path)
    with pytest.raises(FixValidationError, match="Add an SSH key for a non-root user first"):
        fixes.get_plan(ctx, "ssh.disable_password_auth", {})
    with pytest.raises(FixValidationError):
        fixes.run_fix(ctx, "ssh.disable_password_auth", {})
    assert runner.calls == [] and dropin(tmp_path) is None


def test_password_auth_empty_or_root_keys_do_not_count(tmp_path):
    ctx, _ = ssh_ctx(tmp_path)
    ssh = tmp_path / "home" / "alice" / ".ssh"
    ssh.mkdir(parents=True)
    (ssh / "authorized_keys").write_text("  \n")
    rssh = tmp_path / "root" / ".ssh"
    rssh.mkdir(parents=True)
    (rssh / "authorized_keys").write_text("ssh-ed25519 AAAA root\n")
    with pytest.raises(FixValidationError):
        fixes.run_fix(ctx, "ssh.disable_password_auth", {})


def test_password_auth_allowed_with_key(tmp_path):
    ctx, _ = ssh_ctx(tmp_path, with_key=True)
    p = fixes.get_plan(ctx, "ssh.disable_password_auth", {})
    assert p["risk"] == "high" and "key" in p["risk_note"]
    r = fixes.run_fix(ctx, "ssh.disable_password_auth", {})
    assert r["result"] == "applied"
    assert "PasswordAuthentication no" in dropin(tmp_path)


def test_main_sshd_config_untouched(tmp_path):
    ctx, _ = ssh_ctx(tmp_path)
    main = tmp_path / "etc" / "ssh" / "sshd_config"
    fixes.run_fix(ctx, "ssh.disable_root_login", {})
    fixes.run_fix(ctx, "ssh.limit_auth_tries", {})
    assert main.read_text() == MAIN_SSHD


def test_ssh_fix_already_applied_noop(tmp_path):
    ctx, runner = ssh_ctx(tmp_path)
    fixes.run_fix(ctx, "ssh.disable_root_login", {})
    n = len(runner.calls)
    r = fixes.run_fix(ctx, "ssh.disable_root_login", {})
    assert r["result"] == "already_applied" and len(runner.calls) == n
    # PermitEmptyPasswords defaults to no, so there is nothing to do
    assert fixes.run_fix(ctx, "ssh.disable_empty_passwords", {})["result"] == "already_applied"


def test_undo_removes_dropin_when_it_did_not_exist(tmp_path):
    ctx, runner = ssh_ctx(tmp_path)
    rec = fixes.run_fix(ctx, "ssh.disable_root_login", {})["record"]
    assert dropin(tmp_path) is not None
    r = fixes.undo(ctx, rec["id"])
    assert r["result"] == "applied"
    assert dropin(tmp_path) is None
    assert runner.calls[-2:] == [["sshd", "-t"], ["systemctl", "reload", "ssh"]]


def test_undo_restores_previous_merged_dropin(tmp_path):
    ctx, _ = ssh_ctx(tmp_path)
    fixes.run_fix(ctx, "ssh.disable_root_login", {})
    first = dropin(tmp_path)
    rec = fixes.run_fix(ctx, "ssh.limit_auth_tries", {})["record"]
    fixes.undo(ctx, rec["id"])
    assert dropin(tmp_path) == first


# ---------------------------------------------------------------- ufw.*
class FakeUfw:
    """Stateful fake `ufw`; records every command."""

    def __init__(self, active=False, allow=(), deny=(), fail=()):
        self.active, self.allow, self.deny = active, list(allow), list(deny)
        self.fail = set(fail)
        self.calls = []

    def status(self):
        if not self.active:
            return "Status: inactive"
        lines = ["Status: active", "", "To                         Action      From",
                 "--                         ------      ----"]
        lines += ["{:<26} ALLOW       Anywhere".format(a) for a in self.allow]
        lines += ["{:<26} DENY        {}".format("Anywhere", d) for d in self.deny]
        return "\n".join(lines)

    def __call__(self, cmd, timeout=8):
        cmd = list(cmd)
        self.calls.append(cmd)
        if cmd[0] != "ufw":
            return False, "unexpected"
        if " ".join(cmd[1:3]) in self.fail or " ".join(cmd[1:]) in self.fail:
            return False, "boom"
        if cmd[1:] == ["status"]:
            return True, self.status()
        if cmd[1:] == ["show", "added"]:
            return True, "\n".join(["ufw allow " + a for a in self.allow] +
                                   ["ufw deny from " + d for d in self.deny])
        if cmd[1] == "allow":
            if cmd[2] in self.allow:
                return True, "Skipping adding existing rule"
            self.allow.append(cmd[2])
            return True, "Rule added"
        if cmd[1:] == ["--force", "enable"]:
            self.active = True
            return True, "Firewall is active"
        if cmd[1] == "disable":
            self.active = False
            return True, "Firewall stopped"
        if cmd[1:3] == ["deny", "from"]:
            if cmd[3] not in self.deny:
                self.deny.append(cmd[3])
            return True, "Rule added"
        if cmd[1:3] == ["delete", "allow"]:
            self.allow.remove(cmd[3])
            return True, "Rule deleted"
        if cmd[1:4] == ["delete", "deny", "from"]:
            self.deny.remove(cmd[4])
            return True, "Rule deleted"
        return False, "unexpected"

    def mutating(self):
        return [c for c in self.calls if c[1:] not in (["status"], ["show", "added"])]


def ufw_ctx(tmp_path, sshd=None, cfg_fixes=None, client_ip="", **kw):
    etc = tmp_path / "etc" / "ssh"
    etc.mkdir(parents=True, exist_ok=True)
    (etc / "sshd_config").write_text(sshd if sshd is not None else "PermitRootLogin no\n")
    fx = {"backup_dir": "backups", "ssh_dropin_dir": "/etc/ssh/sshd_config.d"}
    fx.update(cfg_fixes or {})
    runner = FakeUfw(**kw)
    cfg = {"fixes": fx, "services": {"ssh_config_path": "/etc/ssh/sshd_config"}}
    return FixContext(cfg=cfg, root=str(tmp_path), base=str(tmp_path), run=runner,
                      client_ip=client_ip), runner


def test_enable_allows_ssh_before_enable(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path)
    r = fixes.run_fix(ctx, "ufw.enable", {})
    assert r["result"] == "applied" and ufw.active
    assert ufw.mutating() == [["ufw", "allow", "22/tcp"], ["ufw", "--force", "enable"]]
    assert r["record"]["details"]["allow_rule_preexisted"] is False
    fix = fixes.CATALOGUE["ufw.enable"]
    assert fix.risk == "medium" and fix.title == "Turn on the firewall"


def test_enable_custom_ssh_port(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path, sshd="Port 2222\n")
    fixes.run_fix(ctx, "ufw.enable", {})
    assert ufw.mutating()[0] == ["ufw", "allow", "2222/tcp"]
    assert "22/tcp" not in ufw.allow


def test_enable_custom_port_from_dropin(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path)
    d = tmp_path / "etc" / "ssh" / "sshd_config.d"
    d.mkdir()
    (d / "10-port.conf").write_text("Port 2200\n")
    fixes.run_fix(ctx, "ufw.enable", {})
    assert ufw.mutating()[0] == ["ufw", "allow", "2200/tcp"]


def test_enable_already_active_is_noop(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path, active=True)
    assert fixes.run_fix(ctx, "ufw.enable", {})["result"] == "already_applied"
    assert ufw.mutating() == []


def test_enable_undo_disables_and_deletes_added_rule(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path)
    rec = fixes.run_fix(ctx, "ufw.enable", {})["record"]
    assert fixes.undo(ctx, rec["id"])["result"] == "applied"
    assert not ufw.active and ufw.allow == []
    assert ufw.mutating()[-2:] == [["ufw", "disable"], ["ufw", "delete", "allow", "22/tcp"]]


def test_enable_undo_keeps_preexisting_rule(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path, allow=["22/tcp"])
    r = fixes.run_fix(ctx, "ufw.enable", {})
    assert r["record"]["details"]["allow_rule_preexisted"] is True
    fixes.undo(ctx, r["record"]["id"])
    assert not ufw.active and ufw.allow == ["22/tcp"]
    assert ["ufw", "delete", "allow", "22/tcp"] not in ufw.calls


def test_enable_failure_cleans_up_added_rule(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path, fail=["--force enable"])
    r = fixes.run_fix(ctx, "ufw.enable", {})
    assert r["result"] in ("error", "reverted")
    assert ufw.allow == [] and not ufw.active


def test_enable_failure_keeps_preexisting_rule(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path, allow=["22/tcp"], fail=["--force enable"])
    fixes.run_fix(ctx, "ufw.enable", {})
    assert ufw.allow == ["22/tcp"]


def test_enable_ufw_missing_reports_error(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path)
    ctx.run = lambda cmd, timeout=8: (False, "Command not found: ufw")
    r = fixes.run_fix(ctx, "ufw.enable", {})
    assert r["result"] in ("error", "reverted")


def block(ctx, ip):
    return fixes.run_fix(ctx, "ufw.block_ip", {"ip": ip})


@pytest.mark.parametrize("bad", ["", "abc", "1.2.3", "1.2.3.4/24", "999.1.1.1", None, 5,
                                 "1.2.3.4; reboot", "-1.2.3.4", "fe80::1%eth0", ["1.2.3.4"]])
def test_block_ip_validates_format(tmp_path, bad):
    ctx, ufw = ufw_ctx(tmp_path)
    with pytest.raises(FixValidationError):
        fixes.get_plan(ctx, "ufw.block_ip", {"ip": bad})
    with pytest.raises(FixValidationError):
        block(ctx, bad)
    assert ufw.mutating() == []


def test_block_ip_refuses_own_ip(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path, client_ip="203.0.113.9")
    with pytest.raises(FixValidationError):
        block(ctx, "203.0.113.9")
    assert ufw.mutating() == []


def test_block_ip_ipv4_mapped_own_ip_refused(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path, client_ip="203.0.113.9")
    with pytest.raises(FixValidationError):
        block(ctx, "::ffff:203.0.113.9")
    ctx2, _ = ufw_ctx(tmp_path, client_ip="::ffff:203.0.113.9")
    with pytest.raises(FixValidationError):
        block(ctx2, "203.0.113.9")
    with pytest.raises(FixValidationError):
        block(ctx2, "::ffff:cb00:7109")
    assert ufw.mutating() == []


def test_block_ip_normalises_ipv4_mapped(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path)
    r = block(ctx, "::ffff:93.184.216.7")
    assert r["result"] == "applied"
    assert ufw.mutating() == [["ufw", "deny", "from", "93.184.216.7"]]
    assert r["record"]["params"] == {"ip": "93.184.216.7"}


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "10.0.0.5", "192.168.1.9", "172.16.0.1",
                                "169.254.1.1", "fe80::1", "224.0.0.1", "ff02::1",
                                "0.0.0.0", "::", "fd00::1", "::ffff:127.0.0.1",
                                "::ffff:10.1.1.1"])
def test_block_ip_refuses_loopback_and_private(tmp_path, ip):
    ctx, ufw = ufw_ctx(tmp_path)
    with pytest.raises(FixValidationError):
        block(ctx, ip)
    assert ufw.mutating() == []


def test_block_ip_private_allowed_when_configured(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path, cfg_fixes={"block_private_ips": False})
    assert block(ctx, "10.0.0.5")["result"] == "applied"
    assert ufw.deny == ["10.0.0.5"]
    for ip in ("127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0"):
        with pytest.raises(FixValidationError):
            block(ctx, ip)


def test_block_ip_accepts_ipv6(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path)
    r = block(ctx, "2606:4700::1")
    assert r["result"] == "applied"
    assert ufw.mutating() == [["ufw", "deny", "from", "2606:4700::1"]]
    plan = fixes.get_plan(ctx, "ufw.block_ip", {"ip": "2606:4700::2"})
    assert plan["risk"] == "medium" and "2606:4700::2" in plan["summary"]


def test_block_ip_undo_deletes_rule(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path, active=True)
    rec = block(ctx, "93.184.216.7")["record"]
    assert ufw.deny == ["93.184.216.7"]
    assert fixes.undo(ctx, rec["id"])["result"] == "applied"
    assert ufw.deny == []
    assert ufw.mutating()[-1] == ["ufw", "delete", "deny", "from", "93.184.216.7"]


def test_block_ip_already_blocked_noop(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path, active=True, deny=["93.184.216.7"])
    r = block(ctx, "93.184.216.7")
    assert r["result"] == "already_applied"
    assert ufw.mutating() == []
    assert fixes.get_plan(ctx, "ufw.block_ip", {"ip": "93.184.216.7"})["already_applied"]


def test_block_ip_already_blocked_while_inactive_and_ipv6(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path, deny=["2606:4700::1"])  # firewall off, rule only "added"
    assert block(ctx, "2606:4700::1")["result"] == "already_applied"


def test_block_ip_works_while_firewall_inactive(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path)
    assert block(ctx, "93.184.216.7")["result"] == "applied"
    assert "off" in fixes.get_plan(ctx, "ufw.block_ip", {"ip": "93.184.216.8"})["risk_note"]


def test_block_ip_failure_reverts(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path, fail=["deny from"])
    r = block(ctx, "93.184.216.7")
    assert r["result"] in ("error", "reverted")
    assert ufw.deny == []


def test_block_ip_similar_ip_not_counted_as_blocked(tmp_path):
    ctx, ufw = ufw_ctx(tmp_path, active=True, deny=["93.184.216.70"])
    assert block(ctx, "93.184.216.7")["result"] == "applied"


def test_ssh_fix_reverted_when_live_config_ignores_dropin(tmp_path):
    """Main sshd_config without an Include line: `sshd -T` still says yes -> revert."""
    ctx, runner = ssh_ctx(tmp_path)

    def run(cmd, timeout=8):
        if cmd == ["sshd", "-T"]:
            return True, "port 22\npermitrootlogin yes\n"
        return runner(cmd, timeout)
    ctx.run = run
    r = fixes.run_fix(ctx, "ssh.disable_root_login", {})
    assert r["result"] == "reverted"
    assert dropin(tmp_path) is None


def test_ssh_fix_accepts_live_config_with_new_value(tmp_path):
    ctx, runner = ssh_ctx(tmp_path)

    def run(cmd, timeout=8):
        if cmd == ["sshd", "-T"]:
            return True, "permitrootlogin no\n"
        return runner(cmd, timeout)
    ctx.run = run
    assert fixes.run_fix(ctx, "ssh.disable_root_login", {})["result"] == "applied"
