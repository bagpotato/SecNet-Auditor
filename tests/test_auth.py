import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import auth  # noqa: E402


def test_verify_login_ok_and_bad():
    cfg = {"auth": {"password_hash": auth.hash_password("s3cret")}}
    assert auth.verify_login(cfg, "s3cret") is True
    assert auth.verify_login(cfg, "wrong") is False
    assert auth.verify_login(cfg, "") is False


def test_no_hash_means_disabled():
    for cfg in ({}, {"auth": {}}, {"auth": {"password_hash": ""}}):
        assert auth.fixes_enabled(cfg) is False
        assert auth.verify_login(cfg, "anything") is False
    assert auth.fixes_enabled({"auth": {"password_hash": auth.hash_password("x")}}) is True


def test_rate_limiter_locks_after_5_fails():
    now = [1000.0]
    rl = auth.RateLimiter(clock=lambda: now[0])
    for _ in range(4):
        rl.fail("1.2.3.4")
        assert rl.allowed("1.2.3.4")
    rl.fail("1.2.3.4")
    assert not rl.allowed("1.2.3.4")
    assert rl.allowed("5.6.7.8")
    now[0] += 299
    assert not rl.allowed("1.2.3.4")
    now[0] += 2
    assert rl.allowed("1.2.3.4")
    rl.fail("1.2.3.4")
    rl.reset("1.2.3.4")
    assert rl.allowed("1.2.3.4")


def test_rate_limiter_window_expires_old_fails():
    now = [0.0]
    rl = auth.RateLimiter(clock=lambda: now[0])
    for _ in range(4):
        rl.fail("k")
    now[0] += 301
    rl.fail("k")
    assert rl.allowed("k")


def test_csrf_mismatch_rejected():
    s = {}
    tok = auth.new_csrf_token(s)
    assert auth.new_csrf_token(s) == tok
    assert auth.check_csrf(s, tok) is True
    assert auth.check_csrf(s, "nope") is False
    assert auth.check_csrf(s, None) is False
    assert auth.check_csrf({}, "x") is False


def test_secret_file_created_once(tmp_path):
    p = str(tmp_path / "instance" / "secret.key")
    a = auth.get_or_create_secret(p)
    b = auth.get_or_create_secret(p)
    assert isinstance(a, bytes) and len(a) == 32
    assert a == b
    if os.name != "nt":
        assert (os.stat(p).st_mode & 0o777) == 0o600


@pytest.fixture
def client(monkeypatch):
    import app as appmod
    cfg = {"auth": {"password_hash": auth.hash_password("pw"), "session_minutes": 30}}
    monkeypatch.setattr(appmod, "load_config", lambda: cfg)
    appmod.limiter.__init__()
    appmod.app.config["TESTING"] = True
    return appmod.app.test_client(), appmod, cfg


def test_login_endpoint_sets_session(client):
    c, appmod, _ = client
    r = c.get("/api/session")
    d = r.get_json()
    assert d["logged_in"] is False and d["fixes_enabled"] is True and d["csrf"]
    assert c.post("/login", json={"password": "bad"}).status_code == 401
    r = c.post("/login", json={"password": "pw"})
    assert r.status_code == 200
    d = c.get("/api/session").get_json()
    assert d["logged_in"] is True and "is_root" in d and d["csrf"]
    assert "HttpOnly" in r.headers.get("Set-Cookie", "")
    assert "SameSite=Strict" in r.headers.get("Set-Cookie", "")


def test_login_rate_limited(client):
    c, _, _ = client
    for _ in range(5):
        assert c.post("/login", json={"password": "bad"}).status_code == 401
    assert c.post("/login", json={"password": "pw"}).status_code == 429


def test_post_without_csrf_403(client):
    c, appmod, _ = client
    c.post("/login", json={"password": "pw"})
    assert c.post("/logout").status_code == 403
    assert c.post("/logout", headers={"X-CSRF-Token": "bad"}).status_code == 403
    tok = c.get("/api/session").get_json()["csrf"]
    assert c.post("/logout", headers={"X-CSRF-Token": tok}).status_code == 200
    assert c.get("/api/session").get_json()["logged_in"] is False


def test_decorators_login_required_states(client):
    c, appmod, cfg = client
    from flask import Flask, jsonify

    # Fresh app (the real app has already served requests); shares secret + config.
    app2 = Flask("t")
    app2.secret_key = appmod.app.secret_key
    app2.config.update(TESTING=True, LOAD_CONFIG=lambda: cfg)

    @app2.route("/guarded", methods=["POST"])
    @auth.login_required
    @auth.csrf_required
    def guarded():
        return jsonify({"ok": True})

    @app2.route("/login", methods=["POST"])
    def login():
        from flask import session
        session["logged_in"] = True
        return jsonify({"csrf": auth.new_csrf_token(session)})

    c = app2.test_client()
    assert c.post("/guarded").status_code == 401
    tok = c.post("/login").get_json()["csrf"]
    assert c.post("/guarded").status_code == 403
    assert c.post("/guarded", headers={"X-CSRF-Token": tok}).status_code == 200
    cfg["auth"]["password_hash"] = ""
    r = c.post("/guarded", headers={"X-CSRF-Token": tok})
    assert r.status_code == 403
    assert "Fixes are disabled: set an admin password" in r.get_json()["message"]


@pytest.mark.parametrize("url", ["/api/logs/view", "/api/logs/download"])
def test_logs_open_when_no_password(client, url):
    c, _, cfg = client
    cfg["auth"]["password_hash"] = ""
    assert c.get(url).status_code != 401
    assert c.get(url).status_code != 403


@pytest.mark.parametrize("url", ["/api/logs/view", "/api/logs/download"])
def test_logs_401_when_password_set_and_anonymous(client, url):
    c, _, _ = client
    r = c.get(url)
    assert r.status_code == 401
    assert r.get_json() == {"status": "ERROR", "message": "Login required"}


@pytest.mark.parametrize("url", ["/api/logs/view", "/api/logs/download"])
def test_logs_ok_when_logged_in(client, url):
    c, _, _ = client
    assert c.post("/login", json={"password": "pw"}).status_code == 200
    assert c.get(url).status_code == 200


def test_write_password_hash_is_atomic_and_keeps_config(tmp_path):
    import json
    import app as appmod
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"server": {"port": 5000}, "auth": {"password_hash": ""}}))
    appmod.write_password_hash(str(path), "HASH")
    cfg = json.loads(path.read_text())
    assert cfg["auth"]["password_hash"] == "HASH" and cfg["auth"]["session_minutes"] == 30
    assert cfg["server"] == {"port": 5000}
    assert [p.name for p in tmp_path.iterdir()] == ["config.json"]   # no temp file left


def test_write_password_hash_refuses_invalid_config(tmp_path):
    import app as appmod
    path = tmp_path / "config.json"
    path.write_text("{ not json")
    with pytest.raises(ValueError):
        appmod.write_password_hash(str(path), "HASH")
    assert path.read_text() == "{ not json"
    assert [p.name for p in tmp_path.iterdir()] == ["config.json"]
