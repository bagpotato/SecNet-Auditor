"""Admin authentication, CSRF and login rate limiting."""
import hmac
import os
import secrets
import threading
import time
from functools import wraps

from flask import current_app, jsonify, session
from werkzeug.security import check_password_hash, generate_password_hash

DISABLED_MSG = "Fixes are disabled: set an admin password"


def _hash(cfg):
    return ((cfg or {}).get("auth") or {}).get("password_hash") or ""


def hash_password(password):
    return generate_password_hash(password)


def fixes_enabled(cfg):
    return bool(_hash(cfg))


def verify_login(cfg, password):
    h = _hash(cfg)
    if not h or not password:
        return False
    try:
        return check_password_hash(h, password)
    except Exception:  # noqa: BLE001 - malformed hash
        return False


class RateLimiter:
    """In-memory: max_fail failures within window seconds -> lockout seconds."""

    def __init__(self, max_fail=5, window=300, lockout=300, clock=time.time):
        self.max_fail, self.window, self.lockout, self.clock = max_fail, window, lockout, clock
        self._fails = {}
        self._locked = {}
        self._lock = threading.Lock()

    def allowed(self, key):
        with self._lock:
            until = self._locked.get(key)
            if until is None:
                return True
            if self.clock() >= until:
                del self._locked[key]
                self._fails.pop(key, None)
                return True
            return False

    def fail(self, key):
        with self._lock:
            now = self.clock()
            recent = [t for t in self._fails.get(key, []) if now - t < self.window]
            recent.append(now)
            self._fails[key] = recent
            if len(recent) >= self.max_fail:
                self._locked[key] = now + self.lockout

    def reset(self, key):
        with self._lock:
            self._fails.pop(key, None)
            self._locked.pop(key, None)


def get_or_create_secret(path):
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        if len(data) >= 32:
            return data
    except FileNotFoundError:
        pass
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    data = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return data


def new_csrf_token(sess):
    tok = sess.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        sess["csrf"] = tok
    return tok


def check_csrf(sess, header_value):
    tok = sess.get("csrf")
    if not tok or not header_value:
        return False
    return hmac.compare_digest(str(tok).encode(), str(header_value).encode())


def _config():
    loader = current_app.config.get("LOAD_CONFIG")
    return loader() if loader else {}


def login_required(fn):
    """403 when no password hash is configured, 401 when not logged in."""
    @wraps(fn)
    def wrapper(*a, **kw):
        if not fixes_enabled(_config()):
            return jsonify({"status": "ERROR", "message": DISABLED_MSG}), 403
        if not session.get("logged_in"):
            return jsonify({"status": "ERROR", "message": "Login required"}), 401
        return fn(*a, **kw)
    return wrapper


def login_required_if_password(fn):
    """Open when no password is configured; 401 when one is set and not logged in."""
    @wraps(fn)
    def wrapper(*a, **kw):
        if fixes_enabled(_config()) and not session.get("logged_in"):
            return jsonify({"status": "ERROR", "message": "Login required"}), 401
        return fn(*a, **kw)
    return wrapper


def csrf_required(fn):
    """403 on a missing/invalid X-CSRF-Token header."""
    @wraps(fn)
    def wrapper(*a, **kw):
        from flask import request
        if not check_csrf(session, request.headers.get("X-CSRF-Token")):
            return jsonify({"status": "ERROR", "message": "Invalid CSRF token"}), 403
        return fn(*a, **kw)
    return wrapper
