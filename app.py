"""SecNet-Auditor - Local Flask web server."""
import json
import os
import argparse
import getpass
import sys
from datetime import datetime, timedelta

from flask import Flask, Response, jsonify, render_template, request, session

from modules import auth, fixes
from modules.hardening import run_hardening_audit
from modules.log_viewer import format_text, query_logs
from modules.log_monitor import run_log_audit
from modules.network_check import run_network_audit
from modules.services import run_services_audit

BASE = os.path.dirname(os.path.abspath(__file__))
FIX_ROOT = "/"   # filesystem root the fixes operate on (tests override)
app = Flask(__name__)
limiter = auth.RateLimiter(max_fail=5, window=300, lockout=300)


def load_config():
    """Load config.json (re-read on every request so changes apply immediately)."""
    try:
        with open(os.path.join(BASE, "config.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as e:  # noqa: BLE001
        app.logger.error("Invalid config.json: %s", e)
        return {}


def _session_minutes(cfg):
    try:
        return max(1, int((cfg.get("auth") or {}).get("session_minutes", 30)))
    except (TypeError, ValueError):
        return 30


app.secret_key = auth.get_or_create_secret(os.path.join(BASE, "instance", "secret.key"))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=_session_minutes(load_config())),
    LOAD_CONFIG=lambda: load_config(),
)


def _is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def safe(fn, *a):
    """Keep a failing module from breaking the whole audit."""
    try:
        return fn(*a)
    except Exception as e:  # noqa: BLE001
        return {"status": "ERROR", "message": f"Exception: {e}"}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    cfg = load_config()
    key = request.remote_addr or "unknown"
    if not auth.fixes_enabled(cfg):
        return jsonify({"status": "ERROR", "message": auth.DISABLED_MSG}), 403
    if not limiter.allowed(key):
        return jsonify({"status": "ERROR",
                        "message": "Too many failed attempts, try again in 5 minutes"}), 429
    body = request.get_json(silent=True) or {}
    pw = body.get("password", "")
    if not isinstance(pw, str) or not auth.verify_login(cfg, pw):
        limiter.fail(key)
        return jsonify({"status": "ERROR", "message": "Wrong password"}), 401
    limiter.reset(key)
    session.clear()
    session["logged_in"] = True
    session.permanent = True
    auth.new_csrf_token(session)
    return jsonify({"status": "OK", "csrf": session["csrf"]})


@app.route("/logout", methods=["POST"])
@auth.csrf_required
def logout():
    session.clear()
    return jsonify({"status": "OK"})


@app.route("/api/session")
def api_session():
    cfg = load_config()
    return jsonify({
        "logged_in": bool(session.get("logged_in")),
        "fixes_enabled": auth.fixes_enabled(cfg),
        "is_root": _is_root(),
        "csrf": auth.new_csrf_token(session),
    })


@app.route("/api/network")
def api_network():
    return jsonify(safe(run_network_audit, load_config()))


@app.route("/api/hardening")
def api_hardening():
    return jsonify(safe(run_hardening_audit, load_config()))


@app.route("/api/logs")
def api_logs():
    return jsonify(safe(run_log_audit, load_config()))


@app.route("/api/services")
def api_services():
    return jsonify(safe(run_services_audit, load_config()))


def _log_query_args():
    a = request.args
    before = a.get("before", type=int)
    return dict(source=a.get("source", ""), q=a.get("q", ""), level=a.get("level", ""),
                ip=a.get("ip", ""), since=a.get("since", ""),
                limit=a.get("limit", default=None, type=int) or 0, before=before)


def _run_log_query(cfg, args):
    if not args["limit"]:
        args["limit"] = (cfg.get("logs") or {}).get("default_limit", 200)
    return query_logs(cfg, **args)


@app.route("/api/logs/view")
@auth.login_required_if_password
def api_logs_view():
    cfg = load_config()
    return jsonify(safe(_run_log_query, cfg, _log_query_args()))


@app.route("/api/logs/download")
@auth.login_required_if_password
def api_logs_download():
    cfg = load_config()
    args = _log_query_args()
    res = safe(_run_log_query, cfg, args)
    if res.get("status") == "ERROR":
        text = "# " + str(res.get("message", "error")) + "\n"
    else:
        text = format_text(res)
    name = "".join(c for c in args["source"] if c.isalnum() or c in "-_")[:32] or "log"
    return Response(text, mimetype="text/plain", headers={
        "Content-Disposition": 'attachment; filename="%s-filtered.log"' % name})


def _fix_ctx():
    return fixes.FixContext(cfg=load_config(), root=FIX_ROOT, is_root=_is_root(),
                            client_ip=request.remote_addr or "", base=BASE)


def _fix_error(msg, code=400):
    return jsonify({"status": "ERROR", "message": msg}), code


def _fix_request():
    """Parse {fix_id, params}; returns (fix_id, params) or raises FixValidationError."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise fixes.FixValidationError("Expected a JSON object")
    fix_id, params = body.get("fix_id"), body.get("params", {})
    if not isinstance(fix_id, str) or not fix_id:
        raise fixes.FixValidationError("Missing fix_id")
    if not isinstance(params, dict):
        raise fixes.FixValidationError("params must be an object")
    return fix_id, params


@app.route("/api/fix/plan", methods=["POST"])
@auth.login_required
@auth.csrf_required
def api_fix_plan():
    try:
        fix_id, params = _fix_request()
        return jsonify(fixes.get_plan(_fix_ctx(), fix_id, params))
    except fixes.FixValidationError as e:
        return _fix_error(str(e))
    except Exception as e:  # noqa: BLE001
        return _fix_error("Exception: %s" % e, 500)


@app.route("/api/fix/apply", methods=["POST"])
@auth.login_required
@auth.csrf_required
def api_fix_apply():
    if not _is_root():
        return _fix_error(fixes.SUDO_MSG, 403)
    try:
        fix_id, params = _fix_request()
        return jsonify(fixes.run_fix(_fix_ctx(), fix_id, params))
    except fixes.FixValidationError as e:
        return _fix_error(str(e))
    except Exception as e:  # noqa: BLE001
        return _fix_error("Exception: %s" % e, 500)


@app.route("/api/fix/history")
@auth.login_required
def api_fix_history():
    try:
        return jsonify(fixes.history(_fix_ctx()))
    except Exception as e:  # noqa: BLE001
        return _fix_error("Exception: %s" % e, 500)


@app.route("/api/fix/undo", methods=["POST"])
@auth.login_required
@auth.csrf_required
def api_fix_undo():
    if not _is_root():
        return _fix_error(fixes.SUDO_MSG, 403)
    body = request.get_json(silent=True)
    rid = body.get("record_id") if isinstance(body, dict) else None
    if not isinstance(rid, str) or not rid:
        return _fix_error("Missing record_id")
    try:
        return jsonify(fixes.undo(_fix_ctx(), rid))
    except Exception as e:  # noqa: BLE001
        return _fix_error("Exception: %s" % e, 500)


@app.route("/api/audit")
def api_audit():
    cfg = load_config()
    return jsonify({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "network": safe(run_network_audit, cfg),
        "hardening": safe(run_hardening_audit, cfg),
        "logs": safe(run_log_audit, cfg),
        "services": safe(run_services_audit, cfg),
        "is_root": _is_root(),
    })


def write_password_hash(path, pw_hash):
    """Store the hash in config.json atomically (temp file + rename, mode 600), so a crash
    or full disk can never leave a truncated config.json behind."""
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)          # refuse to touch a config that is not valid JSON
    cfg.setdefault("auth", {}).setdefault("session_minutes", 30)
    cfg["auth"]["password_hash"] = pw_hash
    tmp = "%s.tmp.%d" % (path, os.getpid())
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def set_password_cli():
    pw = getpass.getpass("New admin password: ")
    if len(pw) < 8:
        print("Password must be at least 8 characters.")
        return 1
    if pw != getpass.getpass("Repeat password: "):
        print("Passwords do not match.")
        return 1
    try:
        write_password_hash(os.path.join(BASE, "config.json"), auth.hash_password(pw))
    except (OSError, ValueError) as e:
        print("Could not update config.json: %s" % e)
        return 1
    print("Admin password saved to config.json.")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--set-password", action="store_true",
                    help="set the admin password used to log in and apply fixes")
    if ap.parse_args().set_password:
        sys.exit(set_password_cli())
    s = load_config().get("server", {})
    app.run(host=s.get("host", "127.0.0.1"), port=s.get("port", 5000), debug=s.get("debug", False))
