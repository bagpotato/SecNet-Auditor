"""SecNet-Auditor - Servidor web Flask local."""
import json
import os
from datetime import datetime

from flask import Flask, jsonify, render_template

from modules.hardening import run_hardening_audit
from modules.log_monitor import run_log_audit
from modules.network_check import run_network_audit

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)


def load_config():
    """Carga config.json (se relee en cada petición para aplicar cambios al vuelo)."""
    try:
        with open(os.path.join(BASE, "config.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as e:  # noqa: BLE001
        app.logger.error("config.json inválido: %s", e)
        return {}


def safe(fn, *a):
    """Evita que un fallo en un módulo tumbe toda la auditoría."""
    try:
        return fn(*a)
    except Exception as e:  # noqa: BLE001
        return {"status": "ERROR", "message": f"Excepción: {e}"}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/network")
def api_network():
    return jsonify(safe(run_network_audit, load_config()))


@app.route("/api/hardening")
def api_hardening():
    return jsonify(safe(run_hardening_audit, load_config()))


@app.route("/api/logs")
def api_logs():
    return jsonify(safe(run_log_audit, load_config()))


@app.route("/api/audit")
def api_audit():
    cfg = load_config()
    return jsonify({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "network": safe(run_network_audit, cfg),
        "hardening": safe(run_hardening_audit, cfg),
        "logs": safe(run_log_audit, cfg),
        "is_root": hasattr(os, "geteuid") and os.geteuid() == 0,
    })


if __name__ == "__main__":
    s = load_config().get("server", {})
    app.run(host=s.get("host", "127.0.0.1"), port=s.get("port", 5000), debug=s.get("debug", False))
