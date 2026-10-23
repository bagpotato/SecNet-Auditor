# 🛡️ SecNet-Auditor

Modular network audit, hardening and defensive monitoring suite for **Ubuntu/Debian** servers, with a local web dashboard (Flask). Educational project for the SMX course.

> ⚠️ **Read-only**: the tool *audits* and never modifies the firewall, users or permissions. Corrective actions are shown as suggestions only. Use it only on systems you own or are authorized to audit.

## Structure

```
SecNet-Auditor/
├── app.py                  # Flask server and JSON API
├── config.json             # Adjustable settings
├── modules/
│   ├── network_check.py    # Netplan, DNS, interfaces (ip link)
│   ├── hardening.py        # UFW, UID 0, octal permissions
│   └── log_monitor.py      # Lightweight SIEM (regex over auth.log)
└── templates/index.html    # Dashboard (Bootstrap 5)
```

## Requirements

- Ubuntu/Debian with Python 3.8+
- `iproute2` (`ip` command), optionally `ufw` and Netplan
- Flask

```bash
sudo apt update && sudo apt install -y python3 python3-venv ufw
cd SecNet-Auditor
python3 -m venv venv && source venv/bin/activate
pip install flask
```

## Running

```bash
# Limited privileges (some data will show as "no access")
python app.py

# Full audit (UFW, auth.log, /etc/netplan, /etc/shadow...)
sudo venv/bin/python app.py
```

Open `http://127.0.0.1:5000` and click **Run Full Audit**. The audit also runs when the page loads.

> Alternative without sudo: add your user to the `adm` group (`sudo usermod -aG adm $USER`) to read `/var/log/auth.log`.

## Configuration (`config.json`)

| Key | Description |
|---|---|
| `server.host` / `server.port` | Bind address and port (localhost only by default) |
| `ssh.failed_attempts_threshold` | Failed attempts from one IP before raising an alert |
| `ssh.auth_log_path` | Log path (`/var/log/auth.log`) |
| `ssh.lines_to_analyze` | Analyze the last N lines |
| `network.netplan_dir`, `network.resolv_conf`, `network.dns_test_host` | Paths and DNS test host |
| `hardening.critical_files` | File → maximum expected octal permissions |

The file is re-read on every audit: no restart needed.

## API

| Route | Content |
|---|---|
| `GET /` | Dashboard |
| `GET /api/audit` | Full audit |
| `GET /api/network` · `/api/hardening` · `/api/logs` | Individual modules |

## What it detects

- **Network**: Netplan YAML (DHCP, IPs, gateway, permissions, tabs), nameservers and a real resolution test, interfaces and their state.
- **Hardening**: UFW active/inactive, non-root accounts with UID 0, permissions more permissive than expected.
- **Logs**: SSH brute force per IP (`Failed password`, `Invalid user`, `authentication failure`). Severity HIGH/CRITICAL; flagged if the IP ever authenticated successfully (`Accepted`).

## Dashboard security

It listens on `127.0.0.1` only and has no authentication. **Do not expose it** to the network (`0.0.0.0`) without a reverse proxy with login and TLS. If you use `sudo`, remember the server runs as root.

## Troubleshooting

- *"No permission to read auth.log"* → use `sudo` or the `adm` group.
- *Missing log* → on pure-journald systems install `rsyslog`.
- *UFW asks for root* → run with `sudo`.

## Extension ideas (SMX exercises)

`sshd_config` audit, open ports (`ss -tulpn`), report export, assisted blocking with confirmation.
