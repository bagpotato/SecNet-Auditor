# 🛡️ SecNet-Auditor

Suite modular de auditoría de red, hardening y monitorización defensiva para servidores **Ubuntu/Debian**, con panel web local (Flask). Proyecto formativo para el ciclo SMX.

> ⚠️ **Solo lectura**: la herramienta *audita*, nunca modifica el firewall, usuarios ni permisos. Las acciones correctoras se muestran como sugerencias. Úsala únicamente en sistemas propios o autorizados.

## Estructura

```
SecNet-Auditor/
├── app.py                  # Servidor Flask y API JSON
├── config.json             # Parámetros ajustables
├── modules/
│   ├── network_check.py    # Netplan, DNS, interfaces (ip link)
│   ├── hardening.py        # UFW, UID 0, permisos octales
│   └── log_monitor.py      # SIEM ligero (regex sobre auth.log)
└── templates/index.html    # Dashboard (Bootstrap 5)
```

## Requisitos

- Ubuntu/Debian con Python 3.8+
- `iproute2` (comando `ip`), opcionalmente `ufw` y Netplan
- Flask

```bash
sudo apt update && sudo apt install -y python3 python3-venv ufw
cd SecNet-Auditor
python3 -m venv venv && source venv/bin/activate
pip install flask
```

## Ejecución

```bash
# Con privilegios limitados (algunos datos aparecerán como "sin acceso")
python app.py

# Auditoría completa (UFW, auth.log, /etc/netplan, /etc/shadow...)
sudo venv/bin/python app.py
```

Abre `http://127.0.0.1:5000` y pulsa **Ejecutar Auditoría Completa**. La auditoría también se lanza al cargar la página.

> Alternativa sin sudo: añade tu usuario al grupo `adm` (`sudo usermod -aG adm $USER`) para leer `/var/log/auth.log`.

## Configuración (`config.json`)

| Clave | Descripción |
|---|---|
| `server.host` / `server.port` | Dirección y puerto (por defecto solo localhost) |
| `ssh.failed_attempts_threshold` | Intentos fallidos desde una IP para generar alerta |
| `ssh.auth_log_path` | Ruta del log (`/var/log/auth.log`) |
| `ssh.lines_to_analyze` | Últimas N líneas a analizar |
| `network.netplan_dir`, `network.resolv_conf`, `network.dns_test_host` | Rutas y host de prueba DNS |
| `hardening.critical_files` | Archivo → permisos octales máximos esperados |

El fichero se relee en cada auditoría: no hace falta reiniciar.

## API

| Ruta | Contenido |
|---|---|
| `GET /` | Dashboard |
| `GET /api/audit` | Auditoría completa |
| `GET /api/network` · `/api/hardening` · `/api/logs` | Módulos por separado |

## Qué detecta

- **Red**: YAML de Netplan (DHCP, IPs, gateway, permisos, tabuladores), nameservers y prueba de resolución real, interfaces y su estado.
- **Hardening**: UFW activo/inactivo, cuentas con UID 0 distintas de root, permisos más permisivos de lo esperado.
- **Logs**: fuerza bruta SSH por IP (`Failed password`, `Invalid user`, `authentication failure`). Severidad ALTA/CRÍTICA; se marca si la IP llegó a autenticarse con éxito (`Accepted`).

## Seguridad del propio panel

Escucha solo en `127.0.0.1` y no tiene autenticación. **No lo expongas** a la red (`0.0.0.0`) sin un proxy inverso con login y TLS. Si usas `sudo`, recuerda que el servidor corre como root.

## Resolución de problemas

- *"Sin permisos para leer auth.log"* → usa `sudo` o el grupo `adm`.
- *Log inexistente* → en sistemas con journald puro instala `rsyslog`.
- *UFW pide root* → ejecuta con `sudo`.

## Ideas de ampliación (ejercicios SMX)

Auditoría de `sshd_config`, puertos abiertos (`ss -tulpn`), exportación de informes, bloqueo asistido con confirmación.
