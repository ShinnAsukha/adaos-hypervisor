import os
import configparser

CONFIG_FILE = os.environ.get("OXWARE_CONFIG", os.environ.get("ADAOS_CONFIG", "/etc/oxware/oxware.conf"))

_defaults = {
    "host": "0.0.0.0",
    "port": "8006",
    "ssl": "true",
    "ssl_cert": "/etc/oxware/ssl/oxware.crt",
    "ssl_key": "/etc/oxware/ssl/oxware.key",
    "secret_key": "",
    "data_dir": "/var/lib/oxware",
    "iso_dir": "/var/lib/oxware/isos",
    "disk_dir": "/var/lib/oxware/disks",
    "backup_dir": "/var/lib/oxware/backups",
    "template_dir": "/var/lib/oxware/templates",
    "vnc_start_port": "5900",
    "vnc_end_port": "5999",
    "websocket_port": "6080",
    "libvirt_uri": "qemu:///system",
    "log_dir": "/var/log/oxware",
    "log_level": "INFO",
    "users_file": "/var/lib/oxware/users.json",
    "novnc_dir": "/usr/share/novnc",
}


def _load():
    cfg = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        cfg.read(CONFIG_FILE)
    return cfg


_cfg = _load()


def get(section, key, fallback=None):
    # Try plain key first, then "section_key" compound form
    default = _defaults.get(key, _defaults.get(f"{section}_{key}", fallback))
    try:
        return _cfg.get(section, key)
    except (configparser.NoSectionError, configparser.NoOptionError):
        return default


HOST          = get("server", "host")
PORT          = int(get("server", "port"))
SSL_ENABLED   = get("server", "ssl", "true").lower() == "true"
SSL_CERT      = get("server", "ssl_cert")
SSL_KEY       = get("server", "ssl_key")

# JWT secret key — auto-generate and persist if not set or default
_SECRET_KEY_FILE = "/etc/oxware/jwt_secret.key"
_raw_secret = get("server", "secret_key") or ""
if not _raw_secret or _raw_secret in ("oxware-change-me-in-production", ""):
    if os.path.exists(_SECRET_KEY_FILE):
        with open(_SECRET_KEY_FILE) as _f:
            _raw_secret = _f.read().strip()
    if not _raw_secret:
        import secrets as _sec
        _raw_secret = _sec.token_hex(64)
        try:
            os.makedirs("/etc/oxware", exist_ok=True)
            with open(_SECRET_KEY_FILE, "w") as _f:
                _f.write(_raw_secret)
            os.chmod(_SECRET_KEY_FILE, 0o600)
        except OSError:
            pass  # /etc/oxware not writable yet (dev mode) — key ephemeral
SECRET_KEY = _raw_secret

DATA_DIR      = get("storage", "data_dir")
ISO_DIR       = get("storage", "iso_dir")
DISK_DIR      = get("storage", "disk_dir")
BACKUP_DIR    = get("storage", "backup_dir")
TEMPLATE_DIR  = get("storage", "template_dir")

VNC_START     = int(get("vnc", "start_port"))
VNC_END       = int(get("vnc", "end_port"))
WS_PORT       = int(get("vnc", "websocket_port"))

LIBVIRT_URI   = get("libvirt", "uri")
LOG_DIR       = get("logging", "log_dir")
LOG_LEVEL     = get("logging", "level")

USERS_FILE    = os.path.join(DATA_DIR, "users.json")
NOVNC_DIR     = get("server", "novnc_dir") or _defaults["novnc_dir"]

# ── Güvenlik yapılandırması ───────────────────────────────────────────────────
# CORS: virgülle ayrılmış izinli origin listesi (boşsa same-origin only)
# Örn: cors_origins = https://panel.example.com,https://admin.example.com
CORS_ORIGINS_RAW = get("server", "cors_origins", "") or ""
CORS_ORIGINS = [o.strip() for o in CORS_ORIGINS_RAW.split(",") if o.strip()]

# Trusted proxy CIDR listesi (XFF başlığına yalnızca bu ağlardan güvenilir)
# Örn: trusted_proxies = 127.0.0.1/32,10.0.0.1/32
TRUSTED_PROXIES_RAW = get("server", "trusted_proxies", "127.0.0.1/32") or "127.0.0.1/32"
TRUSTED_PROXIES = [p.strip() for p in TRUSTED_PROXIES_RAW.split(",") if p.strip()]

# Güncelleme kanalı allow-list (yalnızca bu repo URL'lerine güncelleme izni)
UPDATE_ALLOWED_REPOS_RAW = get("server", "update_allowed_repos",
    "https://github.com/ShinnAsukha/oxware-hypervisor") or ""
UPDATE_ALLOWED_REPOS = [r.strip() for r in UPDATE_ALLOWED_REPOS_RAW.split(",") if r.strip()]

# Build provenance signature (update integrity — do not edit/remove).
_BUILD_PROVENANCE = (
    "gAAAAABqNlv_94hddTqShjBaDsBIj9a7njAlfIZLvlI4DVogTS1yPPD7e2Di-kazLTzgKA7"
    "eEz5udBbBMWtIW0l6zH5dTn7XwGcMqYBeVdsu4qwjma8EYZKi5cj2addYn4Q4PpyLM3apm_"
    "xHF_DM6qd3Y8NGN2Ge-kwNntNExsaTX2XZEdTSCaW5laTU1XANOkWr-wjgrV1r0N07lpl4I"
    "m1VEqRg7R7UPZ-NpOPd7bTKiUxoUPTsUA4="
)

for d in [DATA_DIR, ISO_DIR, DISK_DIR, BACKUP_DIR, TEMPLATE_DIR, LOG_DIR]:
    os.makedirs(d, exist_ok=True)
