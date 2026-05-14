import os
import configparser

CONFIG_FILE = os.environ.get("OXWARE_CONFIG", os.environ.get("ADAOS_CONFIG", "/etc/oxware/oxware.conf"))

_defaults = {
    "host": "0.0.0.0",
    "port": "8006",
    "ssl": "true",
    "ssl_cert": "/etc/oxware/ssl/oxware.crt",
    "ssl_key": "/etc/oxware/ssl/oxware.key",
    "secret_key": "oxware-change-me-in-production",
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
SECRET_KEY    = get("server", "secret_key")

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

for d in [DATA_DIR, ISO_DIR, DISK_DIR, BACKUP_DIR, TEMPLATE_DIR, LOG_DIR]:
    os.makedirs(d, exist_ok=True)
