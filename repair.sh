#!/bin/bash
# ============================================================
#  OXware Onarım Scripti
#  Manuel kurulum sonrası eksik kısımları otomatik tamamlar
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗] HATA:${NC} $1"; exit 1; }
step() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }

[[ $EUID -ne 0 ]] && err "Root gerekli: sudo bash repair.sh"

INSTALL_DIR="/opt/oxware"
APP_DIR="${INSTALL_DIR}/oxware"
VENV_DIR="${INSTALL_DIR}/venv"
CONFIG_DIR="/etc/oxware"
LOG_DIR="/var/log/oxware"
DATA_DIR="/var/lib/oxware"
WEB_PORT=8006

# ── Dizin kontrolü ───────────────────────────────────────────
step "Dizin Yapısı Kontrol"
[ ! -f "${APP_DIR}/backend/app.py" ] && err "Uygulama bulunamadı: ${APP_DIR}/backend/app.py — önce git clone yapın"
log "Uygulama dizini: $APP_DIR"

# ── Gerekli sistem paketleri ─────────────────────────────────
step "Eksik Sistem Paketleri"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq \
    pkg-config gcc build-essential \
    python3 python3-pip python3-venv python3-dev python3-libvirt \
    libvirt-dev libvirt-daemon-system libvirt-clients \
    openssl ca-certificates novnc websockify \
    qemu-kvm qemu-utils 2>/dev/null || warn "Bazı paketler kurulamadı"
log "Sistem paketleri hazır"

# ── Python venv ───────────────────────────────────────────────
step "Python Sanal Ortamı"
if [ ! -f "${VENV_DIR}/bin/python3" ]; then
    python3 -m venv "$VENV_DIR"
    log "Venv oluşturuldu: $VENV_DIR"
else
    log "Venv mevcut: $VENV_DIR"
fi

source "${VENV_DIR}/bin/activate"
pip install --upgrade pip -q

if [ -f "${APP_DIR}/backend/requirements.txt" ]; then
    pip install -r "${APP_DIR}/backend/requirements.txt" -q
else
    pip install -q flask flask-jwt-extended flask-socketio eventlet cryptography paramiko psutil requests
fi
pip install cryptography libvirt-python -q
deactivate
log "Python paketleri kuruldu"

# ── Dizinler ─────────────────────────────────────────────────
step "Veri & Log Dizinleri"
mkdir -p "$LOG_DIR" "$CONFIG_DIR/ssl"
mkdir -p "$DATA_DIR"/{isos,disks,backups,templates}
chmod 755 "$LOG_DIR" "$DATA_DIR"
log "Dizinler hazır"

# ── Config dosyası ────────────────────────────────────────────
step "Konfigürasyon"
if [ ! -f "$CONFIG_DIR/oxware.conf" ]; then
    SECRET=$(openssl rand -hex 32)
    cat > "$CONFIG_DIR/oxware.conf" << CONF
[server]
host       = 0.0.0.0
port       = ${WEB_PORT}
ssl        = true
ssl_cert   = ${CONFIG_DIR}/ssl/oxware.crt
ssl_key    = ${CONFIG_DIR}/ssl/oxware.key
secret_key = ${SECRET}
novnc_dir  = /usr/share/novnc

[storage]
data_dir     = ${DATA_DIR}
iso_dir      = ${DATA_DIR}/isos
disk_dir     = ${DATA_DIR}/disks
backup_dir   = ${DATA_DIR}/backups
template_dir = ${DATA_DIR}/templates

[vnc]
start_port     = 5900
end_port       = 5999
websocket_port = 6080

[libvirt]
uri = qemu:///system

[logging]
log_dir = ${LOG_DIR}
level   = INFO
CONF
    chmod 600 "$CONFIG_DIR/oxware.conf"
    log "Config oluşturuldu: $CONFIG_DIR/oxware.conf"
else
    log "Config mevcut: $CONFIG_DIR/oxware.conf"
fi

# ── SSL sertifikası ───────────────────────────────────────────
step "SSL Sertifikası"
if [ ! -f "$CONFIG_DIR/ssl/oxware.crt" ] || [ ! -f "$CONFIG_DIR/ssl/oxware.key" ]; then
    HOST_IP=$(hostname -I | awk '{print $1}')
    HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
    openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
        -keyout "$CONFIG_DIR/ssl/oxware.key" \
        -out    "$CONFIG_DIR/ssl/oxware.crt" \
        -subj "/C=TR/O=OXware/CN=$HOSTNAME_VAL" \
        -addext "subjectAltName=IP:$HOST_IP,DNS:$HOSTNAME_VAL,DNS:localhost" 2>/dev/null
    chmod 600 "$CONFIG_DIR/ssl/oxware.key"
    log "SSL sertifikası oluşturuldu (10 yıl)"
else
    log "SSL sertifikası mevcut"
fi

# ── libvirt ───────────────────────────────────────────────────
step "libvirt"
systemctl enable --now libvirtd 2>/dev/null || true
virsh net-autostart default 2>/dev/null || true
virsh net-start default 2>/dev/null || true
log "libvirt hazır"

# ── Systemd servisi ───────────────────────────────────────────
step "Systemd Servisi"
cat > /etc/systemd/system/oxware.service << SERVICE
[Unit]
Description=OXware Hypervisor Management Service
After=network.target libvirtd.service
Requires=libvirtd.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${APP_DIR}
Environment=OXWARE_CONFIG=${CONFIG_DIR}/oxware.conf
Environment=PYTHONUNBUFFERED=1
ExecStartPre=/bin/bash -c 'mkdir -p ${LOG_DIR} ${DATA_DIR}/{isos,disks,backups,templates}'
ExecStartPre=/bin/sleep 2
ExecStart=${VENV_DIR}/bin/python3 ${APP_DIR}/backend/app.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
TimeoutStopSec=30
KillMode=mixed
StandardOutput=append:${LOG_DIR}/oxware.log
StandardError=append:${LOG_DIR}/oxware-error.log
SyslogIdentifier=oxware

[Install]
WantedBy=multi-user.target
SERVICE
systemctl daemon-reload
systemctl enable oxware
log "Servis güncellendi"

# ── Başlat ────────────────────────────────────────────────────
step "Servis Başlatılıyor"
systemctl stop oxware 2>/dev/null || true
sleep 1
systemctl start oxware
sleep 4

if systemctl is-active --quiet oxware; then
    HOST_IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════╗"
    echo -e "║       OXware Onarım Tamamlandı!            ║"
    echo -e "╠══════════════════════════════════════════════╣"
    echo -e "║${NC}                                              ${GREEN}║"
    echo -e "║${NC}  🌐 Web UI: ${CYAN}https://${HOST_IP}:${WEB_PORT}${NC}$(printf '%*s' $((14-${#HOST_IP})) '')${GREEN}║"
    echo -e "║${NC}                                              ${GREEN}║"
    echo -e "╚══════════════════════════════════════════════╝${NC}"
else
    echo ""
    warn "Servis hâlâ başlamıyor. Log:"
    tail -20 "$LOG_DIR/oxware-error.log" 2>/dev/null
    echo ""
    err "Servis başlatılamadı — log kontrol edin: cat $LOG_DIR/oxware-error.log"
fi
