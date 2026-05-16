#!/bin/bash
# ============================================================
#  OXware Onarım Scripti — repair.sh
#  Yeniden başlatma sonrası SSH / ağ / servis sorunlarını çözer
#  Sürüm: 2.3
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[✗] HATA:${NC} $1"; exit 1; }
step()  { echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${BOLD}  $1${NC}"; echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
info()  { echo -e "    ${CYAN}→${NC} $1"; }

[[ $EUID -ne 0 ]] && err "Root gerekli: sudo bash repair.sh"

INSTALL_DIR="/opt/oxware"
APP_DIR="${INSTALL_DIR}/oxware"
VENV_DIR="${INSTALL_DIR}/venv"
CONFIG_DIR="/etc/oxware"
LOG_DIR="/var/log/oxware"
DATA_DIR="/var/lib/oxware"
WEB_PORT=8006

echo ""
echo -e "${BOLD}  OXware Onarım Scripti${NC}"
echo -e "  Sistem: $(hostname) | $(date '+%Y-%m-%d %H:%M')"
echo ""

# ── 1. SSH Onarımı ───────────────────────────────────────────
step "SSH Onarımı"
info "SSH servisi başlatılıyor..."
systemctl enable ssh 2>/dev/null || systemctl enable openssh-server 2>/dev/null || true
systemctl start ssh 2>/dev/null || systemctl start openssh-server 2>/dev/null || true

# sshd_config — root + şifre girişine izin ver
SSHD="/etc/ssh/sshd_config"
if [ -f "$SSHD" ]; then
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/'           "$SSHD"
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD"
    sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/'     "$SSHD"
    sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSHD" 2>/dev/null || true
    systemctl restart ssh 2>/dev/null || systemctl restart openssh-server 2>/dev/null || true
    log "SSH yapılandırması düzeltildi (PermitRootLogin yes, PasswordAuthentication yes)"
else
    warn "sshd_config bulunamadı"
fi

# ── 2. Hostname Onarımı ──────────────────────────────────────
step "Hostname Onarımı (cloud-init)"
CURRENT_HOST=$(hostname)
if [ "$CURRENT_HOST" = "localhost" ] || [ "$CURRENT_HOST" = "localhost.localdomain" ] || [ -z "$CURRENT_HOST" ]; then
    HOST_IP=$(hostname -I | awk '{print $1}' | tr -d '\n')
    NEW_HOST="oxware-$(echo "$HOST_IP" | tr '.' '-')"
    warn "Hostname '$CURRENT_HOST' geçersiz → '$NEW_HOST' olarak ayarlanıyor"
    hostnamectl set-hostname "$NEW_HOST"
    CURRENT_HOST="$NEW_HOST"
fi

# /etc/hosts güncelle
HOST_IP=$(hostname -I | awk '{print $1}' | tr -d '\n')
grep -q "^${HOST_IP}" /etc/hosts || echo "${HOST_IP}  ${CURRENT_HOST}  ${CURRENT_HOST}.localdomain" >> /etc/hosts
grep -q "127.0.1.1" /etc/hosts || echo "127.0.1.1  ${CURRENT_HOST}" >> /etc/hosts
sed -i "s/^127\.0\.1\.1.*/127.0.1.1  ${CURRENT_HOST}/" /etc/hosts
log "Hostname: $CURRENT_HOST"

# cloud-init hostname sıfırlamasını engelle
if [ -d /etc/cloud/cloud.cfg.d ]; then
    cat > /etc/cloud/cloud.cfg.d/99_hostname.cfg << 'CLOUDINIT'
preserve_hostname: true
manage_etc_hosts: false
CLOUDINIT
    log "cloud-init hostname sıfırlaması engellendi"
fi

# ── 3. UFW / Güvenlik Duvarı Onarımı ────────────────────────
step "UFW / Güvenlik Duvarı Onarımı"
export DEBIAN_FRONTEND=noninteractive

# iptables-legacy (Ubuntu 20.04+/nftables çakışması çözümü)
if command -v update-alternatives &>/dev/null && command -v iptables-legacy &>/dev/null 2>/dev/null; then
    update-alternatives --set iptables  /usr/sbin/iptables-legacy  2>/dev/null || true
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null || true
    log "iptables → iptables-legacy ayarlandı (UFW çakışması giderildi)"
fi

# UFW portları aç
if command -v ufw &>/dev/null; then
    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming  >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    ufw allow 22/tcp    comment "SSH"       >/dev/null 2>&1
    ufw allow 80/tcp    comment "HTTP"      >/dev/null 2>&1
    ufw allow 443/tcp   comment "HTTPS"     >/dev/null 2>&1
    ufw allow 8006/tcp  comment "OXware UI" >/dev/null 2>&1
    ufw allow 5900:5999/tcp comment "VNC"   >/dev/null 2>&1
    ufw allow 6080/tcp  comment "noVNC WS"  >/dev/null 2>&1
    systemctl enable ufw 2>/dev/null || true
    ufw --force enable >/dev/null 2>&1
    log "UFW aktif — SSH(22), HTTP(80), HTTPS(443), OXware(8006), VNC(5900-5999), noVNC(6080)"
else
    warn "ufw bulunamadı — atlıyorum"
fi

# ── 4. Ağ / KVM Onarımı ─────────────────────────────────────
step "Ağ ve KVM Onarımı"

# KVM modülleri
for mod in kvm kvm_intel kvm_amd; do
    modprobe "$mod" 2>/dev/null || true
done
for mod in kvm kvm_intel kvm_amd; do
    grep -q "^${mod}$" /etc/modules 2>/dev/null || echo "$mod" >> /etc/modules
done
log "KVM modülleri yüklendi"

# br_netfilter (VM güvenlik duvarı için)
modprobe br_netfilter 2>/dev/null || true
grep -q "br_netfilter" /etc/modules-load.d/*.conf 2>/dev/null || \
    echo "br_netfilter" > /etc/modules-load.d/br_netfilter.conf

# NetworkManager-wait-online (yavaş başlatma sorunu)
systemctl disable NetworkManager-wait-online.service 2>/dev/null || true
systemctl mask NetworkManager-wait-online.service    2>/dev/null || true
info "NetworkManager-wait-online devre dışı (boot hızlandırıldı)"

# systemd-networkd-wait-online timeout kısalt
mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d/
cat > /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf << 'OVERRIDE'
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --timeout=10
OVERRIDE

# libvirt varsayılan ağı
systemctl enable --now libvirtd 2>/dev/null || true
virsh net-autostart default 2>/dev/null || true
virsh net-start default 2>/dev/null || true
log "libvirt ağı başlatıldı"

# ── 5. Dizin Kontrolü ────────────────────────────────────────
step "Dizin Yapısı Kontrol"
[ ! -f "${APP_DIR}/backend/app.py" ] && err "Uygulama bulunamadı: ${APP_DIR}/backend/app.py — önce git clone veya scp ile kopyalayın"
log "Uygulama dizini: $APP_DIR"

mkdir -p "$LOG_DIR" "$CONFIG_DIR/ssl"
mkdir -p "$DATA_DIR"/{isos,disks,backups,templates}
chmod 755 "$LOG_DIR" "$DATA_DIR"
log "Dizinler hazır"

# ── 6. Eksik Sistem Paketleri ────────────────────────────────
step "Eksik Sistem Paketleri"
apt-get install -y -qq \
    pkg-config gcc build-essential \
    python3 python3-pip python3-venv python3-dev python3-libvirt \
    libvirt-dev libvirt-daemon-system libvirt-clients \
    openssl ca-certificates novnc websockify \
    qemu-kvm qemu-utils \
    certbot python3-certbot 2>/dev/null || warn "Bazı paketler kurulamadı"
log "Sistem paketleri hazır"

# ── 7. Python venv ───────────────────────────────────────────
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

# ── 8. Config dosyası ─────────────────────────────────────────
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

# ── 9. SSL sertifikası ────────────────────────────────────────
step "SSL Sertifikası"
if [ ! -f "$CONFIG_DIR/ssl/oxware.crt" ] || [ ! -f "$CONFIG_DIR/ssl/oxware.key" ]; then
    HOST_IP=$(hostname -I | awk '{print $1}')
    HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
    mkdir -p "$CONFIG_DIR/ssl"
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

# ── 10. Systemd servisi ───────────────────────────────────────
step "Systemd Servisi"
cat > /etc/systemd/system/oxware.service << SERVICE
[Unit]
Description=OXware Hypervisor Management Service
After=network.target libvirtd.service
Requires=libvirtd.service
StartLimitIntervalSec=120
StartLimitBurst=5

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

# ── 11. Servis Başlat ─────────────────────────────────────────
step "Servis Başlatılıyor"
systemctl stop oxware 2>/dev/null || true
sleep 1
systemctl start oxware
sleep 4

# ── Özet ─────────────────────────────────────────────────────
echo ""
HOST_IP=$(hostname -I | awk '{print $1}')
if systemctl is-active --quiet oxware; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗"
    echo -e "║          OXware Onarım Tamamlandı! ✓               ║"
    echo -e "╠══════════════════════════════════════════════════════╣"
    echo -e "║${NC}                                                      ${GREEN}║"
    echo -e "║${NC}  🌐 Web UI  : ${CYAN}https://${HOST_IP}:${WEB_PORT}${NC}$(printf '%*s' $((18-${#HOST_IP})) '')${GREEN}║"
    echo -e "║${NC}  🔐 SSH     : ${CYAN}ssh root@${HOST_IP}${NC}$(printf '%*s' $((22-${#HOST_IP})) '')${GREEN}║"
    echo -e "║${NC}  📋 Log     : ${CYAN}journalctl -u oxware -f${NC}              ${GREEN}║"
    echo -e "║${NC}                                                      ${GREEN}║"
    echo -e "╚══════════════════════════════════════════════════════╝${NC}"
else
    echo ""
    warn "OXware servisi başlamadı. Hata logu:"
    echo ""
    tail -25 "$LOG_DIR/oxware-error.log" 2>/dev/null || journalctl -u oxware -n 25 --no-pager 2>/dev/null
    echo ""
    echo -e "${YELLOW}Sorun giderme:${NC}"
    echo "  sudo journalctl -u oxware -n 50 --no-pager"
    echo "  cat $LOG_DIR/oxware-error.log"
    echo "  systemctl status oxware"
fi

# SSH bağlantı bilgisi
echo ""
echo -e "${BOLD}SSH hâlâ çalışmıyorsa:${NC}"
echo "  systemctl restart ssh"
echo "  ss -tlnp | grep ':22'"
echo "  sudo ufw allow 22"
