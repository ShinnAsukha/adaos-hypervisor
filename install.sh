#!/bin/bash
# ============================================================
#  OXware Hypervisor Installer v2.2
#  Ubuntu/Debian KVM Hypervisor Yönetim Sistemi
#  https://github.com/ShinnAsukha/oxware-hypervisor
# ============================================================

# set -e kaldırıldı — &&-guard kalıplarıyla çakışıyor, hatalar açıkça yönetiliyor

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

OXWARE_VERSION="2.2.0"
REPO_URL="https://github.com/ShinnAsukha/oxware-hypervisor.git"

# ── Dizin Yapısı (sunucuyla tam uyumlu) ──────────────────────
# /opt/oxware/          → ana dizin (git repo buraya klonlanır)
# /opt/oxware/oxware/   → uygulama dosyaları (backend/ frontend/)
# /opt/oxware/venv/     → Python virtual environment
# /etc/oxware/          → konfigürasyon + SSL sertifikası
# /var/log/oxware/      → loglar
# /var/lib/oxware/      → veri (ISO, disk, yedek)
INSTALL_DIR="/opt/oxware"
APP_DIR="${INSTALL_DIR}/oxware"          # backend/ ve frontend/ burası
VENV_DIR="${INSTALL_DIR}/venv"
CONFIG_DIR="/etc/oxware"
LOG_DIR="/var/log/oxware"
DATA_DIR="/var/lib/oxware"
WEB_PORT=8006
VNC_START_PORT=5900

MIN_RAM_MB=1800
MIN_DISK_GB=15
MIN_CPU_CORES=1

# ── Yardımcı Fonksiyonlar ─────────────────────────────────────
print_banner() {
    clear
    echo -e "${CYAN}"
    cat << 'BANNER'
  ██████╗ ██╗  ██╗██╗    ██╗ █████╗ ██████╗ ███████╗
 ██╔═══██╗╚██╗██╔╝██║    ██║██╔══██╗██╔══██╗██╔════╝
 ██║   ██║ ╚███╔╝ ██║ █╗ ██║███████║██████╔╝█████╗
 ██║   ██║ ██╔██╗ ██║███╗██║██╔══██║██╔══██╗██╔══╝
 ╚██████╔╝██╔╝ ██╗╚███╔███╔╝██║  ██║██║  ██║███████╗
  ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
BANNER
    echo -e "${WHITE}    Hypervisor Management System v${OXWARE_VERSION}${NC}"
    echo -e "${YELLOW}    Ubuntu/KVM — ESXi/Proxmox Alternative${NC}"
    echo ""
}

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗] HATA:${NC} $1"; exit 1; }
step() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

# ── Kontroller ────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Root yetkisi gerekli: sudo bash install.sh"
    fi
}

check_os() {
    if grep -qiE "ubuntu|debian" /etc/os-release 2>/dev/null; then
        OS_NAME=$(grep ^NAME= /etc/os-release | cut -d'"' -f2 || echo "Linux")
        OS_VER=$(grep ^VERSION_ID= /etc/os-release | cut -d'"' -f2 || echo "")
        log "İşletim sistemi: $OS_NAME $OS_VER"
    else
        err "Sadece Ubuntu 20.04+ ve Debian 11+ desteklenmektedir"
    fi
}

check_bios_virtualization() {
    step "CPU Sanallaştırma Kontrolü"
    if grep -qE "vmx|svm" /proc/cpuinfo 2>/dev/null; then
        VIRT_TYPE=$(grep -oE "vmx|svm" /proc/cpuinfo | head -1 | tr 'a-z' 'A-Z')
        if [ "$VIRT_TYPE" = "VMX" ]; then
            log "CPU sanallaştırma aktif: VMX (Intel VT-x)"
        else
            log "CPU sanallaştırma aktif: SVM (AMD-V)"
        fi
    else
        warn "CPU sanallaştırma (VT-x/AMD-V) tespit edilemedi — test modunda devam ediliyor"
    fi
    modprobe kvm 2>/dev/null || true
    modprobe kvm_intel 2>/dev/null || modprobe kvm_amd 2>/dev/null || true
    if [ -e /dev/kvm ]; then log "/dev/kvm hazır"; else warn "/dev/kvm bulunamadı"; fi
}

check_hardware() {
    step "Donanım Gereksinimleri"
    CPU_CORES=$(nproc)
    CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "Bilinmiyor")
    if [[ $CPU_CORES -lt $MIN_CPU_CORES ]]; then
        err "Minimum $MIN_CPU_CORES CPU çekirdeği gerekli (bulunan: $CPU_CORES)"
    fi
    log "CPU: $CPU_MODEL ($CPU_CORES çekirdek)"

    RAM_MB=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
    if [[ $RAM_MB -lt $MIN_RAM_MB ]]; then
        warn "Düşük RAM: ${RAM_MB}MB (önerilen 2048MB+)"
        read -p "Yine de devam et? [e/H]: " -r
        if [[ ! $REPLY =~ ^[Ee]$ ]]; then exit 1; fi
    fi
    log "RAM: ${RAM_MB}MB"

    DISK_GB=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    if [[ $DISK_GB -lt $MIN_DISK_GB ]]; then
        err "Minimum ${MIN_DISK_GB}GB boş disk gerekli (bulunan: ${DISK_GB}GB)"
    fi
    log "Disk: ${DISK_GB}GB boş"
}

# ── Mevcut Kurulum Kontrolü ──────────────────────────────────
check_existing_installation() {
    step "Mevcut Kurulum Kontrolü"

    FOUND=false
    if [ -d "$INSTALL_DIR" ]; then FOUND=true; fi
    if [ -f /etc/systemd/system/oxware.service ]; then FOUND=true; fi

    if $FOUND; then
        warn "Mevcut OXware kurulumu tespit edildi!"
        echo ""
        echo -e "  ${YELLOW}[1]${NC} Tamamen sil ve sıfırdan kur (önerilen)"
        echo -e "  ${YELLOW}[2]${NC} Sadece dosyaları güncelle (konfigürasyon korunur)"
        echo -e "  ${YELLOW}[3]${NC} İptal"
        echo ""
        read -p "Seçim [1/2/3]: " -r OPT
        case $OPT in
            1)
                warn "Mevcut kurulum temizleniyor..."
                purge_existing
                log "Temizleme tamamlandı"
                ;;
            2)
                info "Güncelleme modu..."
                update_mode
                exit 0
                ;;
            *)
                echo "İptal edildi."
                exit 0
                ;;
        esac
    else
        log "Temiz kurulum — mevcut kurulum yok"
    fi
}

purge_existing() {
    systemctl stop oxware 2>/dev/null || true
    systemctl disable oxware 2>/dev/null || true
    rm -f /etc/systemd/system/oxware.service
    systemctl daemon-reload
    rm -rf "$INSTALL_DIR"
    rm -f /usr/local/bin/ox /usr/local/bin/oxupdate
    log "Eski kurulum temizlendi"
}

# ── Güncelleme Modu ───────────────────────────────────────────
update_mode() {
    step "Güncelleme Modu"

    # Git repo güncelle
    if [ -d "${INSTALL_DIR}/.git" ]; then
        cd "$INSTALL_DIR"
        git fetch origin master 2>/dev/null
        git reset --hard origin/master 2>/dev/null
        log "Kod güncellendi"
    else
        warn "Git repo bulunamadı — dosya güncelleme atlanıyor"
    fi

    # Python bağımlılıkları
    if [ -f "${VENV_DIR}/bin/activate" ]; then
        source "${VENV_DIR}/bin/activate"
        pip install -r "${APP_DIR}/backend/requirements.txt" -q 2>/dev/null || true
        pip install cryptography -q 2>/dev/null || true
        deactivate
        log "Python bağımlılıkları güncellendi"
    fi

    install_cli_tools
    download_fontawesome

    systemctl restart oxware 2>/dev/null || true
    sleep 3
    if systemctl is-active --quiet oxware; then
        log "OXware yeniden başlatıldı"
    else
        warn "Servis başlatılamadı — kontrol: journalctl -u oxware -n 30"
    fi

    HOST_IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "${GREEN}[✓] Güncelleme tamamlandı!${NC}"
    echo -e "    Adres: ${CYAN}https://${HOST_IP}:${WEB_PORT}${NC}"
}

# ── Paket Kurulumu ────────────────────────────────────────────
update_system() {
    step "Sistem Güncelleniyor"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get upgrade -y -qq 2>/dev/null || true
    log "Sistem güncellendi"
}

install_packages() {
    step "Paket Kurulumu"
    PKGS=(
        qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients libvirt-dev
        python3 python3-pip python3-venv python3-dev python3-libvirt
        bridge-utils net-tools iptables iptables-persistent socat
        lvm2 parted gdisk
        openssl ca-certificates
        novnc websockify
        cpu-checker htop lsof curl wget git jq smartmontools
        ufw fail2ban
        nftables wireguard
    )
    for pkg in "${PKGS[@]}"; do
        dpkg -l "$pkg" &>/dev/null || apt-get install -y -qq "$pkg" 2>/dev/null \
            || warn "Atlandı: $pkg"
    done
    log "Paketler kuruldu"
}

# ── Repo Clone ───────────────────────────────────────────────
clone_repo() {
    step "OXware Kaynak Kodu İndiriliyor"

    if ! command -v git &>/dev/null; then
        apt-get install -y -qq git
    fi

    mkdir -p "$INSTALL_DIR"

    # Git clone — en son master
    git clone "$REPO_URL" "$INSTALL_DIR" --branch master --depth=1 -q 2>/dev/null \
        || git clone "$REPO_URL" "$INSTALL_DIR" --depth=1 -q

    log "Repo klonlandı → $INSTALL_DIR"
    log "Uygulama dizini → $APP_DIR"

    # Dizin yapısını doğrula
    if [ ! -f "${APP_DIR}/backend/app.py" ]; then
        err "Beklenen dosya bulunamadı: ${APP_DIR}/backend/app.py"
    fi
    chmod -R 750 "$INSTALL_DIR"
}

# ── libvirt ───────────────────────────────────────────────────
configure_libvirt() {
    step "libvirt Yapılandırması"
    systemctl enable --now libvirtd 2>/dev/null || true
    if ! virsh net-list --all 2>/dev/null | grep -q "default"; then
        virsh net-define /usr/share/libvirt/networks/default.xml 2>/dev/null || true
    fi
    virsh net-autostart default 2>/dev/null || true
    virsh net-start default 2>/dev/null || true
    cat > /etc/libvirt/libvirtd.conf << 'EOF'
unix_sock_group = "libvirt"
unix_sock_rw_perms = "0770"
auth_unix_rw = "none"
EOF
    systemctl restart libvirtd 2>/dev/null || true
    log "libvirt yapılandırıldı"
}

# ── Python Ortamı ─────────────────────────────────────────────
setup_python() {
    step "Python Sanal Ortamı"
    python3 -m venv "$VENV_DIR"
    source "${VENV_DIR}/bin/activate"
    pip install --upgrade pip -q

    # requirements.txt'ten kur
    if [ -f "${APP_DIR}/backend/requirements.txt" ]; then
        pip install -r "${APP_DIR}/backend/requirements.txt" -q
    else
        # Temel bağımlılıklar
        pip install -q \
            flask flask-jwt-extended flask-socketio \
            eventlet python-libvirt \
            cryptography paramiko \
            psutil requests
    fi

    # Lisans şifrelemesi için (kritik)
    pip install cryptography -q
    deactivate
    log "Python ortamı hazır: $VENV_DIR"
}

# ── Font Awesome (Yerel) ──────────────────────────────────────
download_fontawesome() {
    step "Font Awesome (Yerel Kurulum)"
    STATIC_DIR="${APP_DIR}/frontend/static"
    mkdir -p "$STATIC_DIR/webfonts"

    FA_BASE="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1"

    if curl -sf "${FA_BASE}/css/all.min.css" -o "$STATIC_DIR/fontawesome.css" 2>/dev/null; then
        # CSS içindeki font yollarını düzelt
        sed -i 's|../webfonts/|/static/webfonts/|g' "$STATIC_DIR/fontawesome.css"

        for font in fa-solid-900.woff2 fa-brands-400.woff2 fa-regular-400.woff2 \
                    fa-solid-900.ttf  fa-brands-400.ttf  fa-regular-400.ttf; do
            curl -sf "${FA_BASE}/webfonts/$font" \
                -o "$STATIC_DIR/webfonts/$font" 2>/dev/null || warn "Atlandı: $font"
        done
        log "Font Awesome 6.5.1 yerel olarak indirildi"
    else
        warn "Font Awesome indirilemedi — CDN linki HTML'de kalacak"
    fi
}

# ── SSL Sertifikası ───────────────────────────────────────────
generate_ssl() {
    step "SSL Sertifikası Oluşturuluyor"
    mkdir -p "$CONFIG_DIR/ssl"
    HOST_IP=$(hostname -I | awk '{print $1}')
    HOSTNAME=$(hostname -f 2>/dev/null || hostname)
    openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
        -keyout "$CONFIG_DIR/ssl/oxware.key" \
        -out    "$CONFIG_DIR/ssl/oxware.crt" \
        -subj "/C=TR/O=OXware/CN=$HOSTNAME" \
        -addext "subjectAltName=IP:$HOST_IP,DNS:$HOSTNAME,DNS:localhost" 2>/dev/null
    chmod 600 "$CONFIG_DIR/ssl/oxware.key"
    log "SSL sertifikası oluşturuldu (10 yıl, $HOSTNAME / $HOST_IP)"
}

# ── Konfigürasyon ─────────────────────────────────────────────
write_config() {
    step "Konfigürasyon Yazılıyor"
    mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"/{isos,disks,backups,templates}
    SECRET=$(openssl rand -hex 32)
    cat > "$CONFIG_DIR/oxware.conf" << CONF
[server]
host       = 0.0.0.0
port       = ${WEB_PORT}
ssl        = true
ssl_cert   = ${CONFIG_DIR}/ssl/oxware.crt
ssl_key    = ${CONFIG_DIR}/ssl/oxware.key
secret_key = ${SECRET}

[storage]
data_dir     = ${DATA_DIR}
iso_dir      = ${DATA_DIR}/isos
disk_dir     = ${DATA_DIR}/disks
backup_dir   = ${DATA_DIR}/backups
template_dir = ${DATA_DIR}/templates

[vnc]
start_port     = ${VNC_START_PORT}
end_port       = 5999
websocket_port = 6080

[libvirt]
uri = qemu:///system

[logging]
log_dir = ${LOG_DIR}
level   = INFO
CONF
    chmod 600 "$CONFIG_DIR/oxware.conf"
    log "Konfigürasyon: $CONFIG_DIR/oxware.conf"
}

# ── noVNC ─────────────────────────────────────────────────────
install_novnc() {
    step "noVNC Konsol"
    NOVNC_DIR="/usr/share/novnc"
    [ ! -d "$NOVNC_DIR" ] && NOVNC_DIR="/opt/novnc"
    if [ ! -d "$NOVNC_DIR" ]; then
        git clone https://github.com/novnc/noVNC.git "$NOVNC_DIR" -q 2>/dev/null \
            || mkdir -p "$NOVNC_DIR"
    fi
    grep -q "novnc_dir" "$CONFIG_DIR/oxware.conf" \
        || echo "novnc_dir = $NOVNC_DIR" >> "$CONFIG_DIR/oxware.conf"
    log "noVNC: $NOVNC_DIR"
}

# ── Systemd Servis ────────────────────────────────────────────
create_service() {
    step "Systemd Servisi Oluşturuluyor"
    cat > /etc/systemd/system/oxware.service << SERVICE
[Unit]
Description=OXware Hypervisor Management Service
Documentation=https://github.com/ShinnAsukha/oxware-hypervisor
After=network.target libvirtd.service
Requires=libvirtd.service
Wants=network-online.target

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
    log "Servis oluşturuldu: /etc/systemd/system/oxware.service"
    info "WorkingDirectory : ${APP_DIR}"
    info "ExecStart        : ${VENV_DIR}/bin/python3 ${APP_DIR}/backend/app.py"
}

# ── CLI Araçları ──────────────────────────────────────────────
install_cli_tools() {
    step "CLI Araçları (ox / oxupdate)"

    # ox
    cat > /usr/local/bin/ox << OXCMD
#!/bin/bash
VERSION="${OXWARE_VERSION}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

show_help() {
cat << HELP
\${CYAN}
  ██████╗ ██╗  ██╗
 ██╔═══██╗\${NC}\${CYAN}╚██╗██╔╝
 ██║   ██║ \${NC}\${CYAN}╚███╔╝
 ██║   ██║ \${NC}\${CYAN}██╔██╗
 ╚██████╔╝██╔╝ ██╗
  ╚═════╝ ╚═╝  ╚═╝\${NC}
\${WHITE}OXware Hypervisor CLI v\${VERSION}\${NC}

\${YELLOW}Kullanım:\${NC} ox [komut]

\${YELLOW}Komutlar:\${NC}
  \${GREEN}--help, -h\${NC}      Bu yardımı göster
  \${GREEN}--status, -s\${NC}    Servis durumunu göster
  \${GREEN}--start\${NC}         OXware'i başlat
  \${GREEN}--stop\${NC}          OXware'i durdur
  \${GREEN}--restart\${NC}       OXware'i yeniden başlat
  \${GREEN}--logs, -l\${NC}      Son 50 log satırını göster
  \${GREEN}--logs -f\${NC}       Canlı log takibi
  \${GREEN}--info\${NC}          Sistem bilgilerini göster
  \${GREEN}--vms\${NC}           Sanal makineleri listele
  \${GREEN}--url\${NC}           Web arayüz adresini göster
  \${GREEN}--update\${NC}        OXware'i güncelle (oxupdate)
  \${GREEN}--version, -v\${NC}   Sürüm bilgisi
HELP
}

show_status() {
    echo -e "\n\${CYAN}━━━ OXware Servis Durumu ━━━\${NC}"
    systemctl status oxware --no-pager -l 2>/dev/null || echo "Servis bulunamadı"
    HOST_IP=\$(hostname -I | awk '{print \$1}')
    echo -e "\n  Web UI: \${CYAN}https://\${HOST_IP}:8006\${NC}\n"
}

show_info() {
    HOST_IP=\$(hostname -I | awk '{print \$1}')
    echo -e "\n\${CYAN}━━━ OXware Bilgileri ━━━\${NC}"
    echo -e "  Sürüm    : \${WHITE}\${VERSION}\${NC}"
    echo -e "  Web URL  : \${CYAN}https://\${HOST_IP}:8006\${NC}"
    echo -e "  Uygulama : ${APP_DIR}"
    echo -e "  Venv     : ${VENV_DIR}"
    echo -e "  Konfig   : ${CONFIG_DIR}/oxware.conf"
    echo -e "  Loglar   : ${LOG_DIR}/"
    echo -e "  Veri     : ${DATA_DIR}/"
    echo -e "\n\${CYAN}━━━ Sistem Kaynakları ━━━\${NC}"
    echo -e "  CPU    : \$(nproc) çekirdek — \$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
    RAM_MB=\$(grep MemTotal /proc/meminfo | awk '{print int(\$2/1024)}')
    FREE_MB=\$(grep MemAvailable /proc/meminfo | awk '{print int(\$2/1024)}')
    echo -e "  RAM    : \${RAM_MB}MB toplam, \${FREE_MB}MB boş"
    echo -e "  Disk   : \$(df / | awk 'NR==2{print \$5}') kullanıldı, \$(df / | awk 'NR==2{print int(\$4/1024/1024)}')GB boş"
    echo -e "\n\${CYAN}━━━ KVM Durumu ━━━\${NC}"
    [ -e /dev/kvm ] && echo -e "  KVM    : \${GREEN}Aktif\${NC}" || echo -e "  KVM    : \${RED}Bulunamadı\${NC}"
    echo ""
}

case "\$1" in
    --help|-h|"") show_help ;;
    --status|-s)  show_status ;;
    --start)      systemctl start oxware  && echo -e "\${GREEN}[✓] OXware başlatıldı\${NC}" ;;
    --stop)       systemctl stop oxware   && echo -e "\${YELLOW}[!] OXware durduruldu\${NC}" ;;
    --restart)    systemctl restart oxware && echo -e "\${GREEN}[✓] OXware yeniden başlatıldı\${NC}" ;;
    --logs|-l)
        [ "\$2" = "-f" ] && journalctl -u oxware -f \
                         || journalctl -u oxware -n 50 --no-pager ;;
    --info)       show_info ;;
    --vms)
        echo -e "\n\${CYAN}━━━ Sanal Makineler ━━━\${NC}"
        virsh list --all 2>/dev/null || echo "libvirt bağlantısı kurulamadı"
        echo "" ;;
    --url)
        HOST_IP=\$(hostname -I | awk '{print \$1}')
        echo -e "  \${CYAN}https://\${HOST_IP}:8006\${NC}" ;;
    --update)     oxupdate ;;
    --version|-v) echo "OXware v\${VERSION}" ;;
    *)
        echo -e "\${RED}Bilinmeyen komut: \$1\${NC}"
        echo "Yardım için: ox --help"
        exit 1 ;;
esac
OXCMD
    chmod +x /usr/local/bin/ox

    # oxupdate
    cat > /usr/local/bin/oxupdate << OXUPDATE
#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

APP_DIR="${APP_DIR}"
VENV_DIR="${VENV_DIR}"
INSTALL_DIR="${INSTALL_DIR}"

echo -e "\${CYAN}━━━ OXware Güncelleme ━━━\${NC}"
[[ \$EUID -ne 0 ]] && { echo -e "\${RED}Root gerekli: sudo oxupdate\${NC}"; exit 1; }

echo -e "\${YELLOW}[!]\${NC} OXware durduruluyor..."
systemctl stop oxware 2>/dev/null || true

if [ -d "\${INSTALL_DIR}/.git" ]; then
    echo -e "\${CYAN}[i]\${NC} GitHub'dan güncelleniyor..."
    cd "\${INSTALL_DIR}"
    git fetch origin master
    git reset --hard origin/master
    echo -e "\${GREEN}[✓]\${NC} Kod güncellendi"
else
    echo -e "\${YELLOW}[!]\${NC} Git repo bulunamadı — atlanıyor"
fi

echo -e "\${CYAN}[i]\${NC} Python bağımlılıkları güncelleniyor..."
source "\${VENV_DIR}/bin/activate"
if [ -f "\${APP_DIR}/backend/requirements.txt" ]; then
    pip install -r "\${APP_DIR}/backend/requirements.txt" -q
fi
pip install cryptography -q
deactivate

echo -e "\${CYAN}[i]\${NC} OXware başlatılıyor..."
systemctl start oxware
sleep 3

if systemctl is-active --quiet oxware; then
    echo -e "\${GREEN}[✓] OXware güncellendi ve çalışıyor!\${NC}"
    HOST_IP=\$(hostname -I | awk '{print \$1}')
    echo -e "    Web UI: \${CYAN}https://\${HOST_IP}:8006\${NC}"
else
    echo -e "\${RED}[✗] Servis başlatılamadı — kontrol: journalctl -u oxware -n 30\${NC}"
    exit 1
fi
OXUPDATE
    chmod +x /usr/local/bin/oxupdate

    log "ox komutu kuruldu → 'ox --help'"
    log "oxupdate komutu kuruldu → 'sudo oxupdate'"
}

# ── Firewall ──────────────────────────────────────────────────
configure_firewall() {
    step "Güvenlik Duvarı (UFW)"
    ufw --force reset 2>/dev/null
    ufw default deny incoming 2>/dev/null
    ufw default allow outgoing 2>/dev/null
    ufw allow 22/tcp   comment "SSH" 2>/dev/null
    ufw allow 8006/tcp comment "OXware Web UI" 2>/dev/null
    ufw allow 5900:5999/tcp comment "VNC" 2>/dev/null
    ufw allow 6080/tcp comment "noVNC WS" 2>/dev/null
    echo "y" | ufw enable 2>/dev/null || true
    log "UFW aktif"
}

configure_fail2ban() {
    step "Fail2ban"
    cat > /etc/fail2ban/jail.d/oxware.conf << 'F2B'
[oxware-web]
enabled  = true
port     = 8006
filter   = oxware-web
logpath  = /var/log/oxware/oxware.log
maxretry = 5
bantime  = 3600
findtime = 600

[sshd]
enabled  = true
maxretry = 5
bantime  = 3600
F2B
    cat > /etc/fail2ban/filter.d/oxware-web.conf << 'F2BFILTER'
[Definition]
failregex = \[auth\].*Failed login.*<HOST>
ignoreregex =
F2BFILTER
    systemctl enable --now fail2ban 2>/dev/null || true
    systemctl reload fail2ban 2>/dev/null || true
    log "Fail2ban yapılandırıldı"
}

# ── Servisleri Başlat ─────────────────────────────────────────
start_services() {
    step "Servisler Başlatılıyor"
    systemctl restart libvirtd
    sleep 2
    systemctl start oxware
    sleep 4

    if systemctl is-active --quiet oxware; then
        log "OXware servisi çalışıyor"
    else
        warn "OXware başlatılamadı — kontrol: journalctl -u oxware -n 30"
    fi
}

# ── Lisans Aktivasyonu ────────────────────────────────────────
activate_license() {
    step "Lisans Aktivasyonu (İsteğe Bağlı)"
    echo ""
    echo -e "${WHITE}Lisans anahtarınız varsa aşağıya girin.${NC}"
    echo -e "${YELLOW}Format: OXWARE-XXXX-XXXX-XXXX-XXXX${NC}"
    echo -e "${BLUE}Atlamak için ENTER'a basın${NC}"
    echo ""
    read -p "Lisans anahtarı: " -r LICENSE_KEY

    if [ -n "$LICENSE_KEY" ]; then
        HOST_IP=$(hostname -I | awk '{print $1}')
        # Admin token al (ilk login — setup yapılmamışsa boş döner)
        RESPONSE=$(curl -sk -X POST "https://${HOST_IP}:${WEB_PORT}/api/license/validate" \
            -H "Content-Type: application/json" \
            -d "{\"code\":\"${LICENSE_KEY}\"}" 2>/dev/null || echo '{}')

        if echo "$RESPONSE" | grep -q '"valid":true'; then
            log "Lisans başarıyla aktive edildi!"
            echo -e "  ${GREEN}✓ 7/24 Destek aktif${NC}"
        else
            warn "Lisans doğrulanamadı — web arayüzünden (Güvenlik → OXware Lisans) ekleyebilirsin"
        fi
    else
        info "Lisans aktivasyonu atlandı — web arayüzünden (Güvenlik → OXware Lisans) ekleyebilirsin"
    fi
}

# ── Tamamlama Ekranı ──────────────────────────────────────────
print_done() {
    HOST_IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗"
    echo -e "║         OXware Hypervisor Kurulumu Tamamlandı!              ║"
    echo -e "╠══════════════════════════════════════════════════════════════╣"
    echo -e "║${NC}                                                              ${GREEN}║"
    echo -e "║${NC}  🌐 Web UI    : ${CYAN}https://${HOST_IP}:${WEB_PORT}${NC}$(printf '%*s' $((21-${#HOST_IP})) '')${GREEN}║"
    echo -e "║${NC}  🔑 İlk giriş : Admin kullanıcısı oluştur                   ${GREEN}║"
    echo -e "║${NC}                                                              ${GREEN}║"
    echo -e "╠══════════════════════════════════════════════════════════════╣"
    echo -e "║${NC}  ${YELLOW}Dizin Yapısı:${NC}                                               ${GREEN}║"
    echo -e "║${NC}  Uygulama : ${APP_DIR}         ${GREEN}║"
    echo -e "║${NC}  Konfig   : ${CONFIG_DIR}/                           ${GREEN}║"
    echo -e "║${NC}  Loglar   : ${LOG_DIR}/                        ${GREEN}║"
    echo -e "║${NC}  Veri     : ${DATA_DIR}/                     ${GREEN}║"
    echo -e "╠══════════════════════════════════════════════════════════════╣"
    echo -e "║${NC}  ${YELLOW}CLI Komutları:${NC}                                              ${GREEN}║"
    echo -e "║${NC}  ${CYAN}ox --status${NC}      — Servis durumu                         ${GREEN}║"
    echo -e "║${NC}  ${CYAN}ox --logs -f${NC}     — Canlı log takibi                      ${GREEN}║"
    echo -e "║${NC}  ${CYAN}ox --vms${NC}         — Sanal makineleri listele              ${GREEN}║"
    echo -e "║${NC}  ${CYAN}ox --restart${NC}     — Servisi yeniden başlat               ${GREEN}║"
    echo -e "║${NC}  ${CYAN}sudo oxupdate${NC}    — Güncel sürüme geç                     ${GREEN}║"
    echo -e "╠══════════════════════════════════════════════════════════════╣"
    echo -e "║${NC}  ${YELLOW}Sorun mu var?${NC}                                               ${GREEN}║"
    echo -e "║${NC}  journalctl -u oxware -n 50 --no-pager                      ${GREEN}║"
    echo -e "╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}SSL uyarısı: Tarayıcıda 'Gelişmiş → Devam et' tıkla.${NC}"
    echo ""
}

# ── Ana Akış ─────────────────────────────────────────────────
main() {
    print_banner
    check_root
    check_os
    check_existing_installation
    check_bios_virtualization
    check_hardware

    echo ""
    echo -e "${WHITE}Kurulum özeti:${NC}"
    echo -e "  Repo URL    : $REPO_URL"
    echo -e "  Kurulum     : $INSTALL_DIR  (git repo)"
    echo -e "  Uygulama    : $APP_DIR"
    echo -e "  Python venv : $VENV_DIR"
    echo -e "  Konfig      : $CONFIG_DIR/oxware.conf"
    echo -e "  Web portu   : $WEB_PORT (HTTPS)"
    echo ""
    read -p "Kuruluma devam edilsin mi? [E/h]: " -r
    [[ $REPLY =~ ^[Hh]$ ]] && exit 0

    update_system
    install_packages
    clone_repo
    configure_libvirt
    setup_python
    download_fontawesome
    generate_ssl
    write_config
    install_novnc
    create_service
    configure_firewall
    configure_fail2ban
    install_cli_tools
    start_services
    activate_license
    print_done
}

main "$@"
