#!/bin/bash
# ============================================================
#  OXware Hypervisor Installer v2.0
#  Ubuntu tabanlı KVM/QEMU Hypervisor Yönetim Sistemi
#  Minimum sistem gereksinimleri optimize edilmiş
# ============================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

OXWARE_VERSION="2.0.0"
INSTALL_DIR="/opt/oxware"
CONFIG_DIR="/etc/oxware"
LOG_DIR="/var/log/oxware"
DATA_DIR="/var/lib/oxware"
WEB_PORT=8006
VNC_START_PORT=5900
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Minimum gereksinimler
MIN_RAM_MB=1800       # 2 GB (biraz tolerans)
MIN_DISK_GB=15
MIN_CPU_CORES=1

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "  ██████╗ ██╗  ██╗██╗    ██╗ █████╗ ██████╗ ███████╗"
    echo " ██╔═══██╗╚██╗██╔╝██║    ██║██╔══██╗██╔══██╗██╔════╝"
    echo " ██║   ██║ ╚███╔╝ ██║ █╗ ██║███████║██████╔╝█████╗  "
    echo " ██║   ██║ ██╔██╗ ██║███╗██║██╔══██║██╔══██╗██╔══╝  "
    echo " ╚██████╔╝██╔╝ ██╗╚███╔███╔╝██║  ██║██║  ██║███████╗"
    echo "  ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝"
    echo -e "${WHITE}    Hypervisor Management System v${OXWARE_VERSION}${NC}"
    echo -e "${YELLOW}    Ubuntu/KVM — ESXi/Proxmox Alternatifi${NC}"
    echo ""
}

log()     { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
err()     { echo -e "${RED}[✗] HATA:${NC} $1"; exit 1; }
step()    { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }
confirm() { echo -e "${BLUE}[?]${NC} $1"; }

# ── Kontroller ────────────────────────────────────────────────────────────────
check_root() {
    [[ $EUID -ne 0 ]] && err "Root yetkisi gerekli: sudo bash install.sh"
}

check_ubuntu() {
    grep -qi "ubuntu" /etc/os-release 2>/dev/null || err "Yalnızca Ubuntu 20.04+ desteklenir"
    UBUNTU_VER=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
    MAJOR=$(echo "$UBUNTU_VER" | cut -d'.' -f1)
    [[ $MAJOR -lt 20 ]] && err "Ubuntu 20.04+ gerekli (mevcut: $UBUNTU_VER)"
    log "Ubuntu $UBUNTU_VER"
}

check_bios_virtualization() {
    step "BIOS Sanallaştırma Kontrolü"

    if grep -qE "vmx|svm" /proc/cpuinfo 2>/dev/null; then
        VIRT_TYPE=$(grep -oE "vmx|svm" /proc/cpuinfo | head -1 | tr 'a-z' 'A-Z')
        log "CPU sanallaştırma aktif: $VIRT_TYPE ($([ "$VIRT_TYPE" = "VMX" ] && echo "Intel VT-x" || echo "AMD-V"))"
    else
        warn "CPU sanallaştırma (VT-x/AMD-V) tespit edilemedi — test ortamında devam ediliyor"
        warn "Üretim ortamında VM'lerin çalışması için BIOS/UEFI'de VT-x veya AMD-V aktif olmalıdır"
    fi

    # KVM modülünü yükle
    modprobe kvm 2>/dev/null || true
    modprobe kvm_intel 2>/dev/null || modprobe kvm_amd 2>/dev/null || true

    if [ -e /dev/kvm ]; then
        log "/dev/kvm mevcut — KVM hazır"
    else
        warn "/dev/kvm yok — KVM desteği sınırlı olabilir"
    fi
}

check_hardware() {
    step "Donanım Gereksinimleri"

    # CPU
    CPU_CORES=$(nproc)
    CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "Bilinmiyor")
    if [[ $CPU_CORES -lt $MIN_CPU_CORES ]]; then
        err "Minimum $MIN_CPU_CORES CPU çekirdeği gerekli (mevcut: $CPU_CORES)"
    fi
    log "CPU: $CPU_MODEL ($CPU_CORES çekirdek)"

    # RAM
    RAM_MB=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
    if [[ $RAM_MB -lt $MIN_RAM_MB ]]; then
        warn "Düşük RAM: ${RAM_MB}MB (önerilen 2048MB+)"
        read -p "Devam edilsin mi? [y/N]: " -r
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
    log "RAM: ${RAM_MB}MB"

    # Disk
    DISK_GB=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    if [[ $DISK_GB -lt $MIN_DISK_GB ]]; then
        err "Minimum ${MIN_DISK_GB}GB disk alanı gerekli (mevcut: ${DISK_GB}GB)"
    fi
    log "Disk: ${DISK_GB}GB boş alan"
}

# ── Kurulum ───────────────────────────────────────────────────────────────────
update_system() {
    step "Sistem Güncellemesi"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get upgrade -y -qq 2>/dev/null || true
    log "Sistem güncellendi"
}

install_packages() {
    step "Paket Kurulumu"

    PKGS=(
        # Hypervisor çekirdeği
        qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients libvirt-dev
        # Python
        python3 python3-pip python3-venv python3-dev python3-libvirt
        # Ağ
        bridge-utils net-tools iptables iptables-persistent socat
        # Depolama
        lvm2 parted gdisk
        # SSL
        openssl ca-certificates
        # noVNC & konsol
        novnc websockify
        # Araçlar
        cpu-checker htop lsof curl wget git jq
        # Güvenlik
        ufw fail2ban
    )

    for pkg in "${PKGS[@]}"; do
        dpkg -l "$pkg" &>/dev/null || apt-get install -y -qq "$pkg" 2>/dev/null || warn "$pkg atlandı"
    done
    log "Paketler kuruldu"
}

configure_libvirt() {
    step "libvirt Yapılandırması"
    systemctl enable --now libvirtd 2>/dev/null || true

    # Default network
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

setup_bridge() {
    step "Köprü Ağ Yapılandırması"
    MAIN_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    if [ -z "$MAIN_IF" ]; then
        warn "Ana ağ arayüzü tespit edilemedi, köprü atlanıyor"
        return
    fi
    log "Ana arayüz: $MAIN_IF"

    # Basit bridge — KVM'in default NAT ağı yeterli çoğu kullanım için
    # Bridge isteğe bağlı; web arayüzünden yapılandırılabilir
}

setup_python() {
    step "Python Ortamı"
    python3 -m venv "$INSTALL_DIR/venv"
    source "$INSTALL_DIR/venv/bin/activate"
    pip install --upgrade pip -q
    pip install -r "$INSTALL_DIR/backend/requirements.txt" -q
    deactivate
    log "Python ortamı hazır"
}

generate_ssl() {
    step "SSL Sertifikası"
    mkdir -p "$CONFIG_DIR/ssl"
    HOST_IP=$(hostname -I | awk '{print $1}')
    HOSTNAME=$(hostname -f 2>/dev/null || hostname)
    openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
        -keyout "$CONFIG_DIR/ssl/oxware.key" \
        -out "$CONFIG_DIR/ssl/oxware.crt" \
        -subj "/C=TR/O=OXware/CN=$HOSTNAME" \
        -addext "subjectAltName=IP:$HOST_IP,DNS:$HOSTNAME,DNS:localhost" \
        2>/dev/null
    chmod 600 "$CONFIG_DIR/ssl/oxware.key"
    log "SSL sertifikası oluşturuldu (10 yıl, $HOSTNAME)"
}

write_config() {
    step "Yapılandırma"
    mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"/{isos,disks,backups,templates}

    SECRET=$(openssl rand -hex 32)

    cat > "$CONFIG_DIR/oxware.conf" << CONF
[server]
host = 0.0.0.0
port = ${WEB_PORT}
ssl = true
ssl_cert = ${CONFIG_DIR}/ssl/oxware.crt
ssl_key  = ${CONFIG_DIR}/ssl/oxware.key
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
    log "Yapılandırma dosyası: $CONFIG_DIR/oxware.conf"
}

copy_files() {
    step "OXware Dosyaları"
    mkdir -p "$INSTALL_DIR"
    cp -r "$SCRIPT_DIR/oxware/"* "$INSTALL_DIR/"
    chmod -R 750 "$INSTALL_DIR"
    log "Dosyalar kopyalandı: $INSTALL_DIR"
}

install_novnc() {
    step "noVNC Konsol"
    NOVNC_DIR="/usr/share/novnc"
    [ ! -d "$NOVNC_DIR" ] && NOVNC_DIR="/opt/novnc"
    if [ ! -d "$NOVNC_DIR" ]; then
        git clone https://github.com/novnc/noVNC.git "$NOVNC_DIR" -q 2>/dev/null || mkdir -p "$NOVNC_DIR"
    fi
    echo "novnc_dir = $NOVNC_DIR" >> "$CONFIG_DIR/oxware.conf"
    log "noVNC: $NOVNC_DIR"
}

create_service() {
    step "Systemd Servisi"
    cat > /etc/systemd/system/oxware.service << SERVICE
[Unit]
Description=OXware Hypervisor Management Service
Documentation=https://github.com/oxware/hypervisor
After=network.target libvirtd.service
Requires=libvirtd.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
Environment=OXWARE_CONFIG=${CONFIG_DIR}/oxware.conf
Environment=PYTHONUNBUFFERED=1
ExecStartPre=/bin/sleep 2
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/backend/app.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
TimeoutStopSec=30
KillMode=mixed
StandardOutput=append:${LOG_DIR}/oxware.log
StandardError=append:${LOG_DIR}/oxware-error.log
SyslogIdentifier=oxware

NoNewPrivileges=false
PrivateTmp=false

[Install]
WantedBy=multi-user.target
SERVICE
    systemctl daemon-reload
    systemctl enable oxware
    log "Servis oluşturuldu: oxware.service"
}

configure_firewall() {
    step "Güvenlik Duvarı"
    ufw --force reset 2>/dev/null
    ufw default deny incoming 2>/dev/null
    ufw default allow outgoing 2>/dev/null
    ufw allow 22/tcp    comment "SSH"            2>/dev/null
    ufw allow 8006/tcp  comment "OXware Web UI"  2>/dev/null
    ufw allow 5900:5999/tcp comment "VNC"        2>/dev/null
    ufw allow 6080/tcp  comment "noVNC WS"       2>/dev/null
    echo "y" | ufw enable 2>/dev/null || true
    log "UFW güvenlik duvarı aktif"
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
failregex = \[auth\].*Başarısız giriş.*<HOST>
            \[AUTH\].*Failed login.*<HOST>
ignoreregex =
F2BFILTER

    systemctl enable --now fail2ban 2>/dev/null || true
    systemctl reload fail2ban 2>/dev/null || true
    log "Fail2ban yapılandırıldı"
}

start_services() {
    step "Servisler Başlatılıyor"
    systemctl restart libvirtd
    sleep 2
    systemctl start oxware
    sleep 3
    if systemctl is-active --quiet oxware; then
        log "OXware servisi çalışıyor"
    else
        warn "OXware başlatılamadı — günlük: journalctl -u oxware -n 30"
    fi
}

print_done() {
    HOST_IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗"
    echo -e "║           OXware Hypervisor Kurulumu Tamamlandı!             ║"
    echo -e "╠══════════════════════════════════════════════════════════════╣"
    echo -e "║${NC}                                                              ${GREEN}║"
    echo -e "║${NC}  🌐 Web Arayüzü : ${CYAN}https://${HOST_IP}:${WEB_PORT}${NC}$(printf '%*s' $((22-${#HOST_IP})) '')${GREEN}║"
    echo -e "║${NC}                                                              ${GREEN}║"
    echo -e "║${NC}  İlk açılışta kullanıcı adı & şifre belirlenir.             ${GREEN}║"
    echo -e "║${NC}                                                              ${GREEN}║"
    echo -e "╠══════════════════════════════════════════════════════════════╣"
    echo -e "║${NC}  ${YELLOW}Şifre Yönetimi:${NC}                                             ${GREEN}║"
    echo -e "║${NC}  Değiştirmek için aşağıdaki formatta dosya oluşturun:       ${GREEN}║"
    echo -e "║${NC}  ${CYAN}sudo nano /etc/oxware/.passwd_reset${NC}                         ${GREEN}║"
    echo -e "║${NC}  Dosya içeriği:                                              ${GREEN}║"
    echo -e "║${NC}    ${WHITE}USERNAME=kullanici_adi${NC}                                   ${GREEN}║"
    echo -e "║${NC}    ${WHITE}PASSWORD=yeni_sifre${NC}                                      ${GREEN}║"
    echo -e "║${NC}  Servisi yeniden başlatınca uygulanır & dosya silinir.       ${GREEN}║"
    echo -e "║${NC}                                                              ${GREEN}║"
    echo -e "╠══════════════════════════════════════════════════════════════╣"
    echo -e "║${NC}  ${YELLOW}Servis Komutları:${NC}                                           ${GREEN}║"
    echo -e "║${NC}  systemctl {status|start|stop|restart} oxware              ${GREEN}║"
    echo -e "║${NC}  journalctl -u oxware -f                                    ${GREEN}║"
    echo -e "║${NC}  cat /var/log/oxware/oxware.log                             ${GREEN}║"
    echo -e "╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}SSL uyarısı için: Tarayıcıda 'Gelişmiş → Devam et' seçin.${NC}"
    echo ""
}

main() {
    print_banner

    check_root
    check_ubuntu
    check_bios_virtualization   # ZORUNLU kontrol
    check_hardware

    echo ""
    echo -e "${WHITE}Kurulum bilgileri:${NC}"
    echo "  Kurulum dizini : $INSTALL_DIR"
    echo "  Yapılandırma   : $CONFIG_DIR/oxware.conf"
    echo "  Web portu      : $WEB_PORT (HTTPS)"
    echo "  SSH portu      : 22"
    echo "  VNC portları   : 5900-5999"
    echo ""
    read -p "Devam edilsin mi? [Y/n]: " -r
    [[ $REPLY =~ ^[Nn]$ ]] && exit 0

    update_system
    install_packages
    copy_files
    configure_libvirt
    setup_bridge
    setup_python
    generate_ssl
    write_config
    install_novnc
    create_service
    configure_firewall
    configure_fail2ban
    start_services
    print_done
}

main "$@"
