#!/bin/bash
# ============================================================
#  OXware Hypervisor Installer v2.1
#  Ubuntu/Debian KVM Hypervisor Yönetim Sistemi
#  https://github.com/ShinnAsukha/oxware-hypervisor
# ============================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

OXWARE_VERSION="2.1.0"
INSTALL_DIR="/opt/oxware"
CONFIG_DIR="/etc/oxware"
LOG_DIR="/var/log/oxware"
DATA_DIR="/var/lib/oxware"
WEB_PORT=8006
VNC_START_PORT=5900
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MIN_RAM_MB=1800
MIN_DISK_GB=15
MIN_CPU_CORES=1

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
err()  { echo -e "${RED}[✗] ERROR:${NC} $1"; exit 1; }
step() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

check_root() {
    [[ $EUID -ne 0 ]] && err "Root privileges required: sudo bash install.sh"
}

check_os() {
    if grep -qi "ubuntu\|debian" /etc/os-release 2>/dev/null; then
        OS_NAME=$(grep ^NAME= /etc/os-release | cut -d'"' -f2)
        OS_VER=$(grep ^VERSION_ID= /etc/os-release | cut -d'"' -f2)
        log "OS: $OS_NAME $OS_VER"
    else
        err "Only Ubuntu 20.04+ and Debian 11+ are supported"
    fi
}

check_existing_installation() {
    step "Checking Existing Installation"
    if [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/backend/app.py" ]; then
        warn "Existing OXware installation detected at $INSTALL_DIR"
        echo ""
        echo -e "${YELLOW}Options:${NC}"
        echo "  [1] Reinstall from scratch (removes existing installation)"
        echo "  [2] Update existing installation (keeps configuration)"
        echo "  [3] Cancel"
        echo ""
        read -p "Select option [1/2/3]: " -r REINSTALL_OPT
        case $REINSTALL_OPT in
            1)
                warn "Removing existing installation..."
                systemctl stop oxware 2>/dev/null || true
                systemctl disable oxware 2>/dev/null || true
                rm -rf "$INSTALL_DIR"
                log "Existing installation removed"
                ;;
            2)
                info "Updating existing installation..."
                update_mode
                exit 0
                ;;
            *)
                echo "Installation cancelled."
                exit 0
                ;;
        esac
    else
        log "No existing installation found — fresh install"
    fi
}

update_mode() {
    step "Update Mode"
    if [ ! -d "$INSTALL_DIR" ]; then
        err "OXware is not installed at $INSTALL_DIR"
    fi

    # Pull latest from git if available
    if [ -d "$INSTALL_DIR/.git" ]; then
        cd "$INSTALL_DIR"
        git fetch origin 2>/dev/null && git reset --hard origin/main 2>/dev/null || true
    fi

    # Update files
    if [ -d "$SCRIPT_DIR/oxware" ]; then
        cp -r "$SCRIPT_DIR/oxware/"* "$INSTALL_DIR/"
        chmod -R 750 "$INSTALL_DIR"
        log "Files updated"
    fi

    # Update Python deps
    source "$INSTALL_DIR/venv/bin/activate" 2>/dev/null || python3 -m venv "$INSTALL_DIR/venv" && source "$INSTALL_DIR/venv/bin/activate"
    pip install -r "$INSTALL_DIR/backend/requirements.txt" -q
    deactivate
    log "Python dependencies updated"

    # Install CLI tools
    install_cli_tools

    # Restart service
    systemctl restart oxware 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet oxware; then
        log "OXware restarted successfully"
    else
        warn "Service restart failed — check: journalctl -u oxware -n 30"
    fi

    HOST_IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "${GREEN}[✓] Update complete!${NC}"
    echo -e "    Access: ${CYAN}https://${HOST_IP}:${WEB_PORT}${NC}"
}

check_bios_virtualization() {
    step "CPU Virtualization Check"
    if grep -qE "vmx|svm" /proc/cpuinfo 2>/dev/null; then
        VIRT_TYPE=$(grep -oE "vmx|svm" /proc/cpuinfo | head -1 | tr 'a-z' 'A-Z')
        log "CPU virtualization active: $VIRT_TYPE ($([ "$VIRT_TYPE" = "VMX" ] && echo "Intel VT-x" || echo "AMD-V"))"
    else
        warn "CPU virtualization (VT-x/AMD-V) not detected — continuing in test mode"
    fi
    modprobe kvm 2>/dev/null || true
    modprobe kvm_intel 2>/dev/null || modprobe kvm_amd 2>/dev/null || true
    [ -e /dev/kvm ] && log "/dev/kvm ready" || warn "/dev/kvm not found — KVM may be limited"
}

check_hardware() {
    step "Hardware Requirements"
    CPU_CORES=$(nproc)
    CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "Unknown")
    [[ $CPU_CORES -lt $MIN_CPU_CORES ]] && err "Minimum $MIN_CPU_CORES CPU core required (found: $CPU_CORES)"
    log "CPU: $CPU_MODEL ($CPU_CORES cores)"

    RAM_MB=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
    if [[ $RAM_MB -lt $MIN_RAM_MB ]]; then
        warn "Low RAM: ${RAM_MB}MB (recommended 2048MB+)"
        read -p "Continue anyway? [y/N]: " -r; [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
    log "RAM: ${RAM_MB}MB"

    DISK_GB=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    [[ $DISK_GB -lt $MIN_DISK_GB ]] && err "Minimum ${MIN_DISK_GB}GB free disk required (found: ${DISK_GB}GB)"
    log "Disk: ${DISK_GB}GB free"
}

update_system() {
    step "System Update"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get upgrade -y -qq 2>/dev/null || true
    log "System updated"
}

install_packages() {
    step "Package Installation"
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
        dpkg -l "$pkg" &>/dev/null || apt-get install -y -qq "$pkg" 2>/dev/null || warn "Skipped: $pkg"
    done
    log "Packages installed"
}

configure_libvirt() {
    step "libvirt Configuration"
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
    log "libvirt configured"
}

setup_python() {
    step "Python Environment"
    python3 -m venv "$INSTALL_DIR/venv"
    source "$INSTALL_DIR/venv/bin/activate"
    pip install --upgrade pip -q
    pip install -r "$INSTALL_DIR/backend/requirements.txt" -q
    deactivate
    log "Python environment ready"
}

# Download Font Awesome locally (CDN reliability fix)
download_fontawesome() {
    step "Font Awesome (Local)"
    STATIC_DIR="$INSTALL_DIR/frontend/static"
    mkdir -p "$STATIC_DIR/webfonts"

    FA_BASE="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1"

    if curl -sf "$FA_BASE/css/all.min.css" -o "$STATIC_DIR/fontawesome.css" 2>/dev/null; then
        # Fix font paths in CSS to point to local /static/webfonts/
        sed -i 's|../webfonts/|/static/webfonts/|g' "$STATIC_DIR/fontawesome.css"

        for font in fa-solid-900.woff2 fa-brands-400.woff2 fa-regular-400.woff2 \
                    fa-solid-900.ttf fa-brands-400.ttf fa-regular-400.ttf; do
            curl -sf "$FA_BASE/webfonts/$font" -o "$STATIC_DIR/webfonts/$font" 2>/dev/null || true
        done
        log "Font Awesome 6.5.1 downloaded locally"
    else
        warn "Could not download Font Awesome — CDN link remains in HTML"
    fi
}

generate_ssl() {
    step "SSL Certificate"
    mkdir -p "$CONFIG_DIR/ssl"
    HOST_IP=$(hostname -I | awk '{print $1}')
    HOSTNAME=$(hostname -f 2>/dev/null || hostname)
    openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
        -keyout "$CONFIG_DIR/ssl/oxware.key" -out "$CONFIG_DIR/ssl/oxware.crt" \
        -subj "/C=TR/O=OXware/CN=$HOSTNAME" \
        -addext "subjectAltName=IP:$HOST_IP,DNS:$HOSTNAME,DNS:localhost" 2>/dev/null
    chmod 600 "$CONFIG_DIR/ssl/oxware.key"
    log "SSL certificate created (10 years, $HOSTNAME)"
}

write_config() {
    step "Configuration"
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
    log "Config: $CONFIG_DIR/oxware.conf"
}

copy_files() {
    step "Copy OXware Files"
    mkdir -p "$INSTALL_DIR"
    cp -r "$SCRIPT_DIR/oxware/"* "$INSTALL_DIR/"
    chmod -R 750 "$INSTALL_DIR"
    log "Files copied to $INSTALL_DIR"
}

install_novnc() {
    step "noVNC Console"
    NOVNC_DIR="/usr/share/novnc"
    [ ! -d "$NOVNC_DIR" ] && NOVNC_DIR="/opt/novnc"
    if [ ! -d "$NOVNC_DIR" ]; then
        git clone https://github.com/novnc/noVNC.git "$NOVNC_DIR" -q 2>/dev/null || mkdir -p "$NOVNC_DIR"
    fi
    grep -q "novnc_dir" "$CONFIG_DIR/oxware.conf" || echo "novnc_dir = $NOVNC_DIR" >> "$CONFIG_DIR/oxware.conf"
    log "noVNC: $NOVNC_DIR"
}

create_service() {
    step "Systemd Service"
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
    log "Service created: oxware.service"
}

install_cli_tools() {
    step "CLI Tools (ox / oxupdate)"

    # ── ox command ──
    cat > /usr/local/bin/ox << 'OXCMD'
#!/bin/bash
# OXware CLI Tool
VERSION="2.1.0"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

show_help() {
cat << HELP
${CYAN}
  ██████╗ ██╗  ██╗
 ██╔═══██╗╚██╗██╔╝
 ██║   ██║ ╚███╔╝
 ██║   ██║ ██╔██╗
 ╚██████╔╝██╔╝ ██╗
  ╚═════╝ ╚═╝  ╚═╝${NC}
${WHITE}OXware Hypervisor CLI v${VERSION}${NC}

${YELLOW}Usage:${NC} ox [command] [options]

${YELLOW}Commands:${NC}
  ${GREEN}--help, -h${NC}          Show this help
  ${GREEN}--status, -s${NC}        Show service status
  ${GREEN}--start${NC}             Start OXware service
  ${GREEN}--stop${NC}              Stop OXware service
  ${GREEN}--restart${NC}           Restart OXware service
  ${GREEN}--logs, -l${NC}          Show recent logs (last 50 lines)
  ${GREEN}--logs -f${NC}           Follow live logs
  ${GREEN}--info${NC}              Show system information
  ${GREEN}--vms${NC}               List virtual machines
  ${GREEN}--url${NC}               Show web interface URL
  ${GREEN}--config${NC}            Show configuration file path
  ${GREEN}--update${NC}            Run oxupdate (update OXware)
  ${GREEN}--version, -v${NC}       Show version

${YELLOW}Examples:${NC}
  ox --status
  ox --logs -f
  ox --vms
  ox --restart
HELP
}

show_status() {
    echo -e "\n${CYAN}━━━ OXware Service Status ━━━${NC}"
    systemctl status oxware --no-pager -l 2>/dev/null || echo "Service not found"
    echo ""
    HOST_IP=$(hostname -I | awk '{print $1}')
    echo -e "  Web UI: ${CYAN}https://${HOST_IP}:8006${NC}"
    echo ""
}

show_info() {
    echo -e "\n${CYAN}━━━ OXware System Information ━━━${NC}"
    echo -e "  Version  : ${WHITE}${VERSION}${NC}"
    HOST_IP=$(hostname -I | awk '{print $1}')
    echo -e "  Web URL  : ${CYAN}https://${HOST_IP}:8006${NC}"
    echo -e "  Install  : /opt/oxware"
    echo -e "  Config   : /etc/oxware/oxware.conf"
    echo -e "  Logs     : /var/log/oxware/"
    echo -e "  Data     : /var/lib/oxware/"
    echo ""
    echo -e "${CYAN}━━━ Host Resources ━━━${NC}"
    echo -e "  CPU    : $(nproc) cores — $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
    RAM_MB=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
    FREE_MB=$(grep MemAvailable /proc/meminfo | awk '{print int($2/1024)}')
    echo -e "  RAM    : ${RAM_MB}MB total, ${FREE_MB}MB free"
    DISK_USED=$(df / | awk 'NR==2{print $5}')
    DISK_FREE=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    echo -e "  Disk   : ${DISK_USED} used, ${DISK_FREE}GB free"
    echo ""
    echo -e "${CYAN}━━━ KVM Status ━━━${NC}"
    [ -e /dev/kvm ] && echo -e "  KVM    : ${GREEN}Active${NC}" || echo -e "  KVM    : ${RED}Not available${NC}"
    virsh list --all 2>/dev/null | head -5 || echo "  VMs    : libvirt not accessible"
    echo ""
}

list_vms() {
    echo -e "\n${CYAN}━━━ Virtual Machines ━━━${NC}"
    virsh list --all 2>/dev/null || echo "Could not connect to libvirt"
    echo ""
}

case "$1" in
    --help|-h|"")  show_help ;;
    --status|-s)   show_status ;;
    --start)       systemctl start oxware && echo -e "${GREEN}[✓] OXware started${NC}" ;;
    --stop)        systemctl stop oxware && echo -e "${YELLOW}[!] OXware stopped${NC}" ;;
    --restart)     systemctl restart oxware && echo -e "${GREEN}[✓] OXware restarted${NC}" ;;
    --logs|-l)
        if [ "$2" = "-f" ]; then
            journalctl -u oxware -f
        else
            journalctl -u oxware -n 50 --no-pager
        fi
        ;;
    --info)        show_info ;;
    --vms)         list_vms ;;
    --url)
        HOST_IP=$(hostname -I | awk '{print $1}')
        echo -e "  ${CYAN}https://${HOST_IP}:8006${NC}"
        ;;
    --config)      echo "/etc/oxware/oxware.conf" ;;
    --update)      oxupdate ;;
    --version|-v)  echo "OXware v${VERSION}" ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo "Run 'ox --help' for usage"
        exit 1
        ;;
esac
OXCMD
    chmod +x /usr/local/bin/ox
    log "ox command installed → 'ox --help'"

    # ── oxupdate command ──
    cat > /usr/local/bin/oxupdate << 'OXUPDATE'
#!/bin/bash
# OXware Update Tool
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

INSTALL_DIR="/opt/oxware"
REPO="https://github.com/ShinnAsukha/oxware-hypervisor.git"

echo -e "${CYAN}━━━ OXware Update ━━━${NC}"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Root required: sudo oxupdate${NC}"
    exit 1
fi

# Check git
if ! command -v git &>/dev/null; then
    echo -e "${RED}git not found — install it: apt-get install git${NC}"
    exit 1
fi

echo -e "${YELLOW}[!]${NC} Stopping OXware service..."
systemctl stop oxware 2>/dev/null || true

if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "${CYAN}[i]${NC} Pulling latest from GitHub..."
    cd "$INSTALL_DIR"
    git fetch origin
    git reset --hard origin/main
else
    echo -e "${YELLOW}[!]${NC} No git repo at $INSTALL_DIR — doing a fresh clone..."
    TEMP=$(mktemp -d)
    git clone "$REPO" "$TEMP/oxware-repo" --depth=1 -q
    cp -r "$TEMP/oxware-repo/oxware/"* "$INSTALL_DIR/"
    rm -rf "$TEMP"
fi

echo -e "${CYAN}[i]${NC} Updating Python dependencies..."
source "$INSTALL_DIR/venv/bin/activate"
pip install -r "$INSTALL_DIR/backend/requirements.txt" -q
deactivate

echo -e "${CYAN}[i]${NC} Starting OXware service..."
systemctl start oxware
sleep 3

if systemctl is-active --quiet oxware; then
    echo -e "${GREEN}[✓] OXware updated and running!${NC}"
    HOST_IP=$(hostname -I | awk '{print $1}')
    echo -e "    Web UI: ${CYAN}https://${HOST_IP}:8006${NC}"
else
    echo -e "${RED}[✗] Service failed to start — check: journalctl -u oxware -n 30${NC}"
    exit 1
fi
OXUPDATE
    chmod +x /usr/local/bin/oxupdate
    log "oxupdate command installed → 'sudo oxupdate'"
}

configure_firewall() {
    step "Firewall (UFW)"
    ufw --force reset 2>/dev/null
    ufw default deny incoming 2>/dev/null
    ufw default allow outgoing 2>/dev/null
    ufw allow 22/tcp   comment "SSH" 2>/dev/null
    ufw allow 8006/tcp comment "OXware Web UI" 2>/dev/null
    ufw allow 5900:5999/tcp comment "VNC" 2>/dev/null
    ufw allow 6080/tcp comment "noVNC WS" 2>/dev/null
    echo "y" | ufw enable 2>/dev/null || true
    log "UFW firewall active"
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
    log "Fail2ban configured"
}

start_services() {
    step "Starting Services"
    systemctl restart libvirtd
    sleep 2
    systemctl start oxware
    sleep 3
    if systemctl is-active --quiet oxware; then
        log "OXware service running"
    else
        warn "OXware failed to start — check: journalctl -u oxware -n 30"
    fi
}

activate_license() {
    step "License Activation (Optional)"
    echo ""
    echo -e "${WHITE}If you have a license key, enter it below.${NC}"
    echo -e "${YELLOW}License format: OXWARE-XXXX-XXXX-XXXX-XXXX${NC}"
    echo -e "${BLUE}Press ENTER to skip${NC}"
    echo ""
    read -p "License key: " -r LICENSE_KEY

    if [ -n "$LICENSE_KEY" ]; then
        HOST_IP=$(hostname -I | awk '{print $1}')
        RESPONSE=$(curl -sk -X POST "https://${HOST_IP}:8006/api/license/validate" \
            -H "Content-Type: application/json" \
            -d "{\"code\":\"${LICENSE_KEY}\"}" 2>/dev/null || echo '{}')

        if echo "$RESPONSE" | grep -q '"valid":true'; then
            log "License activated successfully!"
            echo -e "  ${GREEN}✓ 7/24 Support is now active${NC}"
        else
            warn "License validation failed — you can add it later from the web interface"
        fi
    else
        info "License activation skipped — add later from web interface (Security → License)"
    fi
}

print_done() {
    HOST_IP=$(hostname -I | awk '{print $1}')
    URL_LEN=${#HOST_IP}
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗"
    echo -e "║          OXware Hypervisor Installation Complete!            ║"
    echo -e "╠══════════════════════════════════════════════════════════════╣"
    echo -e "║${NC}                                                              ${GREEN}║"
    echo -e "║${NC}  🌐 Web UI  : ${CYAN}https://${HOST_IP}:${WEB_PORT}${NC}$(printf '%*s' $((22-${URL_LEN})) '')${GREEN}║"
    echo -e "║${NC}  🔑 First login sets your admin credentials               ${GREEN}║"
    echo -e "║${NC}                                                              ${GREEN}║"
    echo -e "╠══════════════════════════════════════════════════════════════╣"
    echo -e "║${NC}  ${YELLOW}CLI Commands:${NC}                                               ${GREEN}║"
    echo -e "║${NC}  ${CYAN}ox --status${NC}      — Check service status                   ${GREEN}║"
    echo -e "║${NC}  ${CYAN}ox --logs -f${NC}     — Follow live logs                        ${GREEN}║"
    echo -e "║${NC}  ${CYAN}ox --vms${NC}         — List virtual machines                   ${GREEN}║"
    echo -e "║${NC}  ${CYAN}sudo oxupdate${NC}    — Update OXware to latest version         ${GREEN}║"
    echo -e "║${NC}  ${CYAN}ox --help${NC}        — Show all commands                       ${GREEN}║"
    echo -e "╠══════════════════════════════════════════════════════════════╣"
    echo -e "║${NC}  ${YELLOW}Service Commands:${NC}                                           ${GREEN}║"
    echo -e "║${NC}  systemctl {status|start|stop|restart} oxware            ${GREEN}║"
    echo -e "║${NC}  journalctl -u oxware -f                                  ${GREEN}║"
    echo -e "╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}SSL warning: In browser, click 'Advanced → Proceed'.${NC}"
    echo ""
}

main() {
    print_banner
    check_root
    check_os
    check_existing_installation
    check_bios_virtualization
    check_hardware

    echo ""
    echo -e "${WHITE}Installation summary:${NC}"
    echo "  Install dir  : $INSTALL_DIR"
    echo "  Config       : $CONFIG_DIR/oxware.conf"
    echo "  Web port     : $WEB_PORT (HTTPS)"
    echo ""
    read -p "Continue? [Y/n]: " -r
    [[ $REPLY =~ ^[Nn]$ ]] && exit 0

    update_system
    install_packages
    copy_files
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
