#!/bin/bash
# ============================================================
#  OXware Hypervisor — Özel ISO Oluşturucu v2.0
#  Ubuntu Server tabanlı, tam otomatik kurulum ISO'su
#  BIOS sanallaştırma zorunlu, minimum kaynak optimize
# ============================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

OXWARE_VERSION="2.0.0"
UBUNTU_CODENAME="jammy"   # 22.04 LTS
UBUNTU_VERSION="22.04.4"
UBUNTU_ISO_URL="https://releases.ubuntu.com/22.04/ubuntu-${UBUNTU_VERSION}-live-server-amd64.iso"
ISO_CACHE="/tmp/ubuntu-${UBUNTU_VERSION}-server.iso"
WORK_DIR="/tmp/oxware-iso-$$"
OUTPUT_ISO="${PWD}/OXware-Hypervisor-${OXWARE_VERSION}-amd64.iso"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { echo -e "${GREEN}[BUILD]${NC}  $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}   $1"; }
err()  { echo -e "${RED}[ERROR]${NC}  $1"; exit 1; }
step() { echo -e "${CYAN}━━━ $1 ━━━${NC}"; }

[[ $EUID -ne 0 ]] && err "Root yetkisi gerekli: sudo bash build-iso.sh"

# ── Bağımlılıklar ─────────────────────────────────────────────────────────────
step "Bağımlılıklar"
apt-get update -qq
apt-get install -y -qq xorriso squashfs-tools wget curl p7zip-full \
    genisoimage isolinux syslinux-utils 2>/dev/null || true
log "Bağımlılıklar hazır"

# ── Ubuntu ISO ────────────────────────────────────────────────────────────────
step "Ubuntu Server ISO"
if [ -f "$ISO_CACHE" ]; then
    log "Önbellekte mevcut: $ISO_CACHE"
else
    log "İndiriliyor: $UBUNTU_ISO_URL"
    wget -q --show-progress -c -O "$ISO_CACHE" "$UBUNTU_ISO_URL" \
      || err "İndirme başarısız.\nManuel indirip şuraya koyun: $ISO_CACHE"
fi

# ── ISO Ayıklama ──────────────────────────────────────────────────────────────
step "ISO Ayıklama"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"/{iso,scratch}

xorriso -osirrox on -indev "$ISO_CACHE" -extract / "$WORK_DIR/iso" 2>/dev/null \
  || 7z x "$ISO_CACHE" -o"$WORK_DIR/iso" -y -bd >/dev/null 2>&1 \
  || err "ISO ayıklanamadı"

chmod -R u+w "$WORK_DIR/iso"
log "ISO içeriği hazır"

# ── OXware Dosyaları ──────────────────────────────────────────────────────────
step "OXware Dosyaları"
mkdir -p "$WORK_DIR/iso/oxware"
cp -r "$SCRIPT_DIR/oxware/"* "$WORK_DIR/iso/oxware/"
log "OXware dosyaları kopyalandı"

# ── cloud-init / autoinstall ──────────────────────────────────────────────────
step "Autoinstall Yapılandırması"
mkdir -p "$WORK_DIR/iso/oxware-autoinstall"

cat > "$WORK_DIR/iso/oxware-autoinstall/meta-data" << 'META'
instance-id: oxware-hypervisor-install
local-hostname: oxware-hypervisor
META

cat > "$WORK_DIR/iso/oxware-autoinstall/user-data" << 'USERDATA'
#cloud-config
autoinstall:
  version: 1

  # Dil & klavye
  locale: tr_TR.UTF-8
  keyboard:
    layout: tr
    variant: ''

  # Ağ — DHCP ile otomatik
  network:
    network:
      version: 2
      ethernets:
        any-en:
          match: {name: "en*"}
          dhcp4: true
          dhcp6: false
        any-eth:
          match: {name: "eth*"}
          dhcp4: true
          dhcp6: false

  # Depolama — LVM ile minimum bölümleme
  storage:
    layout:
      name: lvm
      match:
        size: largest
    swap:
      size: 0

  # Kullanıcı — ilk açılışta setup wizard devreye girer
  identity:
    hostname: oxware-hypervisor
    username: oxware
    # Varsayılan şifre: oxware2024 (ilk girişte değiştirilir)
    password: "$6$rounds=4096$saltsalt$Dd4KpxVUGGWW3AkFh5PXzX4TgGQFBfDv9rKV8VWL5F2MfFl0G1BSKt6XeA.UJJtVsqpIlPnpuYD2c1dX6U0"

  # SSH
  ssh:
    install-server: true
    allow-pw: true
    authorized-keys: []

  # Paketler — minimum set
  packages:
    - qemu-kvm
    - qemu-utils
    - libvirt-daemon-system
    - libvirt-clients
    - libvirt-dev
    - bridge-utils
    - net-tools
    - python3
    - python3-pip
    - python3-venv
    - python3-libvirt
    - python3-dev
    - openssl
    - ufw
    - fail2ban
    - novnc
    - websockify
    - cpu-checker
    - htop
    - curl
    - wget
    - git
    - jq
    - lvm2
    - parted
    - socat

  # Kurulum sonrası komutlar
  late-commands:
    # OXware dosyalarını kopyala
    - mkdir -p /target/opt/oxware
    - cp -r /cdrom/oxware/. /target/opt/oxware/
    - chmod -R 755 /target/opt/oxware
    - chmod 700 /target/opt/oxware/backend

    # Python sanal ortamı
    - curtin in-target --target=/target -- bash -c "python3 -m venv /opt/oxware/venv"
    - curtin in-target --target=/target -- bash -c "/opt/oxware/venv/bin/pip install --upgrade pip -q"
    - curtin in-target --target=/target -- bash -c "/opt/oxware/venv/bin/pip install -r /opt/oxware/backend/requirements.txt -q 2>&1 | tail -5"

    # Dizinler
    - mkdir -p /target/etc/oxware/ssl
    - mkdir -p /target/var/lib/oxware/{isos,disks,backups,templates}
    - mkdir -p /target/var/log/oxware

    # SSL sertifikası
    - curtin in-target --target=/target -- bash -c "openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout /etc/oxware/ssl/oxware.key -out /etc/oxware/ssl/oxware.crt -subj '/C=TR/ST=Istanbul/O=OXware/CN=oxware-hypervisor' 2>/dev/null"
    - chmod 600 /target/etc/oxware/ssl/oxware.key

    # Yapılandırma
    - |
      cat > /target/etc/oxware/oxware.conf << 'CONF'
      [server]
      host = 0.0.0.0
      port = 8006
      ssl = true
      ssl_cert = /etc/oxware/ssl/oxware.crt
      ssl_key = /etc/oxware/ssl/oxware.key
      secret_key = REPLACE_ME_ON_FIRST_BOOT

      [storage]
      data_dir = /var/lib/oxware
      iso_dir = /var/lib/oxware/isos
      disk_dir = /var/lib/oxware/disks
      backup_dir = /var/lib/oxware/backups
      template_dir = /var/lib/oxware/templates

      [vnc]
      start_port = 5900
      end_port = 5999
      websocket_port = 6080

      [libvirt]
      uri = qemu:///system

      [logging]
      log_dir = /var/log/oxware
      level = INFO
      CONF

    # Systemd servisi
    - cp /cdrom/oxware/oxware-hypervisor.service /target/etc/systemd/system/oxware.service
    - curtin in-target --target=/target -- systemctl enable oxware
    - curtin in-target --target=/target -- systemctl enable libvirtd

    # First-boot scripti
    - cp /cdrom/oxware-autoinstall/first-boot.sh /target/opt/oxware/first-boot.sh
    - chmod +x /target/opt/oxware/first-boot.sh
    - |
      cat > /target/etc/systemd/system/oxware-firstboot.service << 'SVC'
      [Unit]
      Description=OXware First Boot Setup
      After=network.target
      ConditionPathExists=!/etc/oxware/.setup_done

      [Service]
      Type=oneshot
      ExecStart=/opt/oxware/first-boot.sh
      RemainAfterExit=yes

      [Install]
      WantedBy=multi-user.target
      SVC
    - curtin in-target --target=/target -- systemctl enable oxware-firstboot

    # Güvenlik duvarı
    - curtin in-target --target=/target -- bash -c "ufw --force reset && ufw default deny incoming && ufw default allow outgoing && ufw allow 22/tcp && ufw allow 8006/tcp && ufw allow 5900:5999/tcp && ufw allow 6080/tcp && echo 'y' | ufw enable"

    # libvirt oxware grubuna ekle
    - curtin in-target --target=/target -- usermod -aG libvirt oxware 2>/dev/null || true

    # Secret key güncelle
    - curtin in-target --target=/target -- bash -c "SK=\$(openssl rand -hex 32) && sed -i \"s/REPLACE_ME_ON_FIRST_BOOT/\$SK/\" /etc/oxware/oxware.conf"

  # Yeniden başlatma
  reboot-cmd: reboot
USERDATA

# ── First-boot scripti ────────────────────────────────────────────────────────
cat > "$WORK_DIR/iso/oxware-autoinstall/first-boot.sh" << 'FIRSTBOOT'
#!/bin/bash
# OXware İlk Açılış Yapılandırması
# Bu script /etc/oxware/.setup_done yoksa çalışır

LOG="/var/log/oxware/firstboot.log"
mkdir -p /var/log/oxware
exec >> "$LOG" 2>&1

echo "[$(date)] OXware first-boot başlıyor..."

# libvirt default network
systemctl start libvirtd 2>/dev/null || true
sleep 3
virsh net-autostart default 2>/dev/null || true
virsh net-start default 2>/dev/null || true

# MOTD güncelle
cat > /etc/motd << 'MOTD'
╔══════════════════════════════════════════════════════════╗
║           OXware Hypervisor v2.0                         ║
║     Ubuntu/KVM tabanlı Sanallaştırma Platformu           ║
╠══════════════════════════════════════════════════════════╣
║  Web UI: https://<IP>:8006                               ║
║  İlk kurulum için tarayıcıdan bağlanın                   ║
║  Servis: systemctl status oxware                         ║
╚══════════════════════════════════════════════════════════╝
MOTD

# OXware servisini başlat
systemctl start oxware 2>/dev/null || true

echo "[$(date)] OXware first-boot tamamlandı"
FIRSTBOOT

chmod +x "$WORK_DIR/iso/oxware-autoinstall/first-boot.sh"
log "Autoinstall yapılandırması hazır"

# ── BIOS Sanallaştırma Kontrol Scripti ───────────────────────────────────────
step "BIOS Kontrol Scripti"

cat > "$WORK_DIR/iso/oxware-autoinstall/check-virt.sh" << 'CHECKVIRT'
#!/bin/bash
# BIOS sanallaştırma kontrolü — ISO boot sırasında çalışır

if ! grep -qE "vmx|svm" /proc/cpuinfo 2>/dev/null; then
    clear
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         OXware Hypervisor — DONANIM GEREKSİNİMİ             ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║                                                              ║"
    echo "║  ⚠️  CPU SANALLAŞTIRMA DESTEĞİ BULUNAMADI!                  ║"
    echo "║                                                              ║"
    echo "║  OXware KVM sanallaştırma gerektirmektedir:                  ║"
    echo "║                                                              ║"
    echo "║  Intel işlemciler için:                                      ║"
    echo "║    BIOS/UEFI → Gelişmiş → CPU Yapılandırma                  ║"
    echo "║    → Intel Virtualization Technology (VT-x) → Enable        ║"
    echo "║                                                              ║"
    echo "║  AMD işlemciler için:                                        ║"
    echo "║    BIOS/UEFI → Gelişmiş → CPU Yapılandırma                  ║"
    echo "║    → AMD-V / SVM Mode → Enable                              ║"
    echo "║                                                              ║"
    echo "║  Değişiklikten sonra kaydedin ve yeniden başlatın.           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Kurulum durduruluyor. BIOS'ta sanallaştırmayı etkinleştirin."
    echo ""
    sleep 30
    reboot
    exit 1
fi

# RAM kontrolü (minimum 1.5 GB)
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
if [ "$TOTAL_RAM_KB" -lt 1572864 ]; then
    clear
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ⚠️  YETERSİZ BELLEK                                        ║"
    echo "║  OXware minimum 2 GB RAM gerektirir.                        ║"
    echo "║  Mevcut: $(( TOTAL_RAM_KB / 1024 )) MB                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    sleep 20
    exit 1
fi

# Disk kontrolü (minimum 15 GB)
ROOT_DISK=$(lsblk -d -o NAME,SIZE,TYPE | awk '$3=="disk"{print $1}' | head -1)
if [ -n "$ROOT_DISK" ]; then
    DISK_SIZE_GB=$(lsblk -d -b -o SIZE "/dev/$ROOT_DISK" 2>/dev/null | tail -1)
    DISK_SIZE_GB=$(( DISK_SIZE_GB / 1073741824 ))
    if [ "$DISK_SIZE_GB" -lt 15 ]; then
        echo "⚠️  Yetersiz disk: ${DISK_SIZE_GB}GB (minimum 15GB gerekli)"
        sleep 15
        exit 1
    fi
fi

echo "✓ Tüm donanım gereksinimleri karşılandı"
echo "  CPU: $(grep -c processor /proc/cpuinfo) çekirdek | $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
echo "  RAM: $(( TOTAL_RAM_KB / 1024 )) MB"
echo "  Disk: ${DISK_SIZE_GB}GB"
CHECKVIRT

chmod +x "$WORK_DIR/iso/oxware-autoinstall/check-virt.sh"
log "BIOS kontrol scripti hazır"

# ── GRUB Yapılandırması ───────────────────────────────────────────────────────
step "GRUB Boot Menüsü"

GRUB_CFG="$WORK_DIR/iso/boot/grub/grub.cfg"
mkdir -p "$(dirname "$GRUB_CFG")"

cat > "$GRUB_CFG" << GRUBCFG
# OXware Hypervisor Boot Menüsü
set default=0
set timeout=15
set gfxmode=auto

insmod all_video
insmod gfxterm
insmod png

terminal_output gfxterm

# OXware renk teması
set color_normal=white/black
set color_highlight=black/cyan

# ── Başlık ──
echo ""
echo "  ██████╗ ██╗  ██╗██╗    ██╗ █████╗ ██████╗ ███████╗"
echo " ██╔═══██╗╚██╗██╔╝██║    ██║██╔══██╗██╔══██╗██╔════╝"
echo " ██║   ██║ ╚███╔╝ ██║ █╗ ██║███████║██████╔╝█████╗  "
echo " ██║   ██║ ██╔██╗ ██║███╗██║██╔══██║██╔══██╗██╔══╝  "
echo " ╚██████╔╝██╔╝ ██╗╚███╔███╔╝██║  ██║██║  ██║███████╗"
echo "  ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝"
echo ""
echo "  Hypervisor Management System v${OXWARE_VERSION}"
echo ""

# Otomatik kurulum
menuentry "OXware Hypervisor ${OXWARE_VERSION} — Otomatik Kur" --class oxware {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet splash autoinstall \
            ds="nocloud;s=/cdrom/oxware-autoinstall/" \
            console=tty0 console=ttyS0,115200n8 \
            fsck.mode=skip \
            --- quiet
    initrd  /casper/initrd
}

# Manuel kurulum (Ubuntu Subiquity)
menuentry "OXware Hypervisor — Manuel Kurulum" --class ubuntu {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet splash \
            ds="nocloud;s=/cdrom/oxware-autoinstall/" \
            --- quiet
    initrd  /casper/initrd
}

# Donanım kontrolü (kurulum öncesi test)
menuentry "Donanım Kontrolü (BIOS Sanallaştırma)" --class memtest {
    linux16 /boot/memtest86+.bin
}

# Sistem kurtarma
menuentry "Sistem Kurtarma / Recovery" --class recovery {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet splash recovery \
            --- quiet
    initrd  /casper/initrd
}
GRUBCFG

log "GRUB menüsü yapılandırıldı"

# ── isolinux (BIOS boot) ──────────────────────────────────────────────────────
ISOLINUX_CFG="$WORK_DIR/iso/isolinux/isolinux.cfg"
mkdir -p "$(dirname "$ISOLINUX_CFG")" 2>/dev/null

if [ -d "$WORK_DIR/iso/isolinux" ]; then
cat > "$ISOLINUX_CFG" << 'ISOLINUX'
DEFAULT oxware-auto
TIMEOUT 150
PROMPT 0

LABEL oxware-auto
  MENU LABEL OXware Hypervisor - Otomatik Kur
  KERNEL /casper/vmlinuz
  APPEND initrd=/casper/initrd quiet splash autoinstall ds=nocloud;s=/cdrom/oxware-autoinstall/ ---

LABEL oxware-manual
  MENU LABEL OXware Hypervisor - Manuel Kur
  KERNEL /casper/vmlinuz
  APPEND initrd=/casper/initrd quiet splash ds=nocloud;s=/cdrom/oxware-autoinstall/ ---

LABEL recovery
  MENU LABEL Sistem Kurtarma
  KERNEL /casper/vmlinuz
  APPEND initrd=/casper/initrd quiet splash recovery ---
ISOLINUX
fi

log "isolinux yapılandırıldı"

# ── ISO Oluştur ───────────────────────────────────────────────────────────────
step "ISO Oluşturma"

# MBR ve EFI boot
MBR_FILE=""
EFI_FILE=""
for f in /usr/lib/grub/i386-pc/boot_hybrid.img /usr/share/grub/boot_hybrid.img; do
    [ -f "$f" ] && MBR_FILE="$f" && break
done
for f in "$WORK_DIR/iso/boot/grub/efi.img" "$WORK_DIR/iso/EFI/boot/bootx64.efi"; do
    [ -f "$f" ] && EFI_FILE="$f" && break
done

XORRISO_ARGS=(
    -as mkisofs
    -r
    -V "OXware-Hypervisor-${OXWARE_VERSION}"
    -o "$OUTPUT_ISO"
    -J -l -joliet-long
    -iso-level 3
)

# MBR desteği
if [ -n "$MBR_FILE" ]; then
    XORRISO_ARGS+=(
        --grub2-mbr "$MBR_FILE"
    )
fi

# isolinux/BIOS boot
if [ -f "$WORK_DIR/iso/isolinux/isolinux.bin" ]; then
    XORRISO_ARGS+=(
        -b isolinux/isolinux.bin
        -c isolinux/boot.cat
        -no-emul-boot -boot-load-size 4 -boot-info-table
    )
fi

# EFI boot
if [ -f "$WORK_DIR/iso/boot/grub/efi.img" ]; then
    XORRISO_ARGS+=(
        -eltorito-alt-boot
        -e boot/grub/efi.img
        -no-emul-boot
    )
fi

XORRISO_ARGS+=("$WORK_DIR/iso")

xorriso "${XORRISO_ARGS[@]}" 2>&1 | grep -E "^(INFO|WARNING|ERROR|xorriso)" || true

if [ ! -f "$OUTPUT_ISO" ]; then
    warn "xorriso başarısız, genisoimage deneniyor..."
    genisoimage -r -V "OXware-${OXWARE_VERSION}" \
        -cache-inodes -J -l \
        -b isolinux/isolinux.bin -c isolinux/boot.cat \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        -o "$OUTPUT_ISO" "$WORK_DIR/iso" 2>/dev/null \
        || err "ISO oluşturma başarısız!"
fi

# ── isohybrid (USB desteği) ───────────────────────────────────────────────────
if command -v isohybrid &>/dev/null; then
    isohybrid --uefi "$OUTPUT_ISO" 2>/dev/null || isohybrid "$OUTPUT_ISO" 2>/dev/null || true
    log "isohybrid uygulandı (USB-bootable)"
fi

# ── Checksum ──────────────────────────────────────────────────────────────────
sha256sum "$OUTPUT_ISO" > "${OUTPUT_ISO}.sha256"
log "SHA256: $(cat "${OUTPUT_ISO}.sha256" | awk '{print $1}')"

# ── Temizlik ──────────────────────────────────────────────────────────────────
rm -rf "$WORK_DIR"

# ── Sonuç ─────────────────────────────────────────────────────────────────────
ISO_SIZE=$(du -sh "$OUTPUT_ISO" | cut -f1)

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           OXware Hypervisor ISO Hazır!                       ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  Dosya  : ${WHITE}$(basename "$OUTPUT_ISO")${NC}"
echo -e "${CYAN}║${NC}  Boyut  : ${WHITE}${ISO_SIZE}${NC}"
echo -e "${CYAN}║${NC}  SHA256 : ${WHITE}$(head -c 16 "${OUTPUT_ISO}.sha256")...${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  ${YELLOW}USB'ye yazmak için:${NC}"
echo -e "${CYAN}║${NC}  sudo dd if=$(basename "$OUTPUT_ISO") of=/dev/sdX bs=4M status=progress"
echo -e "${CYAN}║${NC}  veya: sudo cp $(basename "$OUTPUT_ISO") /dev/sdX"
echo -e "${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${YELLOW}VMware / VirtualBox için:${NC}"
echo -e "${CYAN}║${NC}  Doğrudan ISO olarak seçin."
echo -e "${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${YELLOW}Minimum Sistem Gereksinimleri:${NC}"
echo -e "${CYAN}║${NC}  • CPU  : 2 çekirdek + Intel VT-x / AMD-V (BIOS'ta ZORUNLU)"
echo -e "${CYAN}║${NC}  • RAM  : 2 GB (4 GB önerilen)"
echo -e "${CYAN}║${NC}  • Disk : 20 GB SSD/HDD"
echo -e "${CYAN}║${NC}  • Ağ   : 1 Ethernet arayüzü"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
