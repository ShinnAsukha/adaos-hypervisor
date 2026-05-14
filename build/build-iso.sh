#!/usr/bin/env bash
# ============================================================
#  OXware Hypervisor — ISO Builder v3.0
#  Boot → OXware TUI installer (subiquity tamamen devre dışı)
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

OXWARE_VERSION="2.0.0"
UBUNTU_VERSION="22.04.5"
UBUNTU_ISO_URL="https://releases.ubuntu.com/22.04/ubuntu-${UBUNTU_VERSION}-live-server-amd64.iso"
UBUNTU_ISO_FALLBACK="https://old-releases.ubuntu.com/releases/22.04/ubuntu-${UBUNTU_VERSION}-live-server-amd64.iso"
ISO_CACHE="/tmp/ubuntu-${UBUNTU_VERSION}-server.iso"
WORK_DIR="/tmp/oxware-iso-build"
SQUASHFS_ROOT="$WORK_DIR/squashfs-root"
OUTPUT_ISO="${PWD}/OXware-Hypervisor-${OXWARE_VERSION}-amd64.iso"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log()  { echo -e "${GREEN}[BUILD]${NC}  $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}   $1"; }
err()  { echo -e "${RED}[ERROR]${NC}  $1"; exit 1; }
step() { echo -e "${CYAN}━━━ $1 ━━━${NC}"; }

[[ $EUID -ne 0 ]] && err "Root yetkisi gerekli: sudo bash build/build-iso.sh"

# ── Bağımlılıklar ─────────────────────────────────────────────────────────────
step "Bağımlılıklar"
apt-get update -qq
apt-get install -y -qq \
    xorriso squashfs-tools wget curl \
    genisoimage grub-pc-bin grub-efi-amd64-bin mtools \
    debootstrap git python3 rsync 2>/dev/null || true
log "Bağımlılıklar hazır"

# ── Disk alanı kontrolü (15GB gerek) ──────────────────────────────────────────
_FREE_KB=$(df -k "$PWD" | awk 'NR==2{print $4}')
[ "$_FREE_KB" -lt 15728640 ] && \
    err "Yetersiz disk: $(df -h "$PWD" | awk 'NR==2{print $4}') boş, en az 15GB gerek"
log "Disk alanı yeterli: $(df -h "$PWD" | awk 'NR==2{print $4}') boş"

# ── Ubuntu ISO ────────────────────────────────────────────────────────────────
step "Ubuntu Server ISO"
if [ -f "$ISO_CACHE" ]; then
    log "Önbellekte mevcut: $ISO_CACHE"
else
    log "İndiriliyor: $UBUNTU_ISO_URL"
    if ! wget -q --show-progress -c -O "$ISO_CACHE" "$UBUNTU_ISO_URL" 2>/dev/null; then
        warn "Ana mirror başarısız, fallback deneniyor..."
        wget -q --show-progress -c -O "$ISO_CACHE" "$UBUNTU_ISO_FALLBACK" \
            || err "İndirme başarısız. Manuel indir:\n  wget -O $ISO_CACHE $UBUNTU_ISO_URL"
    fi
fi

# ── ISO Ayıklama ──────────────────────────────────────────────────────────────
step "ISO Ayıklama"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/iso"
# NOT: squashfs-root'u unsquashfs kendisi yaratır — önceden oluşturma!

xorriso -osirrox on -indev "$ISO_CACHE" -extract / "$WORK_DIR/iso" 2>/dev/null \
    || err "ISO ayıklanamadı"
chmod -R u+w "$WORK_DIR/iso"
log "ISO içeriği hazır"

# ── Squashfs Bul ──────────────────────────────────────────────────────────────
step "Squashfs Aranıyor"
SQUASHFS_FILE=""
for f in \
    "$WORK_DIR/iso/casper/ubuntu-server-minimal.squashfs" \
    "$WORK_DIR/iso/casper/ubuntu-server-minimal.ubuntu-server.installer.generic.squashfs" \
    "$WORK_DIR/iso/casper/filesystem.squashfs"; do
    [ -f "$f" ] && SQUASHFS_FILE="$f" && break
done
[ -z "$SQUASHFS_FILE" ] && err "Squashfs dosyası bulunamadı!"
log "Squashfs: $SQUASHFS_FILE ($(du -sh "$SQUASHFS_FILE" | cut -f1))"

# ── Squashfs Aç ───────────────────────────────────────────────────────────────
step "Squashfs Açılıyor (~5-10 dk)"
unsquashfs -d "$SQUASHFS_ROOT" "$SQUASHFS_FILE"
log "Squashfs açıldı: $(du -sh "$SQUASHFS_ROOT" | cut -f1)"

# ── Squashfs Düzenle ──────────────────────────────────────────────────────────
step "Subiquity Devre Dışı + OXware TUI Ekleniyor"

# 1. Subiquity ve console-conf maskele (tty1'i bunlar ele geçiriyor)
MASK_SVCS=(
    subiquity
    "console-conf@tty1.service"
    "console-conf@.service"
    "ubuntu-advantage.service"
    "pollinate.service"
    "ua-reloader.service"
)
for svc in "${MASK_SVCS[@]}"; do
    ln -sf /dev/null "$SQUASHFS_ROOT/etc/systemd/system/$svc" 2>/dev/null || true
done
log "Subiquity maskelendi"

# 2. getty@tty1 maskele — bizim servis tty1'i alacak
ln -sf /dev/null "$SQUASHFS_ROOT/etc/systemd/system/getty@tty1.service"
log "getty@tty1 maskelendi"

# 3. OXware installer script kopyala
mkdir -p "$SQUASHFS_ROOT/opt/oxware-installer"
cp "$SCRIPT_DIR/installer/install.py" "$SQUASHFS_ROOT/opt/oxware-installer/install.py"
chmod +x "$SQUASHFS_ROOT/opt/oxware-installer/install.py"
log "install.py kopyalandı"

# 4. OXware kaynak kopyala (offline fallback için)
mkdir -p "$SQUASHFS_ROOT/opt/oxware"
rsync -a --exclude='.git' --exclude='*.pyc' --exclude='__pycache__' \
    "$REPO_ROOT/oxware/" "$SQUASHFS_ROOT/opt/oxware/"
log "OXware kaynakları kopyalandı"

# 5. oxware-installer.service — tty1'e bağlı, ilk çalışan servis
cat > "$SQUASHFS_ROOT/etc/systemd/system/oxware-installer.service" << 'SVC'
[Unit]
Description=OXware Hypervisor Installer
After=systemd-remount-fs.service systemd-udevd.service
DefaultDependencies=no
Conflicts=getty@tty1.service

[Service]
Type=idle
ExecStart=/usr/bin/python3 /opt/oxware-installer/install.py
StandardInput=tty
StandardOutput=tty
StandardError=tty
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
KillMode=process
IgnoreSIGPIPE=no

[Install]
WantedBy=multi-user.target
SVC

# 6. Servisi etkinleştir
mkdir -p "$SQUASHFS_ROOT/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/oxware-installer.service \
    "$SQUASHFS_ROOT/etc/systemd/system/multi-user.target.wants/oxware-installer.service"
log "oxware-installer.service etkinleştirildi"

# 7. Chroot: gerekli paketleri kur (debootstrap, python3-curses, git)
log "Chroot: paketler kuruluyor..."

# Mount noktaları squashfs içinde yoksa oluştur
mkdir -p "$SQUASHFS_ROOT/proc" "$SQUASHFS_ROOT/sys" \
         "$SQUASHFS_ROOT/dev"  "$SQUASHFS_ROOT/dev/pts"

# Network: resolv.conf kopyala (apt-get için internet erişimi)
cp /etc/resolv.conf "$SQUASHFS_ROOT/etc/resolv.conf" 2>/dev/null || true

# Trap ÖNCE kur — herhangi bir mount failse cleanup çalışsın
cleanup_mounts() {
    umount "$SQUASHFS_ROOT/dev/pts" 2>/dev/null || true
    umount "$SQUASHFS_ROOT/dev"     2>/dev/null || true
    umount "$SQUASHFS_ROOT/sys"     2>/dev/null || true
    umount "$SQUASHFS_ROOT/proc"    2>/dev/null || true
}
trap cleanup_mounts EXIT

mount --bind /proc    "$SQUASHFS_ROOT/proc"
mount --bind /sys     "$SQUASHFS_ROOT/sys"
mount --bind /dev     "$SQUASHFS_ROOT/dev"
mount --bind /dev/pts "$SQUASHFS_ROOT/dev/pts"

chroot "$SQUASHFS_ROOT" /bin/bash << 'CHROOT'
export DEBIAN_FRONTEND=noninteractive
# Debootstrap genelde Ubuntu server squashfs'te yok — kur
apt-get update -qq 2>/dev/null || true
apt-get install -y -qq --no-install-recommends \
    python3 python3-curses debootstrap git \
    parted dosfstools e2fsprogs util-linux \
    2>/dev/null || true
# Debootstrap hala yoksa direkt indir (sadece shell script)
if ! command -v debootstrap &>/dev/null; then
    wget -qO /usr/sbin/debootstrap \
        https://salsa.debian.org/installer-team/debootstrap/-/raw/master/debootstrap \
        2>/dev/null && chmod +x /usr/sbin/debootstrap || true
fi
CHROOT

cleanup_mounts
trap - EXIT
log "Chroot paketler tamam"

# ── Squashfs Yeniden Paketle ──────────────────────────────────────────────────
step "Squashfs Yeniden Paketleniyor (~10 dk)"
rm -f "$SQUASHFS_FILE"
mksquashfs "$SQUASHFS_ROOT" "$SQUASHFS_FILE" \
    -comp xz -noappend -b 1M -no-progress
log "Squashfs hazır: $(du -sh "$SQUASHFS_FILE" | cut -f1)"

# ── GRUB Ayarla — autoinstall YOK ─────────────────────────────────────────────
step "GRUB Boot Menüsü"

# casper vmlinuz/initrd yollarını bul
VMLINUZ_PATH=""
INITRD_PATH=""
for vp in /casper/vmlinuz /casper/vmlinuz.efi; do
    [ -f "$WORK_DIR/iso$vp" ] && VMLINUZ_PATH="$vp" && break
done
for ip in /casper/initrd /casper/initrd.gz; do
    [ -f "$WORK_DIR/iso$ip" ] && INITRD_PATH="$ip" && break
done
[ -z "$VMLINUZ_PATH" ] && VMLINUZ_PATH="/casper/vmlinuz"
[ -z "$INITRD_PATH"  ] && INITRD_PATH="/casper/initrd"

mkdir -p "$WORK_DIR/iso/boot/grub"
cat > "$WORK_DIR/iso/boot/grub/grub.cfg" << GRUBEOF
set timeout=3
set default=0

menuentry "OXware Hypervisor Installer" {
    linux   $VMLINUZ_PATH boot=casper quiet console=tty1 net.ifnames=0 biosdevname=0 ---
    initrd  $INITRD_PATH
}

menuentry "OXware Installer (Debug)" {
    linux   $VMLINUZ_PATH boot=casper console=tty1 net.ifnames=0 biosdevname=0 nomodeset ---
    initrd  $INITRD_PATH
}
GRUBEOF
log "GRUB ayarlandı (autoinstall YOK)"

# ── md5sum güncelle ───────────────────────────────────────────────────────────
cd "$WORK_DIR/iso"
find . -type f ! -name 'md5sum.txt' | sort | xargs md5sum > md5sum.txt 2>/dev/null || true
cd - > /dev/null

# ── ISO Oluştur ───────────────────────────────────────────────────────────────
step "ISO Oluşturma"
_FREE_KB2=$(df -k "$PWD" | awk 'NR==2{print $4}')
[ "$_FREE_KB2" -lt 3145728 ] && err "ISO için yeterli alan yok: $(df -h "$PWD" | awk 'NR==2{print $4}')"

_VOLID="OXWARE_$(echo "$OXWARE_VERSION" | tr '.' '_')"
_TMP_ISO="$WORK_DIR/output.iso"

_make_iso() {
    local OUT="$1"

    # grub-mkrescue (proved to work in previous builds)
    if command -v grub-mkrescue &>/dev/null; then
        log "grub-mkrescue ile ISO oluşturuluyor..."
        grub-mkrescue -o "$OUT" "$WORK_DIR/iso" -- -volid "$_VOLID" 2>&1 | tail -3
        [ -s "$OUT" ] && return 0
        rm -f "$OUT"
    fi

    # xorriso fallback
    if command -v xorriso &>/dev/null; then
        log "xorriso ile ISO oluşturuluyor..."
        MBR_FILE=""
        for f in /usr/lib/grub/i386-pc/boot_hybrid.img /usr/share/grub/boot_hybrid.img; do
            [ -f "$f" ] && MBR_FILE="$f" && break
        done
        local XARGS=(-as mkisofs -r -V "$_VOLID" -o "$OUT" -J -l -iso-level 3)
        [ -n "$MBR_FILE" ] && XARGS+=(--grub2-mbr "$MBR_FILE")
        [ -f "$WORK_DIR/iso/isolinux/isolinux.bin" ] && \
            XARGS+=(-b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table)
        [ -f "$WORK_DIR/iso/boot/grub/efi.img" ] && \
            XARGS+=(-eltorito-alt-boot -e boot/grub/efi.img -no-emul-boot)
        XARGS+=("$WORK_DIR/iso")
        xorriso "${XARGS[@]}" 2>&1 | tail -5
        [ -s "$OUT" ] && return 0
        rm -f "$OUT"
    fi

    # genisoimage fallback
    if command -v genisoimage &>/dev/null; then
        log "genisoimage ile ISO oluşturuluyor..."
        genisoimage -r -V "$_VOLID" -cache-inodes -J -l -joliet-long \
            -o "$OUT" "$WORK_DIR/iso" 2>&1 | tail -3
        [ -s "$OUT" ] && return 0
        rm -f "$OUT"
    fi

    return 1
}

_make_iso "$_TMP_ISO" || err "ISO oluşturma tamamen başarısız!"

log "ISO taşınıyor..."
mv "$_TMP_ISO" "$OUTPUT_ISO"

# isohybrid
if command -v isohybrid &>/dev/null && [ -s "$OUTPUT_ISO" ]; then
    isohybrid --uefi "$OUTPUT_ISO" 2>/dev/null || isohybrid "$OUTPUT_ISO" 2>/dev/null || true
    log "isohybrid uygulandı (USB-bootable)"
fi

[ ! -s "$OUTPUT_ISO" ] && err "ISO boş (0 byte)!"

# ── Checksum ──────────────────────────────────────────────────────────────────
sha256sum "$OUTPUT_ISO" > "${OUTPUT_ISO}.sha256"

# ── Temizlik ──────────────────────────────────────────────────────────────────
rm -rf "$WORK_DIR"

# ── Sonuç ─────────────────────────────────────────────────────────────────────
ISO_SIZE=$(du -sh "$OUTPUT_ISO" | cut -f1)
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}           ${WHITE}OXware Hypervisor ISO Hazır!${NC}                       ${CYAN}║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  Dosya  : ${WHITE}$(basename "$OUTPUT_ISO")${NC}"
echo -e "${CYAN}║${NC}  Boyut  : ${WHITE}${ISO_SIZE}${NC}"
echo -e "${CYAN}║${NC}  SHA256 : ${WHITE}$(head -c 32 "${OUTPUT_ISO}.sha256")...${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  Boot edince: OXware TUI installer açılır                  ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Kullanıcı: oxware  /  Şifre: oxware                       ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Web UI  : https://<ip>:8006 (kurulum sonrası)             ${CYAN}║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  USB: sudo dd if=$(basename "$OUTPUT_ISO") of=/dev/sdX bs=4M${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
