#!/usr/bin/env bash
# ============================================================
#  OXware Hypervisor — ISO Builder v3.0
#  Boot → OXware TUI installer (subiquity tamamen devre dışı)
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Versiyon: build/VERSION dosyasından oku, patch++ yap, geri yaz ────────────
VERSION_FILE="$SCRIPT_DIR/VERSION"
[ -f "$VERSION_FILE" ] || echo "2.0.0" > "$VERSION_FILE"
_PREV_VER="$(cat "$VERSION_FILE" | tr -d '[:space:]')"
_MAJOR="$(echo "$_PREV_VER" | cut -d. -f1)"
_MINOR="$(echo "$_PREV_VER" | cut -d. -f2)"
_PATCH="$(echo "$_PREV_VER" | cut -d. -f3)"
_PATCH=$(( _PATCH + 1 ))
OXWARE_VERSION="${_MAJOR}.${_MINOR}.${_PATCH}"
echo "$OXWARE_VERSION" > "$VERSION_FILE"

UBUNTU_VERSION="22.04.5"
UBUNTU_ISO_URL="https://releases.ubuntu.com/22.04/ubuntu-${UBUNTU_VERSION}-live-server-amd64.iso"
UBUNTU_ISO_FALLBACK="https://old-releases.ubuntu.com/releases/22.04/ubuntu-${UBUNTU_VERSION}-live-server-amd64.iso"
ISO_CACHE="/tmp/ubuntu-${UBUNTU_VERSION}-server.iso"
WORK_DIR="/tmp/oxware-iso-build"
SQUASHFS_ROOT="$WORK_DIR/squashfs-root"
OUTPUT_ISO="$REPO_ROOT/OXware-Hypervisor-${OXWARE_VERSION}-amd64.iso"

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

# ── Squashfs Bul — Ubuntu 22.04 birden fazla squashfs kullanır ───────────────
step "Squashfs Aranıyor"

# Ana squashfs (base sistem — chroot burada yapılır)
SQUASHFS_FILE=""
for f in \
    "$WORK_DIR/iso/casper/ubuntu-server-minimal.squashfs" \
    "$WORK_DIR/iso/casper/filesystem.squashfs"; do
    [ -f "$f" ] && SQUASHFS_FILE="$f" && break
done
[ -z "$SQUASHFS_FILE" ] && err "Ana squashfs dosyası bulunamadı!"
log "Ana squashfs: $SQUASHFS_FILE"

# Installer squashfs (subiquity/console-conf/cloud-init bunun içinde)
INSTALLER_SQUASHFS=""
for f in \
    "$WORK_DIR/iso/casper/ubuntu-server-minimal.ubuntu-server.installer.generic.squashfs" \
    "$WORK_DIR/iso/casper/ubuntu-server-minimal.ubuntu-server.squashfs"; do
    [ -f "$f" ] && INSTALLER_SQUASHFS="$f" && break
done
[ -n "$INSTALLER_SQUASHFS" ] && log "Installer squashfs: $INSTALLER_SQUASHFS"

# Tüm squashfs'leri listele
log "Bulunan tüm squashfs:"
find "$WORK_DIR/iso/casper" -name "*.squashfs" 2>/dev/null | while read -r f; do
    log "  $(basename "$f") ($(du -sh "$f" | cut -f1))"
done

# ── Installer squashfs içindeki servisleri maskele (overlay) ─────────────────
# Ubuntu live'de installer squashfs, base squashfs'in üstüne overlay olarak biner.
# Subiquity/console-conf/cloud-init INSTALLER squashfs içinde — orayı da patchle.
if [ -n "$INSTALLER_SQUASHFS" ]; then
    step "Installer Squashfs Maskeleniyor"
    INST_ROOT="$WORK_DIR/squashfs-installer"
    unsquashfs -d "$INST_ROOT" "$INSTALLER_SQUASHFS"

    INST_MASK_DIR="$INST_ROOT/etc/systemd/system"
    mkdir -p "$INST_MASK_DIR"
    for svc in \
        subiquity.service \
        snap.subiquity.subiquity.service \
        snap.subiquity.subiquity-server.service \
        snap.console-conf.console-conf.service \
        console-conf@tty1.service console-conf@.service console-conf.service \
        cloud-init.service cloud-init-local.service \
        cloud-config.service cloud-final.service \
        getty@tty1.service autovt@tty1.service; do
        ln -sf /dev/null "$INST_MASK_DIR/$svc" 2>/dev/null || true
    done
    # Dinamik — installer squashfs içindeki snap servislerini bul ve maskele
    for sd in "$INST_ROOT/lib/systemd/system" "$INST_ROOT/usr/lib/systemd/system"; do
        [ -d "$sd" ] || continue
        for f in "$sd"/snap.subiquity.*.service "$sd"/snap.console-conf.*.service \
                 "$sd"/cloud-init*.service "$sd"/cloud-config*.service; do
            [ -f "$f" ] && ln -sf /dev/null "$INST_MASK_DIR/$(basename "$f")" 2>/dev/null || true
        done
    done

    rm -f "$INSTALLER_SQUASHFS"
    mksquashfs "$INST_ROOT" "$INSTALLER_SQUASHFS" \
        -comp xz -noappend -b 1M -no-progress
    rm -rf "$INST_ROOT"
    log "Installer squashfs maskelendi ve yeniden paketlendi"
fi

# ── Ana Squashfs Aç ───────────────────────────────────────────────────────────
step "Ana Squashfs Açılıyor (~5-10 dk)"
unsquashfs -d "$SQUASHFS_ROOT" "$SQUASHFS_FILE"
log "Squashfs açıldı: $(du -sh "$SQUASHFS_ROOT" | cut -f1)"

# ── Squashfs Düzenle ──────────────────────────────────────────────────────────
step "Subiquity Devre Dışı + OXware TUI Ekleniyor"

# 1. TÜM Ubuntu live installer servislerini maskele
# (subiquity normal + snap variant, console-conf snap, cloud-init, getty)
MASK_SVCS=(
    # Subiquity — normal ve snap variants
    "subiquity.service"
    "snap.subiquity.subiquity.service"
    "snap.subiquity.subiquity-server.service"
    "snap.subiquity.subiquity-service.service"
    # console-conf snap — dil/klavye ekranını açan bu
    "snap.console-conf.console-conf.service"
    "console-conf@tty1.service"
    "console-conf@.service"
    "console-conf.service"
    # cloud-init — "waiting for cloud-init" mesajı bundan
    "cloud-init.service"
    "cloud-init-local.service"
    "cloud-config.service"
    "cloud-final.service"
    "cloud-init.target"
    # Ubuntu misc live services
    "ubuntu-advantage.service"
    "ubuntu-advantage-timer.service"
    "pollinate.service"
    "ua-reloader.service"
    "apport.service"
    "landscape-client.service"
    "snapd.seeded.service"
    # getty — bizim servis tty1'i alacak
    "getty@tty1.service"
    "autovt@tty1.service"
)
mkdir -p "$SQUASHFS_ROOT/etc/systemd/system"
for svc in "${MASK_SVCS[@]}"; do
    ln -sf /dev/null "$SQUASHFS_ROOT/etc/systemd/system/$svc" 2>/dev/null || true
done

# Squashfs içindeki tüm subiquity/console-conf snap servislerini dinamik bul ve maskele
for svc_file in \
    "$SQUASHFS_ROOT/lib/systemd/system"/snap.subiquity.*.service \
    "$SQUASHFS_ROOT/lib/systemd/system"/snap.console-conf.*.service \
    "$SQUASHFS_ROOT/usr/lib/systemd/system"/snap.subiquity.*.service \
    "$SQUASHFS_ROOT/usr/lib/systemd/system"/snap.console-conf.*.service; do
    [ -f "$svc_file" ] && \
        ln -sf /dev/null "$SQUASHFS_ROOT/etc/systemd/system/$(basename "$svc_file")" 2>/dev/null || true
done

log "Tüm Ubuntu live servisler maskelendi (subiquity/console-conf/cloud-init)"

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
After=systemd-remount-fs.service systemd-udevd.service local-fs.target
DefaultDependencies=no
Conflicts=getty@tty1.service
Conflicts=snap.subiquity.subiquity.service
Conflicts=snap.console-conf.console-conf.service
Conflicts=console-conf@tty1.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/oxware-installer/install.py
StandardInput=tty
StandardOutput=tty
StandardError=journal+console
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
TTYVTDisallocate=yes
KillMode=process
IgnoreSIGPIPE=no
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SVC

# 6. Servisi etkinleştir
mkdir -p "$SQUASHFS_ROOT/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/oxware-installer.service \
    "$SQUASHFS_ROOT/etc/systemd/system/multi-user.target.wants/oxware-installer.service"
log "oxware-installer.service etkinleştirildi"

# 7. debootstrap'i build host'tan kopyala (chroot apt genelde başarısız olur)
log "debootstrap build host'tan kopyalanıyor..."
if [ -f "/usr/sbin/debootstrap" ]; then
    cp /usr/sbin/debootstrap "$SQUASHFS_ROOT/usr/sbin/debootstrap"
    chmod +x "$SQUASHFS_ROOT/usr/sbin/debootstrap"
fi
if [ -d "/usr/share/debootstrap" ]; then
    mkdir -p "$SQUASHFS_ROOT/usr/share/debootstrap"
    cp -r /usr/share/debootstrap/. "$SQUASHFS_ROOT/usr/share/debootstrap/"
fi
# Debian bookworm keyring (debootstrap için gerekli)
for keyring_dir in /usr/share/keyrings /etc/apt/trusted.gpg.d; do
    [ -d "$keyring_dir" ] && {
        mkdir -p "$SQUASHFS_ROOT$keyring_dir"
        cp "$keyring_dir"/*.gpg "$SQUASHFS_ROOT$keyring_dir/" 2>/dev/null || true
        cp "$keyring_dir"/*.asc "$SQUASHFS_ROOT$keyring_dir/" 2>/dev/null || true
    }
done
log "debootstrap hazır: $(debootstrap --version 2>/dev/null || echo 'version unknown')"

# 8. Chroot: python3-curses, git, parted kur
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
# python3-curses, git, parted — debootstrap build host'tan kopyalandı
apt-get update -qq 2>/dev/null || true
apt-get install -y -qq --no-install-recommends \
    python3 python3-curses git \
    parted dosfstools e2fsprogs util-linux \
    2>/dev/null || true
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
    linux   $VMLINUZ_PATH boot=casper quiet loglevel=0 console=tty1 net.ifnames=0 biosdevname=0 systemd.show_status=false systemd.unit=multi-user.target ---
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

# Eski versiyonları temizle (docs'ta tek ISO görünsün)
log "Eski ISO'lar temizleniyor..."
find "$REPO_ROOT" -maxdepth 1 -name "OXware-Hypervisor-*.iso" ! -name "$(basename "$OUTPUT_ISO")" -delete 2>/dev/null || true
find "$REPO_ROOT" -maxdepth 1 -name "OXware-Hypervisor-*.sha256" ! -name "$(basename "$OUTPUT_ISO").sha256" -delete 2>/dev/null || true

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
echo -e "${CYAN}║${NC}  Kurulum: TUI'de kullanıcı adı ve şifre belirle            ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Web UI  : https://<ip>:8006 (kurulum sonrası)             ${CYAN}║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  USB: sudo dd if=$(basename "$OUTPUT_ISO") of=/dev/sdX bs=4M${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
