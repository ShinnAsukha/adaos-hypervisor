#!/usr/bin/env bash
# build/build-iso.sh — OXware Hypervisor ISO builder
# Usage: sudo bash build/build-iso.sh
# Requires: Ubuntu 22.04+ or Debian 12 host with root access

set -euo pipefail

# ── config ─────────────────────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${REPO_ROOT}/work"
ISO_NAME="oxware-$(date +%Y%m%d).iso"
DEBIAN_MIRROR="http://deb.debian.org/debian"
DEBIAN_SUITE="bookworm"
ARCH="amd64"

# ── sanity checks ──────────────────────────────────────────────────────────────
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "${REPO_ROOT}/build/installer/install.py" ]]; then
    echo "ERROR: build/installer/install.py not found." >&2
    echo "       Run this script from the repository root." >&2
    exit 1
fi

# ── helper ─────────────────────────────────────────────────────────────────────
log() { echo -e "\033[1;36m[BUILD]\033[0m $*"; }
die() { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }

# ── install build dependencies ─────────────────────────────────────────────────
log "Installing build dependencies …"
apt-get update -qq
apt-get install -y --no-install-recommends \
    debootstrap \
    xorriso \
    grub-pc-bin \
    grub-efi-amd64-bin \
    mtools \
    squashfs-tools \
    rsync

# ── clean previous work dir (idempotent) ───────────────────────────────────────
log "Cleaning previous build directory …"
if mountpoint -q "${WORK}/rootfs/proc"     2>/dev/null; then umount -lf "${WORK}/rootfs/proc";     fi
if mountpoint -q "${WORK}/rootfs/sys"      2>/dev/null; then umount -lf "${WORK}/rootfs/sys";      fi
if mountpoint -q "${WORK}/rootfs/dev/pts"  2>/dev/null; then umount -lf "${WORK}/rootfs/dev/pts";  fi
if mountpoint -q "${WORK}/rootfs/dev"      2>/dev/null; then umount -lf "${WORK}/rootfs/dev";      fi
rm -rf "${WORK}"

# ── directory layout ───────────────────────────────────────────────────────────
log "Creating directory layout …"
mkdir -p \
    "${WORK}/rootfs" \
    "${WORK}/iso/live" \
    "${WORK}/iso/boot/grub"

# ── debootstrap base system ────────────────────────────────────────────────────
log "Running debootstrap (${DEBIAN_SUITE}/${ARCH}) — this takes a while …"
debootstrap \
    --arch="${ARCH}" \
    --variant=minbase \
    "${DEBIAN_SUITE}" \
    "${WORK}/rootfs" \
    "${DEBIAN_MIRROR}"

# ── mount virtual filesystems for chroot ──────────────────────────────────────
log "Mounting virtual filesystems …"
mount --bind /proc    "${WORK}/rootfs/proc"
mount --bind /sys     "${WORK}/rootfs/sys"
mount --bind /dev     "${WORK}/rootfs/dev"
mount --bind /dev/pts "${WORK}/rootfs/dev/pts"

# ensure these are unmounted even on error
trap 'log "Cleaning up mounts …"
      umount -lf "${WORK}/rootfs/dev/pts"  2>/dev/null || true
      umount -lf "${WORK}/rootfs/dev"      2>/dev/null || true
      umount -lf "${WORK}/rootfs/sys"      2>/dev/null || true
      umount -lf "${WORK}/rootfs/proc"     2>/dev/null || true' EXIT

# ── configure APT inside chroot ───────────────────────────────────────────────
log "Configuring APT sources …"
cat > "${WORK}/rootfs/etc/apt/sources.list" <<EOF
deb ${DEBIAN_MIRROR} ${DEBIAN_SUITE} main contrib non-free non-free-firmware
deb ${DEBIAN_MIRROR}-security ${DEBIAN_SUITE}-security main contrib non-free non-free-firmware
deb ${DEBIAN_MIRROR} ${DEBIAN_SUITE}-updates main contrib non-free non-free-firmware
EOF

# ── install packages inside chroot ────────────────────────────────────────────
log "Installing packages inside chroot …"
chroot "${WORK}/rootfs" /bin/bash -c "apt-get update -qq"
DEBIAN_FRONTEND=noninteractive chroot "${WORK}/rootfs" /bin/bash -c \
    "apt-get install -y --no-install-recommends \
        linux-image-${ARCH} \
        live-boot \
        live-boot-initramfs-tools \
        python3 \
        python3-pip \
        python3-curses \
        qemu-kvm \
        libvirt-daemon-system \
        libvirt-clients \
        bridge-utils \
        nginx \
        python3-flask \
        python3-flask-jwt-extended \
        parted \
        dosfstools \
        e2fsprogs \
        debootstrap \
        curl \
        wget \
        git \
        systemd \
        systemd-sysv \
        openssh-server \
        iproute2 \
        iputils-ping \
        net-tools \
        dialog \
        whiptail \
        grub-pc \
        grub-efi-amd64 \
        grub2-common \
        rsync \
        sudo"

# ── copy oxware source into rootfs ────────────────────────────────────────────
log "Copying OXware source into rootfs …"
mkdir -p "${WORK}/rootfs/opt/oxware"
rsync -a --delete \
    "${REPO_ROOT}/oxware/" \
    "${WORK}/rootfs/opt/oxware/"

# ── copy installer ────────────────────────────────────────────────────────────
log "Copying installer …"
mkdir -p "${WORK}/rootfs/opt/oxware-installer"
cp "${REPO_ROOT}/build/installer/install.py" \
   "${WORK}/rootfs/opt/oxware-installer/install.py"
chmod +x "${WORK}/rootfs/opt/oxware-installer/install.py"

# ── copy rootfs overlay (systemd services, motd, etc.) ───────────────────────
log "Copying rootfs overlay …"
if [[ -d "${REPO_ROOT}/build/rootfs" ]]; then
    rsync -a "${REPO_ROOT}/build/rootfs/" "${WORK}/rootfs/"
fi

# ── system configuration ──────────────────────────────────────────────────────
log "Configuring live system …"
echo "oxware-live" > "${WORK}/rootfs/etc/hostname"

# root password for live env
chroot "${WORK}/rootfs" /bin/bash -c "echo 'root:oxware' | chpasswd"

# autologin on tty1 for the installer
mkdir -p "${WORK}/rootfs/etc/systemd/system/getty@tty1.service.d"
cat > "${WORK}/rootfs/etc/systemd/system/getty@tty1.service.d/autologin.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
EOF

# ── enable services ───────────────────────────────────────────────────────────
log "Enabling services …"
chroot "${WORK}/rootfs" /bin/bash -c \
    "systemctl enable oxware-installer libvirtd nginx 2>/dev/null || true"

# disable services that conflict with live boot
chroot "${WORK}/rootfs" /bin/bash -c \
    "systemctl disable apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true"

# ── build squashfs ────────────────────────────────────────────────────────────
# Unmount before squashfs
log "Unmounting virtual filesystems before squashfs …"
umount -lf "${WORK}/rootfs/dev/pts"  2>/dev/null || true
umount -lf "${WORK}/rootfs/dev"      2>/dev/null || true
umount -lf "${WORK}/rootfs/sys"      2>/dev/null || true
umount -lf "${WORK}/rootfs/proc"     2>/dev/null || true

# clear trap since we unmounted manually
trap - EXIT

log "Building squashfs (xz compression, may take several minutes) …"
mksquashfs \
    "${WORK}/rootfs" \
    "${WORK}/iso/live/filesystem.squashfs" \
    -comp xz \
    -e boot \
    -noappend

# ── copy kernel and initrd ────────────────────────────────────────────────────
log "Copying kernel and initrd …"
KERNEL=$(ls "${WORK}/rootfs/boot/vmlinuz-"* 2>/dev/null | sort -V | tail -1)
INITRD=$(ls "${WORK}/rootfs/boot/initrd.img-"* 2>/dev/null | sort -V | tail -1)

if [[ -z "${KERNEL}" ]]; then
    die "No kernel found in rootfs/boot/. Check package installation."
fi
if [[ -z "${INITRD}" ]]; then
    die "No initrd found in rootfs/boot/. Check package installation."
fi

cp "${KERNEL}" "${WORK}/iso/live/vmlinuz"
cp "${INITRD}" "${WORK}/iso/live/initrd.img"

log "Kernel:  ${KERNEL}"
log "Initrd:  ${INITRD}"

# ── GRUB config ───────────────────────────────────────────────────────────────
log "Writing GRUB configuration …"
# Use build/grub/grub.cfg if it exists, otherwise generate
if [[ -f "${REPO_ROOT}/build/grub/grub.cfg" ]]; then
    cp "${REPO_ROOT}/build/grub/grub.cfg" "${WORK}/iso/boot/grub/grub.cfg"
else
    cat > "${WORK}/iso/boot/grub/grub.cfg" <<'GRUBCFG'
set timeout=5
set default=0

menuentry "OXware Hypervisor Installer" {
    linux   /live/vmlinuz boot=live quiet splash
    initrd  /live/initrd.img
}

menuentry "OXware Installer (Debug)" {
    linux   /live/vmlinuz boot=live
    initrd  /live/initrd.img
}
GRUBCFG
fi

# ── build ISO ─────────────────────────────────────────────────────────────────
log "Building ISO with grub-mkrescue …"
cd "${REPO_ROOT}"
grub-mkrescue \
    --output="${ISO_NAME}" \
    "${WORK}/iso" \
    -- -volid "OXware-Installer"

ISO_SIZE=$(du -sh "${ISO_NAME}" | cut -f1)
log "──────────────────────────────────────────────"
log "SUCCESS!"
log "ISO file : ${REPO_ROOT}/${ISO_NAME}"
log "ISO size : ${ISO_SIZE}"
log ""
log "Write to USB:  dd if=${ISO_NAME} of=/dev/sdX bs=4M status=progress"
log "Or use Rufus / Ventoy on Windows."
log "──────────────────────────────────────────────"
