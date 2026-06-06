#!/usr/bin/env bash
# ============================================================================
# OXware Hypervisor — One-Line Installer (Bootstrap)
# https://oxware.top/install.sh
#
# Usage:
# curl -sSL https://oxware.top/install.sh | sudo bash
# curl -sSL https://oxware.top/install.sh | sudo bash -s -- --force
#
# This bootstrap clones the main repository and runs the real installer.
# ============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
step() { echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${BOLD} $1${NC}"; echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
info() { echo -e " ${CYAN}->${NC} $1"; }

FORCE=0
QUIET="${OXWARE_QUIET:-0}"
BRANCH="${OXWARE_BRANCH:-main}"
CLONE_DIR="${OXWARE_CLONE_DIR:-/opt/oxware-src}"
REPO_URL="https://github.com/ShinnAsukha/oxware-hypervisor.git"
INSTALL_TARGET="/opt/oxware/oxware/backend/app.py"

for a in "${@:-}"; do
 case "${a:-}" in
 --force) FORCE=1 ;;
 --quiet) QUIET=1 ;;
 --branch=*) BRANCH="${a#--branch=}" ;;
 --help|-h)
 echo "Usage: curl -sSL https://oxware.top/install.sh | sudo bash [-- --force]"
 echo " --force Mevcut kuruluma rağmen taze kurulum yap"
 echo " --quiet Minimum çıktı"
 echo " --branch=NAME GitHub branch'i (varsayılan: main)"
 exit 0 ;;
 esac
done

clear 2>/dev/null || true
cat << 'BANNER'

 ██████╗ ██╗ ██╗██╗ ██╗ █████╗ ██████╗ ███████╗
 ██╔═══██╗╚██╗██╔╝██║ ██║██╔══██╗██╔══██╗██╔════╝
 ██║ ██║ ╚███╔╝ ██║ █╗ ██║███████║██████╔╝█████╗
 ██║ ██║ ██╔██╗ ██║███╗██║██╔══██║██╔══██╗██╔══╝
 ╚██████╔╝██╔╝ ██╗╚███╔███╔╝██║ ██║██║ ██║███████╗
 ╚═════╝ ╚═╝ ╚═╝ ╚══╝╚══╝ ╚═╝ ╚═╝╚═╝ ╚═╝╚══════╝

 OXware Hypervisor — One-Line Installer

BANNER

if [ "$(id -u)" -ne 0 ]; then
 err "Root yetkisi gerekli. Çalıştırın: curl -sSL https://oxware.top/install.sh | sudo bash"
fi

step "Sistem Kontrolü"

if [ ! -f /etc/os-release ]; then
 err "/etc/os-release bulunamadı. Desteklenmeyen sistem."
fi

# shellcheck disable=SC1091
. /etc/os-release

OS_ID="${ID:-unknown}"
OS_VERSION="${VERSION_ID:-0}"
OS_PRETTY="${PRETTY_NAME:-${ID:-Unknown}}"

info "OS: ${OS_PRETTY}"
info "Kernel: $(uname -r)"
info "Arch: $(uname -m)"

SUPPORTED=0
case "$OS_ID" in
 ubuntu)
 if [ "${OS_VERSION%%.*}" -ge 22 ] 2>/dev/null; then SUPPORTED=1; fi
 ;;
 debian)
 if [ "${OS_VERSION%%.*}" -ge 12 ] 2>/dev/null; then SUPPORTED=1; fi
 ;;
 oxware) SUPPORTED=1 ;;
esac

if [ "$SUPPORTED" -ne 1 ]; then
 if [ "$FORCE" -eq 1 ]; then
 warn "Desteklenmeyen OS: ${OS_PRETTY} — --force ile devam ediliyor"
 else
 err "Desteklenmeyen OS: ${OS_PRETTY}. Ubuntu 22.04+ veya Debian 12+ gerekli. --force ile zorlayın."
 fi
fi

ARCH="$(uname -m)"
if [ "$ARCH" != "x86_64" ]; then
 if [ "$FORCE" -eq 1 ]; then
 warn "Mimari $ARCH desteklenmeyebilir — --force ile devam"
 else
 err "Mimari $ARCH desteklenmiyor (x86_64 gerekli). --force ile zorlayın."
 fi
fi

log "Sistem desteği OK"

if [ -f "$INSTALL_TARGET" ] && [ "$FORCE" -ne 1 ]; then
 warn "Mevcut OXware kurulumu tespit edildi: $INSTALL_TARGET"
 REPLY=""
 if [ -t 0 ]; then
 read -r -p "Güncelleme moduna geç (mevcut config korunur) [E/h]? " REPLY
 elif [ -r /dev/tty ]; then
 read -r -p "Güncelleme moduna geç (mevcut config korunur) [E/h]? " REPLY < /dev/tty
 fi
 case "${REPLY:-E}" in
 [hH]*) err "Kullanıcı iptal etti. --force ile zorlayabilirsiniz." ;;
 *) info "Güncelleme moduna geçiliyor — config dosyaları korunacak" ;;
 esac
fi

step "Temel Bağımlılıklar"

export DEBIAN_FRONTEND=noninteractive

NEED_INSTALL=()
for cmd in git curl; do
 command -v "$cmd" >/dev/null 2>&1 || NEED_INSTALL+=("$cmd")
done
command -v update-ca-certificates >/dev/null 2>&1 || NEED_INSTALL+=("ca-certificates")

if [ "${#NEED_INSTALL[@]}" -gt 0 ]; then
 info "Eksik paketler kuruluyor: ${NEED_INSTALL[*]}"
 apt-get update -qq
 apt-get install -y -qq "${NEED_INSTALL[@]}"
 log "Bağımlılıklar kuruldu"
else
 log "Tüm bağımlılıklar mevcut (git, curl, ca-certificates)"
fi

step "Kaynak Kodu İndirme"

PARENT_DIR="$(dirname "$CLONE_DIR")"
if [ ! -d "$PARENT_DIR" ] || [ ! -w "$PARENT_DIR" ]; then
 warn "$PARENT_DIR yazılabilir değil — /tmp'ye geçiliyor"
 CLONE_DIR="/tmp/oxware-src"
fi

if [ -d "$CLONE_DIR/.git" ]; then
 info "Mevcut repo bulundu, güncelleniyor: $CLONE_DIR"
 git -C "$CLONE_DIR" fetch --depth=1 origin "$BRANCH" 2>&1 | (grep -v "^$" || true)
 git -C "$CLONE_DIR" reset --hard "origin/$BRANCH"
 log "Repo güncellendi -> branch: $BRANCH"
else
 if [ -e "$CLONE_DIR" ]; then
 warn "$CLONE_DIR mevcut ama .git yok — kaldırılıyor"
 rm -rf "$CLONE_DIR"
 fi
 info "Klonlanıyor: $REPO_URL -> $CLONE_DIR (branch: $BRANCH)"
 git clone --depth=1 --branch "$BRANCH" "$REPO_URL" "$CLONE_DIR" 2>&1 | (grep -v "^$" || true)
 log "Repo klonlandı"
fi

step "Ana Kurulum Çalıştırılıyor"

REAL_INSTALLER="$CLONE_DIR/install.sh"

if [ ! -f "$REAL_INSTALLER" ]; then
 err "Ana installer bulunamadı: $REAL_INSTALLER"
fi

info "Çalıştırılıyor: bash $REAL_INSTALLER"
info "(Bu işlem 3-8 dakika sürebilir...)"
echo ""

# Recursive guard
export OXWARE_BOOTSTRAP_RAN=1

if bash "$REAL_INSTALLER"; then
 log "Ana kurulum tamamlandı"
else
 EXIT=$?
 err "Ana kurulum başarısız (exit $EXIT). Düzeltme: cd $CLONE_DIR && sudo bash repair.sh"
fi

HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -z "$HOST_IP" ] && HOST_IP="localhost"

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN} OXware Kurulumu Tamamlandı${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e " Web UI: ${CYAN}https://${HOST_IP}:8006${NC}"
echo -e " Docs: ${CYAN}https://oxware.top/docs/${NC}"
echo -e " GitHub: ${CYAN}https://github.com/ShinnAsukha/oxware-hypervisor${NC}"
echo -e " Repair: ${CYAN}sudo bash $CLONE_DIR/repair.sh${NC}"
echo -e " Loglar: ${CYAN}journalctl -u oxware -f${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo " İlk girişte kurulum sihirbazı açılacak (admin kullanıcı + şifre)."
echo " Sorun olursa: bash $CLONE_DIR/repair.sh --diagnose"
echo ""
