#!/bin/bash
# ============================================================
#  OXware Hypervisor — Tam Kaldırma Scripti
#  Sistemi sıfırdan kaldırır, temiz kurulum için hazırlar
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
step() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

[[ $EUID -ne 0 ]] && err "Root yetkisi gerekli: sudo bash uninstall.sh"

clear
echo -e "${RED}"
cat << 'BANNER'
  ██████╗ ██╗  ██╗██╗    ██╗ █████╗ ██████╗ ███████╗
 ██╔═══██╗╚██╗██╔╝██║    ██║██╔══██╗██╔══██╗██╔════╝
 ██║   ██║ ╚███╔╝ ██║ █╗ ██║███████║██████╔╝█████╗
 ██║   ██║ ██╔██╗ ██║███╗██║██╔══██║██╔══██╗██╔══╝
 ╚██████╔╝██╔╝ ██╗╚███╔███╔╝██║  ██║██║  ██║███████╗
  ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
BANNER
echo -e "${WHITE}    Hypervisor Management System — TAM KALDIRMA${NC}"
echo -e "${RED}    Bu işlem OXware'i tamamen sistemden siler!${NC}"
echo ""

# ── Uyarı ──────────────────────────────────────────────────
echo -e "${RED}╔══════════════════════════════════════════════════════════╗"
echo -e "║  ⚠  DİKKAT — Aşağıdakiler silinecek:                   ║"
echo -e "╠══════════════════════════════════════════════════════════╣"
echo -e "║${NC}  • OXware servisi ve tüm dosyaları                      ${RED}║"
echo -e "║${NC}  • /opt/oxware/   (uygulama + git repo)                 ${RED}║"
echo -e "║${NC}  • /etc/oxware/   (konfigürasyon + SSL sertifikası)     ${RED}║"
echo -e "║${NC}  • /var/log/oxware/ (loglar)                            ${RED}║"
echo -e "║${NC}  • ox, oxupdate CLI komutları                           ${RED}║"
echo -e "║${NC}  • Fail2ban OXware kuralları                            ${RED}║"
echo -e "╠══════════════════════════════════════════════════════════╣"
echo -e "║${NC}  Sanal Makineler (VM'ler) ETKİLENMEZ.                   ${RED}║"
echo -e "║${NC}  KVM/libvirt kurulumu ETKİLENMEZ.                       ${RED}║"
echo -e "╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${WHITE}Devam etmek istediğine emin misin?${NC}"
read -p "Evet, tamamen kaldır [EVET yaz / Enter ile iptal]: " -r CONFIRM
if [[ "$CONFIRM" != "EVET" ]]; then
    echo "İptal edildi."
    exit 0
fi

# ── Veri dizini sorusu ──────────────────────────────────────
echo ""
echo -e "${YELLOW}Lisans aktivasyon kayıtları ve ISO dizini (/var/lib/oxware/) silinsin mi?${NC}"
echo -e "${BLUE}[E] Evet, her şeyi sil (tam temizlik)${NC}"
echo -e "${BLUE}[H] Hayır, veriyi koru (ISO'lar, aktivasyon logları)${NC}"
read -p "Seçim [E/H]: " -r DELETE_DATA

# ── 1. Servis Durdur ve Devre Dışı Bırak ───────────────────
step "1. Servis Durduruluyor"
if systemctl is-active --quiet oxware 2>/dev/null; then
    systemctl stop oxware
    log "oxware servisi durduruldu"
else
    info "oxware servisi zaten çalışmıyor"
fi

if systemctl is-enabled --quiet oxware 2>/dev/null; then
    systemctl disable oxware
    log "oxware servisi devre dışı bırakıldı"
fi

# ── 2. Service Dosyasını Sil ────────────────────────────────
step "2. Systemd Servis Dosyası Siliniyor"
if [ -f /etc/systemd/system/oxware.service ]; then
    rm -f /etc/systemd/system/oxware.service
    systemctl daemon-reload
    log "oxware.service silindi"
else
    info "Servis dosyası bulunamadı (zaten silinmiş)"
fi

# ── 3. Uygulama Dizini ─────────────────────────────────────
step "3. Uygulama Dosyaları Siliniyor"

# /opt/oxware altındaki tüm oxware klasörleri
for DIR in /opt/oxware /opt/oxware-src; do
    if [ -d "$DIR" ]; then
        rm -rf "$DIR"
        log "Silindi: $DIR"
    fi
done

# ── 4. Konfigürasyon ───────────────────────────────────────
step "4. Konfigürasyon Siliniyor"
if [ -d /etc/oxware ]; then
    rm -rf /etc/oxware
    log "Silindi: /etc/oxware"
fi

# ── 5. Loglar ──────────────────────────────────────────────
step "5. Log Dosyaları Siliniyor"
if [ -d /var/log/oxware ]; then
    rm -rf /var/log/oxware
    log "Silindi: /var/log/oxware"
fi

# ── 6. Veri Dizini (isteğe bağlı) ─────────────────────────
step "6. Veri Dizini"
if [ -d /var/lib/oxware ]; then
    if [[ "$DELETE_DATA" =~ ^[Ee]$ ]]; then
        rm -rf /var/lib/oxware
        log "Silindi: /var/lib/oxware (ISO'lar, lisans kayıtları dahil)"
    else
        warn "Korundu: /var/lib/oxware (ISO'lar ve aktivasyon kayıtları)"
        info "Temiz kurulum sonrası veri kurtarmak için bu dizini kontrol et"
    fi
fi

# ── 7. CLI Araçları ────────────────────────────────────────
step "7. CLI Komutları Kaldırılıyor"
for CMD in /usr/local/bin/ox /usr/local/bin/oxupdate; do
    if [ -f "$CMD" ]; then
        rm -f "$CMD"
        log "Silindi: $CMD"
    fi
done

# ── 8. Fail2ban Kuralları ──────────────────────────────────
step "8. Fail2ban OXware Kuralları Kaldırılıyor"
rm -f /etc/fail2ban/jail.d/oxware.conf 2>/dev/null
rm -f /etc/fail2ban/filter.d/oxware-web.conf 2>/dev/null
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    systemctl reload fail2ban 2>/dev/null || true
    log "Fail2ban yeniden yüklendi"
fi
log "OXware fail2ban kuralları kaldırıldı"

# ── 9. UFW Kuralları ───────────────────────────────────────
step "9. Firewall Kuralları"
echo ""
echo -e "${YELLOW}OXware için açılmış UFW portları kaldırılsın mı?${NC}"
echo -e "  Port 8006 (OXware Web UI)"
echo -e "  Port 5900-5999 (VNC)"
echo -e "  Port 6080 (noVNC)"
echo -e "${BLUE}(SSH 22 dokunulmaz)${NC}"
read -p "UFW kurallarını kaldır? [e/H]: " -r DEL_UFW
if [[ "$DEL_UFW" =~ ^[Ee]$ ]]; then
    ufw delete allow 8006/tcp 2>/dev/null || true
    ufw delete allow 5900:5999/tcp 2>/dev/null || true
    ufw delete allow 6080/tcp 2>/dev/null || true
    log "UFW OXware kuralları kaldırıldı"
else
    info "UFW kuralları korundu"
fi

# ── 10. Python Cache Temizliği ─────────────────────────────
step "10. Python Cache Temizliği"
find /tmp -name "*.pyc" -delete 2>/dev/null || true
find /tmp -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
log "Python cache temizlendi"

# ── Sonuç ──────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗"
echo -e "║        OXware başarıyla kaldırıldı!                     ║"
echo -e "╠══════════════════════════════════════════════════════════╣"
echo -e "║${NC}                                                          ${GREEN}║"
echo -e "║${NC}  ✓ Servis durduruldu ve devre dışı bırakıldı            ${GREEN}║"
echo -e "║${NC}  ✓ Uygulama dosyaları silindi                           ${GREEN}║"
echo -e "║${NC}  ✓ Konfigürasyon silindi                                ${GREEN}║"
echo -e "║${NC}  ✓ Loglar silindi                                        ${GREEN}║"
echo -e "║${NC}  ✓ CLI araçları kaldırıldı                              ${GREEN}║"
echo -e "║${NC}                                                          ${GREEN}║"
echo -e "╠══════════════════════════════════════════════════════════╣"
echo -e "║${NC}  KVM/libvirt ve sanal makineler etkilenmedi.            ${GREEN}║"
echo -e "║${NC}                                                          ${GREEN}║"
echo -e "║${NC}  Temiz kurulum için:                                     ${GREEN}║"
echo -e "║${NC}  ${CYAN}curl -fsSL https://raw.githubusercontent.com/         ${GREEN}║"
echo -e "║${NC}  ${CYAN}ShinnAsukha/oxware-hypervisor/master/install.sh       ${GREEN}║"
echo -e "║${NC}  ${CYAN}| sudo bash${NC}                                          ${GREEN}║"
echo -e "╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
