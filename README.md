# OXware Hypervisor — Kurulum Kılavuzu

> Sürüm: 2.3 · Hazırlayan: Ada Gürsoy

---

## Hızlı Başlangıç

```bash
# 1. Repo'yu sunucuya çek
git clone https://github.com/ShinnAsukha/oxware-hypervisor.git /opt/oxware-src
cd /opt/oxware-src

# 2. Kur (root gerekli)
sudo bash install.sh

# 3. Tarayıcıdan eriş
#    https://<sunucu-ip>:8006
```

> **Sorun mu var?** Sunucu yeniden başladıktan sonra SSH veya panel erişilemez hâle geldiyse:
> ```bash
> sudo bash repair.sh
> ```

---

## İçindekiler

1. [Donanım Gereksinimleri](#1-donanım-gereksinimleri)
2. [BIOS/UEFI Ayarları](#2-biosuefi-ayarları)
3. [Ubuntu Sunucu Hazırlığı](#3-ubuntu-sunucu-hazırlığı)
4. [OXware ISO ile Kurulum (build-iso.sh)](#4-oxware-iso-ile-kurulum-build-isosh)
5. [Script ile Kurulum (Mevcut Ubuntu)](#5-script-ile-kurulum-mevcut-ubuntu)
6. [İlk Giriş ve Parola Belirleme](#6-ilk-giriş-ve-parola-belirleme)
7. [Web Arayüzüne Erişim](#7-web-arayüzüne-erişim)
8. [IP Havuzu Oluşturma](#8-ip-havuzu-oluşturma)
9. [İlk VM Oluşturma](#9-ilk-vm-oluşturma)
10. [VM Tipleri: VPS ve VDS](#10-vm-tipleri-vps-ve-vds)
11. [AI Ajan Kurulumu](#11-ai-ajan-kurulumu)
12. [Telegram ve Discord Bildirimleri](#12-telegram-ve-discord-bildirimleri)
13. [2FA (İki Faktörlü Doğrulama)](#13-2fa-iki-faktörlü-doğrulama)
14. [Güvenlik Denetimi](#14-güvenlik-denetimi)
15. [Otomatik Snapshot ve Yedekleme Diski](#15-otomatik-snapshot-ve-yedekleme-diski)
16. [Otomatik Güncelleme Kontrolü](#16-otomatik-güncelleme-kontrolü)
17. [Parola Sıfırlama](#17-parola-sıfırlama)
18. [Güvenlik Duvarı ve Portlar](#18-güvenlik-duvarı-ve-portlar)
19. [Aktif Oturum Yönetimi (JWT Sessions)](#19-aktif-oturum-yönetimi-jwt-sessions)
20. [IP Erişim Kısıtlaması (Allowlist)](#20-ip-erişim-kısıtlaması-allowlist)
21. [VM Zamanlaması](#21-vm-zamanlaması)
22. [VM Klonlama ve Toplu İşlemler](#22-vm-klonlama-ve-toplu-işlemler)
23. [Prometheus Metrikleri](#23-prometheus-metrikleri)
24. [PWA (Masaüstü / Mobil Uygulama)](#24-pwa-masaüstü--mobil-uygulama)
25. [Domain Bağlama (Nginx + Let's Encrypt)](#25-domain-bağlama-nginx--lets-encrypt)
26. [İnternet Bağlantısı Gereksinimleri](#26-i̇nternet-bağlantısı-gereksinimleri)
27. [Sorun Giderme](#27-sorun-giderme)
28. [AdaOS → OXware Canlı Sunucu Geçişi](#28-adaos--oxware-canlı-sunucu-geçişi)
29. [VM Lifecycle Hook Scripts](#29-vm-lifecycle-hook-scripts)
30. [LDAP / Active Directory Girişi](#30-ldap--active-directory-girişi)
31. [RBAC — Rol Tabanlı Erişim Kontrolü](#31-rbac--rol-tabanlı-erişim-kontrolü)
32. [VM Etiketleme ve Gruplama](#32-vm-etiketleme-ve-gruplama)
33. [VM Notları](#33-vm-notları)
34. [Kimlik Bilgisi Vault](#34-kimlik-bilgisi-vault)
35. [Maliyet Takibi](#35-maliyet-takibi)
36. [Uyarı Kuralları (Alert Rules)](#36-uyarı-kuralları-alert-rules)
37. [Güvenlik Skoru](#37-güvenlik-skoru)
38. [Global Arama ve Klavye Kısayolları](#38-global-arama-ve-klavye-kısayolları)
39. [DNS Watchdog ve Otomatik İyileştirme](#39-dns-watchdog-ve-otomatik-i̇yileştirme)
40. [AI ile VM Oluşturma](#40-ai-ile-vm-oluşturma)

---

## 1. Donanım Gereksinimleri

| Bileşen | Minimum | Önerilen |
|---------|---------|---------|
| **CPU** | 2 çekirdek (VT-x / AMD-V zorunlu) | 8+ çekirdek |
| **RAM** | 2 GB | 32 GB+ |
| **Disk** | 20 GB | 500 GB+ SSD/NVMe |
| **Ağ** | 1x Ethernet | 2x Ethernet (yönetim + VM) |
| **Mimari** | x86_64 | x86_64 |

> **Kritik:** BIOS/UEFI üzerinden donanım sanallaştırma (VT-x / AMD-V) devre dışıysa OXware kurulumu duracaktır.

---

## 2. BIOS/UEFI Ayarları

Sunucuyu kapatın, güç tuşuna basarken **DEL**, **F2** veya **F10** tuşuna basarak BIOS/UEFI'ye girin.

### Intel işlemciler:
```
Advanced → CPU Configuration → Intel Virtualization Technology → Enabled
Advanced → CPU Configuration → VT-d → Enabled   (isteğe bağlı, PCI passthrough için)
```

### AMD işlemciler:
```
Advanced → CPU Configuration → SVM Mode → Enabled
Advanced → CPU Configuration → IOMMU → Enabled   (isteğe bağlı)
```

### Ortak ayarlar:
```
Boot → Secure Boot → Disabled          (Ubuntu kurulumu için)
Boot → Boot Mode    → UEFI (önerilen)
```

Ayarları kaydedin ve çıkın (**F10** → Save & Exit).

Kurulumdan sonra terminalde doğrulama:
```bash
grep -E "vmx|svm" /proc/cpuinfo | head -1
# vmx → Intel VT-x aktif
# svm → AMD-V aktif
```

---

## 3. Ubuntu Sunucu Hazırlığı

OXware'i mevcut bir Ubuntu 22.04 LTS sunucusuna kurmak istiyorsanız bu adımı izleyin.

### Temiz Ubuntu 22.04 LTS kurulumu

1. [ubuntu.com/download/server](https://ubuntu.com/download/server) adresinden Ubuntu Server 22.04.4 LTS ISO indirin.
2. [Rufus](https://rufus.ie/) (Windows) veya `dd` (Linux) ile USB belleğe yazın:
   ```bash
   sudo dd if=ubuntu-22.04.4-live-server-amd64.iso of=/dev/sdX bs=4M status=progress
   ```
3. Sunucuyu USB'den önyükleyin.
4. Kurulum sırasında:
   - Dil: **English** (karakter sorunlarını önler)
   - Disk: Tüm diski kullan, LVM ayarla
   - Kullanıcı: `oxware` / güçlü bir parola
   - **OpenSSH Server**: Kur (opsiyonel ama önerilir)
5. Kurulum tamamlanınca USB'yi çıkarın ve yeniden başlatın.

### NTP / Saat Senkronizasyonu

> **Önemli:** Yanlış sistem saati 2FA kodlarını geçersiz kılar ve SSL/GitHub bağlantılarını bozar.

```bash
# systemd-timesyncd ile senkronize et
timedatectl set-ntp true
systemctl restart systemd-timesyncd

# Durumu kontrol et
timedatectl status
# "System clock synchronized: yes" çıkmalı

# NTP sunucusu erişilemiyorsa manuel ayarla
timedatectl set-ntp false
date -s "YYYY-MM-DD HH:MM:SS"
hwclock --systohc
timedatectl set-ntp true
```

Alternatif NTP sunucuları (`/etc/systemd/timesyncd.conf`):
```ini
[Time]
NTP=time.cloudflare.com time.google.com
FallbackNTP=ntp.ubuntu.com
```

---

## 4. OXware ISO ile Kurulum (build-iso.sh)

`build-iso.sh` — Ubuntu Server 22.04 tabanlı, OXware gömülü, tam otomatik kurulum ISO'su oluşturur.

### Ne yapar?

| Adım | İşlem |
|------|-------|
| 1 | Ubuntu Server 22.04.4 ISO'yu indirir (`/tmp`'ye önbelleğe alır) |
| 2 | ISO içeriğini geçici dizine ayıklar |
| 3 | OXware kaynak dosyalarını ISO'ya gömer (`/oxware/`) |
| 4 | **cloud-init / autoinstall** yapılandırması oluşturur — dil, klavye, disk, kullanıcı, SSH, paket listesi |
| 5 | Kurulum sonrası komutlar: venv, pip, SSL sertifikası, systemd servisi, UFW |
| 6 | BIOS sanallaştırma kontrol scripti ekler (`check-virt.sh`) |
| 7 | GRUB (UEFI) ve isolinux (BIOS) boot menülerini yapılandırır |
| 8 | `xorriso` ile ISO oluşturur, `isohybrid` ile USB-bootable yapar |
| 9 | SHA256 checksum dosyası üretir |

Çıktı: `OXware-Hypervisor-2.0.0-amd64.iso` — USB'ye yazıp sunucuya takarsanız **~15 dakikada** kurulum tamamlanır, OXware çalışır hâlde gelir.

### ISO oluşturma (Linux — Ubuntu 22.04)

```bash
# Gereksinimler
sudo apt update && sudo apt install -y xorriso squashfs-tools syslinux-utils genisoimage p7zip-full wget

# OXware repo klasörüne geçin
cd /path/to/OXware

# Script root yetkisiyle çalışır
sudo bash build-iso.sh
```

Script tamamlandığında:
```
╔══════════════════════════════════════════════════════════════╗
║           OXware Hypervisor ISO Hazır!                       ║
║  Dosya  : OXware-Hypervisor-2.0.0-amd64.iso                 ║
║  Boyut  : ~1.3 GB                                            ║
╚══════════════════════════════════════════════════════════════╝
```

### Windows'ta ISO oluşturabilir miyim?

`build-iso.sh` doğrudan Windows'ta çalışmaz — `xorriso`, `genisoimage`, `squashfs-tools` gibi Linux araçlarına ihtiyaç duyar. Ancak şu yöntemlerle Windows'ta da yapılabilir:

| Yöntem | Kurulum | Zorluk |
|--------|---------|--------|
| **WSL2 (önerilen)** | Microsoft Store → Ubuntu 22.04 → `sudo bash build-iso.sh` | Kolay |
| **VirtualBox / VMware** | Ubuntu 22.04 VM kur, repo'yu paylaşımlı klasörle aktar | Orta |
| **Docker (Linux container)** | `docker run --privileged -v $(pwd):/oxware ubuntu:22.04 bash build-iso.sh` | Orta |

**WSL2 kurulumu (hızlı başlangıç):**
```powershell
# PowerShell (yönetici)
wsl --install -d Ubuntu-22.04
```
```bash
# WSL Ubuntu terminalinde
cd /mnt/c/Users/<kullanici>/Desktop/ada/proje/AdaOS
sudo bash build-iso.sh
```

> **Not:** WSL2'de `xorriso` bazı durumlarda kısıtlıdır. Çalışmazsa VirtualBox VM tercih edin.

### ISO'yu USB'ye yazma

```bash
# Linux / WSL2
sudo dd if=OXware-Hypervisor-2.0.0-amd64.iso of=/dev/sdX bs=4M status=progress conv=fsync

# Windows — Rufus ile (grafik arayüz):
# Device: USB bellek
# Boot selection: OXware-Hypervisor-2.0.0-amd64.iso
# Partition scheme: GPT (UEFI) veya MBR (BIOS)
```

### Önyükleme

1. Sunucuyu USB'den başlatın.
2. GRUB menüsünde **"OXware Hypervisor — Otomatik Kur"** seçeneğini seçin.
3. Kurulum tamamen otomatik (~10-20 dakika). Dokunmanız gerekmez.
4. Sistem yeniden başladığında `https://<IP>:8006` üzerinden erişilebilir.

---

## 5. Script ile Kurulum (Mevcut Ubuntu)

Mevcut Ubuntu 22.04/24.04 LTS sunucusunda:

```bash
# SSH ile bağlanın
ssh oxware@<sunucu-ip>

# OXware dosyalarını kopyalayın (örnek: SCP ile)
scp -r /local/path/OXware oxware@<sunucu-ip>:~/OXware

# Kurulum scriptini çalıştırın
cd ~/OXware
sudo bash install.sh
```

### Kurulum adımları (otomatik):

| Adım | İşlem |
|------|-------|
| 1 | VT-x/AMD-V kontrolü (başarısız → kurulum durur) |
| 2 | Minimum RAM/disk kontrolü |
| 3 | Paket kurulumu: `qemu-kvm libvirt python3 novnc ufw fail2ban` |
| 4 | Python sanal ortam + bağımlılıklar |
| 5 | Self-signed SSL sertifika üretimi (10 yıl) |
| 6 | `/etc/oxware/oxware.conf` yapılandırma dosyası |
| 7 | `oxware.service` systemd servisi oluşturma |
| 8 | UFW güvenlik duvarı ayarları |
| 9 | fail2ban SSH koruması |
| 10 | Servis başlatma |

Kurulum başarıyla tamamlandığında:
```
════════════════════════════════════════════════════════════
  OXware Hypervisor kurulumu tamamlandı!
  Web arayüzü: https://<IP>:8006
  İlk kurulum için tarayıcıdan erişin.
════════════════════════════════════════════════════════════
```

### 2FA için gerekli Python paketleri

```bash
sudo /opt/oxware/venv/bin/pip install pyotp "qrcode[pil]"
```

---

## 6. İlk Giriş ve Parola Belirleme

Kurulumdan sonra ilk kez `https://<sunucu-ip>:8006` adresini açtığınızda **kurulum sihirbazı** açılır.

### İlk kurulum sayfası (`/setup`):

1. **Kullanıcı adı** belirleyin (örn: `admin`)
2. **Parola** girin (en az 8 karakter)
   - Parola gücü göstergesi yeşile dönünce devam edin
3. **Kurulumu Tamamla** düğmesine tıklayın
4. Otomatik olarak ana panele yönlendirilirsiniz

Kimlik bilgileri `/etc/oxware/.auth` dosyasına şifrelenmiş olarak kaydedilir.

### Rol Tabanlı Erişim

| Rol | Yetkiler |
|-----|---------|
| **admin** | Tüm özellikler (güvenlik, ayarlar dahil) |
| **operator** | VM yönetimi, ağ, depolama |
| **viewer** | Sadece izleme ve dashboard |

---

## 7. Web Arayüzüne Erişim

```
URL:      https://<sunucu-ip>:8006
Protokol: HTTPS (self-signed sertifika)
```

### Self-signed sertifika uyarısı

Tarayıcı "Bağlantı güvensiz" uyarısı verecektir. Bu normaldir.

- **Chrome/Edge:** "Gelişmiş" → "sunucu-ip adresine devam et"
- **Firefox:** "Gelişmiş" → "Riski kabul et ve devam et"

Üretim ortamı için Let's Encrypt sertifikası kullanmak isterseniz:
```bash
sudo apt install certbot
sudo certbot certonly --standalone -d yourdomain.com
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem /etc/oxware/ssl/oxware.crt
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem   /etc/oxware/ssl/oxware.key
sudo systemctl restart oxware
```

---

## 8. IP Havuzu Oluşturma

VM'lere otomatik IP atanabilmesi için en az bir IP havuzu tanımlanmalıdır.

### Web arayüzünden:

1. Sol menüden **"Ağ Yönetimi"** → **"IP Havuzları"** sekmesine gidin
2. **"IP Havuzu Ekle"** düğmesine tıklayın
3. Formu doldurun:

```
Havuz Adı:    main-pool
Ağ:           192.168.100.0/24
Gateway:      192.168.100.1
Başlangıç IP: 192.168.100.10
Bitiş IP:     192.168.100.100
```

### API ile:

```bash
curl -k -s -X POST https://localhost:8006/api/ippool \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name":     "main-pool",
    "network":  "192.168.100.0/24",
    "gateway":  "192.168.100.1",
    "start_ip": "192.168.100.10",
    "end_ip":   "192.168.100.100"
  }'
```

---

## 9. İlk VM Oluşturma

### ISO yükleme

1. **Depolama** → **"ISO Yükle"** düğmesine tıklayın
2. `.iso` dosyasını seçin (örn: `ubuntu-22.04-server.iso`)
3. Yükleme tamamlanana kadar bekleyin

### VM oluşturma

1. **Sanal Makineler** → **"VM Oluştur"** düğmesine tıklayın
2. Formu doldurun:

| Alan | Açıklama | Örnek |
|------|----------|-------|
| VM Adı | Benzersiz isim | `web-server-01` |
| ISO | Yüklenen ISO | `ubuntu-22.04-server.iso` |
| vCPU | İşlemci sayısı | `2` |
| RAM | MB cinsinden | `2048` |
| Disk | GB cinsinden | `20` |
| Ağ | libvirt ağı | `default` |

3. **Oluştur** → VM listesinde görünür
4. **▶ Başlat** ile VM'i çalıştırın
5. **🖥 Konsol** ile tarayıcı üzerinden erişin (noVNC)

### Otomatik VM Provisioning

IP havuzu tanımlıysa `POST /api/provision` ile tam otomatik:

```bash
curl -k -X POST https://localhost:8006/api/provision \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name":      "auto-vm-01",
    "memory_mb": 1024,
    "vcpus":     1,
    "disk_gb":   10,
    "pool_name": "main-pool"
  }'
# Yanıt: {"vm_id":"...", "ip":"192.168.100.10", "password":"Xk9..."}
```

---

## 10. VM Tipleri: VPS ve VDS

VM oluştururken **Tip** alanı iki seçenek sunar:

| Tip | CPU Modu | Açıklama |
|-----|---------|----------|
| **VPS — Paylaşımlı** | `host-model` | CPU'yu sanallaştırılmış model üzerinden paylaşır. Çoğu iş yükü için uygundur. |
| **VDS — Özel (Dedicated)** | `host-passthrough` | Fiziksel CPU'yu doğrudan VM'e geçirir. Maksimum performans, iç içe sanallaştırma ve CPU feature'larına tam erişim. |

### Disk Bus Tipi

| Bus | Kullanım |
|-----|---------|
| **SATA** (önerilen) | Windows ve Linux kurulumlarında disk görünür — her zaman güvenli seçim |
| **VirtIO** | Yalnızca Linux için; en yüksek I/O performansı; Windows'ta sürücü olmadan kurulum sırasında disk görünmez |
| **IDE** | Eski işletim sistemleri (WinXP, Win7 vs.) için maksimum uyumluluk |

> **Windows kuruyorsanız:** Bus tipi mutlaka **SATA** olsun. VirtIO seçilirse kurulum sırasında "disk bulunamadı" hatası alırsınız.

---

## 11. AI Ajan Kurulumu

OXware, birden fazla AI sağlayıcısıyla entegre sistem izleme yapabilir.

### OpenRouter (önerilen — çok model desteği)

```bash
sudo nano /etc/oxware/ai_agents.conf
```

```json
{
  "agents": [
    {
      "agent_id":         "main-agent",
      "name":             "OXware AI İzleyici",
      "provider":         "openrouter",
      "api_key":          "sk-or-v1-XXXXXXXXXX",
      "model":            "anthropic/claude-3-haiku",
      "interval_minutes": 15,
      "tasks":            ["monitor", "events"],
      "alert_thresholds": {
        "cpu_percent":    85,
        "memory_percent": 90
      }
    }
  ]
}
```

### Anthropic Claude (direkt)

```json
{
  "provider": "anthropic",
  "api_key":  "sk-ant-XXXXXXXXXX",
  "model":    "claude-haiku-4-5-20251001"
}
```

### Ollama (yerel, ücretsiz)

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3
```

```json
{
  "provider":  "ollama",
  "api_key":   "",
  "model":     "llama3",
  "base_url":  "http://localhost:11434"
}
```

```bash
sudo systemctl restart oxware
```

---

## 12. Telegram ve Discord Bildirimleri

### Telegram Bot kurulumu

1. Telegram'da `@BotFather`'a mesaj atın
2. `/newbot` → bot adı ve kullanıcı adı belirleyin
3. API token'ınızı kopyalayın: `123456789:AAF...`
4. Bot'a `/start` göndererek Chat ID'yi alın:
   ```bash
   curl "https://api.telegram.org/bot<TOKEN>/getUpdates"
   # "chat":{"id":123456789}
   ```

### Discord Webhook kurulumu

1. Discord sunucunuzda bir kanal açın
2. Kanal Ayarları → Entegrasyonlar → **Webhook Oluştur**
3. Webhook URL'sini kopyalayın

### Konfigürasyon

```bash
sudo nano /etc/oxware/notifications.conf
```

```ini
TELEGRAM_TOKEN=123456789:AAFxxxxxxxxxxxxxxx
TELEGRAM_CHAT_ID=123456789
DISCORD_WEBHOOK=https://discord.com/api/webhooks/xxx/yyy
MIN_LEVEL=WARNING
```

```bash
sudo systemctl restart oxware
```

---

## 13. 2FA (İki Faktörlü Doğrulama)

OXware, TOTP tabanlı (Google Authenticator, Authy vb.) 2FA destekler.

### Gereksinim

```bash
sudo /opt/oxware/venv/bin/pip install pyotp "qrcode[pil]"
```

### Kurulum

1. **Güvenlik** → **"2FA Yönetimi"** bölümüne gidin
2. **"2FA Kur"** düğmesine tıklayın — QR kod veya secret gösterilir
3. Authenticator uygulamanızda QR kodu tarayın
4. Uygulama gösterdiği 6 haneli kodu **"Etkinleştir"** alanına girin
5. Onaylandıktan sonra her girişte kod istenir

### Sorun Giderme — "Kod Geçersiz"

En yaygın neden: **sunucu saati ile telefon saati uyumsuz.**

```bash
# Sunucu saatini kontrol et
date && timedatectl status

# Saat yanlışsa düzelt
timedatectl set-ntp false
date -s "YYYY-MM-DD HH:MM:SS"   # gerçek saat
hwclock --systohc
timedatectl set-ntp true
```

> OXware, ±90 saniyelik saat toleransıyla çalışır. Fark bundan fazlaysa kod geçersiz görünür.

---

## 14. Güvenlik Denetimi

**Güvenlik** sayfasındaki **"Güvenlik Denetimi"** kartı sistemi otomatik tarar.

### Kontrol edilen alanlar

| Kontrol | Açıklama |
|---------|---------|
| **br_netfilter** | VM güvenlik duvarı kuralları için kernel modülü |
| **IOMMU / VT-d** | PCI passthrough izolasyonu |
| **Kernel Sysctl** | rp_filter, tcp_syncookies, redirect engelleme vb. |
| **SSH Sertleştirme** | MaxAuthTries, X11Forwarding, LoginGraceTime vb. |
| **QEMU Seccomp** | VM sandbox izolasyonu |
| **Güvenlik Duvarı** | UFW / iptables aktifliği |
| **Açık Portlar** | VNC (5900-5999), Docker (2375) riski |
| **Varsayılan Şifre** | Şifrenin değiştirilip değiştirilmediği |
| **KSM (Kernel Samepage Merging)** | VM bellek yalıtımı — KSM kapalı olmalı |
| **L2 İzolasyon** | VM'ler arası bridge trafiği filtreleme |
| **İç içe sanallaştırma** | Üretimde gereksizse kapalı tutulmalı |
| **VM aygıtları** | Tehlikeli cihaz atamaları (tablet, balloon vb.) |
| **SSL sertifika** | Sertifika süresi kontrolü (30 gün uyarı) |
| **CVE taraması** | NVD API üzerinden QEMU/KVM son 90 gün CVE'leri |

### Puan sistemi

- **Pass** = 100 puan, **Warn** = 50 puan, **Fail** = 0 puan
- Genel skor: `(pass×100 + warn×50) / toplam`
- Yeşil ≥75, Sarı ≥50, Kırmızı <50

### Otomatik düzeltme

`br_netfilter` ve `sysctl` kontrolleri için arayüzden **"Otomatik Düzelt"** butonuna tıklanabilir:

```bash
# Manuel eşdeğeri:
modprobe br_netfilter
echo 'br_netfilter' >> /etc/modules-load.d/oxware.conf

sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
```

### Account Lockout (Brute-force Koruması)

5 başarısız giriş denemesi → hesap **5 dakika** kilitlenir.

```bash
# API ile kilitli hesapları görüntüle
curl -k -H "Authorization: Bearer <TOKEN>" \
  https://localhost:8006/api/security/lockouts

# Belirli bir hesabı manuel aç
curl -k -X DELETE -H "Authorization: Bearer <TOKEN>" \
  https://localhost:8006/api/security/lockouts/<username>
```

---

## 15. Otomatik Snapshot ve Yedekleme Diski

Her gün belirlenen saatte tüm VM'lerin snapshot'ını otomatik alır, eski snapshot'ları temizler.

### Yapılandırma (Web arayüzü)

**Güvenlik** sayfası → **"Otomatik Snapshot"** kartı:

| Alan | Varsayılan | Açıklama |
|------|-----------|---------|
| Aktif | Evet | Zamanlayıcıyı aç/kapat |
| Saat | 2 | Snapshot alınacak saat (0-23) |
| Dakika | 0 | Snapshot alınacak dakika |
| Saklama (gün) | 7 | Bu günden eskiler otomatik silinir |

### API ile

```bash
# Konfigürasyonu güncelle
curl -k -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  https://localhost:8006/api/auto-snapshot/config \
  -d '{"enabled": true, "hour": 3, "minute": 0, "keep_days": 14}'

# Manuel tetikle
curl -k -X POST -H "Authorization: Bearer <TOKEN>" \
  https://localhost:8006/api/auto-snapshot/run
```

Snapshot adlandırma: `oxw-autosnap-<VM_ADI>-YYYYMMDD-HHMMSS`

### Yedekleme Diski

Bir VM'e özel yedekleme diski bağlamak için:

1. **Yedekleme** → **"Yedekleme Diski"** bölümüne gidin
2. VM, etiket, boyut (GB) ve bus tipi seçin
3. **"+ Oluştur ve Bağla"** — disk oluşturulur ve VM'e canlı bağlanır
4. Tablo satırından **"✕ Sil"** ile disk + dosya birlikte kaldırılır

```bash
# API ile
curl -k -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  https://localhost:8006/api/backup/disks \
  -d '{"vm_id": "vm-01", "label": "backup", "size_gb": 100, "bus": "sata"}'
```

---

## 16. Otomatik Güncelleme Kontrolü

OXware her saat başı GitHub'dan yeni commit'leri kontrol eder ve AI analizi yapar.

### GitHub Repo Ayarı

**Güncellemeler** sayfasında repo URL ve branch girin:
```
https://github.com/ShinnAsukha/oxware-hypervisor
```

> **Not:** GitHub API SSL sertifika doğrulaması gerektirir. Sunucu saati yanlışsa bağlantı başarısız olur. Bkz. [NTP / Saat Senkronizasyonu](#3-ubuntu-sunucu-hazırlığı).

### AI Analizi

AI ajan yapılandırıldıysa yeni commit'ler Türkçe olarak özetlenir:
- Güvenlik kritik değişiklikler uyarı olarak işaretlenir
- Olay günlüğüne kaydedilir

### Manuel kontrol

```bash
curl -k -X POST -H "Authorization: Bearer <TOKEN>" \
  https://localhost:8006/api/update/check

# Son kontrol sonucunu al
curl -k -H "Authorization: Bearer <TOKEN>" \
  https://localhost:8006/api/update/last
```

---

## 17. Parola Sıfırlama

### Web arayüzünden (token ile)

1. **Güvenlik** → **"Şifre Sıfırlama"** kartına gidin
2. Kullanıcı adını girin → **"Token Oluştur"**
3. SMTP yapılandırıldıysa e-posta gönderilir; yoksa token ekranda gösterilir
4. Token ve yeni parolayı girerek sıfırlayın (token 1 saat geçerli)

### SSH ile (terminal)

```bash
ssh oxware@<sunucu-ip>
sudo nano /etc/oxware/.passwd_reset
```

Dosya içeriği:
```
USERNAME=yeni_kullanici
PASSWORD=YeniGucluParola123!
```

```bash
sudo systemctl restart oxware
# Servis başlarken reset dosyasını okur ve otomatik siler
```

---

## 18. Güvenlik Duvarı ve Portlar

| Port | Protokol | Amaç |
|------|----------|------|
| **22** | TCP | SSH yönetim erişimi |
| **8006** | TCP (HTTPS) | OXware web arayüzü |
| **5900–5999** | TCP | VM VNC konsolları |
| **6080** | TCP | noVNC WebSocket proxy |

### UFW durum kontrolü

```bash
sudo ufw status verbose
```

### Belirli bir IP'ye kısıtlama (önerilir)

```bash
sudo ufw delete allow 8006/tcp
sudo ufw allow from 203.0.113.10 to any port 8006 proto tcp
sudo ufw reload
```

### fail2ban durumu

```bash
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

---

## 19. Aktif Oturum Yönetimi (JWT Sessions)

OXware her girişte JWT token oluşturur ve sunucu tarafında takip eder.

### Web arayüzünden

**Güvenlik** sekmesi → **"Aktif Oturumlar"** kartı:
- Oturum sahibi, IP adresi, User-Agent ve ne kadar önce oluşturulduğu görünür
- **✕ İptal** butonu ile şüpheli oturumu anında sonlandırın

### API ile

```bash
# Tüm aktif oturumları listele
curl -k -H "Authorization: Bearer <TOKEN>" \
  https://localhost:8006/api/sessions

# Belirli oturumu iptal et (session_id = jti'nin ilk 8 karakteri)
curl -k -X DELETE -H "Authorization: Bearer <TOKEN>" \
  https://localhost:8006/api/sessions/<session_id>
```

- Token süresi **12 saattir**; süresi dolmuş oturumlar 13 saatte bellekten temizlenir.
- `revoked: true` oturumun tokenı geçersiz sayılır, yeniden giriş gerekir.

---

## 20. IP Erişim Kısıtlaması (Allowlist)

API ve web arayüzüne yalnızca belirli IP adreslerinden erişimi kısıtlayabilirsiniz.

### Web arayüzünden

**Güvenlik** sekmesi → **"IP Erişim Kısıtlaması"** kartı:

1. **Aktif** kutucuğunu işaretleyin
2. İzin verilecek IP'leri ekleyin (kendi IP'nizi mutlaka ekleyin!)
3. **Kaydet** butonuna tıklayın

> ⚠️ **Dikkat:** Kendi IP'nizi eklemeden kaydetirseniz kendinizi de kilitlersiniz. Çözmek için SSH ile bağlanıp `/var/lib/oxware/ip_allowlist.json` dosyasını silin veya `"enabled": false` yapın.

### API ile

```bash
# Mevcut listeyi görüntüle
curl -k -H "Authorization: Bearer <TOKEN>" \
  https://localhost:8006/api/settings/ip-allowlist

# Güncelle
curl -k -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  https://localhost:8006/api/settings/ip-allowlist \
  -d '{"enabled": true, "allowed_ips": ["203.0.113.10", "192.168.1.0/24"]}'
```

### Kilitlenme durumunda kurtarma

```bash
# SSH ile sunucuya bağlanın
sudo rm /var/lib/oxware/ip_allowlist.json
sudo systemctl restart oxware
```

---

## 21. VM Zamanlaması

VM'leri belirli saat ve günlerde otomatik olarak başlatın, durdurun veya yeniden başlatın.

### Web arayüzünden

**Ayarlar** sekmesi → **"VM Zamanlaması"** kartı → **"Yeni"** butonu:

| Alan | Açıklama |
|------|---------|
| VM | Zamanlanacak sanal makine |
| İşlem | Başlat / Kapat / Yeniden Başlat / Snapshot |
| Saat / Dakika | Çalışma saati (24 saat formatı) |
| Günler | Boş bırakılırsa her gün; seçilirse yalnızca o günler |

### API ile

```bash
# Zamanlamaları listele
curl -k -H "Authorization: Bearer <TOKEN>" \
  https://localhost:8006/api/vm-schedules

# Yeni zamanlama ekle (her gün 02:00'da vm-01'i kapat)
curl -k -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  https://localhost:8006/api/vm-schedules \
  -d '{"vm_id": "vm-01", "vm_name": "web-server", "action": "shutdown", "hour": 2, "minute": 0}'

# Zamanlama sil
curl -k -X DELETE -H "Authorization: Bearer <TOKEN>" \
  https://localhost:8006/api/vm-schedules/<sched_id>
```

Zamanlama kayıtları `/var/lib/oxware/vm_schedules.json` dosyasında saklanır.

---

## 22. VM Klonlama ve Toplu İşlemler

### VM Klonlama

Mevcut bir VM'in tam kopyasını oluşturun:

```bash
curl -k -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  https://localhost:8006/api/vms/<vm_id>/clone \
  -d '{"new_name": "web-server-clone"}'
```

Veya **Sanal Makineler** sayfasından VM detayına gidin → **"Klonla"** butonu.

### Toplu İşlemler

Birden fazla VM'i tek seferde yönetin:

```bash
# Birden fazla VM'i başlat
curl -k -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  https://localhost:8006/api/vms/bulk \
  -d '{"vm_ids": ["vm-01", "vm-02", "vm-03"], "action": "start"}'

# Desteklenen işlemler: start | stop | reboot | snapshot
```

---

## 23. Prometheus Metrikleri

OXware `/metrics` endpoint'i üzerinden Prometheus formatında metrik sunar.

### Endpoint

```
GET https://<sunucu>:8006/metrics
Authorization: Bearer <TOKEN>
```

### Örnek çıktı

```
# HELP oxware_vms_total Toplam VM sayısı
oxware_vms_total 5
oxware_vms_running 3
oxware_vms_stopped 2

# HELP oxware_host_cpu_percent CPU kullanımı (%)
oxware_host_cpu_percent 34.2
oxware_host_ram_total_mb 32768
oxware_host_ram_used_mb 12420

# HELP oxware_vm_cpu_percent VM başına CPU kullanımı
oxware_vm_cpu_percent{vm_id="vm-01",vm_name="web-server"} 12.4
```

### Prometheus scrape config

```yaml
scrape_configs:
  - job_name: 'oxware'
    scheme: https
    tls_config:
      insecure_skip_verify: true
    bearer_token: '<TOKEN>'
    static_configs:
      - targets: ['<sunucu-ip>:8006']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

---

## 24. PWA (Masaüstü / Mobil Uygulama)

OXware, Progressive Web App (PWA) olarak masaüstüne veya telefona eklenebilir.

### Chrome / Edge (Masaüstü)

1. `https://<sunucu-ip>:8006` adresini açın
2. Adres çubuğundaki **⊞ (Yükle)** simgesine tıklayın
3. **"OXware Hypervisor Yükle"** → uygulama gibi çalışır

### Android / iOS (Mobil)

- **Android Chrome:** ⋮ menüsü → "Ana ekrana ekle"
- **iOS Safari:** Paylaş → "Ana Ekrana Ekle"

---

## 25. Domain Bağlama (Nginx + Let's Encrypt)

OXware varsayılan olarak `https://<IP>:8006` adresinde çalışır. Özel domain ve ücretsiz SSL sertifikası için iki yöntem var.

### Ön koşul — DNS kaydı

Domain DNS panelinden A kaydı ekle:
```
A  oxware.domain.com  →  <sunucu-IP>
```
Yayılmasını bekle (1-10 dakika). Kontrol:
```bash
dig oxware.domain.com +short
# Sunucu IP'si çıkmalı
```

---

### Yöntem 1 — Nginx Reverse Proxy (önerilen)

Nginx önde durur, `oxware.domain.com:443` → `https://localhost:8006` yönlendirir. noVNC WebSocket desteği dahil.

```bash
# Nginx + Certbot kur
apt install -y nginx certbot python3-certbot-nginx

# Site yapılandırması oluştur
cat > /etc/nginx/sites-available/oxware << 'EOF'
server {
    listen 80;
    server_name oxware.domain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name oxware.domain.com;

    ssl_certificate     /etc/letsencrypt/live/oxware.domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/oxware.domain.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # WebSocket desteği (noVNC konsol için şart)
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 86400;

    location / {
        proxy_pass https://127.0.0.1:8006;
        proxy_ssl_verify off;
    }
}
EOF

# Etkinleştir ve test et
ln -s /etc/nginx/sites-available/oxware /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# Let's Encrypt sertifikası al (port 80 dışarıdan açık olmalı)
certbot --nginx -d oxware.domain.com --non-interactive --agree-tos -m admin@domain.com

systemctl reload nginx
```

Tarayıcıda `https://oxware.domain.com` — kilit simgesi, uyarı yok.

**Sertifika otomatik yenileme** (90 günde bir):
```bash
# Cron'a ekle (zaten certbot kurulumda ekler, kontrol et)
crontab -l | grep certbot
# Yoksa:
echo "0 3 * * * certbot renew --quiet && systemctl reload nginx" >> /etc/crontab
```

**UFW'de port 80 ve 443 aç:**
```bash
ufw allow 80/tcp
ufw allow 443/tcp
ufw reload
```

---

### Yöntem 2 — OXware'e Direkt Let's Encrypt (Nginx yok)

Web arayüzü: **Ayarlar → SSL Sertifika Yönetimi → Let's Encrypt** alanını doldur → "Sertifika Al".

Veya API:
```bash
curl -k -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  https://localhost:8006/api/ssl/letsencrypt \
  -d '{"domain": "oxware.domain.com", "email": "admin@domain.com"}'
```

OXware 8006 portunu doğrudan kullanmaya devam eder, sertifikası artık Let's Encrypt olur.
Erişim: `https://oxware.domain.com:8006`

> Port 8006 → 443'e taşımak istersen `/etc/oxware/oxware.conf` içinde `port = 443` yap, UFW'den 443 aç.

---

### Yöntem karşılaştırması

| | Nginx (Yöntem 1) | Direkt (Yöntem 2) |
|--|--|--|
| URL | `https://oxware.domain.com` | `https://oxware.domain.com:8006` |
| Port | 443 (standart) | 8006 |
| WebSocket | ✓ Nginx yapılandırılmış | ✓ Direkt |
| Ek servis | Nginx gerekli | Gerekmez |
| Önerilir | ✓ Üretim | Hızlı kurulum |

---

## 26. İnternet Bağlantısı Gereksinimleri

OXware'in temel işlevleri tamamen **lokal ağda** çalışır. İnternet yalnızca belirli ek özellikler için gerekir.

### İnternet gerektirmeyen özellikler

| Özellik | Açıklama |
|---------|---------|
| VM oluştur / başlat / durdur / sil | Tüm libvirt işlemleri lokal |
| noVNC konsol | Tarayıcı → sunucu, dış bağlantı yok |
| Ağ yönetimi | libvirt ağları, bridge, NAT |
| Depolama yönetimi | Lokal disk/havuz işlemleri |
| ISO yükleme | Sunucuya direkt yükleme |
| Güvenlik denetimi (lokal kontroller) | sysctl, SSH, UFW, KSM vb. |
| 2FA (TOTP) | Lokal hesaplama, dış sunucu yok |
| Web arayüzü | Sunucu ↔ tarayıcı, lokal |
| Prometheus metrikleri | Lokal `/metrics` endpoint |
| Oturum yönetimi / IP allowlist | Lokal bellek |
| VM zamanlama / klonlama | Lokal libvirt |

### İnternet gerektiren özellikler

| Özellik | Neden | Devre dışı kalırsa |
|---------|-------|-------------------|
| **AI analiz (OXY)** | OpenRouter / Anthropic / Ollama API | Chat yanıt vermez |
| **Telegram / Discord bildirimleri** | Dış webhook/API | Bildirim gönderilmez |
| **CVE taraması** | NVD API (`services.nvd.nist.gov`) | Güvenlik puanından düşmez, uyarı çıkar |
| **GitHub güncelleme kontrolü** | GitHub API | "Kontrol edilemedi" gösterir |
| **Let's Encrypt sertifikası** | Certbot ACME doğrulaması | Self-signed sertifika kullanılır |
| **`apt install` / `pip install`** | Paket sunucuları | Kurulum/güncelleme yapılamaz |

### Kapalı ağ (air-gap) kurulum

Ofis içi LAN veya internetsiz ortamda OXware çalışır. Kurulum öncesi paketleri indirip aktarmak gerekir:

```bash
# İnternete erişimi olan makinede paketleri indir
apt-get download qemu-kvm libvirt-daemon-system python3-pip ...
pip download -r requirements.txt -d /tmp/pip-packages/

# Sunucuya kopyala (USB veya SCP)
scp -r /tmp/pip-packages/ oxware@<sunucu>:~/

# Sunucuda offline kur
pip install --no-index --find-links=~/pip-packages/ -r requirements.txt
```

Ollama ile lokal AI modeli kurulursa OXY da internetsiz çalışır:
```bash
# Ollama kur (kurulum sırasında internet gerekir, sonra offline çalışır)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3
# AI Ajanlar sayfasında provider: ollama seç
```

---

## 27. Sorun Giderme

### ⚡ Hızlı Onarım — repair.sh

Yeniden başlatma sonrası SSH kesilmesi, ağ sorunları, servis başlamıyorsa:

```bash
# Web konsol veya fiziksel erişimden:
cd /opt/oxware-src   # veya OXware klasörünüz
sudo bash repair.sh
```

`repair.sh` tek komutla şunları düzeltir:
- SSH servisi ve yapılandırması (`PermitRootLogin yes`)
- Hostname sıfırlanması (cloud-init)
- UFW / iptables-legacy çakışması
- KVM modülleri ve libvirt ağı
- OXware systemd servisi

---

### Yeniden başlatma sonrası SSH bağlanamıyorum

```bash
# Web konsol veya fiziksel terminalde:
systemctl restart ssh

# sshd_config kontrol:
grep "PermitRootLogin\|PasswordAuth" /etc/ssh/sshd_config

# UFW 22. portu kapalıysa:
ufw allow 22/tcp
ufw reload

# SSH dinliyor mu?
ss -tlnp | grep ':22'
```

### Yeniden başlatma sonrası hostname "localhost" oluyor

```bash
# Hostname kalıcı yap
hostnamectl set-hostname oxware-server

# cloud-init sıfırlamasını engelle
echo 'preserve_hostname: true' > /etc/cloud/cloud.cfg.d/99_hostname.cfg
echo 'manage_etc_hosts: false' >> /etc/cloud/cloud.cfg.d/99_hostname.cfg
```

### Yeniden başlatma sonrası UFW başlamıyor (FAILED)

Ubuntu 20.04+ nftables kullanır; UFW iptables bekler:

```bash
# iptables-legacy geçişi
update-alternatives --set iptables  /usr/sbin/iptables-legacy
update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

# UFW yeniden kur
ufw --force reset
ufw allow 22/tcp
ufw allow 8006/tcp
ufw --force enable
systemctl enable ufw
```

### Yeniden başlatma sonrası libvirt ağı başlamıyor

```bash
virsh net-autostart default
virsh net-start default
systemctl enable --now libvirtd
```

---

### Servis çalışmıyor

```bash
sudo systemctl status oxware
sudo journalctl -u oxware -n 50 --no-pager
```

### Logları inceleyin

```bash
tail -f /var/log/oxware/oxware.log      # Uygulama logu
tail -f /var/log/oxware/security.log    # Güvenlik/denetim logu
tail -f /var/log/oxware/events.jsonl    # Olay günlüğü
tail -f /var/log/oxware/ai_agent.jsonl  # AI ajan logu
tail -f /var/log/oxware/updates.jsonl   # Güncelleme logu
```

### libvirt bağlantı hatası

```bash
sudo systemctl status libvirtd
sudo systemctl restart libvirtd
sudo usermod -aG libvirt oxware
```

### noVNC konsol açılmıyor

```bash
sudo systemctl status novnc
sudo ss -tlnp | grep 6080
```

### SSL sertifikası yenileme

```bash
sudo openssl req -x509 -nodes -days 3650 \
  -newkey rsa:2048 \
  -keyout /etc/oxware/ssl/oxware.key \
  -out    /etc/oxware/ssl/oxware.crt \
  -subj   "/CN=$(hostname -I | awk '{print $1}')"
sudo systemctl restart oxware
```

### Sanallaştırma aktif değil

```bash
grep -c vmx /proc/cpuinfo  # Intel: 0 → VT-x kapalı
grep -c svm /proc/cpuinfo  # AMD: 0 → AMD-V kapalı

lsmod | grep kvm
# Çıktı yoksa:
sudo modprobe kvm-intel   # veya kvm-amd
```

### GitHub / SSL bağlantı hatası

```
curl: (60) SSL certificate problem: certificate is not yet valid
```

Sunucu saati yanlış demektir:
```bash
date -s "YYYY-MM-DD HH:MM:SS"   # gerçek tarihi gir
hwclock --systohc
timedatectl set-ntp true
```

### 2FA — "Kod Geçersiz"

1. Sunucu saatini kontrol et (yukarıdaki adım)
2. pyotp kurulu mu kontrol et: `python3 -c "import pyotp; print('ok')"`
3. Kurulu değilse: `pip install pyotp "qrcode[pil]"`
4. QR kodu ilk taramadan sonra tekrar "2FA Kur" tıklandıysa sorun yok — mevcut QR hâlâ geçerli (secret yeniden üretilmez)

### Token süresi doldu

JWT token 12 saat geçerlidir. Tekrar giriş yapın; token localStorage'e otomatik kaydedilir.

---

## Servis Yönetimi

```bash
sudo systemctl start   oxware   # Başlat
sudo systemctl stop    oxware   # Durdur
sudo systemctl restart oxware   # Yeniden başlat
sudo systemctl enable  oxware   # Önyükleme ile başlat
sudo systemctl disable oxware   # Önyükleme ile başlatma
sudo systemctl status  oxware   # Durum
sudo journalctl -u oxware -f    # Canlı log
```

---

## Güncelleme

```bash
cd /path/to/OXware
git pull

sudo /opt/oxware/venv/bin/pip install -r oxware/backend/requirements.txt --upgrade

sudo systemctl restart oxware
```

Veya web arayüzünden: **Güncellemeler → Şimdi Kontrol Et**

---

## 28. AdaOS → OXware Canlı Sunucu Geçişi

> Bu bölüm, halihazırda **AdaOS** kurulu çalışan bir üretim sunucusunu  
> **OXware**'e geçirmek için adım adım kılavuzdur.  
> İşlem boyunca VM'ler **çalışmaya devam eder**; yalnızca yönetim servisi kısa süre kapanır.

### Gereksinimler

```bash
sudo systemctl status adaos
cat /etc/adaos/adaos.conf | head -5
```

### Adım 1 — Yedek Alın

```bash
sudo cp -r /etc/adaos /root/adaos-backup-$(date +%Y%m%d)
sudo cp /var/lib/adaos/users.json /root/users-backup-$(date +%Y%m%d).json 2>/dev/null || true
sudo cp /var/log/adaos/adaos.log /root/adaos-$(date +%Y%m%d).log 2>/dev/null || true
echo "✓ Yedek tamamlandı"
```

### Adım 2 — OXware Dosyalarını Sunucuya Kopyalayın

```bash
# SCP ile
scp -r /local/path/OXware root@<sunucu-ip>:~/OXware

# Ya da git ile
git clone https://github.com/ShinnAsukha/oxware-hypervisor.git OXware
cd OXware
```

### Adım 3 — Servisi Durdurun

```bash
sudo systemctl stop adaos
sudo systemctl disable adaos
echo "✓ AdaOS servisi durduruldu"
```

### Adım 4 — Dizinleri Taşıyın

```bash
sudo cp -r /opt/adaos /opt/oxware
sudo mkdir -p /etc/oxware/ssl
sudo cp /etc/adaos/adaos.conf    /etc/oxware/oxware.conf 2>/dev/null || true
sudo cp /etc/adaos/ssl/*         /etc/oxware/ssl/        2>/dev/null || true
sudo cp /etc/adaos/.auth         /etc/oxware/.auth       2>/dev/null || true
sudo cp /etc/adaos/.setup_done   /etc/oxware/.setup_done 2>/dev/null || true
sudo cp /etc/adaos/ai_agents.conf     /etc/oxware/ai_agents.conf     2>/dev/null || true
sudo cp /etc/adaos/notifications.conf /etc/oxware/notifications.conf 2>/dev/null || true
sudo cp /etc/adaos/update.conf        /etc/oxware/update.conf        2>/dev/null || true
sudo chmod 600 /etc/oxware/.auth /etc/oxware/ssl/* /etc/oxware/oxware.conf 2>/dev/null || true
sudo cp -r /var/lib/adaos /var/lib/oxware
sudo mkdir -p /var/log/oxware
sudo cp /var/log/adaos/*.log   /var/log/oxware/ 2>/dev/null || true
sudo cp /var/log/adaos/*.jsonl /var/log/oxware/ 2>/dev/null || true
echo "✓ Dizinler taşındı"
```

### Adım 5 — oxware.conf Yollarını Düzeltin

```bash
sudo sed -i 's|/etc/adaos|/etc/oxware|g; s|/var/lib/adaos|/var/lib/oxware|g; s|/var/log/adaos|/var/log/oxware|g; s|adaos\.crt|oxware.crt|g; s|adaos\.key|oxware.key|g' /etc/oxware/oxware.conf
sudo mv /etc/oxware/ssl/adaos.crt /etc/oxware/ssl/oxware.crt 2>/dev/null || true
sudo mv /etc/oxware/ssl/adaos.key /etc/oxware/ssl/oxware.key 2>/dev/null || true
```

### Adım 6 — Yeni OXware Dosyalarını Kopyalayın

```bash
cd ~/OXware
sudo cp -r oxware/backend/* /opt/oxware/backend/
sudo cp -r oxware/frontend/* /opt/oxware/frontend/
echo "✓ Kaynak dosyaları güncellendi"
```

### Adım 7 — Python Ortamını Güncelleyin

```bash
sudo /opt/oxware/venv/bin/pip install \
  -r /opt/oxware/backend/requirements.txt \
  --upgrade -q
sudo /opt/oxware/venv/bin/pip install pyotp "qrcode[pil]"
echo "✓ Python bağımlılıkları güncellendi"
```

### Adım 8 — Yeni Systemd Servisi Kur

```bash
sudo rm -f /etc/systemd/system/adaos.service
sudo cp ~/OXware/oxware/oxware-hypervisor.service /etc/systemd/system/oxware.service
sudo systemctl daemon-reload
sudo systemctl enable oxware
sudo systemctl start oxware
sleep 3
sudo systemctl status oxware
```

### Adım 9 — Fail2ban Konfigürasyonunu Güncelleyin

```bash
sudo sed -i 's|adaos|oxware|g; s|/var/log/adaos|/var/log/oxware|g' \
    /etc/fail2ban/jail.d/adaos.conf 2>/dev/null || true
sudo mv /etc/fail2ban/jail.d/adaos.conf    /etc/fail2ban/jail.d/oxware.conf    2>/dev/null || true
sudo mv /etc/fail2ban/filter.d/adaos-web.conf /etc/fail2ban/filter.d/oxware-web.conf 2>/dev/null || true
sudo systemctl reload fail2ban 2>/dev/null || true
```

### Adım 10 — UFW Kurallarını Güncelleyin

```bash
sudo ufw status numbered
# 8006 zaten açıksa ek işlem gerekmez
sudo ufw allow 8006/tcp comment "OXware Web UI"
sudo ufw reload
```

### Adım 11 — Doğrulama

```bash
sudo systemctl status oxware
sudo journalctl -u oxware -n 20 --no-pager
curl -k -s -o /dev/null -w "%{http_code}" https://localhost:8006/
# 200 veya 302 çıkmalı
echo "Web: https://$(hostname -I | awk '{print $1}'):8006"
```

### Adım 12 — Eski Dizinleri Temizleyin

```bash
sudo rm -rf /opt/adaos /etc/adaos
# /var/lib/adaos ve /var/log/adaos'u bir süre saklayın
# Hazır olduğunuzda:
# sudo rm -rf /var/lib/adaos /var/log/adaos
echo "✓ Geçiş tamamlandı."
```

### Geçiş Özeti

| Eski Yol | Yeni Yol |
|----------|----------|
| `/opt/adaos` | `/opt/oxware` |
| `/etc/adaos/adaos.conf` | `/etc/oxware/oxware.conf` |
| `/etc/adaos/.auth` | `/etc/oxware/.auth` |
| `/etc/adaos/ssl/adaos.crt` | `/etc/oxware/ssl/oxware.crt` |
| `/var/lib/adaos` | `/var/lib/oxware` |
| `/var/log/adaos` | `/var/log/oxware` |
| `systemctl ... adaos` | `systemctl ... oxware` |

---

## 29. VM Lifecycle Hook Scripts

VM başlatma, durdurma ve silme olaylarında otomatik bash scriptleri çalıştırın.

### Hook dizin yapısı

```
/etc/oxware/hooks/
├── pre-start/      # VM başlatılmadan önce
├── post-start/     # VM başlatıldıktan sonra
├── pre-stop/       # VM durdurulmadan önce
├── post-stop/      # VM durdurulduktan sonra
├── pre-delete/     # VM silinmeden önce
└── post-delete/    # VM silindikten sonra
```

Her dizindeki `.sh` dosyaları alfabetik sırayla çalıştırılır. Scriptler şu ortam değişkenlerini alır:

| Değişken | Açıklama |
|----------|----------|
| `VM_ID` | Libvirt VM ID'si |
| `VM_NAME` | VM adı |
| `VM_STATE` | Olay adı (ör. `pre-start`) |

Zaman aşımı: 30 saniye. Çıktılar: `/var/log/oxware/hooks.log`

### Örnek hook scripti

```bash
#!/bin/bash
# /etc/oxware/hooks/post-start/10-notify.sh
curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
  -d "chat_id=$CHAT_ID&text=VM $VM_NAME ($VM_ID) başlatıldı."
```

### API

```bash
# Hook listesi
GET /api/hooks

# Script içeriğini getir
GET /api/hooks/<event>/<name>

# Script kaydet / güncelle
PUT /api/hooks/<event>/<name>
Body: {"content": "#!/bin/bash\n..."}

# Script sil
DELETE /api/hooks/<event>/<name>

# Hook'ları manuel tetikle
POST /api/hooks/run
Body: {"event": "pre-start", "vm_id": "vm-123", "vm_name": "webserver"}
```

Web arayüzde: **Entegrasyonlar → Hook Script Yönetimi**

---

## 30. LDAP / Active Directory Girişi

OXware, şirket LDAP veya Active Directory sunucunuzla entegre olarak mevcut kullanıcıları kimlik doğrulayabilir.

### Yapılandırma (Web UI)

**Güvenlik sekmesi → LDAP Yapılandırması** bölümünden:

| Alan | Örnek |
|------|-------|
| LDAP Sunucu | `ldap://192.168.1.10:389` |
| Bind DN | `CN=oxware,OU=Service,DC=firma,DC=com` |
| Bind Parola | `••••••••` |
| Base DN | `DC=firma,DC=com` |
| Kullanıcı Filtresi | `(sAMAccountName={username})` |
| Rol Eşlemesi | `CN=IT-Admin` → `admin` |

### Nasıl çalışır?

1. Kullanıcı login formuna AD kullanıcı adı/parolasıyla girer.
2. OXware önce yerel kullanıcı DB'yi dener.
3. Yerel kullanıcı yoksa LDAP'a bind eder.
4. LDAP doğrularsa kullanıcı otomatik oluşturulur (rol LDAP grubundan alınır).
5. Sonraki girişlerde rol LDAP'tan güncellenir.

```bash
# LDAP bağlantısını test et
POST /api/ldap/test
Body: {"username": "testuser", "password": "testpass"}
```

---

## 31. RBAC — Rol Tabanlı Erişim Kontrolü

OXware üç rol destekler. Her rol hangi API endpoint'lerine erişebileceğini belirler.

| Rol | Açıklama |
|-----|----------|
| `admin` | Tam erişim — tüm VM, ağ, kullanıcı, sistem işlemleri |
| `operator` | VM başlat/durdur, snapshot, izleme — kullanıcı yönetimi yok |
| `viewer` | Sadece okuma — VM listesi, metrikler, loglar |

### Korunan işlemler (52 endpoint)

- VM oluşturma / silme / klonlama
- VM başlatma / durdurma / yeniden başlatma
- Ağ oluşturma / silme
- Kullanıcı yönetimi (oluştur/sil/rol değiştir)
- PCI passthrough ekleme / kaldırma
- NIC hot-plug
- Snapshot silme
- Hook script kaydetme / silme
- Vault kimlik bilgisi ekleme / silme
- Uyarı kuralı oluşturma / silme

### Mevcut kullanıcı bilgisi

```bash
GET /api/auth/me
# → {"username": "...", "role": "admin|operator|viewer", ...}
```

---

## 32. VM Etiketleme ve Gruplama

Her VM'e etiket ekleyerek gruplandırın ve filtreleyin.

### Kurallar

- VM başına maksimum **10 etiket**
- Etiket uzunluğu maksimum **20 karakter**
- Otomatik küçük harfe dönüştürülür
- Alfanümerik, tire ve alt çizgi

### API

```bash
# VM etiketlerini getir
GET /api/vms/<vm_id>/tags

# Etiket listesini güncelle
PUT /api/vms/<vm_id>/tags
Body: {"tags": ["web", "production", "nginx"]}

# Etiket ekle
POST /api/vms/<vm_id>/tags
Body: {"tag": "nginx"}

# Etiket sil
DELETE /api/vms/<vm_id>/tags/<tag>

# Belirli etikete sahip VM'leri listele
GET /api/tags/<tag>/vms

# Tüm etiketleri listele
GET /api/tags
```

Web arayüzde: VM listesinin üstündeki **etiket filtresi** ile anlık filtreleme.

---

## 33. VM Notları

Her VM için markdown destekli not alanı.

- Maksimum **10.000 karakter**
- VM detay modal'ından erişilebilir
- Not olmayan VM'lerde boş görünür

### API

```bash
# Notu getir
GET /api/vms/<vm_id>/note

# Notu kaydet / güncelle
PUT /api/vms/<vm_id>/note
Body: {"content": "Bu VM production web sunucusu..."}

# Notu sil
DELETE /api/vms/<vm_id>/note
```

---

## 34. Kimlik Bilgisi Vault

VM'lere ait SSH anahtarı, root parolası, web paneli kimlik bilgilerini şifreli saklayın.

### Şifreleme

- Anahtar: `/etc/oxware/vault.key` (ilk kullanımda oluşturulur, chmod 600)
- Algoritma: **Fernet** (AES-128-CBC + HMAC-SHA256)
- Veri: `/var/lib/oxware/vault.json`

### Kimlik bilgisi tipleri

| Tip | Açıklama |
|-----|----------|
| `root` | Root / sudo parolası |
| `ssh_key` | SSH özel anahtar |
| `web` | Web paneli giriş bilgisi |
| `custom` | Özel |

### API

```bash
# VM kimlik bilgilerini listele (parola maskeli)
GET /api/vault/<vm_id>

# Tüm vault içeriği (parola maskeli)
GET /api/vault

# Kimlik bilgisi ekle
POST /api/vault/<vm_id>
Body: {
  "cred_type": "root",
  "username": "root",
  "password": "gizli123",
  "notes": "Production DB sunucu"
}

# Kimlik bilgisi sil
DELETE /api/vault/<vm_id>/<cred_type>
```

Web arayüzde: **Güvenlik → Kimlik Bilgisi Vault** — parolalar tarayıcıda maskelidir, 👁 ile göster.

---

## 35. Maliyet Takibi

VM'lerin tahmini aylık maliyetini CPU/RAM/disk birim fiyatlarına göre hesaplayın.

### Yapılandırma

```bash
# Mevcut tarife görüntüle
GET /api/cost/config

# Tarife güncelle
PUT /api/cost/config
Body: {
  "cpu_rate":  0.005,   # vCPU başına saatlik USD
  "ram_rate":  0.001,   # GB RAM başına saatlik USD
  "disk_rate": 0.0001,  # GB disk başına saatlik USD
  "currency":  "USD"
}
```

### VM maliyet hesaplama

```bash
# Tek VM maliyet tahmini
GET /api/cost/<vm_id>?hours=720

# Tüm VM'ler özet
GET /api/cost/summary
# → {"total_monthly": 124.50, "vms": [...]}
```

Web arayüzde: **İzleme → Maliyet Tahmini** — aylık toplam + VM başına döküm tablosu.

---

## 36. Uyarı Kuralları (Alert Rules)

CPU, RAM, disk kullanımı belirli eşiği aştığında bildirim alın veya webhook tetikleyin.

### Kural yapısı

| Alan | Açıklama |
|------|----------|
| `metric` | `cpu_pct` / `mem_pct` / `disk_pct` |
| `operator` | `gt` / `lt` / `gte` / `lte` |
| `threshold` | Eşik değeri (0–100) |
| `cooldown_s` | Aynı kuralın tekrar tetiklenmesi için bekleme süresi (saniye) |
| `webhook_url` | Tetiklenince POST atılacak URL (isteğe bağlı) |

### API

```bash
# Kural listesi
GET /api/alerts/rules

# Yeni kural oluştur
POST /api/alerts/rules
Body: {
  "name": "CPU Yüksek",
  "metric": "cpu_pct",
  "operator": "gt",
  "threshold": 90,
  "cooldown_s": 300,
  "webhook_url": "https://hooks.slack.com/..."
}

# Kural güncelle
PUT /api/alerts/rules/<rule_id>

# Kural sil
DELETE /api/alerts/rules/<rule_id>

# Son uyarı geçmişi
GET /api/alerts/history?n=50
```

Web arayüzde: **İzleme → Uyarı Kuralları**

---

## 37. Güvenlik Skoru

Her VM ve host sistemi için otomatik güvenlik derecelendirmesi.

### Değerlendirme kriterleri

**VM skorlaması:**
- SSH port 22 mi kullanılıyor? (−10 puan)
- Root login aktif mi? (−20 puan)
- Parola ile SSH girişi açık mı? (−15 puan)
- Bilinen CVE sayısı
- Güncel snapshot var mı? (+10 puan)
- Güvenlik duvarı kuralı var mı? (+10 puan)

**Host skorlaması:**
- fail2ban aktif mi?
- UFW aktif ve yapılandırılmış mı?
- Bekleyen apt güvenlik güncellemesi var mı?

### Notlar

| Puan | Not |
|------|-----|
| 90–100 | **A** — Mükemmel |
| 75–89 | **B** — İyi |
| 60–74 | **C** — Orta |
| 40–59 | **D** — Zayıf |
| 0–39 | **F** — Kritik |

### API

```bash
# Tüm VM'leri tara
GET /api/security/score

# Tek VM skoru
GET /api/security/score/<vm_id>

# Host sistem skoru
GET /api/security/host-score
```

Web arayüzde: **Güvenlik → Güvenlik Skoru** — host skoru progress bar, VM'ler tablo.

---

## 38. Global Arama ve Klavye Kısayolları

### Global Arama (Ctrl+K)

Topbar'daki 🔍 düğmesine tıklayın veya `Ctrl+K` basın. VM adı, IP adresi, etiket veya sayfa adı ile arama yapın.

- Sonuçlar: VM'ler (etiket chip'leriyle), sayfalar
- Klavye: `↑↓` gezin, `Enter` git, `Esc` kapat
- Canlı arama (150ms debounce)

### Klavye Kısayolları

| Kısayol | İşlev |
|---------|-------|
| `Ctrl+K` | Global arama aç |
| `Ctrl+Shift+N` | Yeni VM oluştur |
| `Ctrl+Shift+R` | Sayfayı yenile |
| `G` → `V` | VM listesine git |
| `G` → `N` | Ağ sayfasına git |
| `G` → `S` | Depolama sayfasına git |
| `G` → `M` | İzleme sekmesine git |
| `?` | Kısayol listesini göster |
| `Esc` | Açık modal'ı kapat |

---

## 39. DNS Watchdog ve Otomatik İyileştirme

Sunucunuzda DNS çözümlemesi başarısız olduğunda sistem otomatik olarak iyileştirilir.

### Nasıl çalışır?

Her 5 dakikada bir `oxware-dns-watchdog.timer` tetiklenir:

1. `8.8.8.8` ve `1.1.1.1`'e ping atar
2. DNS başarısızsa `/etc/resolv.conf` yeniden yazar:
   ```
   nameserver 8.8.8.8
   nameserver 1.1.1.1
   nameserver 8.8.4.4
   ```
3. `systemd-resolved` yeniden başlatır
4. `git pull` ile OXware güncellemelerini çeker
5. OXware servisini yeniden başlatır

### Statik DNS (kurulum sırasında)

Installer, `systemd-resolved` symlink'ini kırarak statik resolv.conf yazar. DNS sorunu yaşamaz.

```bash
# Watchdog durumu
systemctl status oxware-dns-watchdog.timer

# Manuel tetikle
sudo systemctl start oxware-dns-watchdog.service

# Log görüntüle
journalctl -u oxware-dns-watchdog -n 30
```

---

## 40. AI ile VM Oluşturma

Doğal dil komutlarıyla VM oluşturun.

### Nasıl kullanılır?

1. VM listesinde **🤖 AI ile Oluştur** düğmesine tıklayın.
2. Ne istediğinizi yazın:
   ```
   2 GB RAM, 2 CPU, Ubuntu 22.04, web sunucusu için
   ```
3. AI yapılandırmayı önerir: CPU / RAM / Disk / OS
4. **Uygula ve Oluştur** ile VM oluşturma formuna otomatik doldurulur.

### Backend API

```bash
# AI VM planı oluştur
POST /api/ai/plan
Body: {"description": "2 GB RAM, web sunucusu için Ubuntu VM"}

# Doğal dil komutu (fallback)
POST /api/ai/nl
Body: {"command": "2 vCPU, 4GB RAM, 40GB disk, Debian 12"}
```

---

## 41. Kaynak Havuzları (Resource Pools)

VM'leri mantıksal gruplara ayırın ve her gruba CPU/RAM kotası atayın.

### API

```bash
# Havuzları listele
GET /api/pools

# Yeni havuz oluştur
POST /api/pools
Body: {"name": "web-tier", "cpu_limit_pct": 60, "ram_limit_mb": 8192, "description": "Web VM grubu"}

# Havuzu sil
DELETE /api/pools/<pool_id>
```

### Havuz yapısı

| Alan | Açıklama |
|------|----------|
| `name` | Havuz adı |
| `cpu_limit_pct` | CPU üst sınırı (0-100, 100=sınırsız) |
| `ram_limit_mb` | RAM üst sınırı MB (0=sınırsız) |
| `vm_ids` | Havuzdaki VM UUID listesi |

Havuz verileri `/var/lib/oxware/resource_pools.json` dosyasında saklanır.

---

## 42. Ağ QoS — Bant Genişliği Kısıtlama

VM başına NIC düzeyinde gelen/giden trafik kısıtlaması (virsh domiftune).

### API

```bash
# VM NIC listesi
GET /api/vms/<vm_name>/nics

# QoS uygula
PUT /api/vms/<vm_name>/nics/<iface>/qos
Body: {"inbound_kbps": 10240, "outbound_kbps": 5120}

# QoS temizle (sınırsız)
DELETE /api/vms/<vm_name>/nics/<iface>/qos
```

### Notlar
- `0` = sınırsız (kısıtlama kaldır)
- Maksimum 10 Gbps (10 000 000 Kbps) kabul edilir
- VM çalışırken canlı uygulanır, yeniden başlatma gerekmez
- UI: İzleme sekmesi → "Ağ Bant Genişliği (QoS)" kartı

---

## 43. Canlı Disk Taşıma (Storage Migration)

VM çalışırken diski başka bir depolama yoluna taşır (`virsh blockcopy`).

### API

```bash
# Taşıma başlat
POST /api/vms/<vm_name>/migrate-disk
Body: {"disk_target": "vda", "dest_path": "/pool2/vm.qcow2", "format": "qcow2"}

# Taşıma durumu
GET /api/storage/migrations
GET /api/storage/migrations/<job_id>

# VM disk listesi
GET /api/vms/<vm_name>/disks
```

### İş durumları

| Durum | Anlamı |
|-------|--------|
| `queued` | Kuyruğa alındı |
| `running` | Kopyalama devam ediyor |
| `completed` | Taşıma tamamlandı |
| `failed` | Hata oluştu |

### Güvenlik kısıtlamaları
- `dest_path` mutlak yol (`/` ile başlamalı) ve `..` içermemeli
- `format` yalnızca `qcow2` veya `raw`
- `disk_target` yalnızca alfanümerik karakter ve `-_`

---

## 44. Canlı Hotplug (CPU / RAM)

VM çalışırken vCPU veya RAM ekleme/çıkarma.

### API

```bash
# vCPU ekle/çıkar (live)
POST /api/vms/<vm_name>/hotplug
Body: {"type": "vcpu", "count": 4}

# RAM değiştir (balloon, live)
POST /api/vms/<vm_name>/hotplug
Body: {"type": "memory", "mb": 4096}
```

### Sınırlamalar
- vCPU için VM'de `maxvcpus` tanımlı olmalı
- RAM için balloon sürücüsü (virtio-balloon) gerekir
- VM kapalıyken değişiklik kalıcı hale gelir

---

## 45. Kapasite Tahmini (AI Forecast)

Geçmiş kaynak kullanım trendine dayalı tahminleme.

### API

```bash
# Tahmin al (GET veya POST)
GET /api/ai/forecast?days=30
POST /api/ai/forecast
Body: {"days": 30}

# Alternatif URL (aynı endpoint)
GET /api/ai/predict/capacity?days=30
```

### Yanıt

```json
{
  "forecast": {
    "cpu_pct": 78.3,
    "mem_pct": 65.1,
    "days_until_full": 42,
    "recommendation": "CPU kapasitesi 42 gün içinde kritik eşiğe ulaşabilir."
  }
}
```

UI: AI sekmesi → "Kapasite Tahmini" kartı → Gün sayısı girin → "Tahmin Et".

---

## 46. Güvenlik Duvarı (nftables) — Güncel Notlar

`firewall_manager.py` `get_status()` hem `active` hem `available` anahtarını döndürür:

```json
{"active": true, "available": true, "rule_count": 12}
```

`nft` kurulu değilse `available: false` döner ve UI "Pasif" gösterir.

---

## 47. Sürükle-Bırak Dashboard

Anasayfa dashboardu widget'ları yeniden sıralanabilir.

### Kullanım
1. Dashboard sağ üstündeki **✏️ Düzenle** butonuna tıkla
2. Widget başlıklarından tutup sürükle
3. **✓ Kaydet** ile sıralamayı localStorage'a kaydet

### Mevcut widget'lar
- Hızlı istatistikler (CPU/RAM/Disk/VM)
- Performans geçmişi
- VM listesi
- Uyarı geçmişi
- IDS durumu
- HA kümesi durumu

---

## 48. Hotkey & Global Arama — Özet

| Kısayol | İşlev |
|---------|-------|
| `Ctrl+K` | Global arama overlay |
| `Ctrl+Shift+?` | Klavye kısayolları modalı |
| `Escape` | Açık overlay/modal kapat |

Global arama VM adı, sekme adı ve menü öğelerini tarar; sonuca tıklayarak doğrudan gidilir.

---

*OXware Hypervisor — Açık kaynak, üretim kalitesinde KVM tabanlı sanallaştırma platformu.*
