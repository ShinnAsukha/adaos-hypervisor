# OXware Hypervisor — Kurulum Kılavuzu

> Sürüm: 2.2 · Hazırlayan: Ada Gürsoy
> Test URL: http://oxware.top
Test için Issues kısmından ulaşabilirsiniz, adınıza hesap açalım.

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
10. [AI Ajan Kurulumu](#10-ai-ajan-kurulumu)
11. [Telegram ve Discord Bildirimleri](#11-telegram-ve-discord-bildirimleri)
12. [2FA (İki Faktörlü Doğrulama)](#12-2fa-iki-faktörlü-doğrulama)
13. [Güvenlik Denetimi](#13-güvenlik-denetimi)
14. [Otomatik Snapshot](#14-otomatik-snapshot)
15. [Otomatik Güncelleme Kontrolü](#15-otomatik-güncelleme-kontrolü)
16. [Parola Sıfırlama](#16-parola-sıfırlama)
17. [Güvenlik Duvarı ve Portlar](#17-güvenlik-duvarı-ve-portlar)
18. [Aktif Oturum Yönetimi (JWT Sessions)](#18-aktif-oturum-yönetimi-jwt-sessions)
19. [IP Erişim Kısıtlaması (Allowlist)](#19-ip-erişim-kısıtlaması-allowlist)
20. [VM Zamanlaması](#20-vm-zamanlaması)
21. [VM Klonlama ve Toplu İşlemler](#21-vm-klonlama-ve-toplu-işlemler)
22. [Prometheus Metrikleri](#22-prometheus-metrikleri)
23. [PWA (Masaüstü / Mobil Uygulama)](#23-pwa-masaüstü--mobil-uygulama)
24. [Domain Bağlama (Nginx + Let's Encrypt)](#24-domain-bağlama-nginx--lets-encrypt)
25. [İnternet Bağlantısı Gereksinimleri](#25-i̇nternet-bağlantısı-gereksinimleri)
26. [Sorun Giderme](#26-sorun-giderme)
27. [AdaOS → OXware Canlı Sunucu Geçişi](#27-adaos--oxware-canlı-sunucu-geçişi)

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

## 10. AI Ajan Kurulumu

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

## 11. Telegram ve Discord Bildirimleri

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

## 12. 2FA (İki Faktörlü Doğrulama)

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

## 13. Güvenlik Denetimi

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

## 14. Otomatik Snapshot

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

---

## 15. Otomatik Güncelleme Kontrolü

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

## 16. Parola Sıfırlama

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

## 17. Güvenlik Duvarı ve Portlar

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

## 18. Aktif Oturum Yönetimi (JWT Sessions)

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

## 19. IP Erişim Kısıtlaması (Allowlist)

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

## 20. VM Zamanlaması

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

## 21. VM Klonlama ve Toplu İşlemler

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

## 22. Prometheus Metrikleri

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

## 23. PWA (Masaüstü / Mobil Uygulama)

OXware, Progressive Web App (PWA) olarak masaüstüne veya telefona eklenebilir.

### Chrome / Edge (Masaüstü)

1. `https://<sunucu-ip>:8006` adresini açın
2. Adres çubuğundaki **⊞ (Yükle)** simgesine tıklayın
3. **"OXware Hypervisor Yükle"** → uygulama gibi çalışır

### Android / iOS (Mobil)

- **Android Chrome:** ⋮ menüsü → "Ana ekrana ekle"
- **iOS Safari:** Paylaş → "Ana Ekrana Ekle"

---

## 24. Domain Bağlama (Nginx + Let's Encrypt)

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

## 25. İnternet Bağlantısı Gereksinimleri

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

## 26. Sorun Giderme

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

## 27. AdaOS → OXware Canlı Sunucu Geçişi

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

*OXware Hypervisor — Açık kaynak, üretim kalitesinde KVM tabanlı sanallaştırma platformu.*
