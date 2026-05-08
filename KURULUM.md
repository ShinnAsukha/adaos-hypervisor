# OXware Hypervisor — Kurulum Kılavuzu

> Sürüm: 2.0 · Hazırlayan: Ada Gürsoy

---

## İçindekiler

1. [Donanım Gereksinimleri](#1-donanım-gereksinimleri)
2. [BIOS/UEFI Ayarları](#2-biosuefi-ayarları)
3. [Ubuntu Sunucu Hazırlığı](#3-ubuntu-sunucu-hazırlığı)
4. [OXware ISO ile Kurulum](#4-oxware-iso-ile-kurulum)
5. [Script ile Kurulum (Mevcut Ubuntu)](#5-script-ile-kurulum-mevcut-ubuntu)
6. [İlk Giriş ve Parola Belirleme](#6-ilk-giriş-ve-parola-belirleme)
7. [Web Arayüzüne Erişim](#7-web-arayüzüne-erişim)
8. [IP Havuzu Oluşturma](#8-ip-havuzu-oluşturma)
9. [İlk VM Oluşturma](#9-ilk-vm-oluşturma)
10. [AI Ajan Kurulumu](#10-ai-ajan-kurulumu)
11. [Telegram ve Discord Bildirimleri](#11-telegram-ve-discord-bildirimleri)
12. [Parola Sıfırlama](#12-parola-sıfırlama)
13. [Güvenlik Duvarı ve Portlar](#13-güvenlik-duvarı-ve-portlar)
14. [Sorun Giderme](#14-sorun-giderme)
15. [AdaOS → OXware Canlı Sunucu Geçişi](#15-adaos--oxware-canlı-sunucu-geçişi)

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

---

## 4. OXware ISO ile Kurulum

Sıfırdan tam otomatik kurulum için OXware özel ISO'sunu kullanın.

### ISO oluşturma

```bash
# Gereksinimler: Ubuntu 22.04, xorriso, syslinux
sudo apt update && sudo apt install -y xorriso syslinux-utils genisoimage

# OXware repo klasörüne geçin
cd /path/to/OXware

# ISO oluşturma scriptini çalıştırın
sudo bash build-iso.sh
```

Script çıktıda ISO dosyasının yolu görünür:
```
✓ OXware ISO oluşturuldu: OXware-Hypervisor-2.0.0-amd64.iso
  SHA256: OXware-Hypervisor-2.0.0-amd64.iso.sha256
```

### ISO'yu USB'ye yazma

```bash
# Linux
sudo dd if=OXware-Hypervisor-2.0.0-amd64.iso of=/dev/sdX bs=4M status=progress sync

# Windows — Rufus ile:
# Device: USB bellek | Boot selection: OXware-Hypervisor-2.0.0-amd64.iso | Partition scheme: GPT
```

### Önyükleme

1. Sunucuyu USB'den başlatın.
2. GRUB menüsünde **"Install OXware Hypervisor"** seçeneğini seçin.
3. Kurulum otomatik olarak gerçekleşir (~10-20 dakika).
4. Sistem yeniden başladığında OXware hazır olacaktır.

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
# Sertifikaları /etc/oxware/ssl/ klasörüne kopyalayın
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
# /etc/oxware/ai_agents.conf dosyasını oluşturun/düzenleyin
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
# Önce Ollama kurun
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3

# ai_agents.conf içinde:
{
  "provider":  "ollama",
  "api_key":   "",
  "model":     "llama3",
  "base_url":  "http://localhost:11434"
}
```

Konfigürasyonu uygulamak için:
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

Test etmek için:
```bash
curl -k -X POST https://localhost:8006/api/notifications/test \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"message": "OXware test mesajı", "level": "INFO"}'
```

```bash
sudo systemctl restart oxware
```

---

## 12. Parola Sıfırlama

Parolanızı unutursanız SSH erişimi ile sıfırlayabilirsiniz:

```bash
# Sunucuya SSH ile bağlanın
ssh oxware@<sunucu-ip>

# Reset dosyasını oluşturun
sudo nano /etc/oxware/.passwd_reset
```

Dosya içeriği:
```
USERNAME=yeni_kullanici
PASSWORD=YeniGucluParola123!
```

Kaydedin ve servisi yeniden başlatın:
```bash
sudo systemctl restart oxware
```

Servis başlarken reset dosyasını okur, parolayı günceller ve dosyayı **otomatik olarak siler**.

---

## 13. Güvenlik Duvarı ve Portlar

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
# Önce tüm 8006 erişimini kapat
sudo ufw delete allow 8006/tcp

# Sadece kendi IP'nizden izin verin
sudo ufw allow from 203.0.113.10 to any port 8006 proto tcp

sudo ufw reload
```

### fail2ban durumu

```bash
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

---

## 14. Sorun Giderme

### Servis çalışmıyor

```bash
sudo systemctl status oxware
sudo journalctl -u oxware -n 50 --no-pager
```

### Logları inceleyin

```bash
# OXware uygulama logu
tail -f /var/log/oxware/oxware.log

# Güvenlik/denetim logu
tail -f /var/log/oxware/security.log

# Olay günlüğü
tail -f /var/log/oxware/events.jsonl

# AI ajan logu
tail -f /var/log/oxware/ai_agent.jsonl

# Güncelleme logu
tail -f /var/log/oxware/updates.jsonl
```

### libvirt bağlantı hatası

```bash
sudo systemctl status libvirtd
sudo systemctl restart libvirtd
sudo usermod -aG libvirt oxware  # ve yeniden oturum açın
```

### noVNC konsol açılmıyor

```bash
sudo systemctl status novnc
# Port kontrolü
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
# Kontrol
grep -c vmx /proc/cpuinfo  # Intel: 0 çıkarsa VT-x kapalı
grep -c svm /proc/cpuinfo  # AMD: 0 çıkarsa AMD-V kapalı

# kvm modülleri
lsmod | grep kvm
# Çıktı yoksa:
sudo modprobe kvm-intel   # veya kvm-amd
```

### Token süresi doldu

JWT token 8 saat geçerlidir. Tekrar giriş yapın; token localStorage'e otomatik kaydedilir.

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

# Python bağımlılıklarını güncelle
sudo /opt/oxware/venv/bin/pip install -r oxware/backend/requirements.txt --upgrade

sudo systemctl restart oxware
```

Veya web arayüzünden: **Ayarlar → Güncellemeler → Güncelleme Kontrol Et**

---

## 15. AdaOS → OXware Canlı Sunucu Geçişi

> Bu bölüm, halihazırda **AdaOS** kurulu çalışan bir üretim sunucusunu  
> **OXware**'e geçirmek için adım adım kılavuzdur.  
> İşlem boyunca VM'ler **çalışmaya devam eder**; yalnızca yönetim servisi kısa süre kapanır.

### Gereksinimler

```bash
# Mevcut AdaOS versiyonunu kontrol edin
sudo systemctl status adaos
cat /etc/adaos/adaos.conf | head -5
```

### Adım 1 — Yedek Alın

```bash
# Konfigürasyonu yedekle
sudo cp -r /etc/adaos /root/adaos-backup-$(date +%Y%m%d)

# Kullanıcı veritabanını yedekle
sudo cp /var/lib/adaos/users.json /root/users-backup-$(date +%Y%m%d).json 2>/dev/null || true

# Servis logunu yedekle
sudo cp /var/log/adaos/adaos.log /root/adaos-$(date +%Y%m%d).log 2>/dev/null || true

echo "✓ Yedek tamamlandı: /root/adaos-backup-$(date +%Y%m%d)"
```

### Adım 2 — Yeni OXware Dosyalarını Sunucuya Kopyalayın

```bash
# Geliştirme makinenizde (ya da GitHub'dan çekin):
scp -r /local/path/OXware root@<sunucu-ip>:~/OXware

# Ya da git ile:
cd ~
git clone https://github.com/https://github.com/ShinnAsukha/oxware-hypervisor.git/oxware.git OXware
cd OXware
```

### Adım 3 — Servisi Durdurun

```bash
# AdaOS servisini durdur (VM'ler çalışmaya devam eder)
sudo systemctl stop adaos
sudo systemctl disable adaos
echo "✓ AdaOS servisi durduruldu"
```

### Adım 4 — Dizinleri Taşıyın

```bash
# Kurulum dizini
sudo cp -r /opt/adaos /opt/oxware
echo "✓ /opt/adaos → /opt/oxware kopyalandı"

# Konfigürasyon dizini
sudo mkdir -p /etc/oxware/ssl
sudo cp /etc/adaos/adaos.conf /etc/oxware/oxware.conf 2>/dev/null || true
sudo cp /etc/adaos/ssl/* /etc/oxware/ssl/ 2>/dev/null || true
sudo cp /etc/adaos/.auth /etc/oxware/.auth 2>/dev/null || true
sudo cp /etc/adaos/.setup_done /etc/oxware/.setup_done 2>/dev/null || true
sudo cp /etc/adaos/ai_agents.conf /etc/oxware/ai_agents.conf 2>/dev/null || true
sudo cp /etc/adaos/notifications.conf /etc/oxware/notifications.conf 2>/dev/null || true
sudo cp /etc/adaos/update.conf /etc/oxware/update.conf 2>/dev/null || true
sudo chmod 600 /etc/oxware/.auth /etc/oxware/ssl/* /etc/oxware/oxware.conf 2>/dev/null || true
echo "✓ /etc/adaos → /etc/oxware kopyalandı"

# Veri dizini
sudo cp -r /var/lib/adaos /var/lib/oxware
echo "✓ /var/lib/adaos → /var/lib/oxware kopyalandı"

# Log dizini
sudo mkdir -p /var/log/oxware
sudo cp /var/log/adaos/*.log /var/log/oxware/ 2>/dev/null || true
sudo cp /var/log/adaos/*.jsonl /var/log/oxware/ 2>/dev/null || true
echo "✓ /var/log/adaos → /var/log/oxware kopyalandı"
```

### Adım 5 — oxware.conf Yollarını Düzeltin

```bash
# Konfigürasyondaki adaos referanslarını oxware'e çevir
sudo sed -i 's|/etc/adaos|/etc/oxware|g; s|/var/lib/adaos|/var/lib/oxware|g; s|/var/log/adaos|/var/log/oxware|g; s|adaos\.crt|oxware.crt|g; s|adaos\.key|oxware.key|g' /etc/oxware/oxware.conf

# SSL sertifika dosyalarını yeniden adlandır (varsa)
sudo mv /etc/oxware/ssl/adaos.crt /etc/oxware/ssl/oxware.crt 2>/dev/null || true
sudo mv /etc/oxware/ssl/adaos.key /etc/oxware/ssl/oxware.key 2>/dev/null || true

cat /etc/oxware/oxware.conf
```

### Adım 6 — Yeni OXware Dosyalarını Kopyalayın

```bash
# OXware kaynak dosyalarını /opt/oxware'e kopyala
cd ~/OXware
sudo cp -r oxware/backend/* /opt/oxware/backend/
sudo cp -r oxware/frontend/* /opt/oxware/frontend/
echo "✓ OXware kaynak dosyaları güncellendi"
```

### Adım 7 — Python Ortamını Güncelleyin

```bash
# Mevcut venv'i yeniden kullan, sadece bağımlılıkları güncelle
sudo /opt/oxware/venv/bin/pip install \
  -r /opt/oxware/backend/requirements.txt \
  --upgrade -q
echo "✓ Python bağımlılıkları güncellendi"
```

### Adım 8 — Yeni Systemd Servisi Kur

```bash
# Eski servisi kaldır
sudo rm -f /etc/systemd/system/adaos.service

# Yeni OXware servis dosyasını kopyala
sudo cp ~/OXware/oxware/oxware-hypervisor.service /etc/systemd/system/oxware.service

# oxware.service içindeki yolları doğrula
sudo cat /etc/systemd/system/oxware.service

# Servisi etkinleştir ve başlat
sudo systemctl daemon-reload
sudo systemctl enable oxware
sudo systemctl start oxware
sleep 3
sudo systemctl status oxware
```

### Adım 9 — Fail2ban Konfigürasyonunu Güncelleyin (isteğe bağlı)

```bash
sudo sed -i 's|adaos|oxware|g; s|/var/log/adaos|/var/log/oxware|g' \
    /etc/fail2ban/jail.d/adaos.conf 2>/dev/null || true
sudo mv /etc/fail2ban/jail.d/adaos.conf /etc/fail2ban/jail.d/oxware.conf 2>/dev/null || true
sudo mv /etc/fail2ban/filter.d/adaos-web.conf /etc/fail2ban/filter.d/oxware-web.conf 2>/dev/null || true
sudo systemctl reload fail2ban 2>/dev/null || true
echo "✓ Fail2ban güncellendi"
```

### Adım 10 — UFW Kurallarını Güncelleyin (gerekirse)

```bash
sudo ufw status numbered
# 8006 zaten açıksa ek işlem gerekmez
# Yoksa:
sudo ufw allow 8006/tcp comment "OXware Web UI"
sudo ufw reload
```

### Adım 11 — Doğrulama

```bash
# Servis durumu
sudo systemctl status oxware

# Log kontrolü
sudo journalctl -u oxware -n 20 --no-pager

# Web arayüzüne erişim testi
curl -k -s -o /dev/null -w "%{http_code}" https://localhost:8006/
# 200 veya 302 çıkmalı

echo ""
echo "✓ Tüm kontroller tamamlandı"
echo "  Web: https://$(hostname -I | awk '{print $1}'):8006"
```

### Adım 12 — Eski Dizinleri Temizleyin (doğrulamadan sonra)

```bash
# Onayladıktan sonra eski dizinleri sil
sudo rm -rf /opt/adaos
sudo rm -rf /etc/adaos
# /var/lib/adaos ve /var/log/adaos'u bir süre saklayın (ihtiyaç duyulabilir)
# Hazır olduğunuzda:
# sudo rm -rf /var/lib/adaos /var/log/adaos

echo "✓ Geçiş tamamlandı. OXware çalışıyor."
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
| `adaos.service` | `oxware.service` |

---

*OXware Hypervisor — Açık kaynak, üretim kalitesinde KVM tabanlı sanallaştırma platformu.*
