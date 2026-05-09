# OXware Website

Kurumsal PHP web sitesi — OXware Hypervisor lisans ve tanıtım platformu.

## Gereksinimler

- PHP 8.0+
- SQLite3 extension (`php-sqlite3`)
- Apache 2.4+ veya Nginx
- mod_rewrite (Apache için)

## Kurulum

1. `website/` klasörünü web root'a kopyalayın:
   ```bash
   cp -r website/ /var/www/html/oxware/
   ```

2. `data/` klasörüne yazma izni verin:
   ```bash
   chmod 750 /var/www/html/oxware/data/
   chown www-data:www-data /var/www/html/oxware/data/
   ```

3. `includes/config.php` dosyasını düzenleyin:
   - `SITE_URL` değerini gerçek alan adınızla güncelleyin
   - `COMPANY_IBAN` değerini gerçek IBAN'ınızla güncelleyin
   - Diğer şirket bilgilerini doldurun

4. Apache için örnek VirtualHost:
   ```apache
   <VirtualHost *:443>
       ServerName oxware.example.com
       DocumentRoot /var/www/html/oxware/website
       <Directory /var/www/html/oxware/website>
           AllowOverride All
           Require all granted
       </Directory>
       SSLEngine on
       SSLCertificateFile    /etc/letsencrypt/live/oxware.example.com/fullchain.pem
       SSLCertificateKeyFile /etc/letsencrypt/live/oxware.example.com/privkey.pem
   </VirtualHost>
   ```

5. Site hazır!

## Güvenlik Notları

- HTTPS kullanın (Let's Encrypt ücretsiz sertifika sağlar)
- `data/` klasörüne web erişimi `.htaccess` ile engellenmiştir
- Tüm formlar CSRF korumasına sahiptir
- Şifreler bcrypt (cost=12) ile hashlenmiştir
- Tüm kullanıcı girdileri `htmlspecialchars()` ile temizlenir
- PDO prepared statements ile SQL injection koruması mevcuttur
- Session cookie'leri `httponly`, `secure`, `samesite=Strict` olarak ayarlanmıştır

## Klasör Yapısı

```
website/
├── index.php          Landing page (sistem tanıtımı)
├── login.php          Kullanıcı girişi
├── register.php       Yeni hesap oluşturma
├── dashboard.php      Kullanıcı paneli (lisanslar)
├── purchase.php       Lisans satın alma
├── logout.php         Oturum kapatma
├── includes/
│   ├── config.php     Sabitler ve oturum başlatma
│   ├── auth.php       Auth fonksiyonları, CSRF, XSS helper
│   ├── db.php         SQLite PDO bağlantısı ve tablo kurulumu
│   └── header.php     Ortak HTML head + navbar
├── assets/
│   ├── style.css      Ana CSS (karanlık tema)
│   └── main.js        Minimal JS (nav, IBAN kopyalama, animasyon)
└── data/
    ├── .htaccess      Web erişimini engelle
    └── .gitkeep       Git'e boş klasör izlemesi için
```

## Veritabanı

SQLite kullanılır (`data/oxware.db`). İlk ziyarette otomatik oluşturulur.

Tablolar:
- `users` — Kullanıcı hesapları
- `licenses` — Lisans kodları ve durumları
- `payment_requests` — Havale talepleri

## İletişim

- WhatsApp: [+905439769301](https://wa.me/905439769301)
- GitHub: [ShinnAsukha/oxware-hypervisor](https://github.com/ShinnAsukha/oxware-hypervisor)
