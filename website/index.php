<?php
$page_title = 'Açık Kaynak KVM Yönetim Paneli';
require_once __DIR__ . '/includes/header.php';
?>

<!-- HERO -->
<section class="hero">
    <div class="hero-bg"></div>
    <div class="hero-grid"></div>
    <div class="container" style="position:relative;z-index:1;">
        <div class="hero-eyebrow">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                <circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2" stroke-dasharray="4 4"/>
            </svg>
            Açık Kaynak · KVM/QEMU · Üretim Hazır
        </div>
        <h1>OXware Hypervisor<br><span class="gradient-text">Sanallaştırmayı Yeniden Tanımla</span></h1>
        <p class="hero-sub">ESXi ve Proxmox'a güçlü, açık kaynaklı ve ücretsiz bir alternatif. Tek panel üzerinden tüm sanal makinelerinizi, ağınızı ve yedekleme sistemlerinizi yönetin.</p>
        <div class="hero-actions">
            <a href="<?= GITHUB_REPO ?>" target="_blank" rel="noopener" class="btn btn-ghost btn-lg">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/>
                </svg>
                Ücretsiz Dene (GitHub)
            </a>
            <a href="/purchase.php" class="btn btn-primary btn-lg">
                Lisans Al — $<?= LICENSE_PRICE ?>/ay
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                    <path d="M5 12h14M12 5l7 7-7 7"/>
                </svg>
            </a>
        </div>
        <div class="hero-stats">
            <div class="stat-item">
                <div class="stat-num">100%</div>
                <div class="stat-label">Açık Kaynak</div>
            </div>
            <div class="stat-item">
                <div class="stat-num">KVM</div>
                <div class="stat-label">Hipervizör Çekirdeği</div>
            </div>
            <div class="stat-item">
                <div class="stat-num">7/24</div>
                <div class="stat-label">Lisans Desteği</div>
            </div>
            <div class="stat-item">
                <div class="stat-num">$<?= LICENSE_PRICE ?></div>
                <div class="stat-label">Aylık Lisans</div>
            </div>
        </div>
    </div>
</section>

<!-- FEATURES -->
<section class="section" id="features">
    <div class="container text-center">
        <div class="section-label">Özellikler</div>
        <h2 class="section-title">İhtiyacınız Olan Her Şey, Tek Panelde</h2>
        <p class="section-desc">Kurumsal sanallaştırma altyapısı için eksiksiz araç seti.</p>

        <div class="features-grid">
            <div class="feature-card" data-fade>
                <div class="feature-icon">🖥️</div>
                <h3>VM Yönetimi</h3>
                <p>KVM/QEMU ile tam sanal makine yaşam döngüsü. Oluştur, başlat, durdur, sil, klon. Web konsolu ile doğrudan erişim.</p>
            </div>
            <div class="feature-card" data-fade>
                <div class="feature-icon">🛡️</div>
                <h3>Güvenlik</h3>
                <p>Yerleşik Firewall, WireGuard VPN, İki Faktörlü Kimlik Doğrulama ve kapsamlı Audit Log ile katmanlı güvenlik.</p>
            </div>
            <div class="feature-card" data-fade>
                <div class="feature-icon">🤖</div>
                <h3>AI Asistan</h3>
                <p>Yapay zeka destekli sistem analizi. Performans darboğazlarını tespit et, otomatik iyileştirme önerileri al.</p>
            </div>
            <div class="feature-card" data-fade>
                <div class="feature-icon">📊</div>
                <h3>İzleme</h3>
                <p>CPU, RAM, disk ve ağ için gerçek zamanlı grafikler. Eşik uyarıları ve e-posta bildirimleri.</p>
            </div>
            <div class="feature-card" data-fade>
                <div class="feature-icon">💾</div>
                <h3>Yedekleme</h3>
                <p>Otomatik zamanlanmış snapshot'lar ve uzak sunucuya şifreli yedekleme. Tek tıkla geri yükleme.</p>
            </div>
            <div class="feature-card" data-fade>
                <div class="feature-icon">🌐</div>
                <h3>Ağ Yönetimi</h3>
                <p>DNS, VLAN, Reverse Proxy, Load Balancer ve SDN yönetimi — hepsi tek arayüzden.</p>
            </div>
        </div>
    </div>
</section>

<!-- SYSTEM REQUIREMENTS -->
<section class="section req-section">
    <div class="container">
        <div class="text-center">
            <div class="section-label">Sistem Gereksinimleri</div>
            <h2 class="section-title">Çalıştırmak Kolay</h2>
            <p class="section-desc" style="margin-bottom:36px;">Mevcut donanımınıza kurabilirsiniz.</p>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Bileşen</th>
                        <th>Minimum</th>
                        <th>Önerilen</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>CPU</td>
                        <td>1 Çekirdek (x86-64, VT-x)</td>
                        <td>4+ Çekirdek</td>
                    </tr>
                    <tr>
                        <td>RAM</td>
                        <td>2 GB</td>
                        <td>8 GB+</td>
                    </tr>
                    <tr>
                        <td>Disk</td>
                        <td>20 GB SSD</td>
                        <td>100 GB+ SSD/NVMe</td>
                    </tr>
                    <tr>
                        <td>İşletim Sistemi</td>
                        <td>Ubuntu 20.04 LTS</td>
                        <td>Ubuntu 22.04 LTS</td>
                    </tr>
                    <tr>
                        <td>Ağ</td>
                        <td>100 Mbit</td>
                        <td>1 Gbit+</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</section>

<!-- PRICING CTA -->
<section class="section cta-section">
    <div class="container text-center">
        <div class="section-label">Lisanslama</div>
        <h2 class="section-title">7/24 Destek için Lisans Alın</h2>
        <p class="section-desc">Yazılım tamamen ücretsiz. Lisans, öncelikli teknik destek ve özel güncellemeler içerir.</p>

        <div class="pricing-card">
            <div class="pricing-badge">Standart Lisans</div>
            <div class="pricing-price">
                <sup>$</sup><?= LICENSE_PRICE ?>
            </div>
            <div class="pricing-period">/ aylık</div>
            <ul class="pricing-features" style="list-style:none;">
                <li>7/24 WhatsApp & E-posta Destek</li>
                <li>Öncelikli Bug Fix ve Güncellemeler</li>
                <li>Üretim Ortamı Kurulum Rehberi</li>
                <li>Sınırsız VM ve Kullanıcı</li>
                <li>Özel yapılandırma danışmanlığı</li>
                <li>İstediğiniz zaman iptal edin</li>
            </ul>
            <a href="/purchase.php" class="btn btn-primary btn-lg btn-block">
                Şimdi Satın Al
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                    <path d="M5 12h14M12 5l7 7-7 7"/>
                </svg>
            </a>
            <p style="margin-top:14px;font-size:.82rem;color:var(--text-dim);">
                Banka havalesi ile ödeme · Ödeme sonrası lisans e-posta ile iletilir
            </p>
        </div>
    </div>
</section>

<!-- FOOTER -->
<footer>
    <div class="container">
        <div class="footer-grid">
            <div class="footer-brand">
                <a href="/index.php" class="nav-brand" style="margin-bottom:0">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="2" y="3" width="20" height="14" rx="2"/>
                        <path d="M8 21h8M12 17v4"/>
                        <circle cx="12" cy="10" r="3"/>
                    </svg>
                    <span>OXware</span>
                    <span class="brand-tag">Hypervisor</span>
                </a>
                <p>Açık kaynak KVM sanallaştırma yönetim paneli. Kurumsal altyapınız için güçlü, güvenli ve esnek çözüm.</p>
                <a href="https://wa.me/<?= WHATSAPP_SUPPORT ?>" target="_blank" rel="noopener" class="whatsapp-btn" style="margin-top:16px;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/>
                    </svg>
                    WhatsApp Destek
                </a>
            </div>
            <div class="footer-col">
                <h4>Ürün</h4>
                <ul>
                    <li><a href="/index.php#features">Özellikler</a></li>
                    <li><a href="/purchase.php">Fiyatlandırma</a></li>
                    <li><a href="<?= GITHUB_REPO ?>" target="_blank" rel="noopener">Belgeler</a></li>
                    <li><a href="<?= GITHUB_REPO ?>/releases" target="_blank" rel="noopener">Sürüm Notları</a></li>
                </ul>
            </div>
            <div class="footer-col">
                <h4>Hesap</h4>
                <ul>
                    <li><a href="/login.php">Giriş</a></li>
                    <li><a href="/register.php">Kayıt Ol</a></li>
                    <li><a href="/dashboard.php">Panelim</a></li>
                    <li><a href="/purchase.php">Lisans Al</a></li>
                </ul>
            </div>
            <div class="footer-col">
                <h4>İletişim</h4>
                <ul>
                    <li><a href="https://wa.me/<?= WHATSAPP_SUPPORT ?>" target="_blank" rel="noopener">WhatsApp</a></li>
                    <li><a href="<?= GITHUB_REPO ?>/issues" target="_blank" rel="noopener">GitHub Issues</a></li>
                </ul>
                <p style="color:var(--text-dim);font-size:.8rem;margin-top:16px;">
                    <?= COMPANY_NAME ?><br>
                    <?= COMPANY_ADDRESS ?>
                </p>
            </div>
        </div>
        <div class="footer-bottom">
            <span>&copy; <?= date('Y') ?> <?= COMPANY_NAME ?>. Tüm hakları saklıdır.</span>
            <span>
                <a href="<?= GITHUB_REPO ?>" target="_blank" rel="noopener">GitHub</a>
                &nbsp;·&nbsp;
                <a href="https://wa.me/<?= WHATSAPP_SUPPORT ?>" target="_blank" rel="noopener">Destek</a>
            </span>
        </div>
    </div>
</footer>

<script src="/assets/main.js"></script>
</body>
</html>
