<?php
$page_title = 'Lisans Satın Al';
require_once __DIR__ . '/includes/auth.php';

$user     = current_user();
$errors   = [];
$success  = false;
$req_id   = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();

    $buyer_name   = trim($_POST['buyer_name']   ?? '');
    $buyer_email  = trim($_POST['buyer_email']  ?? '');
    $receipt_note = trim($_POST['receipt_note'] ?? '');

    if (strlen($buyer_name) < 2) {
        $errors[] = 'Ad Soyad en az 2 karakter olmalıdır.';
    }
    if (!filter_var($buyer_email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Geçerli bir e-posta adresi giriniz.';
    }

    if (!$errors) {
        $req_id = create_payment_request([
            'user_id'      => $user ? $user['id'] : null,
            'iban_name'    => $buyer_name,
            'receipt_note' => "Alıcı: {$buyer_name} | E-posta: {$buyer_email}" . ($receipt_note ? " | Not: {$receipt_note}" : ''),
        ]);
        $success = true;
        $success_email = $buyer_email;
    }
}

require_once __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <div class="container">
        <h1>Lisans Satın Al</h1>
        <p>OXware Hypervisor standart lisansı — aylık $<?= LICENSE_PRICE ?></p>
    </div>
</div>

<div class="container section-sm">

<?php if ($success): ?>
    <!-- Success State -->
    <div class="success-box" style="max-width:600px;margin:0 auto;">
        <span class="success-icon">✅</span>
        <h3>Ödeme Talebiniz Alındı!</h3>
        <p style="margin-bottom:16px;">
            Havaleyi tamamladıktan sonra lisans kodunuz <strong><?= e($success_email ?? '') ?></strong>
            adresine <strong>24 saat içinde</strong> gönderilecektir.
        </p>
        <p style="margin-bottom:16px;">
            Acil destek ve hızlı işlem için WhatsApp'tan ulaşabilirsiniz:
        </p>
        <a href="https://wa.me/<?= WHATSAPP_SUPPORT ?>?text=Merhaba%2C+OXWARE+lisans+ödeme+talebim+var.+Talep+No%3A+<?= $req_id ?>+E-posta%3A+<?= urlencode($success_email ?? '') ?>"
           target="_blank" rel="noopener" class="whatsapp-btn" style="display:inline-flex;margin:0 auto 20px;">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                <path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/>
            </svg>
            WhatsApp ile Bildir
        </a>
        <p style="color:var(--text-dim);font-size:.82rem;">Talep No: #<?= $req_id ?></p>
    </div>

<?php else: ?>

    <?php if ($errors): ?>
        <div class="alert alert-error" style="max-width:880px;margin:0 auto 24px;">
            <ul><?php foreach ($errors as $e): ?><li><?= e($e) ?></li><?php endforeach; ?></ul>
        </div>
    <?php endif; ?>

    <div class="purchase-grid" style="max-width:880px;margin:0 auto;">

        <!-- Order Summary -->
        <div class="order-summary card">
            <div class="order-header">Sipariş Özeti</div>

            <div class="order-item">
                <div>
                    <div class="order-item-name">OXware Hypervisor Lisansı</div>
                    <div class="order-item-desc">Standart Plan · Aylık yenileme · 1 adet</div>
                </div>
                <div class="order-item-price">$<?= LICENSE_PRICE ?></div>
            </div>

            <div class="order-total">
                <span>Toplam</span>
                <span class="order-total-price">$<?= LICENSE_PRICE ?>/ay</span>
            </div>

            <div style="margin-top:20px;padding-top:20px;border-top:1px solid var(--border);">
                <p style="font-size:.85rem;color:var(--text-muted);margin-bottom:12px;font-weight:600;">Bu lisans kapsar:</p>
                <ul style="list-style:none;font-size:.85rem;color:var(--text-muted);">
                    <?php $features = [
                        '7/24 WhatsApp & E-posta Destek',
                        'Sınırsız VM yönetimi',
                        'Öncelikli güncellemeler',
                        'Kurulum danışmanlığı',
                        'İstediğiniz zaman iptal',
                    ]; foreach ($features as $f): ?>
                    <li style="padding:6px 0;border-bottom:1px solid var(--border);display:flex;gap:8px;">
                        <span style="color:var(--green);font-weight:700;">✓</span> <?= e($f) ?>
                    </li>
                    <?php endforeach; ?>
                </ul>
            </div>

            <div style="margin-top:20px;text-align:center;">
                <p style="font-size:.8rem;color:var(--text-dim);">
                    Ödemenizi havale ile yapın.<br>
                    24 saat içinde lisansınız e-postanıza gelir.
                </p>
            </div>
        </div>

        <!-- Payment Form -->
        <div class="card">
            <div class="order-header">Ödeme Bilgileri</div>

            <form method="POST" action="/purchase.php" novalidate>
                <?= csrf_field() ?>

                <div class="form-group">
                    <label class="form-label" for="buyer_name">Ad Soyad</label>
                    <input
                        type="text"
                        id="buyer_name"
                        name="buyer_name"
                        class="form-control"
                        placeholder="Havale yapacağınız kişinin adı"
                        value="<?= e($_POST['buyer_name'] ?? $user['name'] ?? '') ?>"
                        required
                    >
                    <div class="form-text">Banka hesabınızdaki isim ile aynı olmalıdır.</div>
                </div>

                <div class="form-group">
                    <label class="form-label" for="buyer_email">E-posta Adresi</label>
                    <input
                        type="email"
                        id="buyer_email"
                        name="buyer_email"
                        class="form-control"
                        placeholder="lisans@email.com"
                        value="<?= e($_POST['buyer_email'] ?? $user['email'] ?? '') ?>"
                        required
                    >
                    <div class="form-text">Lisans kodu bu adrese gönderilecektir.</div>
                </div>

                <div class="form-group">
                    <label class="form-label">Ödeme Yöntemi</label>
                    <div class="radio-group">
                        <label class="radio-item">
                            <input type="radio" name="payment_method" value="bank_transfer" checked>
                            <div>
                                <div class="fw-600">Banka Havalesi (IBAN)</div>
                                <div style="font-size:.8rem;color:var(--text-muted);">TL veya USD havale</div>
                            </div>
                        </label>
                    </div>
                </div>

                <!-- IBAN Box -->
                <div id="ibanSection" class="form-group">
                    <label class="form-label">Havale Bilgileri</label>
                    <div class="iban-box">
                        <button type="button" class="iban-copy-btn">Kopyala</button>
                        <strong>Alıcı:</strong> <?= COMPANY_NAME ?><br>
                        <strong>IBAN: </strong> <?= COMPANY_IBAN ?><br>
                        <strong>Açıklama:</strong> OXWARE-LIS + e-posta adresiniz
                    </div>
                    <div class="alert alert-info" style="margin-top:12px;font-size:.85rem;">
                        <strong>Önemli:</strong> Açıklama alanına <code class="code">OXWARE-LIS <?= $user ? e($user['email']) : 'email@adresiniz.com' ?></code>
                        yazmanız işlem sürecini hızlandırır.
                    </div>
                </div>

                <div class="form-group">
                    <label class="form-label" for="receipt_note">Ek Not <span style="font-weight:400;color:var(--text-dim)">(isteğe bağlı)</span></label>
                    <textarea
                        id="receipt_note"
                        name="receipt_note"
                        class="form-control"
                        rows="3"
                        placeholder="Havale referans numarası veya ek bilgi..."
                    ><?= e($_POST['receipt_note'] ?? '') ?></textarea>
                </div>

                <button type="submit" class="btn btn-success btn-block btn-lg">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                        <polyline points="20 6 9 17 4 12"/>
                    </svg>
                    Havaleyi Yaptım — Talebi Gönder
                </button>

                <p style="text-align:center;margin-top:14px;font-size:.8rem;color:var(--text-dim);">
                    Bu butona tıklayarak ödeme talebinizi sisteme kaydetmiş olursunuz.<br>
                    Havaleinizi yaptıktan sonra en kısa sürede lisansınız iletilir.
                </p>
            </form>
        </div>

    </div>
<?php endif; ?>

</div>

<!-- Footer -->
<footer>
    <div class="container">
        <div class="footer-bottom">
            <span>&copy; <?= date('Y') ?> <?= COMPANY_NAME ?>. Tüm hakları saklıdır.</span>
            <span>
                <a href="<?= GITHUB_REPO ?>" target="_blank" rel="noopener">GitHub</a>
                &nbsp;·&nbsp;
                <a href="https://wa.me/<?= WHATSAPP_SUPPORT ?>" target="_blank" rel="noopener">Destek: <?= WHATSAPP_SUPPORT ?></a>
            </span>
        </div>
    </div>
</footer>

<script src="/assets/main.js"></script>
</body>
</html>
