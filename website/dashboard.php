<?php
$page_title = 'Panelim';
require_once __DIR__ . '/includes/auth.php';
require_login();

$user     = current_user();
$licenses = user_licenses((int) $_SESSION['user_id']);

$active  = array_filter($licenses, fn($l) => $l['status'] === 'active');
$pending = array_filter($licenses, fn($l) => $l['status'] === 'pending');

require_once __DIR__ . '/includes/header.php';
?>

<div class="container dashboard-wrap">

    <div class="dashboard-header">
        <h1>Hoş Geldiniz, <?= e($user['name']) ?></h1>
        <p class="text-muted">Lisanslarınızı ve ödeme isteklerinizi buradan yönetebilirsiniz.</p>
    </div>

    <!-- Stats -->
    <div class="stats-row">
        <div class="stat-card">
            <div class="stat-card-label">Toplam Lisans</div>
            <div class="stat-card-value"><?= count($licenses) ?></div>
            <div class="stat-card-sub">Tüm zamanlar</div>
        </div>
        <div class="stat-card">
            <div class="stat-card-label">Aktif Lisans</div>
            <div class="stat-card-value text-green"><?= count($active) ?></div>
            <div class="stat-card-sub">Şu anda geçerli</div>
        </div>
        <div class="stat-card">
            <div class="stat-card-label">Bekleyen Ödeme</div>
            <div class="stat-card-value text-yellow"><?= count($pending) ?></div>
            <div class="stat-card-sub">İnceleniyor</div>
        </div>
        <div class="stat-card">
            <div class="stat-card-label">Hesap Durumu</div>
            <div class="stat-card-value" style="font-size:1.2rem;padding-top:4px;">
                <span class="badge badge-green">Aktif</span>
            </div>
            <div class="stat-card-sub">E-posta doğrulandı</div>
        </div>
    </div>

    <!-- Licenses -->
    <div class="licenses-table-wrap">
        <div class="licenses-table-header">
            <span>Lisanslarım</span>
            <a href="/purchase.php" class="btn btn-primary btn-sm">+ Yeni Lisans Al</a>
        </div>

        <?php if (empty($licenses)): ?>
            <div class="empty-state">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <rect x="2" y="3" width="20" height="14" rx="2"/>
                    <path d="M8 21h8M12 17v4"/>
                </svg>
                <h3>Henüz lisansınız yok</h3>
                <p>İlk lisansınızı satın alarak 7/24 desteğe kavuşun.</p>
                <a href="/purchase.php" class="btn btn-primary">Lisans Satın Al</a>
            </div>
        <?php else: ?>
            <div class="table-wrap" style="border:none;border-radius:0;">
                <table>
                    <thead>
                        <tr>
                            <th>Lisans Kodu</th>
                            <th>Durum</th>
                            <th>Satın Alım Tarihi</th>
                            <th>Bitiş Tarihi</th>
                            <th>Ödeme</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($licenses as $lic): ?>
                        <tr>
                            <td>
                                <?php if ($lic['status'] === 'active'): ?>
                                    <code class="license-code"><?= e($lic['code']) ?></code>
                                <?php else: ?>
                                    <span class="text-muted" style="font-size:.85rem;font-style:italic;">Henüz atanmadı</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php
                                $badge = match($lic['status']) {
                                    'active'   => '<span class="badge badge-green">Aktif</span>',
                                    'pending'  => '<span class="badge badge-yellow">Bekliyor</span>',
                                    'expired'  => '<span class="badge badge-red">Süresi Doldu</span>',
                                    'cancelled'=> '<span class="badge badge-red">İptal</span>',
                                    default    => '<span class="badge">' . e($lic['status']) . '</span>',
                                };
                                echo $badge;
                                ?>
                            </td>
                            <td><?= e(substr($lic['purchased_at'], 0, 10)) ?></td>
                            <td><?= $lic['expires_at'] ? e(substr($lic['expires_at'], 0, 10)) : '<span class="text-muted">—</span>' ?></td>
                            <td><?= $lic['payment_method'] === 'bank_transfer' ? 'Banka Havalesi' : e($lic['payment_method']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>

    <!-- Account Info -->
    <div class="card" style="margin-top:28px;">
        <h3 style="margin-bottom:18px;font-size:1rem;font-weight:700;">Hesap Bilgileri</h3>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;">
            <div>
                <div class="form-label">Ad Soyad</div>
                <div class="fw-600"><?= e($user['name']) ?></div>
            </div>
            <div>
                <div class="form-label">E-posta</div>
                <div class="fw-600"><?= e($user['email']) ?></div>
            </div>
            <div>
                <div class="form-label">Hesap ID</div>
                <div class="fw-600">#<?= (int)$user['id'] ?></div>
            </div>
        </div>
    </div>

    <!-- Support -->
    <div class="alert alert-info" style="margin-top:24px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0">
            <circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>
        </svg>
        <span>
            Ödemenizi yaptıysanız ve lisansınız hâlâ "Bekliyor" ise WhatsApp üzerinden bizimle iletişime geçin:
            <a href="https://wa.me/<?= WHATSAPP_SUPPORT ?>" target="_blank" rel="noopener" class="fw-600">
                <?= WHATSAPP_SUPPORT ?>
            </a>
        </span>
    </div>

</div>

<script src="/assets/main.js"></script>
</body>
</html>
