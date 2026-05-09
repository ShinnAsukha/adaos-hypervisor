<?php
require_once __DIR__ . '/auth.php';
$_user = current_user();
$_page = basename($_SERVER['PHP_SELF'], '.php');
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="OXware Hypervisor — Açık kaynak KVM sanallaştırma yönetim paneli. ESXi ve Proxmox'a profesyonel alternatif.">
    <title><?= isset($page_title) ? e($page_title) . ' — ' : '' ?><?= SITE_NAME ?></title>
    <link rel="stylesheet" href="/assets/style.css">
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚙️</text></svg>">
</head>
<body>
<nav class="navbar">
    <div class="nav-container">
        <a href="/index.php" class="nav-brand">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="2" y="3" width="20" height="14" rx="2"/>
                <path d="M8 21h8M12 17v4"/>
                <circle cx="12" cy="10" r="3"/>
                <path d="M12 7v0M12 13v0M9 10H6M18 10h-3"/>
            </svg>
            <span>OXware</span>
            <span class="brand-tag">Hypervisor</span>
        </a>
        <button class="nav-toggle" id="navToggle" aria-label="Menüyü aç/kapat">
            <span></span><span></span><span></span>
        </button>
        <ul class="nav-links" id="navLinks">
            <li><a href="/index.php" class="<?= $_page === 'index' ? 'active' : '' ?>">Ana Sayfa</a></li>
            <li><a href="<?= GITHUB_REPO ?>" target="_blank" rel="noopener">Docs</a></li>
            <li><a href="/purchase.php" class="<?= $_page === 'purchase' ? 'active' : '' ?>">Lisans Al</a></li>
            <?php if ($_user): ?>
                <li><a href="/dashboard.php" class="<?= $_page === 'dashboard' ? 'active' : '' ?>">Panelim</a></li>
                <li>
                    <a href="/logout.php" class="btn btn-outline btn-sm">Çıkış</a>
                </li>
                <li class="nav-user">
                    <span class="avatar"><?= strtoupper(mb_substr($_user['name'], 0, 1)) ?></span>
                    <span><?= e($_user['name']) ?></span>
                </li>
            <?php else: ?>
                <li><a href="/login.php" class="<?= $_page === 'login' ? 'active' : '' ?>">Giriş</a></li>
                <li><a href="/register.php" class="btn btn-primary btn-sm">Kayıt Ol</a></li>
            <?php endif; ?>
        </ul>
    </div>
</nav>
