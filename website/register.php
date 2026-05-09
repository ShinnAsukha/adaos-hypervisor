<?php
$page_title = 'Kayıt Ol';
require_once __DIR__ . '/includes/auth.php';

if (is_logged_in()) {
    header('Location: /dashboard.php');
    exit;
}

$errors  = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $name     = trim($_POST['name']     ?? '');
    $email    = trim($_POST['email']    ?? '');
    $password = $_POST['password']      ?? '';
    $confirm  = $_POST['password_conf'] ?? '';

    if ($password !== $confirm) {
        $errors[] = 'Şifreler eşleşmiyor.';
    } else {
        $result = register_user($name, $email, $password);
        if ($result['ok']) {
            header('Location: /dashboard.php');
            exit;
        }
        $errors = $result['errors'];
    }
}

require_once __DIR__ . '/includes/header.php';
?>

<div class="auth-wrap">
    <div class="auth-card">
        <div class="auth-logo">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                <rect x="2" y="3" width="20" height="14" rx="2"/>
                <path d="M8 21h8M12 17v4"/>
                <circle cx="12" cy="10" r="3"/>
            </svg>
            <h2>Hesap Oluştur</h2>
            <p>OXware'e ücretsiz kaydolun</p>
        </div>

        <?php if ($errors): ?>
            <div class="alert alert-error">
                <ul><?php foreach ($errors as $e): ?><li><?= e($e) ?></li><?php endforeach; ?></ul>
            </div>
        <?php endif; ?>

        <form method="POST" action="/register.php" novalidate>
            <?= csrf_field() ?>
            <div class="form-group">
                <label class="form-label" for="name">Ad Soyad</label>
                <input
                    type="text"
                    id="name"
                    name="name"
                    class="form-control"
                    placeholder="Adınız Soyadınız"
                    value="<?= e($_POST['name'] ?? '') ?>"
                    required
                    autocomplete="name"
                >
            </div>
            <div class="form-group">
                <label class="form-label" for="email">E-posta Adresi</label>
                <input
                    type="email"
                    id="email"
                    name="email"
                    class="form-control"
                    placeholder="ornek@email.com"
                    value="<?= e($_POST['email'] ?? '') ?>"
                    required
                    autocomplete="email"
                >
            </div>
            <div class="form-group">
                <label class="form-label" for="password">Şifre</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    class="form-control"
                    placeholder="En az 8 karakter"
                    required
                    autocomplete="new-password"
                >
                <div class="form-text">En az 8 karakter olmalıdır.</div>
            </div>
            <div class="form-group">
                <label class="form-label" for="password_conf">Şifre Tekrar</label>
                <input
                    type="password"
                    id="password_conf"
                    name="password_conf"
                    class="form-control"
                    placeholder="Şifrenizi tekrar girin"
                    required
                    autocomplete="new-password"
                >
            </div>
            <button type="submit" class="btn btn-primary btn-block btn-lg" style="margin-top:8px;">
                Hesap Oluştur
            </button>
        </form>

        <div class="auth-divider">veya</div>

        <p style="text-align:center;font-size:.875rem;color:var(--text-muted);">
            Zaten hesabınız var mı?
            <a href="/login.php" class="fw-600">Giriş Yapın</a>
        </p>
    </div>
</div>

<script src="/assets/main.js"></script>
</body>
</html>
