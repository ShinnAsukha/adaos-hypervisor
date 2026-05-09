<?php
$page_title = 'Giriş Yap';
require_once __DIR__ . '/includes/auth.php';

if (is_logged_in()) {
    header('Location: /dashboard.php');
    exit;
}

$errors  = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $email    = $_POST['email']    ?? '';
    $password = $_POST['password'] ?? '';
    $result   = login_user($email, $password);
    if ($result['ok']) {
        $next = isset($_GET['next']) ? filter_var($_GET['next'], FILTER_SANITIZE_URL) : '/dashboard.php';
        // Prevent open redirect
        if (!str_starts_with($next, '/')) $next = '/dashboard.php';
        header('Location: ' . $next);
        exit;
    }
    $errors = $result['errors'];
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
            <h2>Tekrar Hoş Geldiniz</h2>
            <p>OXware hesabınıza giriş yapın</p>
        </div>

        <?php if ($errors): ?>
            <div class="alert alert-error">
                <ul><?php foreach ($errors as $e): ?><li><?= e($e) ?></li><?php endforeach; ?></ul>
            </div>
        <?php endif; ?>

        <form method="POST" action="/login.php<?= isset($_GET['next']) ? '?next=' . urlencode($_GET['next']) : '' ?>" novalidate>
            <?= csrf_field() ?>
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
                    placeholder="Şifrenizi girin"
                    required
                    autocomplete="current-password"
                >
            </div>
            <button type="submit" class="btn btn-primary btn-block btn-lg" style="margin-top:8px;">
                Giriş Yap
            </button>
        </form>

        <div class="auth-divider">veya</div>

        <p style="text-align:center;font-size:.875rem;color:var(--text-muted);">
            Hesabınız yok mu?
            <a href="/register.php" class="fw-600">Kayıt Olun</a>
        </p>
        <p style="text-align:center;margin-top:12px;font-size:.8rem;color:var(--text-dim);">
            Lisans satın almak için hesap gerekmez —
            <a href="/purchase.php">buradan devam edin</a>
        </p>
    </div>
</div>

<script src="/assets/main.js"></script>
</body>
</html>
