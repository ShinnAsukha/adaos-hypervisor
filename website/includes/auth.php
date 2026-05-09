<?php
require_once __DIR__ . '/db.php';

/* ---------- CSRF ---------- */

function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_field(): string {
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES) . '">';
}

function verify_csrf(): void {
    $token = $_POST['csrf_token'] ?? '';
    if (!hash_equals(csrf_token(), $token)) {
        http_response_code(403);
        exit('Geçersiz CSRF token.');
    }
}

/* ---------- Auth helpers ---------- */

function is_logged_in(): bool {
    return !empty($_SESSION['user_id']);
}

function current_user(): ?array {
    if (!is_logged_in()) return null;
    static $user = null;
    if ($user) return $user;
    $db   = get_db();
    $stmt = $db->prepare("SELECT id, email, name, verified FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch() ?: null;
    return $user;
}

function require_login(): void {
    if (!is_logged_in()) {
        header('Location: /login.php?next=' . urlencode($_SERVER['REQUEST_URI']));
        exit;
    }
}

/* ---------- Register ---------- */

function register_user(string $name, string $email, string $password): array {
    $name     = trim($name);
    $email    = strtolower(trim($email));
    $errors   = [];

    if (strlen($name) < 2) {
        $errors[] = 'Ad en az 2 karakter olmalıdır.';
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Geçerli bir e-posta adresi giriniz.';
    }
    if (strlen($password) < 8) {
        $errors[] = 'Şifre en az 8 karakter olmalıdır.';
    }

    if ($errors) return ['ok' => false, 'errors' => $errors];

    $db   = get_db();
    $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        return ['ok' => false, 'errors' => ['Bu e-posta adresi zaten kayıtlı.']];
    }

    $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    $stmt = $db->prepare("INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)");
    $stmt->execute([$email, $hash, $name]);
    $id = (int) $db->lastInsertId();

    $_SESSION['user_id']   = $id;
    $_SESSION['user_name'] = $name;
    $_SESSION['user_email']= $email;

    return ['ok' => true, 'user_id' => $id];
}

/* ---------- Login ---------- */

function login_user(string $email, string $password): array {
    $email = strtolower(trim($email));

    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 1) {
        return ['ok' => false, 'errors' => ['E-posta veya şifre hatalı.']];
    }

    $db   = get_db();
    $stmt = $db->prepare("SELECT id, email, name, password_hash FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($password, $user['password_hash'])) {
        return ['ok' => false, 'errors' => ['E-posta veya şifre hatalı.']];
    }

    session_regenerate_id(true);
    $_SESSION['user_id']    = $user['id'];
    $_SESSION['user_name']  = $user['name'];
    $_SESSION['user_email'] = $user['email'];

    return ['ok' => true, 'user_id' => $user['id']];
}

/* ---------- Logout ---------- */

function logout_user(): void {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
}

/* ---------- Licenses ---------- */

function user_licenses(int $user_id): array {
    $db   = get_db();
    $stmt = $db->prepare(
        "SELECT * FROM licenses WHERE user_id = ? ORDER BY purchased_at DESC"
    );
    $stmt->execute([$user_id]);
    return $stmt->fetchAll();
}

/* ---------- Payment request ---------- */

function create_payment_request(array $data): int {
    $db   = get_db();
    $stmt = $db->prepare(
        "INSERT INTO payment_requests (user_id, amount, method, iban_name, receipt_note)
         VALUES (:user_id, :amount, :method, :iban_name, :receipt_note)"
    );
    $stmt->execute([
        ':user_id'      => $data['user_id']      ?? null,
        ':amount'       => LICENSE_PRICE,
        ':method'       => 'bank_transfer',
        ':iban_name'    => $data['iban_name']     ?? '',
        ':receipt_note' => $data['receipt_note']  ?? '',
    ]);
    return (int) $db->lastInsertId();
}

/* ---------- XSS helper ---------- */

function e(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
