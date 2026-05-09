<?php
define('SITE_NAME', 'OXware Hypervisor');
define('SITE_URL', 'https://oxware.example.com');
define('LICENSE_PRICE', 20);
define('LICENSE_CURRENCY', 'USD');
define('DB_PATH', __DIR__ . '/../../data/oxware.db');
define('COMPANY_IBAN', 'TR00 0000 0000 0000 0000 0000 00');
define('COMPANY_NAME', 'OXware Teknoloji');
define('COMPANY_ADDRESS', 'İstanbul, Türkiye');
define('WHATSAPP_SUPPORT', '+905439769301');
define('GITHUB_REPO', 'https://github.com/ShinnAsukha/oxware-hypervisor');

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 86400,
        'path'     => '/',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}
