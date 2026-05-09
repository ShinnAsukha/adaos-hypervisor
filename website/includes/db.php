<?php
require_once __DIR__ . '/config.php';

function get_db(): PDO {
    static $pdo = null;
    if ($pdo !== null) return $pdo;

    $dir = dirname(DB_PATH);
    if (!is_dir($dir)) {
        mkdir($dir, 0750, true);
    }

    $pdo = new PDO('sqlite:' . DB_PATH, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    $pdo->exec("PRAGMA journal_mode = WAL;");
    $pdo->exec("PRAGMA foreign_keys = ON;");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            email        TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            name         TEXT NOT NULL,
            created_at   DATETIME DEFAULT (datetime('now')),
            verified     INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS licenses (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code           TEXT NOT NULL UNIQUE,
            status         TEXT NOT NULL DEFAULT 'pending',
            purchased_at   DATETIME DEFAULT (datetime('now')),
            expires_at     DATETIME,
            payment_method TEXT DEFAULT 'bank_transfer'
        );

        CREATE TABLE IF NOT EXISTS payment_requests (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
            amount       REAL NOT NULL,
            method       TEXT NOT NULL DEFAULT 'bank_transfer',
            iban_name    TEXT,
            receipt_note TEXT,
            status       TEXT NOT NULL DEFAULT 'pending',
            created_at   DATETIME DEFAULT (datetime('now'))
        );
    ");

    return $pdo;
}
