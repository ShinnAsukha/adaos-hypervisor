"""
OXware Çok Kullanıcı Yönetim Modülü
─────────────────────────────────────
Kullanıcılar /var/lib/oxware/users.json dosyasında saklanır.
Admin (tek kullanıcı) credentials.py ile yönetilir.
Ek kullanıcılar bu modül ile eklenir.
"""

import os
import json
import time
import secrets
import hashlib
import config

USERS_FILE = os.path.join(config.DATA_DIR, "users.json")


def _load() -> dict:
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"users": {}}


def _save(data: dict):
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(USERS_FILE, 0o600)


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}${h.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$", 1)
        new_h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return secrets.compare_digest(h, new_h.hex())
    except Exception:
        return False


def list_users() -> list:
    """Tüm kullanıcıları döndür (password_hash hariç)."""
    data = _load()
    users = []
    for username, info in data.get("users", {}).items():
        users.append({
            "username": username,
            "role": info.get("role", "viewer"),
            "created": info.get("created"),
            "last_login": info.get("last_login"),
        })
    return users


def add_user(username: str, password: str, role: str = "viewer") -> dict:
    """Yeni kullanıcı ekle."""
    if not username or len(username) < 2:
        raise ValueError("Kullanıcı adı en az 2 karakter olmalı")
    if len(password) < 8:
        raise ValueError("Şifre en az 8 karakter olmalı")
    valid_roles = {"viewer", "operator", "administrator"}
    if role not in valid_roles:
        raise ValueError(f"Geçersiz rol. Kabul edilenler: {', '.join(valid_roles)}")

    data = _load()
    if "users" not in data:
        data["users"] = {}
    if username in data["users"]:
        raise ValueError(f"Kullanıcı zaten mevcut: {username}")

    data["users"][username] = {
        "password_hash": _hash_password(password),
        "role": role,
        "created": time.time(),
    }
    _save(data)
    return {"username": username, "role": role, "created": data["users"][username]["created"]}


def delete_user(username: str):
    """Kullanıcı sil."""
    data = _load()
    if username not in data.get("users", {}):
        raise KeyError(f"Kullanıcı bulunamadı: {username}")
    del data["users"][username]
    _save(data)


def update_user_role(username: str, role: str):
    """Kullanıcı rolünü güncelle."""
    valid_roles = {"viewer", "operator", "administrator"}
    if role not in valid_roles:
        raise ValueError(f"Geçersiz rol: {role}")
    data = _load()
    if username not in data.get("users", {}):
        raise KeyError(f"Kullanıcı bulunamadı: {username}")
    data["users"][username]["role"] = role
    _save(data)


def verify_user(username: str, password: str) -> bool:
    """Kullanıcı şifresini doğrula."""
    data = _load()
    user = data.get("users", {}).get(username)
    if not user:
        return False
    return _verify_password(password, user.get("password_hash", ""))


def get_user_role(username: str) -> str:
    """Kullanıcının rolünü döndür."""
    data = _load()
    user = data.get("users", {}).get(username)
    return user.get("role", "viewer") if user else "viewer"
