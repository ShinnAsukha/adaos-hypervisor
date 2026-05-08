"""
AdaOS Şifreli Kimlik Bilgisi Sistemi
─────────────────────────────────────
Dosya konumları:
  /etc/adaos/.auth            — Şifreli kimlik bilgileri (AES-256-CBC)
  /etc/adaos/.passwd_reset    — Şifre sıfırlama dosyası (varsa uygula, sonra sil)

Şifre değiştirme:
  Aşağıdaki formatta /etc/adaos/.passwd_reset dosyası oluşturun:
    USERNAME=yeni_kullanici
    PASSWORD=yeni_sifre
  Servis yeniden başladığında otomatik uygular ve dosyayı siler.

Encryption key: Makine UUID'sinden türetilir (her sunucuya özgü).
"""

import os
import json
import hashlib
import secrets
import time
import struct
from pathlib import Path

AUTH_FILE        = os.environ.get("OXWARE_AUTH_FILE",  os.environ.get("ADAOS_AUTH_FILE",  "/etc/oxware/.auth"))
RESET_FILE       = os.environ.get("OXWARE_RESET_FILE", os.environ.get("ADAOS_RESET_FILE", "/etc/oxware/.passwd_reset"))
SETUP_FLAG_FILE  = "/etc/oxware/.setup_done"

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    _CRYPTO = True
except ImportError:
    _CRYPTO = False


def _machine_key() -> bytes:
    """Makineye özgü şifreleme anahtarı üretir."""
    seeds = []
    for f in ["/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"]:
        try:
            seeds.append(Path(f).read_text().strip())
        except Exception:
            pass
    if not seeds:
        # Fallback: sabit ama tutarlı bir seed
        seeds.append("adaos-fallback-key-2024")
    combined = "|".join(seeds) + "|adaos-v1"
    return hashlib.sha256(combined.encode()).digest()


def _xor_cipher(data: bytes, key: bytes) -> bytes:
    """Kriptografi kütüphanesi yoksa XOR şifreleme."""
    key_bytes = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, key_bytes))


def _encrypt(plaintext: str) -> str:
    key = _machine_key()
    data = plaintext.encode("utf-8")

    if _CRYPTO:
        iv = secrets.token_bytes(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(padded) + enc.finalize()
        return (iv + ct).hex()
    else:
        iv = secrets.token_bytes(16)
        return (iv + _xor_cipher(data, key)).hex()


def _decrypt(hex_data: str) -> str:
    key = _machine_key()
    raw = bytes.fromhex(hex_data)
    iv, ct = raw[:16], raw[16:]

    if _CRYPTO:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")
    else:
        return _xor_cipher(ct, key).decode("utf-8")


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return f"{salt}${h.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$", 1)
        new_h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
        return secrets.compare_digest(h, new_h.hex())
    except Exception:
        return False


def _load_auth() -> dict:
    if not os.path.exists(AUTH_FILE):
        return {}
    try:
        raw = Path(AUTH_FILE).read_text().strip()
        return json.loads(_decrypt(raw))
    except Exception:
        return {}


def _save_auth(data: dict):
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    encrypted = _encrypt(json.dumps(data))
    Path(AUTH_FILE).write_text(encrypted)
    os.chmod(AUTH_FILE, 0o600)


def is_setup_done() -> bool:
    return os.path.exists(SETUP_FLAG_FILE) and os.path.exists(AUTH_FILE)


def first_setup(username: str, password: str):
    """İlk kurulum sırasında kimlik bilgilerini ayarla."""
    if is_setup_done():
        raise RuntimeError("Kurulum zaten tamamlanmış. Şifre değiştirmek için .passwd_reset kullanın.")

    data = {
        "username": username,
        "password_hash": _hash_password(password),
        "created_at": time.time(),
        "last_changed": time.time(),
    }
    _save_auth(data)

    os.makedirs(os.path.dirname(SETUP_FLAG_FILE), exist_ok=True)
    Path(SETUP_FLAG_FILE).write_text(f"setup_completed={time.time()}\n")
    os.chmod(SETUP_FLAG_FILE, 0o600)


def verify_credentials(username: str, password: str) -> bool:
    data = _load_auth()
    if not data:
        return False
    if data.get("username") != username:
        return False
    return _verify_password(password, data.get("password_hash", ""))


def get_username() -> str:
    return _load_auth().get("username", "admin")


def apply_reset_if_exists():
    """
    /etc/adaos/.passwd_reset dosyası varsa şifreyi günceller ve dosyayı siler.
    Servis başlangıcında çağrılmalıdır.

    Dosya formatı:
        USERNAME=yeni_kullanici_adi
        PASSWORD=yeni_sifre
    """
    if not os.path.exists(RESET_FILE):
        return False

    try:
        content = Path(RESET_FILE).read_text().strip()
        params = {}
        for line in content.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                params[k.strip().upper()] = v.strip()

        new_user = params.get("USERNAME", "").strip()
        new_pass = params.get("PASSWORD", "").strip()

        if not new_user or not new_pass:
            raise ValueError("USERNAME veya PASSWORD eksik")

        data = _load_auth()
        data["username"] = new_user
        data["password_hash"] = _hash_password(new_pass)
        data["last_changed"] = time.time()
        _save_auth(data)

        # Dosyayı güvenli şekilde sil
        os.remove(RESET_FILE)
        print(f"[credentials] Şifre sıfırlama uygulandı. Kullanıcı: {new_user}")
        return True

    except Exception as e:
        print(f"[credentials] Sıfırlama dosyası işlenemedi: {e}")
        # Güvenlik için yine de sil
        try:
            os.remove(RESET_FILE)
        except Exception:
            pass
        return False


def change_password(old_password: str, new_password: str) -> bool:
    """Mevcut şifre doğrulanarak yeni şifre ayarla."""
    data = _load_auth()
    if not _verify_password(old_password, data.get("password_hash", "")):
        return False
    data["password_hash"] = _hash_password(new_password)
    data["last_changed"] = time.time()
    _save_auth(data)
    return True


def get_credential_info() -> dict:
    """Şifre bilgilerini döndür (hash olmadan)."""
    data = _load_auth()
    return {
        "username": data.get("username", "—"),
        "created_at": data.get("created_at"),
        "last_changed": data.get("last_changed"),
        "setup_done": is_setup_done(),
    }
