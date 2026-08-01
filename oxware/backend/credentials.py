"""
OXware Şifreli Kimlik Bilgisi Sistemi
─────────────────────────────────────
Dosya konumları:
  /etc/oxware/.auth            — Şifreli kimlik bilgileri (AES-256-CBC)
  /etc/oxware/.passwd_reset    — Şifre sıfırlama dosyası (varsa uygula, sonra sil)

Şifre değiştirme:
  Aşağıdaki formatta /etc/oxware/.passwd_reset dosyası oluşturun:
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
from pathlib import Path

AUTH_FILE        = os.environ.get("OXWARE_AUTH_FILE",  os.environ.get("ADAOS_AUTH_FILE",  "/etc/oxware/.auth"))
RESET_FILE       = os.environ.get("OXWARE_RESET_FILE", os.environ.get("ADAOS_RESET_FILE", "/etc/oxware/.passwd_reset"))
SETUP_FLAG_FILE  = "/etc/oxware/.setup_done"
# Username plaintext yedek dosyası — machine-id değişse bile username okunabilir kalır
USERNAME_FILE    = "/etc/oxware/.username"
# Tek-kullanımlık kurulum token'ı — uzaktan (localhost dışı) ilk kurulum için.
# İlk boot'ta üretilir (root-only), başarılı kurulumda silinir.
SETUP_TOKEN_FILE = os.environ.get("OXWARE_SETUP_TOKEN_FILE", "/etc/oxware/setup-token")

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    _CRYPTO = True
except ImportError:
    _CRYPTO = False


_FALLBACK_KEY_FILE = "/etc/oxware/.machine_fallback_key"


def _machine_key() -> bytes:
    """Makineye özgü şifreleme anahtarı üretir."""
    seeds = []
    for f in ["/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"]:
        try:
            seeds.append(Path(f).read_text().strip())
        except Exception:
            pass
    if not seeds:
        # machine-id yoksa: cihaza özel rastgele anahtar üret ve sakla
        try:
            if os.path.exists(_FALLBACK_KEY_FILE):
                seeds.append(Path(_FALLBACK_KEY_FILE).read_text().strip())
            else:
                fallback = secrets.token_hex(32)
                os.makedirs(os.path.dirname(_FALLBACK_KEY_FILE), exist_ok=True)
                Path(_FALLBACK_KEY_FILE).write_text(fallback)
                os.chmod(_FALLBACK_KEY_FILE, 0o600)
                seeds.append(fallback)
        except Exception:
            seeds.append(secrets.token_hex(32))
    combined = "|".join(seeds) + "|oxware-v1"
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
    # Username ayrıca plaintext kaydedilir — machine-id değişse bile okunabilir
    try:
        if data.get("username"):
            Path(USERNAME_FILE).write_text(data["username"])
            os.chmod(USERNAME_FILE, 0o600)
    except Exception:
        pass


def is_setup_done() -> bool:
    # Auth dosyası veya username yedeği varsa setup tamamlanmış sayılır.
    # machine-id değişmiş olsa bile setup sayfası AÇILMAZ.
    if os.path.exists(SETUP_FLAG_FILE) and os.path.exists(AUTH_FILE):
        return True
    # Yedek: username dosyası varsa setup yapılmış ama auth silinmiş/bozulmuş olabilir
    if os.path.exists(USERNAME_FILE) and os.path.exists(AUTH_FILE):
        return True
    return False


def ensure_setup_token() -> str | None:
    """Fresh install (setup bitmemiş): yoksa tek-kullanımlık setup token üret.
    Token'ı döndür (setup bitmişse veya yazılamıyorsa None). root-only 0600."""
    if is_setup_done():
        return None
    try:
        if os.path.exists(SETUP_TOKEN_FILE):
            return Path(SETUP_TOKEN_FILE).read_text().strip()
        tok = secrets.token_urlsafe(24)
        os.makedirs(os.path.dirname(SETUP_TOKEN_FILE), exist_ok=True)
        Path(SETUP_TOKEN_FILE).write_text(tok)
        os.chmod(SETUP_TOKEN_FILE, 0o600)
        return tok
    except OSError:
        return None   # /etc yazılamıyor (non-root/dev) — token yok, localhost setup çalışır


def verify_setup_token(token: str) -> bool:
    """Verilen token dosyadakiyle sabit-zaman eşleşiyor mu."""
    if not token:
        return False
    try:
        if not os.path.exists(SETUP_TOKEN_FILE):
            return False
        stored = Path(SETUP_TOKEN_FILE).read_text().strip()
        if not stored:
            return False
        # compare_digest str girdide non-ASCII olursa TypeError atar → bytes karşılaştır
        # (aksi halde `{"setup_token":"ü"}` 403 yerine 500 döndürüyordu).
        return secrets.compare_digest(token.strip().encode("utf-8"),
                                      stored.encode("utf-8"))
    except (OSError, TypeError, ValueError, UnicodeError):
        return False


def clear_setup_token() -> None:
    """Kurulum bitince token'ı sil (tek kullanımlık)."""
    try:
        if os.path.exists(SETUP_TOKEN_FILE):
            os.remove(SETUP_TOKEN_FILE)
    except OSError:
        pass


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
        # Auth dosyası çözülemedi (machine-id değişmiş olabilir)
        import logging as _log
        _log.getLogger("oxware.credentials").critical(
            "GİRİŞ BAŞARISIZ: .auth dosyası çözülemedi. "
            "machine-id değişmiş olabilir. "
            "Şifreyi sıfırlamak için root olarak: "
            "printf 'USERNAME=%s\\nPASSWORD=yeni_sifre\\n' > /etc/oxware/.passwd_reset && "
            "chmod 600 /etc/oxware/.passwd_reset && systemctl restart oxware",
            username
        )
        return False
    if data.get("username", "").lower() != username.lower():
        return False
    return _verify_password(password, data.get("password_hash", ""))


def get_username() -> str:
    # Önce şifreli auth dosyasından dene
    # NOTE: login her zaman .lower() uygular (api_login satır ~889), bu yüzden
    # burada da normalize ediyoruz — JWT identity her zaman lowercase olduğu için
    # username == get_username() karşılaştırmaları case-mismatch yüzünden "viewer"
    # dönmesin diye. (OXW-RBAC-001 fix)
    data = _load_auth()
    if data.get("username"):
        return data["username"].strip().lower()
    # Şifreli dosya çözülemediyse (machine-id değişmiş olabilir) plaintext yedeğe bak
    try:
        if os.path.exists(USERNAME_FILE):
            uname = Path(USERNAME_FILE).read_text().strip().lower()
            if uname:
                import logging as _log
                _log.getLogger("oxware.credentials").critical(
                    "AUTH DOSYASI ÇÖZÜLEMEDI! machine-id değişmiş olabilir. "
                    "USERNAME_FILE yedeğinden '%s' okundu. "
                    "Şifreyi sıfırlamak için: /etc/oxware/.passwd_reset dosyası oluşturun.",
                    uname
                )
                return uname
    except Exception:
        pass
    return "admin"


def apply_reset_if_exists():
    """
    /etc/oxware/.passwd_reset dosyası varsa şifreyi günceller ve dosyayı siler.
    Servis başlangıcında çağrılmalıdır.

    Dosya formatı:
        USERNAME=yeni_kullanici_adi
        PASSWORD=yeni_sifre
    """
    if not os.path.exists(RESET_FILE):
        return False

    try:
        import stat as _stat
        _st = os.stat(RESET_FILE)

        # Dosya root (uid=0) tarafından oluşturulmuş olmalı
        if _st.st_uid != 0:
            print(f"[credentials] RESET_FILE root'a ait değil (uid={_st.st_uid}) — reddedildi: {RESET_FILE}")
            try:
                os.remove(RESET_FILE)
            except OSError:
                pass
            return False

        # Güvenlik: dosya group/world-readable ise reddet
        if _st.st_mode & (_stat.S_IRWXG | _stat.S_IRWXO):
            print(f"[credentials] RESET_FILE group/world-readable — güvenlik riski, reddedildi: {RESET_FILE}")
            try:
                os.remove(RESET_FILE)
            except OSError:
                pass
            return False
    except OSError:
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

