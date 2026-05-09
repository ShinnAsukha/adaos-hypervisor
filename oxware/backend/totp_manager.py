"""
totp_manager.py - Kullanıcı bazlı TOTP (Time-based One-Time Password) 2FA yönetimi.
Veri: /var/lib/oxware/totp_data.json
pyotp yüklü değilse graceful fallback.
"""

try:
    import pyotp
    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False

import json
import os
import time
import threading
import logging

log = logging.getLogger("oxware.totp")

DATA_PATH = "/var/lib/oxware/totp_data.json"
_ISSUER   = "OXware Hypervisor"
_lock     = threading.Lock()


# ---------------------------------------------------------------------------
# Dosya I/O
# ---------------------------------------------------------------------------

def _load():
    """JSON dosyasını yükler; yoksa boş dict döndürür."""
    try:
        if os.path.exists(DATA_PATH):
            with open(DATA_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        log.error("_load hatası: %s", e)
    return {}


def _save(data):
    """JSON dosyasını atomik yazar."""
    try:
        os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
        tmp = DATA_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, DATA_PATH)
    except Exception as e:
        log.error("_save hatası: %s", e)


# ---------------------------------------------------------------------------
# TOTP yönetimi
# ---------------------------------------------------------------------------

def setup_totp(username):
    """
    Kullanıcı için yeni TOTP secret üretir (henüz etkin değil).
    Döner: {"secret": str, "uri": str, "available": True}
    pyotp yoksa: {"available": False, "error": "pyotp not installed"}
    """
    if not PYOTP_AVAILABLE:
        log.warning("setup_totp: pyotp yok.")
        return {"available": False, "error": "pyotp not installed"}
    try:
        secret = pyotp.random_base32()
        totp   = pyotp.TOTP(secret)
        uri    = totp.provisioning_uri(name=username, issuer_name=_ISSUER)

        with _lock:
            data = _load()
            data[username] = {
                "secret":     secret,
                "enabled":    False,
                "created_at": time.time(),
            }
            _save(data)

        log.info("setup_totp: %s için yeni secret oluşturuldu.", username)
        return {"secret": secret, "uri": uri, "available": True}
    except Exception as e:
        log.error("setup_totp hatası (username=%s): %s", username, e)
        return {"available": False, "error": str(e)}


def verify_totp(username, code):
    """
    Kullanıcının TOTP kodunu doğrular.
    pyotp yoksa veya kullanıcı kayıtlı değilse False döndürür.
    window=1 → ±1 periyot (30 saniyelik) tolerans.
    """
    if not PYOTP_AVAILABLE:
        return False
    try:
        with _lock:
            data = _load()
        entry = data.get(username)
        if not entry or not entry.get("secret"):
            return False
        totp = pyotp.TOTP(entry["secret"])
        return totp.verify(str(code), valid_window=1)
    except Exception as e:
        log.error("verify_totp hatası (username=%s): %s", username, e)
        return False


def enable_totp(username, code):
    """
    Kodu doğrulayıp TOTP'u etkinleştirir.
    Döner: True (başarı) / False (kod yanlış veya hata)
    """
    if not PYOTP_AVAILABLE:
        log.warning("enable_totp: pyotp yok.")
        return False
    try:
        if not verify_totp(username, code):
            log.warning("enable_totp: geçersiz kod (username=%s).", username)
            return False
        with _lock:
            data = _load()
            if username not in data:
                log.warning("enable_totp: kullanıcı bulunamadı (%s).", username)
                return False
            data[username]["enabled"] = True
            _save(data)
        log.info("enable_totp: %s için TOTP etkinleştirildi.", username)
        return True
    except Exception as e:
        log.error("enable_totp hatası (username=%s): %s", username, e)
        return False


def disable_totp(username):
    """
    Kullanıcının TOTP'unu devre dışı bırakır.
    Döner: True (başarı) / False (hata veya kullanıcı bulunamadı)
    """
    try:
        with _lock:
            data = _load()
            if username not in data:
                log.warning("disable_totp: kullanıcı bulunamadı (%s).", username)
                return False
            data[username]["enabled"] = False
            _save(data)
        log.info("disable_totp: %s için TOTP devre dışı.", username)
        return True
    except Exception as e:
        log.error("disable_totp hatası (username=%s): %s", username, e)
        return False


def is_enabled(username):
    """Kullanıcı için TOTP etkin mi? bool döndürür."""
    try:
        with _lock:
            data = _load()
        entry = data.get(username)
        if not entry:
            return False
        return bool(entry.get("enabled", False))
    except Exception as e:
        log.error("is_enabled hatası (username=%s): %s", username, e)
        return False


def get_status(username):
    """
    Kullanıcı TOTP durumunu döndürür.
    {"enabled": bool, "available": bool}
    """
    return {
        "enabled":   is_enabled(username),
        "available": PYOTP_AVAILABLE,
    }
