"""
OXware Lisans Yöneticisi
─────────────────────────
Lisans kodlarını GitHub üzerinden doğrular.
Repo: https://github.com/ShinnAsukha/oxware-license
"""
import os
import json
import hashlib
import logging
import time
from pathlib import Path

log = logging.getLogger("oxware.license")

LICENSE_FILE    = "/var/lib/oxware/license.json"
LICENSE_REPO    = "ShinnAsukha/oxware-license"
LICENSE_RAW_URL = f"https://raw.githubusercontent.com/{LICENSE_REPO}/main/.licensecodes"

# Şifreleme anahtarı — paroladan SHA-256 ile türetilmiş, Fernet için base64
_PASSPHRASE = b"OXware-License-Secret-2024-ShinnAsukha"

_codes_cache: list = []
_cache_ts: float = 0.0
CACHE_TTL = 3600  # 1 saat

def _get_fernet():
    try:
        from cryptography.fernet import Fernet
        import base64
        key_bytes = hashlib.sha256(_PASSPHRASE).digest()  # 32 bytes
        key = base64.urlsafe_b64encode(key_bytes)
        return Fernet(key)
    except Exception as e:
        log.warning("Fernet yüklenemedi: %s", e)
        return None

def _fetch_license_codes() -> list:
    """GitHub'dan şifreli .licensecodes dosyasını çek, Fernet ile çöz."""
    global _codes_cache, _cache_ts

    # Cache geçerliyse tekrar çekme
    if _codes_cache and (time.time() - _cache_ts) < CACHE_TTL:
        return _codes_cache

    try:
        import urllib.request
        req = urllib.request.Request(
            LICENSE_RAW_URL,
            headers={"User-Agent": "OXware/2.1", "Cache-Control": "no-cache"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            encrypted_data = resp.read().strip()

        fernet = _get_fernet()
        if not fernet:
            log.error("Fernet başlatılamadı")
            return []

        decrypted = fernet.decrypt(encrypted_data)
        codes = [line.strip() for line in decrypted.decode("utf-8").splitlines()
                 if line.strip() and line.strip().startswith("OXWARE-")]

        _codes_cache = codes
        _cache_ts = time.time()
        log.info("Lisans listesi güncellendi: %d kod", len(codes))
        return codes

    except Exception as e:
        log.warning("Lisans dosyası alınamadı (%s): %s", LICENSE_RAW_URL, e)
        return _codes_cache  # cache varsa eski listeyi döndür

def validate_license(code: str) -> dict:
    """Lisans kodunu doğrula."""
    code = code.strip().upper()
    if not code.startswith("OXWARE-"):
        return {"valid": False, "error": "Geçersiz lisans kodu formatı"}

    # Format check: OXWARE-XXXX-XXXX-XXXX-XXXX
    parts = code.split("-")
    if len(parts) != 5:
        return {"valid": False, "error": "Geçersiz lisans kodu formatı"}

    codes = _fetch_license_codes()
    if not codes:
        return {"valid": False, "error": "Lisans sunucusuna bağlanılamadı"}

    if code in codes:
        # Kaydet
        _save_license(code)
        return {"valid": True, "code": code, "message": "Lisans başarıyla doğrulandı"}
    else:
        return {"valid": False, "error": "Lisans kodu bulunamadı"}

def _save_license(code: str):
    """Lisans bilgisini yerel olarak kaydet."""
    try:
        os.makedirs(os.path.dirname(LICENSE_FILE), exist_ok=True)
        data = {
            "active": True,
            "code_hash": hashlib.sha256(code.encode()).hexdigest(),
            "code_prefix": code[:14],  # OXWARE-XXXX sadece
            "activated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        with open(LICENSE_FILE, "w") as f:
            json.dump(data, f, indent=2)
        try:
            os.chmod(LICENSE_FILE, 0o600)
        except Exception:
            pass
    except Exception as e:
        log.error("Lisans kaydetme hatası: %s", e)

def get_license_status() -> dict:
    """Mevcut lisans durumunu döndür."""
    try:
        if os.path.exists(LICENSE_FILE):
            with open(LICENSE_FILE) as f:
                data = json.load(f)
            if data.get("active"):
                return {
                    "active": True,
                    "code_prefix": data.get("code_prefix", ""),
                    "activated_at": data.get("activated_at", ""),
                }
    except Exception as e:
        log.warning("Lisans okuma hatası: %s", e)
    return {"active": False}

def deactivate_license() -> dict:
    """Lisansı deaktive et."""
    try:
        if os.path.exists(LICENSE_FILE):
            with open(LICENSE_FILE) as f:
                data = json.load(f)
            data["active"] = False
            with open(LICENSE_FILE, "w") as f:
                json.dump(data, f, indent=2)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}
