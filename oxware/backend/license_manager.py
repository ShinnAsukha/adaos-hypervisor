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

LICENSE_FILE = "/var/lib/oxware/license.json"
LICENSE_REPO = "ShinnAsukha/oxware-license"
LICENSE_FILE_PATH = ".licensecodes"
# Bu key license repo'sundaki .licensecodes dosyasını şifrelemek için kullanılır.
# Ayrı bir araçla üretilmiş Fernet anahtarı (base64 URL-safe):
_FERNET_KEY = b"YWRhb3N3YXJlbGljZW5zZWtleS0zMmJ5dGVzLTIwMjQ="  # placeholder - gerçek projede değiştirilecek

_license_cache = None
_cache_ts = 0
CACHE_TTL = 3600  # 1 saat

def _get_fernet():
    try:
        from cryptography.fernet import Fernet
        import base64
        # 32 byte key oluştur
        raw = b"oxware-license-secret-key-2024!!"  # 32 bytes
        key = base64.urlsafe_b64encode(raw)
        return Fernet(key)
    except Exception as e:
        log.warning("Fernet yüklenemedi: %s", e)
        return None

def _fetch_license_codes() -> list:
    """GitHub'dan şifreli lisans dosyasını çek, çöz, kodları döndür."""
    try:
        import urllib.request
        url = f"https://raw.githubusercontent.com/{LICENSE_REPO}/main/{LICENSE_FILE_PATH}"
        req = urllib.request.Request(url, headers={"User-Agent": "OXware/2.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            encrypted_data = resp.read()

        f = _get_fernet()
        if not f:
            return []

        decrypted = f.decrypt(encrypted_data)
        codes = [line.strip() for line in decrypted.decode("utf-8").splitlines() if line.strip()]
        return codes
    except Exception as e:
        log.warning("Lisans dosyası alınamadı: %s", e)
        return []

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
