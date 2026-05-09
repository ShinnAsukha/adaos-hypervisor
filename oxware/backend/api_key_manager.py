"""
api_key_manager.py - API anahtar yönetimi.
Veri: /var/lib/oxware/api_keys.json
"""

import json
import hashlib
import secrets
import uuid
import threading
import time
import os
import logging

log = logging.getLogger("oxware.apikeys")

DATA_PATH = "/var/lib/oxware/api_keys.json"
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


def _hash(key):
    """API key'i SHA-256 ile hash'ler; hex string döndürür."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# API Key işlemleri
# ---------------------------------------------------------------------------

def create_key(username, name, permissions=None, expires_days=None):
    """
    Yeni API key üretir ve kaydeder.
    Döner: {"id": str, "key": "oxw_xxx", "name": str, "created_at": float}
    """
    try:
        raw_key   = "oxw_" + secrets.token_hex(32)
        key_id    = str(uuid.uuid4())
        key_hash  = _hash(raw_key)
        created   = time.time()
        expires   = (created + expires_days * 86400) if expires_days else None

        entry = {
            "id":          key_id,
            "name":        name,
            "username":    username,
            "key_hash":    key_hash,
            "permissions": permissions or [],
            "created_at":  created,
            "expires_at":  expires,
            "last_used":   None,
            "use_count":   0,
            "active":      True,
        }

        with _lock:
            data = _load()
            data[key_id] = entry
            _save(data)

        log.info("create_key: %s için '%s' key oluşturuldu.", username, name)
        return {
            "id":         key_id,
            "key":        raw_key,
            "name":       name,
            "created_at": created,
        }
    except Exception as e:
        log.error("create_key hatası (username=%s): %s", username, e)
        return {}


def validate_key(raw_key):
    """
    Ham key'i doğrular.
    Döner: {"username": str, "permissions": list, "key_id": str} veya None.
    """
    try:
        if not raw_key or not raw_key.startswith("oxw_"):
            return None
        key_hash = _hash(raw_key)
        now = time.time()

        with _lock:
            data = _load()
            for key_id, entry in data.items():
                if entry.get("key_hash") != key_hash:
                    continue
                if not entry.get("active", False):
                    return None
                if entry.get("expires_at") and now > entry["expires_at"]:
                    return None
                # Kullanım istatistiklerini güncelle
                entry["last_used"] = now
                entry["use_count"] = entry.get("use_count", 0) + 1
                _save(data)
                return {
                    "username":    entry["username"],
                    "permissions": entry.get("permissions", []),
                    "key_id":      key_id,
                }
        return None
    except Exception as e:
        log.error("validate_key hatası: %s", e)
        return None


def revoke_key(key_id, username=None):
    """
    Key'i devre dışı bırakır (active=False).
    username verilirse yetki kontrolü yapılır.
    Döner: bool
    """
    try:
        with _lock:
            data = _load()
            entry = data.get(key_id)
            if not entry:
                return False
            if username and entry.get("username") != username:
                log.warning("revoke_key: yetki reddi (key_id=%s, username=%s)", key_id, username)
                return False
            entry["active"] = False
            _save(data)
        log.info("revoke_key: %s devre dışı bırakıldı.", key_id)
        return True
    except Exception as e:
        log.error("revoke_key hatası (key_id=%s): %s", key_id, e)
        return False


def delete_key(key_id):
    """
    Key'i kalıcı olarak siler.
    Döner: bool
    """
    try:
        with _lock:
            data = _load()
            if key_id not in data:
                return False
            del data[key_id]
            _save(data)
        log.info("delete_key: %s silindi.", key_id)
        return True
    except Exception as e:
        log.error("delete_key hatası (key_id=%s): %s", key_id, e)
        return False


def list_keys(username):
    """
    Kullanıcının tüm key'lerini döndürür (key_hash gösterilmez).
    Döner: list of dict
    """
    try:
        with _lock:
            data = _load()
        result = []
        for key_id, entry in data.items():
            if entry.get("username") != username:
                continue
            safe = {k: v for k, v in entry.items() if k != "key_hash"}
            result.append(safe)
        return result
    except Exception as e:
        log.error("list_keys hatası (username=%s): %s", username, e)
        return []


def get_key(key_id):
    """
    Tek key bilgisi döndürür (key_hash gösterilmez).
    Döner: dict veya None
    """
    try:
        with _lock:
            data = _load()
        entry = data.get(key_id)
        if not entry:
            return None
        return {k: v for k, v in entry.items() if k != "key_hash"}
    except Exception as e:
        log.error("get_key hatası (key_id=%s): %s", key_id, e)
        return None
