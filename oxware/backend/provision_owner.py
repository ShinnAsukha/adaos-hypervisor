#!/usr/bin/env python3
# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy. MIT License.
"""
Provisioning sahiplik kaydı — bayi/müşteri izolasyonu (tenant scoping)
──────────────────────────────────────────────────────────────────────
Sorun: /api/provision/* uçları X-API-Key ile kimlik doğruluyor ama anahtarın
KİMİN olduğu hiçbir yerde VM ile karşılaştırılmıyordu. Bayi A'nın anahtarı,
müşteri B'nin VM UUID'sini bilirse (veya denerse) o VM'i silebiliyor,
reinstall edip diskini uçurabiliyor, vault'taki root şifresini okuyabiliyor
ya da 5 dakikalık konsol linki üretip klavye erişimi alabiliyordu.

Bu modül `vm_id -> owner` eşlemesini tutar ve erişimi kontrol eder.

GEÇİŞ POLİTİKASI (yükseltmede kimseyi kırmamak için):
  - Kayıtlı sahibi OLAN VM  → sahip eşleşmeli, aksi halde REDDET.  ← asıl düzeltme
  - Kayıtlı sahibi OLMAYAN VM (yükseltmeden önce oluşturulmuş) → İZİN VER,
    uyarı logla. Böylece mevcut WHMCS/WISECP entegrasyonları kesintiye uğramaz.
  - `[provision] enforce_owner = true` yapılınca sahipsiz VM'ler de reddedilir
    (operatör kayıtları doldurduktan sonra tam sıkılaştırma).

`all` iznine sahip anahtarlar (ana operatör paneli) her zaman geçer.
"""

from __future__ import annotations

import os
import json
import time
import logging
import threading

log = logging.getLogger("oxware.provision_owner")

_lock = threading.RLock()


def _store_path() -> str:
    try:
        import config
        base = config.DATA_DIR
    except Exception:
        base = os.environ.get("OXWARE_DATA_DIR", "/var/lib/oxware")
    return os.environ.get("OXWARE_PROVISION_OWNERS",
                          os.path.join(base, "provision_owners.json"))


def _load() -> dict:
    try:
        p = _store_path()
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
    except (OSError, ValueError) as e:
        log.warning("provision_owners okunamadı: %s", e)
    return {}


def _save(data: dict) -> None:
    p = _store_path()
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, p)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    except OSError as e:
        log.warning("provision_owners yazılamadı: %s", e)


def _enforce_unowned() -> bool:
    """Sahipsiz (legacy) VM'ler de reddedilsin mi?"""
    env = os.environ.get("OXWARE_PROVISION_ENFORCE_OWNER", "")
    if env:
        return env.strip().lower() in ("1", "true", "yes", "on")
    try:
        import config
        return bool(getattr(config, "PROVISION_ENFORCE_OWNER", False))
    except Exception:
        return False


# ── Public API ────────────────────────────────────────────────────────────────

def record(vm_id: str, owner: str) -> None:
    """VM oluşturulurken sahibini kaydet."""
    if not vm_id or not owner:
        return
    with _lock:
        data = _load()
        data[vm_id] = {"owner": owner, "created_at": time.time()}
        _save(data)
    log.info("provision sahibi kaydedildi: %s -> %s", vm_id, owner)


def owner_of(vm_id: str) -> str | None:
    if not vm_id:
        return None
    with _lock:
        entry = _load().get(vm_id)
    if isinstance(entry, dict):
        return entry.get("owner")
    return entry if isinstance(entry, str) else None


def forget(vm_id: str) -> None:
    """VM silinince kaydı da temizle."""
    if not vm_id:
        return
    with _lock:
        data = _load()
        if vm_id in data:
            data.pop(vm_id, None)
            _save(data)


def check(vm_id: str, requester: str, permissions=None) -> bool:
    """`requester` bu VM üzerinde işlem yapabilir mi?"""
    perms = permissions or []
    if "all" in perms:
        return True                      # ana operatör anahtarı
    owner = owner_of(vm_id)
    if owner is None:
        if _enforce_unowned():
            log.warning("provision: sahipsiz VM reddedildi (enforce_owner) vm=%s "
                        "requester=%s", vm_id, requester)
            return False
        # Legacy VM — yükseltmeden önce oluşturulmuş. İzin ver ama izini bırak.
        log.warning("provision: sahibi kayıtlı olmayan VM'e erişim vm=%s requester=%s "
                    "(legacy; sıkılaştırmak için [provision] enforce_owner=true)",
                    vm_id, requester)
        return True
    if owner == requester:
        return True
    log.warning("provision: SAHİPLİK REDDİ vm=%s owner=%s requester=%s",
                vm_id, owner, requester)
    return False


def stats() -> dict:
    with _lock:
        data = _load()
    return {
        "tracked_vms": len(data),
        "enforce_unowned": _enforce_unowned(),
        "store": _store_path(),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(stats(), indent=2, ensure_ascii=False))
