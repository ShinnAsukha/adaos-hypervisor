#!/usr/bin/env python3
# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy. MIT License.
"""
OXware Dark Site Mode — offline / hava-boşluklu (air-gapped) tek anahtar
───────────────────────────────────────────────────────────────────────
İnternetsiz kurumlar (kamu, savunma, banka, izole VDS) için tek toggle ile
tam offline çalışma. Açıkken:

  - egress_guard        → `enforce`'a ZORLANIR (tüm public çıkış bloklu)
  - App Marketplace     → uzak fetch kapalı; sadece bundled + yerel mirror
  - Template/Cloud image→ uzak indirme kapalı; sadece önbellek + yerel mirror
  - Updater / Telemetry → egress enforce olduğu için zaten susar (is_offline)

Katmanlarla ilişki:
  Dark Site = "niyet" katmanı (offline istiyorum).
  egress_guard = "zorlama" katmanı (socket'te blokla).
  Dark site AÇIK → egress_guard'ı enforce'a çevirir. Bu yüzden apply()
  egress_guard.install()'tan ÖNCE çağrılmalı.

Yapılandırma:
  [darksite] enabled = true            (veya env OXWARE_DARK_SITE=1)
  [darksite] mirror_dir = /var/lib/oxware/mirror   (env OXWARE_MIRROR_DIR)
"""

import os
import logging

log = logging.getLogger("oxware.darksite")

_ENABLED = None                       # None = henüz yüklenmedi
_MIRROR = "/var/lib/oxware/mirror"


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _load() -> None:
    global _ENABLED, _MIRROR
    en = os.environ.get("OXWARE_DARK_SITE", "")
    mirror = os.environ.get("OXWARE_MIRROR_DIR", "")
    try:
        import config as _c
        if en == "":
            en = str(getattr(_c, "DARK_SITE", False))
        if not mirror:
            mirror = getattr(_c, "DARK_SITE_MIRROR", "") or _MIRROR
    except Exception:
        pass
    _ENABLED = _truthy(en)
    _MIRROR = mirror or _MIRROR


def apply() -> bool:
    """Dark site politikasını uygula. egress_guard.install()'tan ÖNCE çağır.
    Açıksa egress modunu enforce'a zorlar (monitor/off dese bile override)."""
    _load()
    if _ENABLED:
        os.environ["OXWARE_EGRESS_MODE"] = "enforce"   # override — offline şart
        log.warning("DARK SITE MODE AKTİF — offline. egress=enforce, "
                    "marketplace/cloud-image uzak fetch kapalı, mirror=%s", _MIRROR)
    return _ENABLED


def is_enabled() -> bool:
    if _ENABLED is None:
        _load()
    return bool(_ENABLED)


def mirror_dir() -> str:
    if _ENABLED is None:
        _load()
    return _MIRROR


def block_remote(feature: str) -> dict:
    """Online-gerektiren işlem için standart offline yanıtı.
    Çağıran modüller bunu doğrudan döndürür (return şekli uyumlu:
    ok/offline/error)."""
    return {
        "ok": False,
        "offline": True,
        "darksite": True,
        "error": "Dark Site Mode aktif — '%s' internet gerektirir, devre dışı. "
                 "Yerel mirror (%s) kullanın veya dark_site'ı kapatın."
                 % (feature, mirror_dir()),
    }


def status() -> dict:
    on = is_enabled()
    return {
        "enabled": on,
        "mirror_dir": mirror_dir(),
        "effects": {
            "egress":               "enforce (forced)" if on else "unchanged",
            "app_marketplace":      "offline (bundled+mirror)" if on else "online",
            "cloud_image_prefetch": "offline (cache+mirror)" if on else "online",
            "updater":              "offline (via egress)" if on else "online",
            "telemetry":            "offline (via egress)" if on else "config-controlled",
        },
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import json
    apply()
    print(json.dumps(status(), indent=2, ensure_ascii=False))
