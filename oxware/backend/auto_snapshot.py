"""
auto_snapshot.py — Otomatik günlük VM snapshot + X-gün temizleme.
Yapılandırma: /var/lib/oxware/auto_snapshot_config.json
  {
    "enabled": true,
    "hour": 2,          // her gün kaçta (0-23)
    "minute": 0,
    "keep_days": 7,     // kaç günlük snapshot saklanacak
    "vm_filter": []     // boşsa tüm VM'ler, doluysa sadece bunlar
  }
"""

import json
import logging
import os
import subprocess
import threading
import time
from datetime import datetime, timedelta

log = logging.getLogger("oxware.auto_snapshot")

CONFIG_PATH = "/var/lib/oxware/auto_snapshot_config.json"
_lock       = threading.Lock()

_DEFAULT_CONFIG = {
    "enabled":   True,
    "hour":      2,
    "minute":    0,
    "keep_days": 7,
    "vm_filter": [],
}


# ---------------------------------------------------------------------------
# Config I/O
# ---------------------------------------------------------------------------

def _load_config():
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            # Merge defaults
            return {**_DEFAULT_CONFIG, **cfg}
    except Exception as e:
        log.error("_load_config hatası: %s", e)
    return dict(_DEFAULT_CONFIG)


def _save_config(cfg):
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        os.replace(tmp, CONFIG_PATH)
    except Exception as e:
        log.error("_save_config hatası: %s", e)


def get_config():
    return _load_config()


def update_config(**kwargs):
    with _lock:
        cfg = _load_config()
        for k, v in kwargs.items():
            if k in _DEFAULT_CONFIG:
                cfg[k] = v
        _save_config(cfg)
    return cfg


# ---------------------------------------------------------------------------
# VM listesi yardımcı
# ---------------------------------------------------------------------------

def _list_vms():
    try:
        out = subprocess.check_output(
            ["virsh", "list", "--all", "--name"],
            stderr=subprocess.DEVNULL, timeout=30
        ).decode("utf-8", errors="replace").strip().splitlines()
        return [v.strip() for v in out if v.strip()]
    except FileNotFoundError:
        log.warning("virsh bulunamadı — auto-snapshot çalışmayacak.")
        return []
    except Exception as e:
        log.error("_list_vms hatası: %s", e)
        return []


# ---------------------------------------------------------------------------
# Snapshot işlemleri
# ---------------------------------------------------------------------------

def _take_snapshot(vm_name):
    ts   = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"oxw-autosnap-{vm_name}-{ts}"
    try:
        result = subprocess.run(
            ["virsh", "snapshot-create-as", vm_name, name,
             "--description", f"OXware auto-snapshot {ts}", "--atomic"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            log.info("auto-snapshot oluşturuldu: %s / %s", vm_name, name)
            return True, name
        else:
            err = result.stderr.strip()
            log.warning("auto-snapshot başarısız: %s — %s", vm_name, err)
            return False, err
    except Exception as e:
        log.error("_take_snapshot hatası (vm=%s): %s", vm_name, e)
        return False, str(e)


def _cleanup_old_snapshots(vm_name, keep_days):
    """keep_days'den eski oxw-autosnap-* snapshot'larını siler."""
    try:
        out = subprocess.check_output(
            ["virsh", "snapshot-list", vm_name, "--name"],
            stderr=subprocess.DEVNULL, timeout=30
        ).decode("utf-8", errors="replace").strip().splitlines()

        cutoff = datetime.now() - timedelta(days=keep_days)
        deleted = 0

        for sname in out:
            sname = sname.strip()
            if not sname.startswith("oxw-autosnap-"):
                continue
            # Parse date from name: oxw-autosnap-VMNAME-YYYYMMDD-HHMMSS
            parts = sname.rsplit("-", 2)  # ['oxw-autosnap-VMNAME', 'YYYYMMDD', 'HHMMSS']
            if len(parts) < 3:
                continue
            try:
                snap_dt = datetime.strptime(parts[-2] + parts[-1], "%Y%m%d%H%M%S")
                if snap_dt < cutoff:
                    r = subprocess.run(
                        ["virsh", "snapshot-delete", vm_name, sname],
                        capture_output=True, timeout=60
                    )
                    if r.returncode == 0:
                        deleted += 1
                        log.info("Eski auto-snapshot silindi: %s / %s", vm_name, sname)
            except Exception as pe:
                log.debug("Tarih ayrıştırma hatası (%s): %s", sname, pe)

        if deleted:
            log.info("cleanup: %s için %d eski snapshot silindi.", vm_name, deleted)
    except Exception as e:
        log.error("_cleanup_old_snapshots hatası (vm=%s): %s", vm_name, e)


# ---------------------------------------------------------------------------
# Toplu çalıştırma
# ---------------------------------------------------------------------------

def run_auto_snapshots():
    """Tüm VM'ler için auto-snapshot alır ve temizler."""
    cfg       = _load_config()
    keep_days = cfg.get("keep_days", 7)
    vm_filter = cfg.get("vm_filter", [])

    all_vms   = _list_vms()
    targets   = [v for v in all_vms if not vm_filter or v in vm_filter]

    log.info("run_auto_snapshots başladı: %d VM hedefleniyor.", len(targets))
    for vm_name in targets:
        _take_snapshot(vm_name)
        _cleanup_old_snapshots(vm_name, keep_days)
    log.info("run_auto_snapshots tamamlandı.")


# ---------------------------------------------------------------------------
# Scheduler thread
# ---------------------------------------------------------------------------

_scheduler_started = False


def _seconds_until_next(hour, minute):
    """Sonraki hedef saate kaç saniye kaldığını hesaplar."""
    now = datetime.now()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


def start_scheduler():
    """
    Daemon thread başlatır.
    Her gün config'deki saat:dakikada auto-snapshot çalıştırır.
    """
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True

    def _loop():
        log.info("auto_snapshot scheduler başladı.")
        while True:
            try:
                cfg = _load_config()
                if not cfg.get("enabled", True):
                    time.sleep(300)
                    continue

                hour   = int(cfg.get("hour", 2))
                minute = int(cfg.get("minute", 0))
                wait   = _seconds_until_next(hour, minute)
                log.info("Sonraki auto-snapshot: %.0f dakika sonra (%02d:%02d).",
                         wait / 60, hour, minute)
                time.sleep(wait)

                # Tekrar okuyarak enabled kontrolü yap
                cfg = _load_config()
                if cfg.get("enabled", True):
                    t = threading.Thread(
                        target=run_auto_snapshots,
                        name="auto-snap-run",
                        daemon=True,
                    )
                    t.start()
            except Exception as e:
                log.error("auto_snapshot loop hatası: %s", e)
                time.sleep(60)

    t = threading.Thread(target=_loop, name="auto-snapshot-scheduler", daemon=True)
    t.start()
    log.info("auto_snapshot scheduler thread başlatıldı.")
    return t
