"""
AdaOS Olay Defteri (Event Logger)
Her hypervisor'ın olaylarını JSON formatında kaydeder.
"""

import os
import json
import time
import threading
from datetime import datetime
from pathlib import Path
import config

EVENT_FILE    = os.path.join(config.LOG_DIR, "events.jsonl")
MAX_EVENTS    = 10_000
_lock         = threading.Lock()

LEVELS = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}

CATEGORIES = {
    "vm":      "Sanal Makine",
    "network": "Ağ",
    "storage": "Depolama",
    "system":  "Sistem",
    "auth":    "Kimlik Doğrulama",
    "ai":      "Yapay Zeka",
    "alert":   "Uyarı",
    "provision":"Otomatik Kurulum",
}


def log_event(
    message: str,
    level: str = "INFO",
    category: str = "system",
    details: dict = None,
    vm_id: str = None,
    source: str = "oxware",
):
    """Olayı kaydet."""
    entry = {
        "id":        f"{int(time.time()*1000)}-{os.getpid()}",
        "timestamp": time.time(),
        "datetime":  datetime.now().isoformat(),
        "level":     level.upper(),
        "category":  category,
        "message":   message,
        "source":    source,
    }
    if vm_id:
        entry["vm_id"] = vm_id
    if details:
        entry["details"] = details

    with _lock:
        os.makedirs(os.path.dirname(EVENT_FILE), exist_ok=True)
        with open(EVENT_FILE, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # Konsol çıktısı
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level.upper():8s}] [{category}] {message}")

    return entry


def get_events(
    limit: int = 100,
    level: str = None,
    category: str = None,
    vm_id: str = None,
    since: float = None,
    offset: int = 0,
) -> list:
    """Olayları filtreli getir."""
    if not os.path.exists(EVENT_FILE):
        return []

    events = []
    with open(EVENT_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue

            if level and LEVELS.get(e.get("level", "INFO"), 0) < LEVELS.get(level.upper(), 0):
                continue
            if category and e.get("category") != category:
                continue
            if vm_id and e.get("vm_id") != vm_id:
                continue
            if since and e.get("timestamp", 0) < since:
                continue

            events.append(e)

    # En yeni önce
    events.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    return events[offset:offset + limit]


def get_event_stats() -> dict:
    """Kategori/seviye bazında istatistikler."""
    if not os.path.exists(EVENT_FILE):
        return {}

    stats = {
        "by_level": {},
        "by_category": {},
        "total": 0,
        "last_24h": 0,
    }
    cutoff = time.time() - 86400

    with open(EVENT_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue

            stats["total"] += 1
            lvl = e.get("level", "INFO")
            cat = e.get("category", "system")

            stats["by_level"][lvl] = stats["by_level"].get(lvl, 0) + 1
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

            if e.get("timestamp", 0) > cutoff:
                stats["last_24h"] += 1

    return stats


def clear_old_events(keep_days: int = 30):
    """Eski olayları temizle."""
    if not os.path.exists(EVENT_FILE):
        return 0

    cutoff = time.time() - keep_days * 86400
    kept = []

    with open(EVENT_FILE) as f:
        for line in f:
            try:
                e = json.loads(line.strip())
                if e.get("timestamp", 0) > cutoff:
                    kept.append(line)
            except Exception:
                pass

    removed = 0
    with _lock:
        with open(EVENT_FILE, "w") as f:
            for line in kept:
                f.write(line)
        removed = len(kept)

    return removed


# Kısayol fonksiyonlar
def info(msg, **kw):     log_event(msg, "INFO",     **kw)
def warn(msg, **kw):     log_event(msg, "WARNING",  **kw)
def error(msg, **kw):    log_event(msg, "ERROR",    **kw)
def critical(msg, **kw): log_event(msg, "CRITICAL", **kw)
def vm_event(msg, vm_id, level="INFO", **kw):
    log_event(msg, level, category="vm", vm_id=vm_id, **kw)
