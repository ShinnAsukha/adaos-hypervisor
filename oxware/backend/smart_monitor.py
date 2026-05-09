"""
smart_monitor.py — SMART disk health monitoring via smartctl
OXware Hypervisor backend module
"""

import subprocess
import json
import logging
import threading
import time
import os

log = logging.getLogger("oxware.smart")

_lock = threading.Lock()
_cache = {}          # {device: {"data": {...}, "ts": float}}
CACHE_TTL = 300      # seconds


# ---------------------------------------------------------------------------
# Device enumeration
# ---------------------------------------------------------------------------

def list_devices():
    """
    Return a list of block devices (type == "disk") via lsblk -J.

    Returns:
        list[dict]: [{"device": "/dev/sda", "model": "...", "size": "..."}]
    """
    try:
        result = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,TYPE,SIZE,MODEL"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            log.warning("lsblk failed: %s", result.stderr.strip())
            return []

        data = json.loads(result.stdout)
        devices = []
        for dev in data.get("blockdevices", []):
            if dev.get("type") == "disk":
                devices.append({
                    "device": f"/dev/{dev.get('name', '')}",
                    "model":  (dev.get("model") or "").strip(),
                    "size":   dev.get("size", ""),
                })
        return devices
    except FileNotFoundError:
        log.error("lsblk not found")
        return []
    except Exception as exc:
        log.exception("list_devices error: %s", exc)
        return []


# ---------------------------------------------------------------------------
# SMART data retrieval
# ---------------------------------------------------------------------------

def get_smart_data(device):
    """
    Retrieve SMART data for *device* using ``smartctl -A -H -j``.

    Returns a dict with keys:
        device, health, temperature, power_on_hours,
        reallocated_sectors, pending_sectors, raw_data
    """
    now = time.time()

    with _lock:
        cached = _cache.get(device)
        if cached and (now - cached["ts"]) < CACHE_TTL:
            return cached["data"]

    try:
        result = subprocess.run(
            ["smartctl", "-A", "-H", "-j", device],
            capture_output=True, text=True, timeout=30
        )
        # smartctl returns non-zero even on partial success; parse anyway
        raw = json.loads(result.stdout)
    except FileNotFoundError:
        log.error("smartctl not found — install smartmontools")
        return _unknown_entry(device)
    except json.JSONDecodeError as exc:
        log.warning("smartctl JSON parse error for %s: %s", device, exc)
        return _unknown_entry(device)
    except Exception as exc:
        log.exception("get_smart_data(%s) error: %s", device, exc)
        return _unknown_entry(device)

    # Health status
    health_obj = raw.get("smart_status", {})
    if health_obj.get("passed") is True:
        health = "PASSED"
    elif health_obj.get("passed") is False:
        health = "FAILED"
    else:
        health = "UNKNOWN"

    # Temperature
    temp = None
    temp_obj = raw.get("temperature", {})
    if isinstance(temp_obj, dict):
        temp = temp_obj.get("current")
    if temp is None:
        # Fallback: look in ata_smart_attributes
        for attr in raw.get("ata_smart_attributes", {}).get("table", []):
            if attr.get("id") == 194:
                temp = attr.get("raw", {}).get("value")
                break

    # Power-on hours
    poh = None
    poh_obj = raw.get("power_on_time", {})
    if isinstance(poh_obj, dict):
        poh = poh_obj.get("hours")

    def _attr_raw(attr_id):
        for attr in raw.get("ata_smart_attributes", {}).get("table", []):
            if attr.get("id") == attr_id:
                v = attr.get("raw", {}).get("value")
                try:
                    return int(v)
                except (TypeError, ValueError):
                    return 0
        return 0

    reallocated = _attr_raw(5)
    pending = _attr_raw(197)

    entry = {
        "device":             device,
        "health":             health,
        "temperature":        int(temp) if temp is not None else None,
        "power_on_hours":     int(poh) if poh is not None else None,
        "reallocated_sectors": reallocated,
        "pending_sectors":    pending,
        "raw_data":           raw,
    }

    with _lock:
        _cache[device] = {"data": entry, "ts": now}

    return entry


def _unknown_entry(device):
    return {
        "device":             device,
        "health":             "UNKNOWN",
        "temperature":        None,
        "power_on_hours":     None,
        "reallocated_sectors": 0,
        "pending_sectors":    0,
        "raw_data":           {},
    }


# ---------------------------------------------------------------------------
# Aggregate health
# ---------------------------------------------------------------------------

def get_all_devices_health():
    """
    Return health summary for every detected disk.

    Status rules:
        critical — FAILED, or reallocated_sectors > 0, or pending_sectors > 0
        warning  — temperature > 50
        ok       — everything else
    """
    devices = list_devices()
    results = []
    for dev_info in devices:
        device = dev_info["device"]
        data = get_smart_data(device)

        health = data.get("health", "UNKNOWN")
        realloc = data.get("reallocated_sectors", 0) or 0
        pending = data.get("pending_sectors", 0) or 0
        temp = data.get("temperature")

        if health == "FAILED" or realloc > 0 or pending > 0:
            status = "critical"
        elif temp is not None and temp > 50:
            status = "warning"
        else:
            status = "ok"

        results.append({
            "device":      device,
            "model":       dev_info.get("model", ""),
            "size":        dev_info.get("size", ""),
            "health":      health,
            "temperature": temp,
            "status":      status,
        })

    return results


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def check_and_alert():
    """Check all disks and send notifications for warning / critical states."""
    try:
        from notifications import send_alert  # type: ignore
        _has_notifications = True
    except ImportError:
        _has_notifications = False
        log.debug("notifications module not available — skipping alerts")

    health_list = get_all_devices_health()
    for entry in health_list:
        if entry["status"] in ("warning", "critical"):
            msg = (
                f"Disk {entry['device']} [{entry.get('model', '')}] "
                f"status={entry['status']}, health={entry['health']}, "
                f"temp={entry['temperature']}°C, "
                f"reallocated={entry.get('reallocated_sectors', 0)}, "
                f"pending={entry.get('pending_sectors', 0)}"
            )
            log.warning(msg)
            if _has_notifications:
                try:
                    send_alert(
                        level=entry["status"],
                        title=f"SMART Alert: {entry['device']}",
                        message=msg,
                        source="smart_monitor",
                    )
                except Exception as exc:
                    log.error("Failed to send notification: %s", exc)


# ---------------------------------------------------------------------------
# Background monitoring thread
# ---------------------------------------------------------------------------

def start_monitoring(interval=3600):
    """
    Start a daemon thread that calls :func:`check_and_alert` every
    *interval* seconds.
    """
    def _worker():
        log.info("SMART monitoring thread started (interval=%ds)", interval)
        while True:
            try:
                check_and_alert()
            except Exception as exc:
                log.exception("SMART monitor loop error: %s", exc)
            time.sleep(interval)

    t = threading.Thread(target=_worker, daemon=True, name="smart-monitor")
    t.start()
    return t


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def get_summary():
    """
    Return disk health counts.

    Returns:
        dict: {"total_disks": int, "healthy": int, "warning": int,
               "critical": int, "unknown": int}
    """
    health_list = get_all_devices_health()
    summary = {"total_disks": len(health_list), "healthy": 0, "warning": 0,
               "critical": 0, "unknown": 0}
    for entry in health_list:
        s = entry.get("status", "ok")
        h = entry.get("health", "UNKNOWN")
        if s == "critical":
            summary["critical"] += 1
        elif s == "warning":
            summary["warning"] += 1
        elif h == "UNKNOWN":
            summary["unknown"] += 1
        else:
            summary["healthy"] += 1
    return summary
