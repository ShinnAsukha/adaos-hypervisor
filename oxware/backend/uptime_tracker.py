"""
uptime_tracker.py — Per-VM uptime tracking
OXware Hypervisor backend module
"""

import json
import logging
import os
import threading
import time
import subprocess

log = logging.getLogger("oxware.uptime")

UPTIME_FILE = "/var/lib/oxware/uptime_data.json"
_lock       = threading.Lock()

# Data format:
# {
#   "<vm_id>": {
#     "name":                 str,
#     "total_uptime_seconds": int,
#     "last_start":           float | null,
#     "last_stop":            float | null,
#     "state":                "running" | "stopped",
#     "boot_count":           int,
#     "history":              [{"start": float, "stop": float | null}]  # last 30
#   }
# }

_MAX_HISTORY = 30


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _load():
    if not os.path.isfile(UPTIME_FILE):
        return {}
    try:
        with open(UPTIME_FILE) as f:
            return json.load(f)
    except Exception as exc:
        log.error("_load uptime_data error: %s", exc)
        return {}


def _save(data):
    try:
        os.makedirs(os.path.dirname(UPTIME_FILE), exist_ok=True)
        with open(UPTIME_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as exc:
        log.error("_save uptime_data error: %s", exc)


# ---------------------------------------------------------------------------
# Record events
# ---------------------------------------------------------------------------

def record_start(vm_id, vm_name):
    """
    Record that *vm_id* has started.

    Args:
        vm_id   (str): Unique VM identifier.
        vm_name (str): Human-readable VM name.
    """
    now = time.time()
    with _lock:
        data = _load()
        entry = data.get(vm_id, {
            "name":                 vm_name,
            "total_uptime_seconds": 0,
            "last_start":           None,
            "last_stop":            None,
            "state":                "stopped",
            "boot_count":           0,
            "history":              [],
        })

        # If already running (e.g. crash-recovery), close the open session first
        if entry.get("state") == "running" and entry.get("last_start") is not None:
            elapsed = now - entry["last_start"]
            entry["total_uptime_seconds"] += int(elapsed)
            if entry["history"] and entry["history"][-1].get("stop") is None:
                entry["history"][-1]["stop"] = now

        entry["name"]       = vm_name
        entry["last_start"] = now
        entry["state"]      = "running"
        entry["boot_count"] = entry.get("boot_count", 0) + 1

        # Append a new history entry
        entry.setdefault("history", []).append({"start": now, "stop": None})
        entry["history"] = entry["history"][-_MAX_HISTORY:]

        data[vm_id] = entry
        _save(data)
    log.info("VM started: %s (%s)", vm_name, vm_id)


def record_stop(vm_id):
    """
    Record that *vm_id* has stopped.

    Args:
        vm_id (str): Unique VM identifier.
    """
    now = time.time()
    with _lock:
        data = _load()
        if vm_id not in data:
            log.warning("record_stop: unknown vm_id '%s'", vm_id)
            return

        entry = data[vm_id]
        if entry.get("state") == "running" and entry.get("last_start") is not None:
            elapsed = now - entry["last_start"]
            entry["total_uptime_seconds"] += int(elapsed)
            # Close the open history entry
            for h in reversed(entry.get("history", [])):
                if h.get("stop") is None:
                    h["stop"] = now
                    break

        entry["state"]     = "stopped"
        entry["last_stop"] = now
        data[vm_id]        = entry
        _save(data)
    log.info("VM stopped: %s", vm_id)


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def get_uptime(vm_id):
    """
    Return detailed uptime info for *vm_id*.

    Returns:
        dict: vm_id, name, total_seconds, current_session_seconds,
              formatted, availability_pct, boot_count
        None if the VM is unknown.
    """
    with _lock:
        data = _load()

    entry = data.get(vm_id)
    if entry is None:
        return None

    now                    = time.time()
    total                  = entry.get("total_uptime_seconds", 0)
    current_session_secs   = 0

    if entry.get("state") == "running" and entry.get("last_start") is not None:
        current_session_secs = int(now - entry["last_start"])

    grand_total = total + current_session_secs

    # Determine tracking start (oldest history entry or last_start)
    history   = entry.get("history", [])
    first_ts  = history[0]["start"] if history else entry.get("last_start") or now
    track_secs = max(1, now - first_ts)
    avail_pct  = round((grand_total / track_secs) * 100, 2)

    # Human-readable format
    days    = grand_total // 86400
    hours   = (grand_total % 86400) // 3600
    minutes = (grand_total % 3600)  // 60
    formatted = f"{days} days, {hours} hours, {minutes} minutes"

    return {
        "vm_id":                   vm_id,
        "name":                    entry.get("name", vm_id),
        "total_seconds":           grand_total,
        "current_session_seconds": current_session_secs,
        "formatted":               formatted,
        "availability_pct":        avail_pct,
        "boot_count":              entry.get("boot_count", 0),
        "state":                   entry.get("state", "stopped"),
    }


def get_all_uptimes():
    """Return uptime info for every tracked VM."""
    with _lock:
        data = _load()
    return [get_uptime(vm_id) for vm_id in data]


def delete_uptime(vm_id):
    """Remove uptime record for a deleted VM."""
    with _lock:
        data = _load()
        if vm_id in data:
            del data[vm_id]
            _save(data)
            log.info("Uptime record deleted: %s", vm_id)


# ---------------------------------------------------------------------------
# virsh synchronisation
# ---------------------------------------------------------------------------

def sync_from_virsh():
    """
    Synchronise state from ``virsh list --all``.

    VMs reported as *running* that are not already tracked are added;
    running→stopped transitions are recorded.
    """
    try:
        r = subprocess.run(
            ["virsh", "list", "--all"],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode != 0:
            log.warning("virsh list failed: %s", r.stderr.strip())
            return
    except FileNotFoundError:
        log.debug("virsh not found — skipping sync")
        return
    except Exception as exc:
        log.exception("sync_from_virsh error: %s", exc)
        return

    # Parse virsh table:
    # Id   Name      State
    # 1    myvm      running
    # -    stopped1  shut off
    running_vms  = {}
    stopped_vms  = {}

    for line in r.stdout.splitlines()[2:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        vm_id_raw = parts[0]
        name      = parts[1]
        state_str = " ".join(parts[2:]).lower()

        if "running" in state_str:
            running_vms[name]  = name
        else:
            stopped_vms[name] = name

    with _lock:
        data = _load()

    for name in running_vms:
        entry = next((v for v in data.values() if v.get("name") == name), None)
        if entry is None:
            # New VM — start tracking
            record_start(name, name)
        elif entry.get("state") != "running":
            record_start(name, name)

    for name in stopped_vms:
        for vm_id, entry in data.items():
            if entry.get("name") == name and entry.get("state") == "running":
                record_stop(vm_id)
                break


# ---------------------------------------------------------------------------
# Background tracker
# ---------------------------------------------------------------------------

def start_tracker(interval=60):
    """
    Start a daemon thread that calls :func:`sync_from_virsh` every
    *interval* seconds.
    """
    def _worker():
        log.info("Uptime tracker thread started (interval=%ds)", interval)
        while True:
            try:
                sync_from_virsh()
            except Exception as exc:
                log.exception("Uptime tracker loop error: %s", exc)
            time.sleep(interval)

    t = threading.Thread(target=_worker, daemon=True, name="uptime-tracker")
    t.start()
    return t


# ---------------------------------------------------------------------------
# Availability over a time window
# ---------------------------------------------------------------------------

def get_availability(vm_id, days=30):
    """
    Calculate availability percentage over the last *days* days.

    Args:
        vm_id (str): VM identifier.
        days  (int): Lookback window in days.

    Returns:
        float: Availability percentage (0–100), or None if unknown.
    """
    with _lock:
        data = _load()

    entry = data.get(vm_id)
    if entry is None:
        return None

    now       = time.time()
    window    = days * 86400
    window_start = now - window

    history   = entry.get("history", [])
    uptime_in_window = 0

    for h in history:
        start = h.get("start") or 0
        stop  = h.get("stop") or now  # still running

        # Clamp to window
        seg_start = max(start, window_start)
        seg_stop  = min(stop, now)

        if seg_stop > seg_start:
            uptime_in_window += seg_stop - seg_start

    avail = (uptime_in_window / window) * 100 if window > 0 else 0
    return round(min(avail, 100.0), 2)
