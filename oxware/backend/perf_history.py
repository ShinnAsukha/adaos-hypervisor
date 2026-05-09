"""
perf_history.py - SQLite tabanlı sistem ve VM metrik geçmişi.
DB: /var/lib/oxware/metrics.db
"""

import sqlite3
import threading
import time
import os
import logging
import subprocess

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False

log = logging.getLogger("oxware.perf_history")

DB_PATH = "/var/lib/oxware/metrics.db"
_lock   = threading.Lock()

PERIODS = {
    "1h":  3600,
    "6h":  21600,
    "24h": 86400,
    "7d":  604800,
    "30d": 2592000,
}

_last_disk  = None
_last_net   = None
_last_ts    = None
_last_cleanup = 0


# ---------------------------------------------------------------------------
# DB kurulumu
# ---------------------------------------------------------------------------

def init_db():
    """system_metrics ve vm_metrics tablolarını oluşturur."""
    try:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        with _lock:
            conn = sqlite3.connect(DB_PATH)
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts             INTEGER NOT NULL,
                    cpu_pct        REAL,
                    mem_pct        REAL,
                    mem_used_mb    REAL,
                    mem_total_mb   REAL,
                    disk_read_bps  REAL,
                    disk_write_bps REAL,
                    net_rx_bps     REAL,
                    net_tx_bps     REAL
                );
                CREATE INDEX IF NOT EXISTS idx_sys_ts ON system_metrics(ts);

                CREATE TABLE IF NOT EXISTS vm_metrics (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts       INTEGER NOT NULL,
                    vm_id    TEXT    NOT NULL,
                    vm_name  TEXT,
                    cpu_pct  REAL,
                    mem_mb   REAL,
                    state    TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_vm_ts ON vm_metrics(ts);
                CREATE INDEX IF NOT EXISTS idx_vm_id ON vm_metrics(vm_id);
            """)
            conn.commit()
            conn.close()
        log.info("perf_history DB hazır: %s", DB_PATH)
    except Exception as e:
        log.error("init_db hatası: %s", e)


# ---------------------------------------------------------------------------
# Anlık kayıt
# ---------------------------------------------------------------------------

def _parse_virsh_domstats():
    """virsh domstats --all çıktısını parse eder, list of dict döndürür."""
    vms = []
    try:
        out = subprocess.check_output(
            ["virsh", "domstats", "--all"],
            stderr=subprocess.DEVNULL,
            timeout=10,
        ).decode("utf-8", errors="replace")
        current = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Domain:"):
                if current:
                    vms.append(current)
                current = {"vm_name": line.split("Domain:")[-1].strip(),
                           "vm_id": line.split("Domain:")[-1].strip(),
                           "cpu_pct": 0.0, "mem_mb": 0.0, "state": "running"}
            elif "=" in line and current:
                k, _, v = line.partition("=")
                k = k.strip(); v = v.strip()
                if k == "state.state":
                    states = {"1": "running", "3": "paused", "5": "shut off"}
                    current["state"] = states.get(v, v)
                elif k == "cpu.time":
                    try:
                        current["cpu_pct"] = float(v) / 1e9 / 1.0
                    except Exception:
                        pass
                elif k == "balloon.current":
                    try:
                        current["mem_mb"] = float(v) / 1024.0
                    except Exception:
                        pass
        if current:
            vms.append(current)
    except FileNotFoundError:
        log.debug("virsh bulunamadı, VM metrikleri atlanıyor.")
    except Exception as e:
        log.debug("virsh domstats hatası: %s", e)
    return vms


def record_snapshot():
    """psutil ile sistem verisi, virsh ile VM verisi alır ve DB'ye kaydeder."""
    global _last_disk, _last_net, _last_ts

    try:
        ts = int(time.time())

        # --- Sistem metrikleri ---
        if _PSUTIL_OK:
            cpu_pct = psutil.cpu_percent(interval=0)
            mem = psutil.virtual_memory()
            mem_pct      = mem.percent
            mem_used_mb  = mem.used  / 1024 / 1024
            mem_total_mb = mem.total / 1024 / 1024

            # Disk I/O delta (bps)
            disk_now = psutil.disk_io_counters()
            net_now  = psutil.net_io_counters()
            now_t    = time.time()

            if _last_disk and _last_net and _last_ts:
                dt = max(now_t - _last_ts, 0.001)
                disk_read_bps  = (disk_now.read_bytes  - _last_disk.read_bytes)  / dt
                disk_write_bps = (disk_now.write_bytes - _last_disk.write_bytes) / dt
                net_rx_bps     = (net_now.bytes_recv   - _last_net.bytes_recv)   / dt
                net_tx_bps     = (net_now.bytes_sent   - _last_net.bytes_sent)   / dt
            else:
                disk_read_bps = disk_write_bps = net_rx_bps = net_tx_bps = 0.0

            _last_disk = disk_now
            _last_net  = net_now
            _last_ts   = now_t

            with _lock:
                conn = sqlite3.connect(DB_PATH)
                conn.execute(
                    """INSERT INTO system_metrics
                       (ts, cpu_pct, mem_pct, mem_used_mb, mem_total_mb,
                        disk_read_bps, disk_write_bps, net_rx_bps, net_tx_bps)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (ts, cpu_pct, mem_pct, mem_used_mb, mem_total_mb,
                     disk_read_bps, disk_write_bps, net_rx_bps, net_tx_bps),
                )
                conn.commit()
                conn.close()
        else:
            log.debug("psutil yok, sistem snapshot atlandı.")

        # --- VM metrikleri ---
        vms = _parse_virsh_domstats()
        if vms:
            rows = [(ts, v["vm_id"], v["vm_name"], v["cpu_pct"], v["mem_mb"], v["state"])
                    for v in vms]
            with _lock:
                conn = sqlite3.connect(DB_PATH)
                conn.executemany(
                    """INSERT INTO vm_metrics
                       (ts, vm_id, vm_name, cpu_pct, mem_mb, state)
                       VALUES (?,?,?,?,?,?)""",
                    rows,
                )
                conn.commit()
                conn.close()

    except Exception as e:
        log.error("record_snapshot hatası: %s", e)


# ---------------------------------------------------------------------------
# Sorgular
# ---------------------------------------------------------------------------

def get_system_history(period="1h"):
    """
    Belirtilen periyottaki sistem metriklerini döndürür.
    period: "1h" | "6h" | "24h" | "7d" | "30d"
    """
    try:
        seconds = PERIODS.get(period, PERIODS["1h"])
        since   = int(time.time()) - seconds
        with _lock:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM system_metrics WHERE ts >= ? ORDER BY ts ASC", (since,)
            ).fetchall()]
            conn.close()
        return rows
    except Exception as e:
        log.error("get_system_history hatası: %s", e)
        return []


def get_vm_history(vm_id, period="1h"):
    """Belirtilen VM'nin geçmiş metriklerini döndürür."""
    try:
        seconds = PERIODS.get(period, PERIODS["1h"])
        since   = int(time.time()) - seconds
        with _lock:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM vm_metrics WHERE vm_id=? AND ts >= ? ORDER BY ts ASC",
                (str(vm_id), since),
            ).fetchall()]
            conn.close()
        return rows
    except Exception as e:
        log.error("get_vm_history hatası (vm_id=%s): %s", vm_id, e)
        return []


# ---------------------------------------------------------------------------
# Temizlik
# ---------------------------------------------------------------------------

def cleanup_old_data():
    """30 günden eski kayıtları siler."""
    try:
        cutoff = int(time.time()) - 2592000  # 30d
        with _lock:
            conn = sqlite3.connect(DB_PATH)
            r1 = conn.execute("DELETE FROM system_metrics WHERE ts < ?", (cutoff,))
            r2 = conn.execute("DELETE FROM vm_metrics    WHERE ts < ?", (cutoff,))
            conn.commit()
            total = r1.rowcount + r2.rowcount
            conn.close()
        log.info("cleanup_old_data: %d eski kayıt silindi.", total)
    except Exception as e:
        log.error("cleanup_old_data hatası: %s", e)


# ---------------------------------------------------------------------------
# Arka plan toplayıcı
# ---------------------------------------------------------------------------

def start_collector(interval=60):
    """
    Daemon thread başlatır. Her `interval` saniyede bir record_snapshot çağırır.
    Her 24 saatte bir cleanup_old_data çalıştırır.
    """
    init_db()

    def _loop():
        global _last_cleanup
        log.info("perf_history toplayıcı başladı (interval=%ds).", interval)
        while True:
            try:
                record_snapshot()
            except Exception as e:
                log.error("Toplayıcı snapshot hatası: %s", e)
            try:
                now = time.time()
                if now - _last_cleanup >= 86400:
                    cleanup_old_data()
                    _last_cleanup = now
            except Exception as e:
                log.error("Toplayıcı cleanup hatası: %s", e)
            time.sleep(interval)

    t = threading.Thread(target=_loop, name="perf-history-collector", daemon=True)
    t.start()
    log.info("perf_history collector thread başlatıldı.")
    return t
