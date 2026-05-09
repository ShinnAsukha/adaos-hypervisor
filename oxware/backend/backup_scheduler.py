"""
backup_scheduler.py - Zamanlanmış VM backup yönetimi.
Schedules: /var/lib/oxware/backup_schedules.json
History:   /var/log/oxware/backup_history.jsonl
"""

try:
    from croniter import croniter
    CRONITER_AVAILABLE = True
except ImportError:
    CRONITER_AVAILABLE = False

try:
    import boto3
    _BOTO3_OK = True
except ImportError:
    _BOTO3_OK = False

import json
import threading
import time
import uuid
import os
import subprocess
import logging
import ftplib

log = logging.getLogger("oxware.backup_scheduler")

SCHEDULES_PATH = "/var/lib/oxware/backup_schedules.json"
HISTORY_PATH   = "/var/log/oxware/backup_history.jsonl"
_lock          = threading.Lock()
_history_lock  = threading.Lock()


# ---------------------------------------------------------------------------
# Dosya I/O
# ---------------------------------------------------------------------------

def _load():
    """Schedules JSON dosyasını yükler."""
    try:
        if os.path.exists(SCHEDULES_PATH):
            with open(SCHEDULES_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        log.error("_load hatası: %s", e)
    return {}


def _save(data):
    """Schedules JSON dosyasını atomik yazar."""
    try:
        os.makedirs(os.path.dirname(SCHEDULES_PATH), exist_ok=True)
        tmp = SCHEDULES_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, SCHEDULES_PATH)
    except Exception as e:
        log.error("_save hatası: %s", e)


# ---------------------------------------------------------------------------
# Cron yardımcısı
# ---------------------------------------------------------------------------

def _next_run(cron_expr):
    """
    Sonraki çalışma zamanını unix timestamp olarak döndürür.
    croniter yoksa None döndürür.
    """
    if not CRONITER_AVAILABLE:
        return None
    try:
        it = croniter(cron_expr, time.time())
        return it.get_next(float)
    except Exception as e:
        log.error("_next_run hatası (expr=%s): %s", cron_expr, e)
        return None


# ---------------------------------------------------------------------------
# Schedule CRUD
# ---------------------------------------------------------------------------

def create_schedule(vm_id, vm_name, cron_expr, retention_count=7,
                    description="", remote_type=None, remote_config=None):
    """
    Yeni backup schedule oluşturur.
    remote_type: "s3" | "ftp" | None
    Döner: schedule dict
    """
    try:
        schedule_id = str(uuid.uuid4())
        now         = time.time()
        schedule = {
            "id":              schedule_id,
            "vm_id":           vm_id,
            "vm_name":         vm_name,
            "cron_expr":       cron_expr,
            "retention_count": retention_count,
            "description":     description,
            "remote_type":     remote_type,
            "remote_config":   remote_config or {},
            "created_at":      now,
            "last_run":        None,
            "next_run":        _next_run(cron_expr),
            "enabled":         True,
        }
        with _lock:
            data = _load()
            data[schedule_id] = schedule
            _save(data)
        log.info("create_schedule: vm=%s cron='%s' id=%s", vm_name, cron_expr, schedule_id)
        return schedule
    except Exception as e:
        log.error("create_schedule hatası: %s", e)
        return {}


def list_schedules():
    """Tüm schedule'ları liste olarak döndürür."""
    try:
        with _lock:
            data = _load()
        return list(data.values())
    except Exception as e:
        log.error("list_schedules hatası: %s", e)
        return []


def get_schedule(schedule_id):
    """Tek schedule döndürür veya None."""
    try:
        with _lock:
            data = _load()
        return data.get(schedule_id)
    except Exception as e:
        log.error("get_schedule hatası: %s", e)
        return None


def update_schedule(schedule_id, **kwargs):
    """
    Schedule alanlarını günceller.
    cron_expr değişirse next_run yeniden hesaplanır.
    """
    try:
        with _lock:
            data = _load()
            if schedule_id not in data:
                return False
            entry = data[schedule_id]
            for k, v in kwargs.items():
                if k in entry:
                    entry[k] = v
            if "cron_expr" in kwargs:
                entry["next_run"] = _next_run(entry["cron_expr"])
            _save(data)
        log.info("update_schedule: %s güncellendi.", schedule_id)
        return True
    except Exception as e:
        log.error("update_schedule hatası: %s", e)
        return False


def delete_schedule(schedule_id):
    """Schedule'ı kalıcı olarak siler."""
    try:
        with _lock:
            data = _load()
            if schedule_id not in data:
                return False
            del data[schedule_id]
            _save(data)
        log.info("delete_schedule: %s silindi.", schedule_id)
        return True
    except Exception as e:
        log.error("delete_schedule hatası: %s", e)
        return False


# ---------------------------------------------------------------------------
# Backup çalıştırma
# ---------------------------------------------------------------------------

def _run_backup(schedule):
    """
    Verilen schedule için:
      1) virsh snapshot-create-as ile snapshot alır
      2) retention uygulanır (eski snapshot'lar silinir)
      3) remote_type varsa uzak hedefe yükler
    """
    vm_id    = schedule["vm_id"]
    vm_name  = schedule["vm_name"]
    snap_ts  = int(time.time())
    snap_name = f"oxw-backup-{vm_name}-{snap_ts}"

    success = False
    error   = ""

    try:
        # 1. Snapshot oluştur
        cmd = ["virsh", "snapshot-create-as",
               vm_name, snap_name,
               "--description", f"OXware auto-backup {snap_ts}",
               "--atomic"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            raise RuntimeError(f"virsh snapshot-create-as failed: {result.stderr.strip()}")
        log.info("_run_backup: snapshot '%s' oluşturuldu.", snap_name)

        # 2. Retention – eski snapshot'ları listele ve sil
        try:
            ls_out = subprocess.check_output(
                ["virsh", "snapshot-list", vm_name, "--name"],
                stderr=subprocess.DEVNULL, timeout=30
            ).decode("utf-8", errors="replace").strip().splitlines()

            oxw_snaps = sorted(
                [s for s in ls_out if s.startswith("oxw-backup-")],
            )
            retention = schedule.get("retention_count", 7)
            to_delete = oxw_snaps[:-retention] if len(oxw_snaps) > retention else []
            for old_snap in to_delete:
                subprocess.run(
                    ["virsh", "snapshot-delete", vm_name, old_snap],
                    capture_output=True, timeout=60
                )
                log.info("_run_backup: eski snapshot silindi: %s", old_snap)
        except Exception as re:
            log.warning("_run_backup: retention hatası: %s", re)

        # 3. Remote yükleme
        remote_type   = schedule.get("remote_type")
        remote_config = schedule.get("remote_config", {})

        if remote_type == "s3":
            _upload_s3(vm_name, snap_name, remote_config)
        elif remote_type == "ftp":
            _upload_ftp(vm_name, snap_name, remote_config)

        success = True

    except FileNotFoundError:
        error = "virsh bulunamadı"
        log.error("_run_backup: %s", error)
    except Exception as e:
        error = str(e)
        log.error("_run_backup hatası (vm=%s): %s", vm_name, e)

    _log_history(vm_id, vm_name, snap_name, success, error)
    return success


def _upload_s3(vm_name, snap_name, cfg):
    """boto3 ile S3'e snapshot meta yükleme (graceful fallback)."""
    if not _BOTO3_OK:
        log.warning("_upload_s3: boto3 yok, atlanıyor.")
        return
    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id     = cfg.get("access_key"),
            aws_secret_access_key = cfg.get("secret_key"),
            region_name           = cfg.get("region", "us-east-1"),
            endpoint_url          = cfg.get("endpoint"),
        )
        bucket  = cfg.get("bucket", "oxware-backups")
        key     = f"{vm_name}/{snap_name}.json"
        payload = json.dumps({"vm_name": vm_name, "snapshot": snap_name,
                              "ts": time.time()}).encode("utf-8")
        s3.put_object(Bucket=bucket, Key=key, Body=payload)
        log.info("_upload_s3: s3://%s/%s yüklendi.", bucket, key)
    except Exception as e:
        log.error("_upload_s3 hatası: %s", e)


def _upload_ftp(vm_name, snap_name, cfg):
    """ftplib ile FTP'ye snapshot meta yükleme."""
    try:
        host    = cfg.get("host", "localhost")
        port    = int(cfg.get("port", 21))
        user    = cfg.get("username", "anonymous")
        passwd  = cfg.get("password", "")
        remote_dir = cfg.get("remote_dir", "/")
        filename   = f"{snap_name}.json"
        payload    = json.dumps({"vm_name": vm_name, "snapshot": snap_name,
                                 "ts": time.time()}).encode("utf-8")
        import io
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=30)
        ftp.login(user, passwd)
        try:
            ftp.cwd(remote_dir)
        except Exception:
            pass
        ftp.storbinary(f"STOR {filename}", io.BytesIO(payload))
        ftp.quit()
        log.info("_upload_ftp: ftp://%s/%s/%s yüklendi.", host, remote_dir, filename)
    except Exception as e:
        log.error("_upload_ftp hatası: %s", e)


# ---------------------------------------------------------------------------
# History log
# ---------------------------------------------------------------------------

def _log_history(vm_id, vm_name, snapshot_name, success, error=""):
    """JSONL history dosyasına yeni satır ekler."""
    try:
        os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
        entry = {
            "ts":            time.time(),
            "vm_id":         vm_id,
            "vm_name":       vm_name,
            "snapshot_name": snapshot_name,
            "success":       success,
            "error":         error,
        }
        with _history_lock:
            with open(HISTORY_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        log.error("_log_history hatası: %s", e)


def get_history(vm_id=None, limit=50):
    """
    JSONL history dosyasından kayıtları okur.
    vm_id verilirse filtreler. En yeni `limit` kadar döndürür.
    """
    try:
        if not os.path.exists(HISTORY_PATH):
            return []
        with _history_lock:
            with open(HISTORY_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()

        records = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if vm_id and rec.get("vm_id") != vm_id:
                    continue
                records.append(rec)
            except Exception:
                pass

        # En yeni önce, limit uygula
        records.sort(key=lambda r: r.get("ts", 0), reverse=True)
        return records[:limit]
    except Exception as e:
        log.error("get_history hatası: %s", e)
        return []


# ---------------------------------------------------------------------------
# Scheduler döngüsü
# ---------------------------------------------------------------------------

def check_due():
    """Zamanı gelen (next_run <= now) ve enabled schedule'ları çalıştırır."""
    try:
        now = time.time()
        with _lock:
            data = _load()

        for schedule_id, schedule in list(data.items()):
            if not schedule.get("enabled", True):
                continue
            next_run = schedule.get("next_run")
            if next_run is None:
                continue
            if now < next_run:
                continue

            # Yeni next_run hesapla (çalıştırmadan önce kaydet)
            new_next = _next_run(schedule["cron_expr"])
            with _lock:
                fresh = _load()
                if schedule_id in fresh:
                    fresh[schedule_id]["last_run"]  = now
                    fresh[schedule_id]["next_run"]  = new_next
                    _save(fresh)

            # Backup'ı ayrı thread'de çalıştır
            t = threading.Thread(
                target=_run_backup,
                args=(schedule,),
                name=f"backup-{schedule_id[:8]}",
                daemon=True,
            )
            t.start()
            log.info("check_due: schedule %s tetiklendi (vm=%s).",
                     schedule_id, schedule.get("vm_name"))

    except Exception as e:
        log.error("check_due hatası: %s", e)


def start_scheduler():
    """
    Daemon thread başlatır; her 30 saniyede check_due çağırır.
    """
    def _loop():
        log.info("backup_scheduler başladı.")
        while True:
            try:
                check_due()
            except Exception as e:
                log.error("Scheduler döngüsü hatası: %s", e)
            time.sleep(30)

    t = threading.Thread(target=_loop, name="backup-scheduler", daemon=True)
    t.start()
    log.info("backup_scheduler thread başlatıldı.")
    return t


def trigger_now(schedule_id):
    """
    Belirtilen schedule'ı elle tetikler.
    Döner: True (başarı) / False (bulunamadı veya hata)
    """
    try:
        with _lock:
            data = _load()
        schedule = data.get(schedule_id)
        if not schedule:
            log.warning("trigger_now: schedule bulunamadı (%s).", schedule_id)
            return False

        t = threading.Thread(
            target=_run_backup,
            args=(schedule,),
            name=f"backup-manual-{schedule_id[:8]}",
            daemon=True,
        )
        t.start()
        log.info("trigger_now: %s manuel tetiklendi.", schedule_id)
        return True
    except Exception as e:
        log.error("trigger_now hatası: %s", e)
        return False
