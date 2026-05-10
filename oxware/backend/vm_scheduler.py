"""
vm_scheduler.py — OXware VM Zamanlanmış Görev Yöneticisi
VM'leri belirli gün/saat kombinasyonlarında otomatik başlat, durdur,
yeniden başlat veya snapshot al.
"""

import json
import os
import time
import threading
import subprocess
import logging
import uuid
from datetime import datetime

logger = logging.getLogger("oxware.vm_scheduler")

# Zamanlama verilerinin saklandığı dosya
SCHEDULES_FILE = "/var/lib/oxware/vm_schedules.json"

# Thread-safe erişim için kilit
_lock = threading.Lock()

# ─────────────────────────────────────────────
# Yardımcı fonksiyonlar
# ─────────────────────────────────────────────

def _ensure_data_dir():
    """Veri dizininin var olduğundan emin ol."""
    os.makedirs(os.path.dirname(SCHEDULES_FILE), exist_ok=True)


def _load_schedules() -> list:
    """JSON dosyasından zamanlama listesini oku."""
    _ensure_data_dir()
    if not os.path.exists(SCHEDULES_FILE):
        return []
    try:
        with open(SCHEDULES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Zamanlama dosyası okunamadı: %s", exc)
        return []


def _save_schedules(schedules: list) -> None:
    """Zamanlama listesini JSON dosyasına yaz."""
    _ensure_data_dir()
    try:
        with open(SCHEDULES_FILE, "w", encoding="utf-8") as f:
            json.dump(schedules, f, indent=2, ensure_ascii=False)
    except OSError as exc:
        logger.error("Zamanlama dosyası yazılamadı: %s", exc)


# ─────────────────────────────────────────────
# Genel API
# ─────────────────────────────────────────────

def get_schedules() -> list:
    """Tüm zamanlama kayıtlarını döndür."""
    with _lock:
        return _load_schedules()


def add_schedule(
    vm_id: str,
    vm_name: str,
    action: str,
    hour: int,
    minute: int,
    days: list = None,
    enabled: bool = True,
) -> dict:
    """
    Yeni zamanlama ekle.

    action: "start" | "shutdown" | "reboot" | "snapshot"
    days  : Haftanın günleri listesi (0=Pzt … 6=Paz). Boş = her gün.
    Döndürür: Oluşturulan zamanlama dict'i.
    """
    valid_actions = {"start", "shutdown", "reboot", "snapshot"}
    if action not in valid_actions:
        raise ValueError(f"Geçersiz aksiyon: {action}. Geçerli: {valid_actions}")
    if not (0 <= hour <= 23):
        raise ValueError("hour 0-23 arasında olmalıdır.")
    if not (0 <= minute <= 59):
        raise ValueError("minute 0-59 arasında olmalıdır.")

    schedule = {
        "id": str(uuid.uuid4()),
        "vm_id": vm_id,
        "vm_name": vm_name,
        "action": action,
        "hour": hour,
        "minute": minute,
        "days": days if days is not None else [],   # Boş = her gün
        "enabled": enabled,
        "created_at": datetime.utcnow().isoformat(),
        "last_run": None,
    }

    with _lock:
        schedules = _load_schedules()
        schedules.append(schedule)
        _save_schedules(schedules)

    logger.info(
        "Zamanlama eklendi: %s — vm=%s aksiyon=%s %02d:%02d günler=%s",
        schedule["id"], vm_name, action, hour, minute, days,
    )
    return schedule


def update_schedule(sched_id: str, **kwargs) -> bool:
    """
    Mevcut zamanlamayı güncelle.
    Güncellenebilir alanlar: action, hour, minute, days, enabled.
    Döndürür: True (başarılı) | False (bulunamadı).
    """
    allowed_keys = {"action", "hour", "minute", "days", "enabled", "vm_name"}

    with _lock:
        schedules = _load_schedules()
        for sched in schedules:
            if sched["id"] == sched_id:
                for key, value in kwargs.items():
                    if key in allowed_keys:
                        sched[key] = value
                _save_schedules(schedules)
                logger.info("Zamanlama güncellendi: %s", sched_id)
                return True

    logger.warning("Güncellenecek zamanlama bulunamadı: %s", sched_id)
    return False


def delete_schedule(sched_id: str) -> bool:
    """
    Zamanlamayı sil.
    Döndürür: True (silindi) | False (bulunamadı).
    """
    with _lock:
        schedules = _load_schedules()
        new_schedules = [s for s in schedules if s["id"] != sched_id]
        if len(new_schedules) == len(schedules):
            logger.warning("Silinecek zamanlama bulunamadı: %s", sched_id)
            return False
        _save_schedules(new_schedules)

    logger.info("Zamanlama silindi: %s", sched_id)
    return True


# ─────────────────────────────────────────────
# Aksiyon uygulayıcı
# ─────────────────────────────────────────────

def _execute_action(sched: dict) -> None:
    """Zamanlanmış aksiyonu gerçekten çalıştır."""
    vm_id = sched["vm_id"]
    vm_name = sched["vm_name"]
    action = sched["action"]

    logger.info(
        "Zamanlama çalışıyor: id=%s vm=%s aksiyon=%s",
        sched["id"], vm_name, action,
    )

    try:
        if action == "snapshot":
            # virsh snapshot-create-as ile snapshot oluştur
            ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            snap_name = f"scheduled-{vm_name}-{ts}"
            cmd = [
                "virsh", "snapshot-create-as",
                vm_name,
                snap_name,
                "--atomic",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                logger.info("Snapshot oluşturuldu: %s", snap_name)
            else:
                logger.error(
                    "Snapshot hatası (vm=%s): %s", vm_name, result.stderr.strip()
                )
        else:
            # vm_manager'ı yerel import et (döngüsel bağımlılığı önlemek için)
            import vm_manager  # noqa: PLC0415

            if action == "start":
                vm_manager.start_vm(vm_id)
                logger.info("VM başlatıldı: %s", vm_name)
            elif action == "shutdown":
                vm_manager.stop_vm(vm_id)
                logger.info("VM durduruldu: %s", vm_name)
            elif action == "reboot":
                vm_manager.reboot_vm(vm_id)
                logger.info("VM yeniden başlatıldı: %s", vm_name)

    except Exception as exc:  # pylint: disable=broad-except
        logger.exception(
            "Aksiyon çalıştırılırken hata (vm=%s aksiyon=%s): %s",
            vm_name, action, exc,
        )


def _update_last_run(sched_id: str) -> None:
    """last_run alanını şimdiki zamana güncelle."""
    now_iso = datetime.utcnow().isoformat()
    with _lock:
        schedules = _load_schedules()
        for sched in schedules:
            if sched["id"] == sched_id:
                sched["last_run"] = now_iso
                break
        _save_schedules(schedules)


# ─────────────────────────────────────────────
# Zamanlayıcı döngüsü
# ─────────────────────────────────────────────

def _scheduler_loop() -> None:
    """
    Daemon thread'de çalışan ana döngü.
    Her dakika tetiklenen zamanlamaları kontrol eder.
    """
    logger.info("VM zamanlayıcı döngüsü başladı.")
    while True:
        try:
            _check_schedules()
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("Zamanlayıcı döngüsünde beklenmeyen hata: %s", exc)
        time.sleep(60)


def _check_schedules() -> None:
    """Şu anki saat/gün ile eşleşen zamanlamaları çalıştır."""
    now = datetime.utcnow()  # Sunucu UTC saatiyle çalışır; gerekirse localtime al
    current_hour = now.hour
    current_minute = now.minute
    current_weekday = now.weekday()  # 0=Pzt, 6=Paz
    now_ts = now.timestamp()

    with _lock:
        schedules = _load_schedules()

    for sched in schedules:
        if not sched.get("enabled", False):
            continue

        # Saat/dakika kontrolü
        if sched["hour"] != current_hour or sched["minute"] != current_minute:
            continue

        # Gün kontrolü — boş liste = her gün
        days = sched.get("days", [])
        if days and current_weekday not in days:
            continue

        # Son çalışma kontrolü — 55 saniyeden kısa önce çalıştıysa atla
        last_run = sched.get("last_run")
        if last_run:
            try:
                last_run_dt = datetime.fromisoformat(last_run)
                elapsed = now_ts - last_run_dt.timestamp()
                if elapsed < 55:
                    logger.debug(
                        "Zamanlama %s son %d sn önce çalıştı, atlanıyor.",
                        sched["id"], int(elapsed),
                    )
                    continue
            except (ValueError, OSError):
                pass  # Ayrıştırma hatası → yine de çalıştır

        # Aksiyonu ayrı thread'de çalıştır (döngüyü bloklamaz)
        threading.Thread(
            target=_run_and_update,
            args=(sched,),
            daemon=True,
            name=f"sched-{sched['id'][:8]}",
        ).start()


def _run_and_update(sched: dict) -> None:
    """Aksiyonu çalıştır ve last_run'ı güncelle."""
    _execute_action(sched)
    _update_last_run(sched["id"])


def start_scheduler() -> threading.Thread:
    """
    VM zamanlayıcısını daemon thread olarak başlat.
    Döndürür: Başlatılan Thread nesnesi.
    """
    t = threading.Thread(
        target=_scheduler_loop,
        daemon=True,
        name="vm-scheduler",
    )
    t.start()
    logger.info("VM zamanlayıcı thread'i başlatıldı.")
    return t
