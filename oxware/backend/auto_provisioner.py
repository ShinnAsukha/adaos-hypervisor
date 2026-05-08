"""
AdaOS Otomatik VM Kurulum Sistemi
──────────────────────────────────
Tek API çağrısıyla:
  - ISO seçimi (havuzdan)
  - Disk oluşturma
  - IP tahsisi
  - Güçlü şifre üretimi
  - VM tanımlama ve başlatma
  - Olay kaydı + bildirim
"""

import os
import secrets
import string
import time
import json
import threading
from datetime import datetime
import config
import vm_manager
import ip_pool as ip_pool_mgr
import storage_manager
import event_logger
import notifications

PROVISION_LOG = os.path.join(config.DATA_DIR, "provisions.json")
_lock = threading.Lock()

# Şifre karakterleri: büyük+küçük harf + rakam + sembol (güvenli set)
_PWD_CHARS = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"


def generate_password(length: int = 20) -> str:
    """Güçlü rastgele şifre üret."""
    while True:
        pwd = "".join(secrets.choice(_PWD_CHARS) for _ in range(length))
        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_sym   = any(c in "!@#$%^&*()-_=+" for c in pwd)
        if has_upper and has_lower and has_digit and has_sym:
            return pwd


def _load_provisions() -> list:
    if os.path.exists(PROVISION_LOG):
        with open(PROVISION_LOG) as f:
            return json.load(f)
    return []


def _save_provision(entry: dict):
    with _lock:
        provisions = _load_provisions()
        provisions.append(entry)
        # Son 1000 kayıt
        if len(provisions) > 1000:
            provisions = provisions[-1000:]
        os.makedirs(os.path.dirname(PROVISION_LOG), exist_ok=True)
        with open(PROVISION_LOG, "w") as f:
            json.dump(provisions, f, indent=2, ensure_ascii=False)


def provision_vm(
    name: str,
    memory_mb: int = 2048,
    vcpus: int = 2,
    disk_gb: int = 20,
    iso_name: str = None,          # Havuzdan ISO adı (None = otomatik seç)
    pool_name: str = None,         # IP havuzu (None = ilk havuzu kullan)
    network: str = "default",
    disk_format: str = "qcow2",
    os_variant: str = "generic",
    boot_order: str = "cdrom,hd",
    password_length: int = 20,
    start_after: bool = True,
    notify: bool = True,
    tags: list = None,
) -> dict:
    """
    Tam otomatik VM kurulumu.
    Döndürür: {vm_id, name, ip, password, vnc_port, ...}
    """

    provision_id = f"prov-{int(time.time())}-{secrets.token_hex(4)}"
    started_at = time.time()

    event_logger.info(
        f"Otomatik kurulum başladı: {name}",
        category="provision",
        details={"name": name, "memory_mb": memory_mb, "vcpus": vcpus, "disk_gb": disk_gb},
    )

    result = {
        "provision_id": provision_id,
        "name":        name,
        "status":      "pending",
        "started_at":  started_at,
    }

    try:
        # 1. ISO seç
        iso_path = None
        if iso_name:
            isos = storage_manager.list_isos()
            iso_map = {i["name"]: i["path"] for i in isos}
            iso_path = iso_map.get(iso_name)
            if not iso_path:
                raise ValueError(f"ISO bulunamadı: {iso_name}")
        else:
            # Havuzdaki ilk ISO'yu seç
            isos = storage_manager.list_isos()
            if isos:
                iso_path = isos[0]["path"]
                iso_name = isos[0]["name"]

        # 2. VM oluştur
        vm_result = vm_manager.create_vm(
            name=name,
            memory_mb=memory_mb,
            vcpus=vcpus,
            disk_gb=disk_gb,
            iso_path=iso_path,
            network=network,
            disk_format=disk_format,
            os_variant=os_variant,
            boot_order=boot_order,
        )
        vm_id = vm_result["id"]
        vnc_port = vm_result.get("vnc_port", -1)

        event_logger.vm_event(f"VM oluşturuldu: {name}", vm_id, level="INFO")

        # 3. IP tahsis et
        ip_info = None
        assigned_ip = None
        if pool_name:
            try:
                ip_info = ip_pool_mgr.allocate_ip(pool_name, vm_id, name)
                assigned_ip = ip_info["ip"]
                event_logger.vm_event(
                    f"IP tahsis edildi: {assigned_ip}",
                    vm_id, level="INFO",
                    details={"ip": assigned_ip, "pool": pool_name},
                )
            except Exception as e:
                event_logger.warn(f"IP tahsisi başarısız: {e}", category="provision")
        else:
            # Mevcut ilk havuzdan tahsis et
            pools = ip_pool_mgr.list_pools()
            if pools:
                try:
                    ip_info = ip_pool_mgr.allocate_ip(pools[0]["name"], vm_id, name)
                    assigned_ip = ip_info["ip"]
                    pool_name = pools[0]["name"]
                except Exception:
                    pass

        # 4. Şifre üret
        password = generate_password(password_length)

        # 5. VM'i başlat
        if start_after:
            vm_manager.start_vm(vm_id)
            event_logger.vm_event(f"VM başlatıldı: {name}", vm_id, level="INFO")

        # 6. Kayıt
        provision_entry = {
            "provision_id": provision_id,
            "vm_id":        vm_id,
            "name":         name,
            "memory_mb":    memory_mb,
            "vcpus":        vcpus,
            "disk_gb":      disk_gb,
            "iso_used":     iso_name or "",
            "ip":           assigned_ip or "",
            "ip_pool":      pool_name or "",
            "ip_info":      ip_info or {},
            "password":     password,
            "vnc_port":     vnc_port,
            "network":      network,
            "os_variant":   os_variant,
            "tags":         tags or [],
            "status":       "completed",
            "started_at":   started_at,
            "completed_at": time.time(),
        }
        _save_provision(provision_entry)

        event_logger.info(
            f"Otomatik kurulum tamamlandı: {name} → IP: {assigned_ip or 'N/A'}",
            category="provision",
            vm_id=vm_id,
        )

        # 7. Bildirim gönder
        if notify:
            notifications.notify_provision_complete(name, vm_id, assigned_ip or "N/A", password)

        return {
            **provision_entry,
            "status": "completed",
        }

    except Exception as e:
        error_entry = {
            **result,
            "status": "failed",
            "error": str(e),
            "failed_at": time.time(),
        }
        _save_provision(error_entry)
        event_logger.error(
            f"Otomatik kurulum başarısız: {name} — {e}",
            category="provision",
        )
        notifications.send_alert(
            f"VM kurulumu başarısız: {name}\nHata: {e}",
            level="ERROR",
            category="provision",
        )
        raise


def list_provisions(limit: int = 50) -> list:
    provisions = _load_provisions()
    return sorted(provisions, key=lambda x: x.get("started_at", 0), reverse=True)[:limit]


def get_provision(provision_id: str) -> dict | None:
    for p in _load_provisions():
        if p.get("provision_id") == provision_id:
            return p
    return None


def bulk_provision(specs: list) -> list:
    """
    Toplu VM kurulumu.
    specs: [{name, memory_mb, vcpus, disk_gb, ...}, ...]
    """
    results = []
    for spec in specs:
        try:
            r = provision_vm(**spec)
            results.append({"status": "ok", **r})
        except Exception as e:
            results.append({"status": "error", "name": spec.get("name"), "error": str(e)})
        time.sleep(1)  # Ardışık kurulumlar arasında kısa bekleme
    return results
