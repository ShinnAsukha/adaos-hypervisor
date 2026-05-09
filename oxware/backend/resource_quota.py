"""
resource_quota.py — VM başına kaynak limitleri (OXware Hypervisor)
"""

import subprocess
import json
import logging
import os
import threading

log = logging.getLogger("oxware.quota")

QUOTAS_FILE = "/var/lib/oxware/quotas.json"
GLOBAL_QUOTA_KEY = "__global__"

_lock = threading.Lock()

# ---------------------------------------------------------------------------
# İç yardımcılar
# ---------------------------------------------------------------------------

def _run(*cmd):
    """subprocess.run çalıştırır; hata fırlatmaz."""
    try:
        result = subprocess.run(
            list(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            log.warning("Komut başarısız [%d]: %s | stderr: %s",
                        result.returncode, " ".join(cmd), result.stderr.strip())
        return result
    except FileNotFoundError:
        log.error("Komut bulunamadı: %s", cmd[0])
        return None
    except Exception as exc:
        log.exception("_run hatası: %s", exc)
        return None


def _load():
    """QUOTAS_FILE'dan kota verilerini yükler."""
    try:
        os.makedirs(os.path.dirname(QUOTAS_FILE), exist_ok=True)
        if not os.path.exists(QUOTAS_FILE):
            return {}
        with open(QUOTAS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log.error("QUOTAS_FILE okunamadı: %s", exc)
        return {}


def _save(data):
    """Kota verilerini QUOTAS_FILE'a kaydeder."""
    try:
        os.makedirs(os.path.dirname(QUOTAS_FILE), exist_ok=True)
        with open(QUOTAS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except OSError as exc:
        log.error("QUOTAS_FILE yazılamadı: %s", exc)
        raise

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_quota(vm_id):
    """
    VM'in kota bilgisini döner.
    {"max_vcpus": int, "max_memory_mb": int, "cpu_shares": int, "io_weight": int}
    veya {} (kota tanımlı değilse)
    """
    try:
        data = _load()
        return data.get(str(vm_id), {})
    except Exception as exc:
        log.exception("get_quota hatası: %s", exc)
        return {}


def set_quota(vm_id, vm_name=None, max_vcpus=None, max_memory_mb=None,
              cpu_shares=1024, io_weight=100):
    """
    VM için kota ayarlar ve virsh ile uygular.
    """
    with _lock:
        try:
            data = _load()
            vm_id_str = str(vm_id)

            existing = data.get(vm_id_str, {})
            quota = {
                "vm_id": vm_id_str,
                "vm_name": vm_name or existing.get("vm_name", ""),
                "max_vcpus": max_vcpus if max_vcpus is not None else existing.get("max_vcpus"),
                "max_memory_mb": max_memory_mb if max_memory_mb is not None else existing.get("max_memory_mb"),
                "cpu_shares": cpu_shares,
                "io_weight": io_weight,
            }

            # virsh setvcpus
            if quota["max_vcpus"] is not None:
                r = _run("virsh", "setvcpus", str(vm_id),
                         str(quota["max_vcpus"]), "--maximum", "--config")
                if r and r.returncode == 0:
                    log.info("vCPU limiti ayarlandı: vm=%s vcpus=%d", vm_id, quota["max_vcpus"])

            # virsh setmaxmem
            if quota["max_memory_mb"] is not None:
                r = _run("virsh", "setmaxmem", str(vm_id),
                         f"{quota['max_memory_mb']}M", "--config")
                if r and r.returncode == 0:
                    log.info("Maksimum bellek ayarlandı: vm=%s mem=%dM", vm_id, quota["max_memory_mb"])

            # cgroups cpu.shares (opsiyonel)
            try:
                cgroup_path = f"/sys/fs/cgroup/cpu/machine.slice/machine-qemu\\x2d{vm_id_str}.scope/cpu.shares"
                if os.path.exists(cgroup_path):
                    with open(cgroup_path, "w", encoding="utf-8") as f:
                        f.write(str(cpu_shares))
                    log.info("cgroup cpu.shares ayarlandı: vm=%s shares=%d", vm_id, cpu_shares)
            except (OSError, PermissionError) as exc:
                log.warning("cgroup cpu.shares ayarlanamadı: %s", exc)

            # io_weight (blkio)
            try:
                blkio_path = f"/sys/fs/cgroup/blkio/machine.slice/machine-qemu\\x2d{vm_id_str}.scope/blkio.weight"
                if os.path.exists(blkio_path):
                    with open(blkio_path, "w", encoding="utf-8") as f:
                        f.write(str(io_weight))
            except (OSError, PermissionError) as exc:
                log.warning("blkio weight ayarlanamadı: %s", exc)

            data[vm_id_str] = quota
            _save(data)

            log.info("Kota kaydedildi: vm=%s", vm_id)
            return {"success": True, "quota": quota}
        except Exception as exc:
            log.exception("set_quota hatası: %s", exc)
            return {"success": False, "error": str(exc)}


def delete_quota(vm_id):
    """VM kotasını siler."""
    with _lock:
        try:
            data = _load()
            vm_id_str = str(vm_id)
            if vm_id_str not in data:
                return {"success": False, "error": "Kota bulunamadı"}
            data.pop(vm_id_str)
            _save(data)
            log.info("Kota silindi: vm=%s", vm_id)
            return {"success": True}
        except Exception as exc:
            log.exception("delete_quota hatası: %s", exc)
            return {"success": False, "error": str(exc)}


def list_quotas():
    """Tüm VM kotalarını listeler (global kota hariç)."""
    try:
        data = _load()
        return [v for k, v in data.items() if k != GLOBAL_QUOTA_KEY]
    except Exception as exc:
        log.exception("list_quotas hatası: %s", exc)
        return []


def get_global_quota():
    """
    Global kota ayarlarını döner.
    {"max_vms_per_user": int, "max_total_vcpus": int, "max_total_memory_gb": int}
    """
    try:
        data = _load()
        return data.get(GLOBAL_QUOTA_KEY, {
            "max_vms_per_user": 10,
            "max_total_vcpus": 64,
            "max_total_memory_gb": 256,
        })
    except Exception as exc:
        log.exception("get_global_quota hatası: %s", exc)
        return {}


def set_global_quota(max_vms_per_user=None, max_total_vcpus=None, max_total_memory_gb=None):
    """Global kota ayarlarını günceller."""
    with _lock:
        try:
            data = _load()
            current = data.get(GLOBAL_QUOTA_KEY, {})

            if max_vms_per_user is not None:
                current["max_vms_per_user"] = max_vms_per_user
            if max_total_vcpus is not None:
                current["max_total_vcpus"] = max_total_vcpus
            if max_total_memory_gb is not None:
                current["max_total_memory_gb"] = max_total_memory_gb

            data[GLOBAL_QUOTA_KEY] = current
            _save(data)

            log.info("Global kota güncellendi: %s", current)
            return {"success": True, "global_quota": current}
        except Exception as exc:
            log.exception("set_global_quota hatası: %s", exc)
            return {"success": False, "error": str(exc)}


def check_quota(username, vcpus, memory_mb):
    """
    Yeni VM oluşturulmadan önce kaynak kontrolü yapar.
    Dönüş: (ok: bool, reason: str)
    """
    try:
        global_quota = get_global_quota()
        all_quotas = list_quotas()

        max_vcpus = global_quota.get("max_total_vcpus", 64)
        max_memory_gb = global_quota.get("max_total_memory_gb", 256)
        max_vms = global_quota.get("max_vms_per_user", 10)

        # Mevcut toplam kullanım
        total_vcpus = sum(q.get("max_vcpus") or 0 for q in all_quotas)
        total_memory_mb = sum(q.get("max_memory_mb") or 0 for q in all_quotas)
        total_memory_gb = total_memory_mb / 1024

        if total_vcpus + vcpus > max_vcpus:
            return False, (f"Toplam vCPU limiti aşılıyor: "
                           f"mevcut={total_vcpus}, istenen={vcpus}, limit={max_vcpus}")

        if total_memory_gb + (memory_mb / 1024) > max_memory_gb:
            return False, (f"Toplam bellek limiti aşılıyor: "
                           f"mevcut={total_memory_gb:.1f}GB, "
                           f"istenen={memory_mb/1024:.1f}GB, limit={max_memory_gb}GB")

        # Kullanıcı VM sayısı (kullanıcı bazlı filtreleme gerekirse vm_name'e username eklenebilir)
        # Şimdilik toplam VM sayısına bakalım
        if len(all_quotas) >= max_vms:
            return False, f"Maksimum VM sayısına ulaşıldı: {max_vms}"

        return True, "OK"
    except Exception as exc:
        log.exception("check_quota hatası: %s", exc)
        return False, f"Kota kontrolü başarısız: {exc}"


def apply_quota_to_vm(vm_id):
    """Mevcut kotayı virsh ile VM'e uygular."""
    try:
        quota = get_quota(vm_id)
        if not quota:
            return {"success": False, "error": "Kota bulunamadı"}

        return set_quota(
            vm_id=vm_id,
            vm_name=quota.get("vm_name"),
            max_vcpus=quota.get("max_vcpus"),
            max_memory_mb=quota.get("max_memory_mb"),
            cpu_shares=quota.get("cpu_shares", 1024),
            io_weight=quota.get("io_weight", 100),
        )
    except Exception as exc:
        log.exception("apply_quota_to_vm hatası: %s", exc)
        return {"success": False, "error": str(exc)}
