"""
OXware Auto Scaler
──────────────────
Otomatik VM kaynak ölçeklendirme (CPU & RAM).
Policy tabanlı, cooldown korumalı.
"""

import json
import logging
import os
import subprocess
import threading
import time
import uuid
from datetime import datetime

log = logging.getLogger("oxware.auto_scaler")

POLICIES_FILE = "/var/lib/oxware/scaling_policies.json"
SCALE_LOG     = "/var/log/oxware/scaling_events.jsonl"

_lock = threading.Lock()

try:
    import notifications as _notif
    NOTIF_AVAILABLE = True
except Exception:
    _notif = None
    NOTIF_AVAILABLE = False


# ── Yardımcı ──────────────────────────────────────────────────────────────────

def _ensure_dir(path: str):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass


def _virsh(args: list, timeout: int = 15) -> tuple:
    """virsh komutu çalıştır. (stdout, stderr, returncode) döndür."""
    try:
        r = subprocess.run(
            ["virsh"] + args,
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        log.debug("virsh hatası: %s", e)
        return "", str(e), -1


# ── Politika CRUD ─────────────────────────────────────────────────────────────

def _load() -> list:
    try:
        if os.path.exists(POLICIES_FILE):
            with open(POLICIES_FILE) as f:
                return json.load(f)
    except Exception as e:
        log.warning("Policy yükleme hatası: %s", e)
    return []


def _save(data: list):
    _ensure_dir(POLICIES_FILE)
    try:
        with open(POLICIES_FILE, "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log.error("Policy kaydetme hatası: %s", e)


def create_policy(vm_id: str, vm_name: str, **kwargs) -> dict:
    """Yeni ölçeklendirme politikası oluştur."""
    try:
        policy = {
            "id": str(uuid.uuid4()),
            "vm_id": vm_id,
            "vm_name": vm_name,
            "cpu_scale_up_threshold": kwargs.get("cpu_scale_up_threshold", 85),
            "cpu_scale_down_threshold": kwargs.get("cpu_scale_down_threshold", 20),
            "mem_scale_up_threshold": kwargs.get("mem_scale_up_threshold", 90),
            "mem_scale_down_threshold": kwargs.get("mem_scale_down_threshold", 30),
            "min_vcpus": kwargs.get("min_vcpus", 1),
            "max_vcpus": kwargs.get("max_vcpus", 16),
            "min_memory_mb": kwargs.get("min_memory_mb", 512),
            "max_memory_mb": kwargs.get("max_memory_mb", 32768),
            "scale_step_vcpus": kwargs.get("scale_step_vcpus", 1),
            "scale_step_memory_mb": kwargs.get("scale_step_memory_mb", 1024),
            "cooldown_seconds": kwargs.get("cooldown_seconds", 300),
            "enabled": kwargs.get("enabled", True),
            "last_action": None,
            "created_at": datetime.now().isoformat(),
        }
        with _lock:
            policies = _load()
            policies.append(policy)
            _save(policies)
        log.info("Policy oluşturuldu: %s (%s)", policy["id"], vm_name)
        return policy
    except Exception as e:
        log.error("create_policy hatası: %s", e)
        return {"error": str(e)}


def list_policies() -> list:
    """Tüm politikaları listele."""
    try:
        with _lock:
            return _load()
    except Exception as e:
        log.error("list_policies hatası: %s", e)
        return []


def get_policy(policy_id: str) -> dict:
    """Belirli bir politikayı getir."""
    try:
        with _lock:
            for p in _load():
                if p["id"] == policy_id:
                    return p
        return {"error": "Policy bulunamadı."}
    except Exception as e:
        log.error("get_policy hatası: %s", e)
        return {"error": str(e)}


def update_policy(policy_id: str, **kwargs) -> dict:
    """Politikayı güncelle."""
    try:
        with _lock:
            policies = _load()
            for i, p in enumerate(policies):
                if p["id"] == policy_id:
                    for k, v in kwargs.items():
                        if k in p:
                            policies[i][k] = v
                    policies[i]["updated_at"] = datetime.now().isoformat()
                    _save(policies)
                    return policies[i]
        return {"error": "Policy bulunamadı."}
    except Exception as e:
        log.error("update_policy hatası: %s", e)
        return {"error": str(e)}


def delete_policy(policy_id: str) -> dict:
    """Politikayı sil."""
    try:
        with _lock:
            policies = _load()
            new_list = [p for p in policies if p["id"] != policy_id]
            if len(new_list) == len(policies):
                return {"error": "Policy bulunamadı."}
            _save(new_list)
        log.info("Policy silindi: %s", policy_id)
        return {"success": True, "deleted_id": policy_id}
    except Exception as e:
        log.error("delete_policy hatası: %s", e)
        return {"error": str(e)}


# ── VM Metrik ve Ölçeklendirme ────────────────────────────────────────────────

def _get_vm_metrics(vm_id: str) -> dict:
    """virsh domstats ile VM CPU ve bellek metrikleri al."""
    try:
        stdout, _, rc = _virsh(["domstats", "--cpu-total", "--balloon", vm_id])
        if rc != 0:
            return {}

        stats = {}
        for line in stdout.splitlines():
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                stats[k.strip()] = v.strip()

        cpu_time  = float(stats.get("cpu.time", 0))
        cpu_user  = float(stats.get("cpu.user", 0))
        # Basit CPU yüzdesi tahmini (gerçek ortamda zaman farkı hesaplanmalı)
        cpu_pct   = min((cpu_user / max(cpu_time, 1)) * 100, 100) if cpu_time else 0

        balloon_cur = float(stats.get("balloon.current", 0))  # KB
        balloon_max = float(stats.get("balloon.maximum", 1))  # KB
        mem_pct = (balloon_cur / max(balloon_max, 1)) * 100 if balloon_max else 0

        # Mevcut vCPU sayısı
        vcpu_out, _, _ = _virsh(["vcpucount", vm_id, "--current"])
        try:
            vcpus = int(vcpu_out.strip())
        except Exception:
            vcpus = 0

        return {
            "cpu_pct": round(cpu_pct, 2),
            "mem_pct": round(mem_pct, 2),
            "current_vcpus": vcpus,
            "current_memory_mb": int(balloon_cur / 1024),
        }
    except Exception as e:
        log.debug("_get_vm_metrics hatası (%s): %s", vm_id, e)
        return {}


def _scale_up_cpu(vm_id: str, current_vcpus: int, step: int) -> int:
    """CPU scale-up uygula."""
    new_vcpus = current_vcpus + step
    stdout, stderr, rc = _virsh(["setvcpus", vm_id, str(new_vcpus), "--live", "--config"])
    if rc != 0:
        log.warning("setvcpus başarısız (%s): %s", vm_id, stderr)
    return new_vcpus if rc == 0 else current_vcpus


def _scale_down_cpu(vm_id: str, current_vcpus: int, step: int) -> int:
    """CPU scale-down uygula."""
    new_vcpus = max(1, current_vcpus - step)
    stdout, stderr, rc = _virsh(["setvcpus", vm_id, str(new_vcpus), "--live", "--config"])
    if rc != 0:
        log.warning("setvcpus başarısız (%s): %s", vm_id, stderr)
    return new_vcpus if rc == 0 else current_vcpus


def _scale_up_mem(vm_id: str, current_mem_mb: int, step: int) -> int:
    """Bellek scale-up uygula."""
    new_mem_mb = current_mem_mb + step
    new_mem_kb = new_mem_mb * 1024
    stdout, stderr, rc = _virsh(["setmem", vm_id, str(new_mem_kb), "--live", "--config"])
    if rc != 0:
        log.warning("setmem başarısız (%s): %s", vm_id, stderr)
    return new_mem_mb if rc == 0 else current_mem_mb


def _scale_down_mem(vm_id: str, current_mem_mb: int, step: int) -> int:
    """Bellek scale-down uygula."""
    new_mem_mb = max(512, current_mem_mb - step)
    new_mem_kb = new_mem_mb * 1024
    stdout, stderr, rc = _virsh(["setmem", vm_id, str(new_mem_kb), "--live", "--config"])
    if rc != 0:
        log.warning("setmem başarısız (%s): %s", vm_id, stderr)
    return new_mem_mb if rc == 0 else current_mem_mb


def _log_event(policy_id: str, vm_id: str, action: str, old_val, new_val, reason: str):
    """Ölçeklendirme olayını SCALE_LOG'a kaydet."""
    event = {
        "ts": datetime.now().isoformat(),
        "policy_id": policy_id,
        "vm_id": vm_id,
        "action": action,
        "old_value": old_val,
        "new_value": new_val,
        "reason": reason,
    }
    _ensure_dir(SCALE_LOG)
    try:
        with open(SCALE_LOG, "a") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception as e:
        log.error("Scale log yazma hatası: %s", e)

    if NOTIF_AVAILABLE:
        try:
            _notif.send_alert(
                message=f"Auto-scale: {action} — VM {vm_id} | {old_val} → {new_val}",
                level="INFO",
                category="auto_scaler",
                details={"policy_id": policy_id, "reason": reason},
                vm_id=vm_id,
            )
        except Exception:
            pass


# ── Kontrol Döngüsü ───────────────────────────────────────────────────────────

def check_and_scale():
    """Tüm aktif politikaları kontrol et ve gerekirse ölçeklendir."""
    try:
        with _lock:
            policies = _load()

        now_ts = time.time()
        updated = []

        for policy in policies:
            if not policy.get("enabled", True):
                updated.append(policy)
                continue

            vm_id = policy["vm_id"]
            vm_name = policy.get("vm_name", vm_id)

            # Cooldown kontrolü
            last_action = policy.get("last_action")
            if last_action:
                try:
                    last_ts = datetime.fromisoformat(last_action).timestamp()
                    if (now_ts - last_ts) < policy.get("cooldown_seconds", 300):
                        log.debug("Cooldown aktif: %s", vm_id)
                        updated.append(policy)
                        continue
                except Exception:
                    pass

            metrics = _get_vm_metrics(vm_id)
            if not metrics:
                updated.append(policy)
                continue

            cpu_pct    = metrics.get("cpu_pct", 0)
            mem_pct    = metrics.get("mem_pct", 0)
            cur_vcpus  = metrics.get("current_vcpus", policy.get("min_vcpus", 1))
            cur_mem_mb = metrics.get("current_memory_mb", policy.get("min_memory_mb", 512))
            scaled     = False

            # CPU Scale Up
            if cpu_pct >= policy["cpu_scale_up_threshold"] and cur_vcpus < policy["max_vcpus"]:
                new_vcpus = min(
                    cur_vcpus + policy["scale_step_vcpus"],
                    policy["max_vcpus"]
                )
                actual = _scale_up_cpu(vm_id, cur_vcpus, policy["scale_step_vcpus"])
                _log_event(policy["id"], vm_id, "cpu_scale_up", cur_vcpus, actual,
                           f"CPU %{cpu_pct:.1f} >= eşik %{policy['cpu_scale_up_threshold']}")
                policy["last_action"] = datetime.now().isoformat()
                scaled = True
                log.info("CPU scale-up: %s %d→%d", vm_name, cur_vcpus, actual)

            # CPU Scale Down
            elif cpu_pct <= policy["cpu_scale_down_threshold"] and cur_vcpus > policy["min_vcpus"]:
                actual = _scale_down_cpu(vm_id, cur_vcpus, policy["scale_step_vcpus"])
                _log_event(policy["id"], vm_id, "cpu_scale_down", cur_vcpus, actual,
                           f"CPU %{cpu_pct:.1f} <= eşik %{policy['cpu_scale_down_threshold']}")
                policy["last_action"] = datetime.now().isoformat()
                scaled = True
                log.info("CPU scale-down: %s %d→%d", vm_name, cur_vcpus, actual)

            # Mem Scale Up
            if mem_pct >= policy["mem_scale_up_threshold"] and cur_mem_mb < policy["max_memory_mb"]:
                actual = _scale_up_mem(vm_id, cur_mem_mb, policy["scale_step_memory_mb"])
                _log_event(policy["id"], vm_id, "mem_scale_up", cur_mem_mb, actual,
                           f"MEM %{mem_pct:.1f} >= eşik %{policy['mem_scale_up_threshold']}")
                policy["last_action"] = datetime.now().isoformat()
                scaled = True
                log.info("MEM scale-up: %s %dMB→%dMB", vm_name, cur_mem_mb, actual)

            # Mem Scale Down
            elif mem_pct <= policy["mem_scale_down_threshold"] and cur_mem_mb > policy["min_memory_mb"]:
                actual = _scale_down_mem(vm_id, cur_mem_mb, policy["scale_step_memory_mb"])
                _log_event(policy["id"], vm_id, "mem_scale_down", cur_mem_mb, actual,
                           f"MEM %{mem_pct:.1f} <= eşik %{policy['mem_scale_down_threshold']}")
                policy["last_action"] = datetime.now().isoformat()
                scaled = True
                log.info("MEM scale-down: %s %dMB→%dMB", vm_name, cur_mem_mb, actual)

            updated.append(policy)

        with _lock:
            _save(updated)

    except Exception as e:
        log.error("check_and_scale hatası: %s", e)


def get_scaling_events(vm_id: str = None, limit: int = 50) -> list:
    """Ölçeklendirme olaylarını SCALE_LOG'dan oku."""
    try:
        if not os.path.exists(SCALE_LOG):
            return []
        events = []
        with open(SCALE_LOG) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    if vm_id is None or e.get("vm_id") == vm_id:
                        events.append(e)
                except Exception:
                    pass
        return list(reversed(events))[:limit]
    except Exception as e:
        log.error("get_scaling_events hatası: %s", e)
        return []


def start_auto_scaler(interval: int = 60):
    """Auto-scaler'ı daemon thread olarak başlat."""
    def _worker():
        while True:
            try:
                check_and_scale()
            except Exception as e:
                log.error("Auto-scaler döngü hatası: %s", e)
            time.sleep(interval)

    t = threading.Thread(target=_worker, daemon=True, name="auto-scaler")
    t.start()
    log.info("Auto-scaler başlatıldı. Aralık: %ds", interval)
    return t
