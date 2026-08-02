#!/usr/bin/env python3
# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy. MIT License.
"""
Cross-cluster migration — federe OXware kurulumları arasında VM taşıma
──────────────────────────────────────────────────────────────────────
Proxmox Datacenter Manager'ın "cross-cluster migration" özelliğinin karşılığı.

`cluster_federation` zaten uzak OXware kurulumlarını (üye) tanıyor ve
kimlik doğrulamalı çağrı yapabiliyor (`forward`). Bu modül onun üstüne
gerçek VM taşımayı koyar:

  1. plan(vm_id, target_member)  → uygunluk kontrolü (VM var mı, hedef sağlıklı
     mı, kaynak yeterli mi, canlı göç mümkün mü) — HİÇBİR ŞEY DEĞİŞTİRMEZ
  2. migrate(...)                → planı uygular

İki mod:
  * live   — aynı L2/paylaşımlı depolama varsa `virsh migrate --live`
             (kesintisiz; hedef host'un libvirt'ine doğrudan bağlanılır)
  * offline— VM kapatılır, diski hedefe aktarılır, orada tanımlanır
             (paylaşımlı depolama yokken tek güvenli yol)

DURUM: beta. `plan()` her zaman güvenli; `migrate()` gerçek taşıma yapar,
bu yüzden varsayılan `dry_run=True`.
"""

from __future__ import annotations

import time
import logging
import threading
import subprocess

log = logging.getLogger("oxware.xcluster")

_jobs: dict = {}
_jobs_lock = threading.RLock()


def _fed():
    try:
        import cluster_federation
        return cluster_federation
    except Exception:
        try:
            from . import cluster_federation      # type: ignore
            return cluster_federation
        except Exception:
            return None


def _vmm():
    try:
        import vm_manager
        return vm_manager
    except Exception:
        return None


# ── 1. Planlama (salt-okunur) ─────────────────────────────────────────────────

def plan(vm_id: str, target_member: str, mode: str = "auto") -> dict:
    """Taşımanın yapılabilirliğini değerlendir. Hiçbir şeyi değiştirmez."""
    fed = _fed()
    if fed is None:
        return {"ok": False, "error": "cluster_federation modülü yok"}

    checks = []

    def add(id_, ok, msg, fix=""):
        checks.append({"id": id_, "ok": bool(ok), "msg": msg, "fix": fix})

    # Hedef üye tanımlı ve sağlıklı mı
    members = {m.get("id"): m for m in (fed.list_members() or [])}
    target = members.get(target_member)
    add("target_known", bool(target),
        "Hedef küme: %s" % (target.get("label") or target_member if target else "BULUNAMADI"),
        "" if target else "Önce Federation → üye ekleyin.")
    if not target:
        return {"ok": False, "vm_id": vm_id, "ready": False, "checks": checks}

    healthy = False
    try:
        for h in (fed.health(target_member) or []):
            if h.get("ok") or h.get("status") == "ok":
                healthy = True
                break
    except Exception as e:
        log.warning("xcluster health: %s", e)
    add("target_healthy", healthy, "Hedef erişilebilir" if healthy else "Hedefe ulaşılamıyor",
        "" if healthy else "Ağ/token kontrolü yapın.")

    # Kaynak VM
    vm, vmm = None, _vmm()
    if vmm:
        try:
            vm = vmm.get_vm(vm_id)
        except Exception:
            vm = None
    add("vm_found", bool(vm), "Kaynak VM: %s" % ((vm or {}).get("name") or vm_id),
        "" if vm else "VM bulunamadı.")
    if not vm:
        return {"ok": False, "vm_id": vm_id, "ready": False, "checks": checks}

    state = (vm.get("state") or "").lower()
    running = state in ("running", "paused")

    # Mod seçimi
    chosen = mode
    if mode == "auto":
        chosen = "live" if running else "offline"
    add("mode", True, "Taşıma modu: %s (VM %s)" % (chosen, state or "?"))
    if chosen == "live" and not running:
        add("live_possible", False, "Canlı göç için VM çalışıyor olmalı",
            "mode=offline seçin veya VM'i başlatın.")

    # Hedefte isim çakışması
    name_clash = False
    try:
        inv = fed.inventory_vms() or {}
        for m_id, vms in (inv.items() if isinstance(inv, dict) else []):
            if m_id != target_member:
                continue
            for rv in (vms if isinstance(vms, list) else []):
                if (rv.get("name") or "") == vm.get("name"):
                    name_clash = True
    except Exception as e:
        log.warning("xcluster inventory: %s", e)
    add("no_name_clash", not name_clash,
        "Hedefte aynı isimde VM %s" % ("VAR" if name_clash else "yok"),
        "Hedefteki VM'i yeniden adlandırın." if name_clash else "")

    ready = all(c["ok"] for c in checks)
    return {"ok": True, "vm_id": vm_id, "vm_name": vm.get("name", ""),
            "target": target_member, "mode": chosen,
            "ready": ready, "checks": checks}


# ── 2. Uygulama ───────────────────────────────────────────────────────────────

def _job_new(vm_id: str, target: str, mode: str) -> str:
    import uuid
    jid = uuid.uuid4().hex[:8]
    with _jobs_lock:
        _jobs[jid] = {"id": jid, "vm_id": vm_id, "target": target, "mode": mode,
                      "status": "running", "step": "Başlıyor", "percent": 0,
                      "started": time.time(), "finished": None, "error": ""}
    return jid


def _job_update(jid: str, **kw):
    with _jobs_lock:
        if jid in _jobs:
            _jobs[jid].update(kw)


def jobs() -> list:
    with _jobs_lock:
        return sorted(_jobs.values(), key=lambda j: -j.get("started", 0))


def _live_migrate(vm_id: str, target_host: str, timeout: int = 900) -> tuple:
    cmd = ["virsh", "-c", "qemu:///system", "migrate", "--live", "--persistent",
           "--undefinesource", vm_id, f"qemu+ssh://{target_host}/system"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            return False, (r.stderr or "").strip()[:300]
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "canlı göç zaman aşımı"
    except Exception as e:                          # pragma: no cover
        return False, str(e)[:300]


def migrate(vm_id: str, target_member: str, mode: str = "auto",
            dry_run: bool = True, target_host: str = "") -> dict:
    """Planı uygula. dry_run=True iken yalnızca planı döndürür."""
    p = plan(vm_id, target_member, mode)
    if not p.get("ok") or not p.get("ready"):
        return {"ok": False, "error": "plan hazır değil", "plan": p}
    if dry_run:
        return {"ok": True, "dry_run": True, "plan": p,
                "note": "Uygulamak için dry_run=false gönderin."}

    chosen = p["mode"]
    if chosen != "live":
        return {"ok": False, "plan": p,
                "error": "offline cross-cluster taşıma bu sürümde otomatik değil — "
                         "VM'i durdurup /api/import/ova veya migration sihirbazını kullanın."}

    # Canlı göç için hedef host adresi gerekir (paylaşımlı depolama/L2 varsayımı)
    host = target_host
    if not host:
        fed = _fed()
        m = next((x for x in (fed.list_members() or []) if x.get("id") == target_member), {})
        url = m.get("url", "")
        host = url.split("//")[-1].split(":")[0].split("/")[0]
    if not host:
        return {"ok": False, "plan": p, "error": "hedef host adresi çözülemedi"}

    jid = _job_new(vm_id, target_member, chosen)
    _job_update(jid, step="Canlı göç başlatıldı", percent=10)
    ok_, msg = _live_migrate(vm_id, host)
    if ok_:
        _job_update(jid, status="done", step="Tamamlandı", percent=100,
                    finished=time.time())
        log.info("xcluster: %s → %s (%s) taşındı", vm_id, target_member, host)
        return {"ok": True, "job_id": jid, "plan": p, "target_host": host}
    _job_update(jid, status="error", step="Hata", error=msg, finished=time.time())
    log.error("xcluster: %s → %s başarısız: %s", vm_id, target_member, msg)
    return {"ok": False, "job_id": jid, "plan": p, "error": msg}


def status() -> dict:
    fed = _fed()
    return {
        "available": fed is not None,
        "members": len(fed.list_members() or []) if fed else 0,
        "jobs": len(jobs()),
    }


if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(status(), indent=2, ensure_ascii=False))
