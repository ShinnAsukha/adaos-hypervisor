# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware vApp — VM group boot orchestration.

Group VMs and start/stop them in a defined order with per-member delays (e.g.
DB first, wait 20s, then app servers). vSphere-vApp equivalent. Per-VM disk
boot order already exists; this adds cross-VM orchestration.

State: /var/lib/oxware/vapps.json
"""
from __future__ import annotations
import json
import logging
import os
import threading
import time
import uuid

log = logging.getLogger("oxware.vapp")
_STORE = "/var/lib/oxware/vapps.json"
_LOCK = threading.Lock()


def _vm():
    try:
        import vm_manager as m
        return m
    except Exception:
        try:
            from oxware.backend import vm_manager as m
            return m
        except Exception:
            return None


def _load():
    if not os.path.exists(_STORE):
        return {"vapps": []}
    try:
        return json.loads(open(_STORE, encoding="utf-8").read())
    except Exception:
        return {"vapps": []}


def _save(d):
    os.makedirs(os.path.dirname(_STORE), exist_ok=True)
    tmp = _STORE + ".tmp"
    open(tmp, "w", encoding="utf-8").write(json.dumps(d, indent=2, ensure_ascii=False))
    os.replace(tmp, _STORE)


def list_vapps():
    return _load()["vapps"]


def get_vapp(vapp_id):
    return next((v for v in _load()["vapps"] if v["id"] == vapp_id), None)


def _clean_members(members):
    out = []
    for m in (members or []):
        vm = (m.get("vm") or "").strip()
        if not vm:
            continue
        out.append({"vm": vm[:64],
                    "order": int(m.get("order", 0)),
                    "delay_sec": max(0, min(int(m.get("delay_sec", 0)), 600))})
    out.sort(key=lambda x: x["order"])
    return out


def upsert_vapp(name, members, vapp_id=None):
    name = (name or "").strip()[:64]
    if not name:
        return {"ok": False, "error": "ad gerekli"}
    rec = {"id": vapp_id or ("vapp-" + uuid.uuid4().hex[:8]),
           "name": name, "members": _clean_members(members),
           "updated": time.time()}
    with _LOCK:
        d = _load()
        d["vapps"] = [v for v in d["vapps"] if v["id"] != rec["id"]] + [rec]
        _save(d)
    return {"ok": True, "vapp": rec}


def delete_vapp(vapp_id):
    with _LOCK:
        d = _load()
        d["vapps"] = [v for v in d["vapps"] if v["id"] != vapp_id]
        _save(d)
    return {"ok": True, "id": vapp_id}


def _run_power(vapp, action):
    vm = _vm()
    if not vm:
        return
    members = sorted(vapp["members"], key=lambda x: x["order"],
                     reverse=(action == "stop"))
    for m in members:
        try:
            if action == "start":
                vm.start_vm(m["vm"])
            else:
                vm.stop_vm(m["vm"])
            log.info("vApp %s: %s %s", vapp["name"], action, m["vm"])
        except Exception as e:
            log.warning("vApp %s: %s %s hata: %s", vapp["name"], action, m["vm"], e)
        if m.get("delay_sec"):
            time.sleep(m["delay_sec"])


def power_vapp(vapp_id, action):
    if action not in ("start", "stop"):
        return {"ok": False, "error": "action start|stop"}
    vapp = get_vapp(vapp_id)
    if not vapp:
        return {"ok": False, "error": "vApp bulunamadı"}
    if not vapp["members"]:
        return {"ok": False, "error": "üye yok"}
    threading.Thread(target=_run_power, args=(vapp, action), daemon=True).start()
    return {"ok": True, "vapp": vapp["name"], "action": action,
            "members": len(vapp["members"]),
            "note": f"{len(vapp['members'])} VM sırayla {action} ediliyor"}
