# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware Cluster Time-Machine.

Point-in-time snapshots of the WHOLE cluster *configuration* (VMs, networks,
DVS, vApps) — then a git-style diff between any two points so you can see
exactly what changed and when. Restore is intentionally ADVISORY (it shows the
delta to re-apply) — auto-reapplying cluster state is destructive, so the
operator acts on the diff deliberately.

State: /var/lib/oxware/timemachine/<id>.json
"""
from __future__ import annotations
import json
import logging
import os
import time
import uuid
from pathlib import Path

log = logging.getLogger("oxware.timemachine")
_DIR = Path("/var/lib/oxware/timemachine")


def _mod(name):
    try:
        return __import__(name)
    except Exception:
        try:
            return __import__(f"oxware.backend.{name}", fromlist=["*"])
        except Exception:
            return None


def _capture() -> dict:
    out = {"vms": [], "networks": [], "dvs": [], "vapps": []}
    vm = _mod("vm_manager")
    if vm:
        try:
            out["vms"] = [{"name": v["name"], "state": v.get("state"),
                           "vcpus": v.get("vcpus"), "memory_mb": v.get("memory_mb")}
                          for v in vm.list_vms()]
        except Exception:
            pass
    nm = _mod("network_manager")
    if nm:
        try:
            out["networks"] = [{"name": n.get("name"), "forward_mode": n.get("forward_mode"),
                                "dhcp": bool(n.get("dhcp"))} for n in nm.list_networks()]
        except Exception:
            pass
    dm = _mod("dvs_manager")
    if dm:
        try:
            out["dvs"] = [{"name": d.get("name"), "vlan_id": d.get("vlan_id"),
                           "port_groups": len(d.get("port_groups", [])),
                           "uplinks": d.get("uplinks", [])} for d in dm.list_dvs()]
        except Exception:
            pass
    va = _mod("vapp_manager")
    if va:
        try:
            out["vapps"] = [{"name": v.get("name"), "members": len(v.get("members", []))}
                            for v in va.list_vapps()]
        except Exception:
            pass
    return out


def snapshot(label: str = "") -> dict:
    snap = {
        "id": "tm-" + uuid.uuid4().hex[:10],
        "label": (label or "").strip()[:120] or time.strftime("%Y-%m-%d %H:%M"),
        "ts": time.time(),
        "state": _capture(),
    }
    counts = {k: len(v) for k, v in snap["state"].items()}
    snap["counts"] = counts
    _DIR.mkdir(parents=True, exist_ok=True)
    (_DIR / f"{snap['id']}.json").write_text(
        json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("timemachine snapshot: %s %s", snap["id"], counts)
    return {"ok": True, "id": snap["id"], "label": snap["label"], "counts": counts}


def list_snapshots() -> list:
    if not _DIR.is_dir():
        return []
    out = []
    for p in _DIR.glob("tm-*.json"):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            out.append({"id": d["id"], "label": d.get("label"), "ts": d.get("ts"),
                        "counts": d.get("counts", {})})
        except Exception:
            pass
    out.sort(key=lambda x: x.get("ts", 0), reverse=True)
    return out


def _load(snap_id) -> dict | None:
    p = _DIR / f"{snap_id}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def delete_snapshot(snap_id) -> dict:
    p = _DIR / f"{snap_id}.json"
    if p.exists():
        p.unlink()
        return {"ok": True, "id": snap_id}
    return {"ok": False, "error": "bulunamadı"}


def _key(section, item):
    return item.get("name")


def diff(id_a: str, id_b: str) -> dict:
    a, b = _load(id_a), _load(id_b)
    if not a or not b:
        return {"ok": False, "error": "snapshot bulunamadı"}
    result = {}
    for section in ("vms", "networks", "dvs", "vapps"):
        am = {_key(section, x): x for x in a["state"].get(section, [])}
        bm = {_key(section, x): x for x in b["state"].get(section, [])}
        added = [k for k in bm if k not in am]
        removed = [k for k in am if k not in bm]
        changed = []
        for k in am:
            if k in bm and am[k] != bm[k]:
                changed.append({"name": k, "from": am[k], "to": bm[k]})
        result[section] = {"added": added, "removed": removed, "changed": changed}
    return {"ok": True, "from": {"id": id_a, "label": a.get("label")},
            "to": {"id": id_b, "label": b.get("label")}, "diff": result}
