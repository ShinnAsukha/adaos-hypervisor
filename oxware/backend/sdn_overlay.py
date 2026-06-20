# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware SDN overlay networks (VXLAN).

Creates L2-over-L3 overlay segments so tenants get isolated networks that
span hosts without VLAN reconfiguration. Real `ip link ... type vxlan`
plumbing, guarded on iproute2. Definitions are persisted so they can be
re-applied after reboot.

State: /var/lib/oxware/sdn_overlays.json
"""
from __future__ import annotations
import json
import logging
import os
import re
import shutil
import subprocess
import threading

log = logging.getLogger("oxware.sdn")
_STORE = "/var/lib/oxware/sdn_overlays.json"
_LOCK = threading.Lock()
_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")  # netdev name limit


def _ip():
    return shutil.which("ip")


def available() -> bool:
    return _ip() is not None


def _run(args, timeout=15):
    exe = _ip()
    if not exe:
        return None
    try:
        return subprocess.run([exe] + args, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        log.warning("ip hata: %s", e)
        return None


def _load():
    if not os.path.exists(_STORE):
        return {"overlays": []}
    try:
        return json.loads(open(_STORE, encoding="utf-8").read())
    except Exception:
        return {"overlays": []}


def _save(d):
    os.makedirs(os.path.dirname(_STORE), exist_ok=True)
    tmp = _STORE + ".tmp"
    open(tmp, "w", encoding="utf-8").write(json.dumps(d, indent=2))
    os.replace(tmp, _STORE)


def list_overlays():
    # annotate with live presence
    live = set()
    r = _run(["-o", "link", "show", "type", "vxlan"])
    if r and r.returncode == 0:
        for line in r.stdout.splitlines():
            m = re.search(r"\d+:\s+([\w-]+)[:@]", line)
            if m:
                live.add(m.group(1))
    out = []
    for o in _load()["overlays"]:
        o = dict(o)
        o["up"] = o["name"] in live
        out.append(o)
    return out


def create_overlay(name: str, vni: int, dev: str = "", mtu: int = 1450) -> dict:
    if not _NAME_RE.match(name or ""):
        return {"ok": False, "error": "geçersiz ad (a-z0-9_-, ≤15)"}
    try:
        vni = int(vni)
    except (ValueError, TypeError):
        return {"ok": False, "error": "vni sayı olmalı"}
    if not (1 <= vni <= 16777215):
        return {"ok": False, "error": "vni 1..16777215"}
    if dev and not re.match(r"^[\w.-]{1,32}$", dev):
        return {"ok": False, "error": "geçersiz dev"}
    if not _ip():
        return {"ok": False, "error": "iproute2 (ip) yok"}
    args = ["link", "add", name, "type", "vxlan", "id", str(vni),
            "dstport", "4789"]
    if dev:
        args += ["dev", dev]
    r = _run(args)
    if r is None or r.returncode != 0:
        return {"ok": False, "error": (r.stderr or "ip link add hata").strip()[:200] if r else "ip yok"}
    _run(["link", "set", name, "mtu", str(int(mtu))])
    _run(["link", "set", name, "up"])
    rec = {"name": name, "vni": vni, "dev": dev, "mtu": int(mtu)}
    with _LOCK:
        d = _load()
        d["overlays"] = [o for o in d["overlays"] if o["name"] != name] + [rec]
        _save(d)
    log.info("VXLAN overlay oluşturuldu: %s vni=%s", name, vni)
    return {"ok": True, "overlay": rec}


def delete_overlay(name: str) -> dict:
    if not _NAME_RE.match(name or ""):
        return {"ok": False, "error": "geçersiz ad"}
    if _ip():
        _run(["link", "del", name])
    with _LOCK:
        d = _load()
        before = len(d["overlays"])
        d["overlays"] = [o for o in d["overlays"] if o["name"] != name]
        _save(d)
    return {"ok": True, "name": name, "removed": before != len(_load()["overlays"]) or True}
