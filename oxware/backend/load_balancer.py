# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware built-in L4 load balancer.

Manages simple TCP load-balancer pools in front of VMs and renders an
isolated HAProxy config + (optionally) runs a dedicated HAProxy instance for
it — it never touches a system-wide HAProxy. Each pool: a frontend port and a
list of backend ip:port with health checks.

State: /var/lib/oxware/lb_pools.json
Config: /var/lib/oxware/lb/oxware-lb.cfg   PID: /run/oxware/lb.pid
"""
from __future__ import annotations
import json
import logging
import os
import re
import shutil
import subprocess
import threading

log = logging.getLogger("oxware.lb")
_STORE = "/var/lib/oxware/lb_pools.json"
_CFG = "/var/lib/oxware/lb/oxware-lb.cfg"
_PID = "/run/oxware/lb.pid"
_LOCK = threading.Lock()
_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")
_HOSTPORT_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$")


def _haproxy():
    return shutil.which("haproxy")


def available() -> bool:
    return _haproxy() is not None


def _load():
    if not os.path.exists(_STORE):
        return {"pools": []}
    try:
        return json.loads(open(_STORE, encoding="utf-8").read())
    except Exception:
        return {"pools": []}


def _save(d):
    os.makedirs(os.path.dirname(_STORE), exist_ok=True)
    tmp = _STORE + ".tmp"
    open(tmp, "w", encoding="utf-8").write(json.dumps(d, indent=2))
    os.replace(tmp, _STORE)


def list_pools():
    return _load()["pools"]


def _validate(name, port, backends, algo):
    if not _NAME_RE.match(name or ""):
        return "geçersiz ad (a-z0-9_-, ≤32)"
    try:
        port = int(port)
    except (ValueError, TypeError):
        return "port sayı olmalı"
    if not (1 <= port <= 65535):
        return "port 1..65535"
    if algo not in ("roundrobin", "leastconn", "source"):
        return "algo: roundrobin|leastconn|source"
    if not backends or not isinstance(backends, list):
        return "en az bir backend (ip:port) gerekli"
    for b in backends:
        if not _HOSTPORT_RE.match(str(b)):
            return f"geçersiz backend: {b} (ip:port bekleniyor)"
    return None


def upsert_pool(name, port, backends, algo="roundrobin") -> dict:
    err = _validate(name, port, backends, algo)
    if err:
        return {"ok": False, "error": err}
    rec = {"name": name, "port": int(port), "backends": list(backends), "algo": algo}
    with _LOCK:
        d = _load()
        d["pools"] = [p for p in d["pools"] if p["name"] != name] + [rec]
        _save(d)
    return {"ok": True, "pool": rec, "applied": _render_and_reload().get("applied", False)}


def delete_pool(name) -> dict:
    with _LOCK:
        d = _load()
        d["pools"] = [p for p in d["pools"] if p["name"] != name]
        _save(d)
    _render_and_reload()
    return {"ok": True, "name": name}


def render_config() -> str:
    pools = _load()["pools"]
    lines = ["# OXware built-in LB — generated, do not edit by hand",
             "global", "    daemon", "    maxconn 4096",
             "defaults", "    mode tcp", "    timeout connect 5s",
             "    timeout client 50s", "    timeout server 50s",
             "    option tcplog"]
    for p in pools:
        lines.append(f"frontend ox_{p['name']}_fe")
        lines.append(f"    bind *:{p['port']}")
        lines.append(f"    default_backend ox_{p['name']}_be")
        lines.append(f"backend ox_{p['name']}_be")
        lines.append(f"    balance {p.get('algo','roundrobin')}")
        for i, b in enumerate(p["backends"]):
            lines.append(f"    server s{i} {b} check")
    return "\n".join(lines) + "\n"


def _render_and_reload() -> dict:
    cfg = render_config()
    try:
        os.makedirs(os.path.dirname(_CFG), exist_ok=True)
        open(_CFG, "w", encoding="utf-8").write(cfg)
    except Exception as e:
        return {"applied": False, "error": str(e)[:160]}
    hap = _haproxy()
    if not hap:
        return {"applied": False, "note": "haproxy yok — config yazıldı, çalıştırılmadı"}
    # Validate config first.
    chk = subprocess.run([hap, "-c", "-f", _CFG], capture_output=True, text=True)
    if chk.returncode != 0:
        return {"applied": False, "error": "config geçersiz: " + (chk.stderr or "")[:160]}
    # Soft-reload dedicated instance (-sf old pid).
    try:
        os.makedirs(os.path.dirname(_PID), exist_ok=True)
        old = ""
        if os.path.exists(_PID):
            old = open(_PID).read().strip()
        args = [hap, "-D", "-f", _CFG, "-p", _PID]
        if old:
            args += ["-sf", old]
        subprocess.run(args, capture_output=True, text=True, timeout=15)
        return {"applied": True}
    except Exception as e:
        return {"applied": False, "error": str(e)[:160]}


def apply() -> dict:
    return _render_and_reload()
