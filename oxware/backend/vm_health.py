# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware VM boot health-check.

"Started" is not "working". A VM can be running in libvirt while its OS hung
on boot or a critical service failed. This module verifies real readiness via
the QEMU guest agent (systemd state + named service checks) and host-side TCP
port probes, against an optional per-VM policy.

State: /var/lib/oxware/vm_health.json  (per-VM expected services + ports)
"""
from __future__ import annotations
import base64
import json
import logging
import os
import socket
import threading
import time
from pathlib import Path

log = logging.getLogger("oxware.vm_health")
_STORE = Path("/var/lib/oxware/vm_health.json")
_LOCK = threading.Lock()
_SYSTEMCTL = ("/usr/bin/systemctl", "/bin/systemctl")


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


def _load() -> dict:
    if not _STORE.exists():
        return {"policies": {}}
    try:
        return json.loads(_STORE.read_text(encoding="utf-8"))
    except Exception:
        return {"policies": {}}


def _save(d: dict) -> None:
    _STORE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _STORE.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, _STORE)


def get_policy(vm_name: str) -> dict:
    p = _load()["policies"].get(vm_name) or {}
    return {"services": p.get("services", []), "ports": p.get("ports", [])}


def set_policy(vm_name: str, services: list = None, ports: list = None) -> dict:
    services = [str(s)[:128] for s in (services or [])][:32]
    ports = [int(p) for p in (ports or []) if 1 <= int(p) <= 65535][:32]
    with _LOCK:
        d = _load()
        d["policies"][vm_name] = {"services": services, "ports": ports}
        _save(d)
    return {"ok": True, "vm": vm_name, "services": services, "ports": ports}


def _guest_run(vm, vm_name: str, path: str, args: list) -> dict | None:
    """guest-exec + poll guest-exec-status. Returns {exitcode, out} or None."""
    started = vm._qemu_agent_cmd(vm_name, "guest-exec", {
        "path": path, "arg": args, "capture-output": True}, timeout=5)
    if not started or "pid" not in started:
        return None
    pid = started["pid"]
    for _ in range(12):
        st = vm._qemu_agent_cmd(vm_name, "guest-exec-status", {"pid": pid}, timeout=5)
        if st and st.get("exited"):
            txt = ""
            try:
                txt = base64.b64decode(st.get("out-data") or "").decode(errors="ignore")
            except Exception:
                pass
            return {"exitcode": st.get("exitcode"), "out": txt.strip()}
        time.sleep(0.3)
    return None


def _systemctl(vm, vm_name: str, args: list) -> dict | None:
    for path in _SYSTEMCTL:
        r = _guest_run(vm, vm_name, path, args)
        if r is not None:
            return r
    return None


def _tcp_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def check(vm_id: str) -> dict:
    vm = _vm()
    if not vm:
        return {"ok": False, "error": "vm_manager yok"}
    try:
        info = vm.get_vm(vm_id)
    except Exception as e:
        return {"ok": False, "error": f"VM bulunamadı: {str(e)[:120]}"}
    vm_name = info["name"]
    state = info.get("state")
    res = {
        "ok": True, "vm": vm_name, "state": state,
        "running": state == "running",
        "agent_responsive": False, "boot_state": None,
        "services": [], "ports": [], "ip": "",
        "healthy": False, "checks_total": 0, "checks_passed": 0,
    }
    if state != "running":
        res["summary"] = "VM çalışmıyor"
        return res

    status = vm.get_guest_agent_status(vm_id)
    res["agent_responsive"] = (status == "running")

    # Resolve an IP for TCP probes (guest agent first, then libvirt nets).
    ip = ""
    try:
        gi = vm.get_guest_agent_info(vm_id)
        for ifc in gi.get("interfaces", []):
            for a in ifc.get("ips", []):
                if a.get("type") == "ipv4" and not a["ip"].startswith("127."):
                    ip = a["ip"]; break
            if ip:
                break
    except Exception:
        pass
    if not ip:
        for n in (info.get("networks") or []):
            if n.get("ip"):
                ip = n["ip"]; break
    res["ip"] = ip

    policy = get_policy(vm_name)
    checks_total = 1  # agent responsiveness counts as a check
    checks_passed = 1 if res["agent_responsive"] else 0

    if res["agent_responsive"]:
        sysrun = _systemctl(vm, vm_name, ["is-system-running"])
        if sysrun is not None:
            res["boot_state"] = sysrun["out"] or "unknown"
            checks_total += 1
            # 'running' = clean; 'degraded' = booted but a unit failed.
            if sysrun["out"] in ("running", "degraded"):
                checks_passed += 1
        for svc in policy["services"]:
            r = _systemctl(vm, vm_name, ["is-active", svc])
            active = bool(r) and r["out"] == "active"
            res["services"].append({"name": svc, "active": active})
            checks_total += 1
            checks_passed += 1 if active else 0

    for port in policy["ports"]:
        opn = _tcp_open(ip, port) if ip else False
        res["ports"].append({"port": port, "open": opn})
        checks_total += 1
        checks_passed += 1 if opn else 0

    res["checks_total"] = checks_total
    res["checks_passed"] = checks_passed
    res["healthy"] = (res["running"] and res["agent_responsive"]
                      and checks_passed == checks_total)
    res["summary"] = f"{checks_passed}/{checks_total} kontrol geçti"
    return res
