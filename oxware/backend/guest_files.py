# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware guest file browser — browse/read files inside a VM via the guest
agent (no SSH, no network). Uses the QEMU guest-agent guest-exec command,
which takes an argv list (no shell), so directory/file names cannot inject
commands. Read-only by design.
"""
from __future__ import annotations
import base64
import logging
import time

log = logging.getLogger("oxware.guest_files")
_MAX_READ = 256 * 1024  # 256 KB cap for in-panel file view


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


def _name(vm, vm_id):
    try:
        return vm.get_vm(vm_id).get("name", vm_id)
    except Exception:
        return vm_id


def _gexec(vm, vm_name, path, args):
    """Run a binary in the guest via the agent (argv list, no shell)."""
    started = vm._qemu_agent_cmd(vm_name, "guest-exec", {
        "path": path, "arg": args, "capture-output": True}, timeout=8)
    if not started or "pid" not in started:
        return None
    pid = started["pid"]
    for _ in range(20):
        st = vm._qemu_agent_cmd(vm_name, "guest-exec-status", {"pid": pid}, timeout=8)
        if st and st.get("exited"):
            out = ""
            try:
                out = base64.b64decode(st.get("out-data") or "").decode(errors="replace")
            except Exception:
                out = ""
            return {"exitcode": st.get("exitcode"), "out": out}
        time.sleep(0.25)
    return None


def list_dir(vm_id: str, path: str = "/") -> dict:
    vm = _vm()
    if not vm:
        return {"ok": False, "error": "vm_manager yok"}
    if not isinstance(path, str) or "\x00" in path or len(path) > 4096:
        return {"ok": False, "error": "geçersiz yol"}
    name = _name(vm, vm_id)
    if vm.get_guest_agent_status(vm_id) != "running":
        return {"ok": False, "error": "Guest agent yanıt vermiyor (VM + agent gerekli)"}
    for binp in ("/bin/ls", "/usr/bin/ls"):
        r = _gexec(vm, name, binp, ["-la", "--time-style=long-iso", path])
        if r is not None:
            break
    else:
        return {"ok": False, "error": "ls çalıştırılamadı (Linux guest gerekli)"}
    entries = []
    for ln in (r.get("out") or "").splitlines():
        parts = ln.split(None, 7)
        if len(parts) < 8 or parts[0] == "total":
            continue
        perm, _, owner, group, size, date, tm, nm = parts
        if nm in (".", ".."):
            continue
        entries.append({"name": nm, "perm": perm, "owner": owner,
                        "size": size, "modified": f"{date} {tm}",
                        "dir": perm.startswith("d"), "link": perm.startswith("l")})
    entries.sort(key=lambda e: (not e["dir"], e["name"].lower()))
    return {"ok": True, "vm": name, "path": path, "entries": entries}


def read_file(vm_id: str, path: str) -> dict:
    vm = _vm()
    if not vm:
        return {"ok": False, "error": "vm_manager yok"}
    if not isinstance(path, str) or "\x00" in path or len(path) > 4096:
        return {"ok": False, "error": "geçersiz yol"}
    name = _name(vm, vm_id)
    if vm.get_guest_agent_status(vm_id) != "running":
        return {"ok": False, "error": "Guest agent yanıt vermiyor"}
    for binp in ("/usr/bin/head", "/bin/head"):
        r = _gexec(vm, name, binp, ["-c", str(_MAX_READ), path])
        if r is not None:
            break
    else:
        return {"ok": False, "error": "okunamadı"}
    if r.get("exitcode") not in (0, None):
        return {"ok": False, "error": f"okuma hatası (exit {r.get('exitcode')})"}
    content = r.get("out") or ""
    return {"ok": True, "vm": name, "path": path,
            "content": content[:_MAX_READ], "truncated": len(content) >= _MAX_READ}
