"""OXware Firecracker microVM runtime (v3.0).

A second-tier runtime alongside QEMU/KVM. Firecracker starts in ~125ms
and uses ~5MB RAM overhead, ideal for serverless / per-request VM
workloads. This module exposes microVM lifecycle through the same VM
API surface so panel code can treat them as just another VM type.

State: /var/lib/oxware/firecracker_vms.json
"""
from __future__ import annotations
import json
import logging
import os
import shutil
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path

log = logging.getLogger("oxware.firecracker")
_CATALOG = Path("/var/lib/oxware/firecracker_vms.json")
_SOCKETS_DIR = Path("/run/oxware/firecracker")
_LOCK = threading.Lock()


def _firecracker_bin() -> str | None:
    return shutil.which("firecracker")


def runtime_status() -> dict:
    """Report whether the firecracker binary + /dev/kvm are present so the
    panel can show a clear 'ready / not installed' badge."""
    fc = _firecracker_bin()
    return {
        "firecracker_bin": fc or "(not found)",
        "kvm_available": os.path.exists("/dev/kvm"),
        "ready": bool(fc) and os.path.exists("/dev/kvm"),
        "maturity": "experimental",
    }


def _load() -> dict:
    if not _CATALOG.exists():
        return {"vms": []}
    try:
        return json.loads(_CATALOG.read_text(encoding="utf-8"))
    except Exception:
        return {"vms": []}


def _save(d: dict) -> None:
    _CATALOG.parent.mkdir(parents=True, exist_ok=True)
    tmp = _CATALOG.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2), encoding="utf-8")
    os.replace(tmp, _CATALOG)


def list_microvms() -> list:
    return _load().get("vms", [])


def _write_fc_config(vm: dict, cfg_path: Path) -> None:
    """Write a Firecracker JSON machine config (boot-source + drives + machine)."""
    cfg = {
        "boot-source": {
            "kernel_image_path": vm["kernel_path"],
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off",
        },
        "drives": [{
            "drive_id": "rootfs",
            "path_on_host": vm["rootfs_path"],
            "is_root_device": True,
            "is_read_only": False,
        }],
        "machine-config": {
            "vcpu_count": vm["vcpus"],
            "mem_size_mib": vm["memory_mb"],
            "smt": False,
        },
    }
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def launch(name: str, kernel_path: str, rootfs_path: str,
           vcpus: int = 1, memory_mb: int = 128) -> dict:
    """Launch a Firecracker microVM. Spawns the real firecracker process
    with a generated machine config when the binary + /dev/kvm exist;
    otherwise records the intent for an out-of-band runner."""
    if vcpus < 1 or vcpus > 16:
        return {"ok": False, "error": "vcpus must be 1..16"}
    if memory_mb < 64 or memory_mb > 16384:
        return {"ok": False, "error": "memory_mb must be 64..16384"}
    if not name or "/" in name or ".." in name:
        return {"ok": False, "error": "invalid name"}
    vm_id = f"fc-{uuid.uuid4().hex[:8]}"
    sock = _SOCKETS_DIR / f"{name}.sock"
    cfg_path = _SOCKETS_DIR / f"{name}.json"
    vm = {
        "id": vm_id,
        "name": name,
        "kernel_path": kernel_path,
        "rootfs_path": rootfs_path,
        "vcpus": vcpus,
        "memory_mb": memory_mb,
        "api_socket": str(sock),
        "config_path": str(cfg_path),
        "pid": None,
        "state": "pending",
        "created_at": time.time(),
    }
    fc = _firecracker_bin()
    kvm = os.path.exists("/dev/kvm")
    if fc and kvm:
        # Validate the kernel + rootfs exist before spending a process slot.
        if not Path(kernel_path).exists():
            vm["state"] = "error"
            vm["error"] = f"kernel not found: {kernel_path}"
        elif not Path(rootfs_path).exists():
            vm["state"] = "error"
            vm["error"] = f"rootfs not found: {rootfs_path}"
        else:
            try:
                _SOCKETS_DIR.mkdir(parents=True, exist_ok=True)
                if sock.exists():
                    sock.unlink()
                _write_fc_config(vm, cfg_path)
                proc = subprocess.Popen(
                    [fc, "--api-sock", str(sock), "--config-file", str(cfg_path)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                # Give it a beat to crash on bad args.
                time.sleep(0.2)
                if proc.poll() is None:
                    vm["state"] = "running"
                    vm["pid"] = proc.pid
                else:
                    vm["state"] = "error"
                    vm["error"] = f"firecracker exited rc={proc.returncode}"
            except Exception as e:
                vm["state"] = "error"
                vm["error"] = str(e)[:300]
    else:
        vm["state"] = "pending"
        vm["note"] = ("firecracker binary or /dev/kvm missing; "
                      "intent recorded for out-of-band runner")
    with _LOCK:
        d = _load()
        d["vms"].append(vm)
        _save(d)
    log.info("firecracker launch: %s (%d vcpus, %dMB, state=%s)",
             name, vcpus, memory_mb, vm["state"])
    return {"ok": vm["state"] != "error", "vm": vm}


def stop(vm_id: str) -> dict:
    with _LOCK:
        d = _load()
        for vm in d["vms"]:
            if vm["id"] == vm_id:
                pid = vm.get("pid")
                if pid:
                    try:
                        os.kill(int(pid), signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    except Exception as e:
                        log.warning("fc stop: kill %s failed: %s", pid, e)
                sock = vm.get("api_socket")
                if sock:
                    try:
                        sp = Path(sock)
                        if sp.exists():
                            sp.unlink()
                    except Exception:
                        pass
                vm["state"] = "stopped"
                vm["pid"] = None
                _save(d)
                return {"ok": True, "vm_id": vm_id, "state": "stopped"}
    return {"ok": False, "error": "not found"}


def delete(vm_id: str) -> dict:
    with _LOCK:
        d = _load()
        new = [v for v in d["vms"] if v["id"] != vm_id]
        if len(new) == len(d["vms"]):
            return {"ok": False, "error": "not found"}
        d["vms"] = new
        _save(d)
    return {"ok": True, "vm_id": vm_id}
