# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware per-VM disk QoS (storage I/O throttling).

Stops a single noisy VM from starving the shared datastore by capping its
block-device IOPS and/or bandwidth via libvirt blkdeviotune (applied --live
and --config so it survives reboot). Network QoS already exists separately;
this is the disk side.

libvirt rule: for a given axis you set EITHER the total_* limit OR the
read_*/write_* pair, never both. We enforce that and report a clear error.
"""
from __future__ import annotations
import logging
import re
import shutil
import subprocess

log = logging.getLogger("oxware.storage_qos")
_NAME_RE = re.compile(r"^[a-zA-Z0-9._:-]{1,64}$")

# field -> virsh flag
_FIELDS = {
    "total_bytes_sec": "--total-bytes-sec",
    "read_bytes_sec":  "--read-bytes-sec",
    "write_bytes_sec": "--write-bytes-sec",
    "total_iops_sec":  "--total-iops-sec",
    "read_iops_sec":   "--read-iops-sec",
    "write_iops_sec":  "--write-iops-sec",
}


def _virsh():
    return shutil.which("virsh")


def _run(args: list, timeout: int = 15):
    v = _virsh()
    if not v:
        return None
    try:
        return subprocess.run([v] + args, capture_output=True, text=True,
                              timeout=timeout)
    except Exception as e:
        log.warning("virsh hata: %s", e)
        return None


def available() -> bool:
    return _virsh() is not None


def list_disks(vm_name: str) -> dict:
    if not _NAME_RE.match(vm_name):
        return {"ok": False, "error": "geçersiz VM adı"}
    r = _run(["domblklist", vm_name, "--details"])
    if r is None:
        return {"ok": False, "error": "virsh bulunamadı"}
    if r.returncode != 0:
        return {"ok": False, "error": (r.stderr or "domblklist hata").strip()[:200]}
    disks = []
    for line in r.stdout.splitlines():
        parts = line.split()
        # columns: Type Device Target Source ; only real disk devices
        if len(parts) >= 3 and parts[1] == "disk" and parts[0] in ("file", "block"):
            disks.append({"target": parts[2],
                          "source": parts[3] if len(parts) >= 4 else ""})
    return {"ok": True, "vm": vm_name, "disks": disks}


def get_qos(vm_name: str, dev: str) -> dict:
    if not _NAME_RE.match(vm_name) or not _NAME_RE.match(dev):
        return {"ok": False, "error": "geçersiz ad"}
    r = _run(["blkdeviotune", vm_name, dev])
    if r is None:
        return {"ok": False, "error": "virsh bulunamadı"}
    if r.returncode != 0:
        return {"ok": False, "error": (r.stderr or "blkdeviotune hata").strip()[:200]}
    qos = {}
    for line in r.stdout.splitlines():
        if ":" in line:
            k, _, val = line.partition(":")
            k = k.strip()
            if k in _FIELDS:
                try:
                    qos[k] = int(val.strip())
                except ValueError:
                    pass
    return {"ok": True, "vm": vm_name, "dev": dev, "qos": qos}


def set_qos(vm_name: str, dev: str, limits: dict) -> dict:
    if not _NAME_RE.match(vm_name) or not _NAME_RE.match(dev):
        return {"ok": False, "error": "geçersiz ad"}
    clean = {}
    for k, flag in _FIELDS.items():
        if k in limits and limits[k] is not None:
            try:
                v = int(limits[k])
            except (ValueError, TypeError):
                return {"ok": False, "error": f"{k} sayı olmalı"}
            if v < 0:
                return {"ok": False, "error": f"{k} negatif olamaz"}
            clean[k] = v
    if not clean:
        return {"ok": False, "error": "en az bir limit gerekli (0 = sınırsız)"}
    # libvirt: total_* and read/write_* on the same axis are mutually exclusive.
    for axis in ("bytes_sec", "iops_sec"):
        has_total = f"total_{axis}" in clean and clean[f"total_{axis}"] > 0
        has_rw = (clean.get(f"read_{axis}", 0) > 0 or clean.get(f"write_{axis}", 0) > 0)
        if has_total and has_rw:
            return {"ok": False,
                    "error": f"{axis}: total ile read/write aynı anda olamaz"}
    args = ["blkdeviotune", vm_name, dev]
    for k, v in clean.items():
        args += [_FIELDS[k], str(v)]
    args += ["--live", "--config"]
    r = _run(args)
    if r is None:
        return {"ok": False, "error": "virsh bulunamadı"}
    if r.returncode != 0:
        return {"ok": False, "error": (r.stderr or "set hata").strip()[:200]}
    log.info("disk QoS uygulandı: %s/%s %s", vm_name, dev, clean)
    return {"ok": True, "vm": vm_name, "dev": dev, "applied": clean}
