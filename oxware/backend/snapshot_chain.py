# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware snapshot / backing-chain analysis.

Long qcow2 backing chains (many external snapshots never consolidated) hurt
read performance and inflate restore risk. This module reports, per VM disk,
the backing-chain depth and the libvirt snapshot count, and warns when either
crosses a threshold — so an operator knows to consolidate.

Read-only and safe: it inspects with `virsh domblklist` + `qemu-img info
--backing-chain`. It does NOT mutate disks (live blockcommit is delicate and
left to an explicit, separately-gated action).
"""
from __future__ import annotations
import json
import logging
import re
import shutil
import subprocess

log = logging.getLogger("oxware.snapshot_chain")
_NAME_RE = re.compile(r"^[a-zA-Z0-9._:-]{1,64}$")
_CHAIN_WARN = 4   # backing-chain images beyond this → warn
_SNAP_WARN = 10   # libvirt snapshots beyond this → warn


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


def _run(args, timeout=20):
    exe = shutil.which(args[0])
    if not exe:
        return None
    try:
        return subprocess.run([exe] + args[1:], capture_output=True,
                              text=True, timeout=timeout)
    except Exception as e:
        log.warning("%s hata: %s", args[0], e)
        return None


def _disk_sources(vm_name):
    r = _run(["virsh", "domblklist", vm_name, "--details"])
    if r is None or r.returncode != 0:
        return []
    out = []
    for line in r.stdout.splitlines():
        p = line.split()
        if len(p) >= 4 and p[1] == "disk" and p[0] in ("file", "block"):
            out.append({"target": p[2], "source": p[3]})
    return out


def _chain_depth(source):
    r = _run(["qemu-img", "info", "--backing-chain", "--output=json", source])
    if r is None or r.returncode != 0:
        return None
    try:
        data = json.loads(r.stdout)
        return len(data) if isinstance(data, list) else 1
    except Exception:
        return None


def analyze(vm_id: str) -> dict:
    vm = _vm()
    if not vm:
        return {"ok": False, "error": "vm_manager yok"}
    try:
        info = vm.get_vm(vm_id)
    except Exception as e:
        return {"ok": False, "error": f"VM bulunamadı: {str(e)[:120]}"}
    name = info["name"]
    if not _NAME_RE.match(name):
        return {"ok": False, "error": "geçersiz VM adı"}

    try:
        snaps = vm.list_snapshots(vm_id) or []
        snap_count = len(snaps)
    except Exception:
        snap_count = 0

    disks = []
    max_depth = 0
    warnings = []
    for d in _disk_sources(name):
        depth = _chain_depth(d["source"])
        if depth is not None:
            max_depth = max(max_depth, depth)
            if depth > _CHAIN_WARN:
                warnings.append(f"{d['target']}: backing-chain derinliği {depth} "
                                f"(eşik {_CHAIN_WARN}) — konsolidasyon önerilir")
        disks.append({"target": d["target"], "source": d["source"],
                      "chain_depth": depth})

    if snap_count > _SNAP_WARN:
        warnings.append(f"{snap_count} snapshot (eşik {_SNAP_WARN}) — eski "
                        f"snapshot'ları silmeyi düşünün")

    healthy = not warnings
    return {
        "ok": True, "vm": name, "snapshot_count": snap_count,
        "max_chain_depth": max_depth, "disks": disks,
        "warnings": warnings, "healthy": healthy,
        "thresholds": {"chain": _CHAIN_WARN, "snapshots": _SNAP_WARN},
        "recommendation": ("Zincir/snapshot sağlıklı." if healthy else
                           "Performans için canlı blockcommit ile düzleştirin "
                           "(aşağıdaki Konsolide butonu) ya da eski snapshot'ları silin."),
    }


def consolidate(vm_id: str, dev: str) -> dict:
    """Flatten a disk's backing chain into its base via live blockcommit
    (virsh blockcommit --active --pivot). Reduces read overhead from long
    external-snapshot chains. Guarded on virsh; the caller gates with a
    confirm since this rewrites the active disk image."""
    vm = _vm()
    if not vm:
        return {"ok": False, "error": "vm_manager yok"}
    if not _NAME_RE.match(dev or ""):
        return {"ok": False, "error": "geçersiz disk hedefi"}
    try:
        name = vm.get_vm(vm_id)["name"]
    except Exception as e:
        return {"ok": False, "error": f"VM bulunamadı: {str(e)[:120]}"}
    if not _NAME_RE.match(name):
        return {"ok": False, "error": "geçersiz VM adı"}
    r = _run(["virsh", "blockcommit", name, dev,
              "--active", "--pivot", "--wait", "--verbose"], timeout=3600)
    if r is None:
        return {"ok": False, "error": "virsh bulunamadı"}
    if r.returncode != 0:
        return {"ok": False, "error": (r.stderr or "blockcommit hata").strip()[:300]}
    log.info("blockcommit consolidate: %s/%s", name, dev)
    return {"ok": True, "vm": name, "dev": dev,
            "message": "Backing-chain düzleştirildi (blockcommit --pivot)."}
