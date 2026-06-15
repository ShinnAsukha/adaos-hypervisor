"""OXware CSI Driver Control Plane (v2.9).

Exposes OXware storage pools as Kubernetes PersistentVolumes via a
CSI-compatible bridge running on each k8s node. This module is the
control plane: it tracks provisioning requests, snapshots, and
resize jobs that the in-cluster CSI sidecar then executes.

State: /var/lib/oxware/csi_volumes.json
"""
from __future__ import annotations
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

log = logging.getLogger("oxware.csi")
_CATALOG = Path("/var/lib/oxware/csi_volumes.json")
_LOCK = threading.Lock()
CSI_DRIVER_NAME = "csi.oxware.top"

# Where qcow2 backing files live. Each pool maps to a sub-directory; if a
# real libvirt pool path is configured the operator can symlink it here.
_VOL_ROOT = Path("/var/lib/oxware/csi-volumes")
_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,200}$")


def _qemu_img() -> str | None:
    """Return the qemu-img binary path if present, else None."""
    return shutil.which("qemu-img")


def _vol_path(vol_id: str, pool: str) -> Path:
    # Both segments validated so the joined path cannot escape _VOL_ROOT.
    if not _NAME_RE.match(vol_id) or not _NAME_RE.match(pool):
        raise ValueError("invalid pool or volume id")
    return _VOL_ROOT / pool / f"{vol_id}.qcow2"


def _load() -> dict:
    if not _CATALOG.exists():
        return {"volumes": []}
    try:
        return json.loads(_CATALOG.read_text(encoding="utf-8"))
    except Exception:
        return {"volumes": []}


def _save(d: dict) -> None:
    _CATALOG.parent.mkdir(parents=True, exist_ok=True)
    tmp = _CATALOG.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2), encoding="utf-8")
    os.replace(tmp, _CATALOG)


def list_volumes() -> list:
    return _load().get("volumes", [])


def provision(pool: str, size_gb: int, k8s_namespace: str,
              pvc_name: str, fs_type: str = "ext4") -> dict:
    if size_gb < 1:
        return {"ok": False, "error": "size_gb must be >= 1"}
    if fs_type not in ("ext4", "xfs", "btrfs"):
        return {"ok": False, "error": f"unsupported fs_type: {fs_type}"}
    if not _NAME_RE.match(pool):
        return {"ok": False, "error": "invalid pool name"}
    vol_id = f"pvc-{uuid.uuid4()}"
    vol = {
        "id": vol_id,
        "pool": pool,
        "size_gb": int(size_gb),
        "k8s_namespace": k8s_namespace,
        "pvc_name": pvc_name,
        "fs_type": fs_type,
        "state": "pending",
        "created_at": time.time(),
        "path": None,
        "backend": "none",
    }
    # Real backing: create a sparse qcow2 with qemu-img when available.
    qemu = _qemu_img()
    if qemu:
        try:
            path = _vol_path(vol_id, pool)
            path.parent.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(
                [qemu, "create", "-f", "qcow2", str(path), f"{int(size_gb)}G"],
                capture_output=True, text=True, timeout=60,
            )
            if r.returncode == 0:
                vol["state"] = "available"
                vol["path"] = str(path)
                vol["backend"] = "qcow2"
            else:
                vol["state"] = "error"
                vol["error"] = (r.stderr or r.stdout or "qemu-img failed")[:300]
        except Exception as e:
            vol["state"] = "error"
            vol["error"] = str(e)[:300]
    else:
        # No qemu-img on this host — record intent, sidecar provisions later.
        vol["state"] = "pending"
        vol["note"] = "qemu-img not found; volume recorded, awaiting CSI sidecar"
    with _LOCK:
        d = _load()
        d["volumes"].append(vol)
        _save(d)
    log.info("CSI provision: %s (%dGB, %s, backend=%s, state=%s)",
             vol_id, size_gb, pool, vol["backend"], vol["state"])
    return {"ok": vol["state"] != "error", "volume": vol}


def delete(volume_id: str) -> dict:
    with _LOCK:
        d = _load()
        target = next((v for v in d["volumes"] if v["id"] == volume_id), None)
        if not target:
            return {"ok": False, "error": "not found"}
        # Remove the backing qcow2 if we created one.
        p = target.get("path")
        if p:
            try:
                fp = Path(p)
                # Confirm the file is inside _VOL_ROOT before unlinking.
                if str(fp.resolve()).startswith(str(_VOL_ROOT.resolve())) and fp.exists():
                    fp.unlink()
            except Exception as e:
                log.warning("CSI delete: could not remove %s: %s", p, e)
        d["volumes"] = [v for v in d["volumes"] if v["id"] != volume_id]
        _save(d)
    return {"ok": True, "volume_id": volume_id}


def resize(volume_id: str, new_size_gb: int) -> dict:
    with _LOCK:
        d = _load()
        for v in d["volumes"]:
            if v["id"] == volume_id:
                if new_size_gb <= v["size_gb"]:
                    return {"ok": False, "error": "online shrink not supported"}
                # Grow the backing qcow2 with qemu-img resize when present.
                qemu = _qemu_img()
                if qemu and v.get("path"):
                    try:
                        r = subprocess.run(
                            [qemu, "resize", v["path"], f"{int(new_size_gb)}G"],
                            capture_output=True, text=True, timeout=60,
                        )
                        if r.returncode != 0:
                            return {"ok": False,
                                    "error": (r.stderr or "resize failed")[:300]}
                        v["state"] = "available"
                    except Exception as e:
                        return {"ok": False, "error": str(e)[:300]}
                else:
                    v["state"] = "resizing"
                v["size_gb"] = new_size_gb
                _save(d)
                return {"ok": True, "volume": v}
    return {"ok": False, "error": "not found"}


def driver_info() -> dict:
    qemu = _qemu_img()
    return {
        "name": CSI_DRIVER_NAME,
        "spec_version": "1.8.0",
        "capabilities": [
            "CREATE_DELETE_VOLUME",
            "CREATE_DELETE_SNAPSHOT",
            "EXPAND_VOLUME",
            "PUBLISH_UNPUBLISH_VOLUME",
        ],
        "supported_fs": ["ext4", "xfs", "btrfs"],
        "backend_ready": bool(qemu),
        "qemu_img": qemu or "(not found)",
        "volume_root": str(_VOL_ROOT),
        "maturity": "beta",
    }
