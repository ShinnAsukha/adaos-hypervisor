# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""
OXware Kernel Module Manager
────────────────────────────
Yerleşik OXware LKM'lerini (kprobe tabanlı) yönetir + çıktılarını okur:
  - oxware_audit : KVM/QEMU yaşam döngüsü audit (kvm_vm_ioctl, do_execve)
                   → /dev/oxware_audit
  - oxware_guard : anti-tamper (ptrace/mmap kprobe) → /dev/oxware_guard

build/load/unload + canlı durum + cihaz okuma. Linux/yetki yoksa düzgün
hata döner. Kaynak: <repo>/kernel/modules veya /opt/oxware/kernel/modules.
"""
from __future__ import annotations

import logging
import os
import subprocess

log = logging.getLogger("oxware.kernel_modules")

_MODULES = ("oxware_audit", "oxware_guard")
_DEV = {"oxware_audit": "/dev/oxware_audit", "oxware_guard": "/dev/oxware_guard"}


def _is_root() -> bool:
    return (os.geteuid() == 0) if hasattr(os, "geteuid") else False


def _src_dir() -> str | None:
    for base in ("/opt/oxware/kernel/modules",
                 os.path.join(os.path.dirname(__file__), "..", "..",
                              "kernel", "modules")):
        p = os.path.abspath(base)
        if os.path.isdir(p):
            return p
    return None


def _loaded() -> set:
    """lsmod'dan yüklü oxware modüllerini bul."""
    try:
        r = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=5)
        names = {ln.split()[0] for ln in r.stdout.splitlines()[1:] if ln.split()}
        return {m for m in _MODULES if m in names}
    except Exception:
        return set()


def status() -> dict:
    src = _src_dir()
    loaded = _loaded()
    mods = []
    for m in _MODULES:
        ko = None
        if src:
            cand = os.path.join(src, m, f"{m}.ko")
            ko = cand if os.path.exists(cand) else None
        mods.append({
            "name": m,
            "loaded": m in loaded,
            "built": bool(ko),
            "device": _DEV[m],
            "device_present": os.path.exists(_DEV[m]),
        })
    return {"ok": True, "src_dir": src, "modules": mods,
            "is_root": _is_root()}


def build(name: str) -> dict:
    if name not in _MODULES:
        return {"ok": False, "error": "bilinmeyen modül"}
    src = _src_dir()
    if not src:
        return {"ok": False, "error": "kernel/modules kaynağı bulunamadı"}
    mdir = os.path.join(src, name)
    if not os.path.isdir(mdir):
        return {"ok": False, "error": f"{name} dizini yok"}
    try:
        r = subprocess.run(["make", "-C", mdir], capture_output=True,
                           text=True, timeout=180)
        if r.returncode != 0:
            return {"ok": False, "error": (r.stderr or r.stdout).strip()[-2000:]}
        return {"ok": True, "built": name,
                "ko": os.path.join(mdir, f"{name}.ko")}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def load(name: str) -> dict:
    if name not in _MODULES:
        return {"ok": False, "error": "bilinmeyen modül"}
    if not _is_root():
        return {"ok": False, "error": "root gerekli"}
    if name in _loaded():
        return {"ok": True, "already_loaded": True, "name": name}
    src = _src_dir()
    ko = os.path.join(src, name, f"{name}.ko") if src else ""
    if not ko or not os.path.exists(ko):
        return {"ok": False, "error": f"{name}.ko derlenmemiş — önce build et"}
    try:
        r = subprocess.run(["insmod", ko], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return {"ok": False, "error": r.stderr.strip()}
        log.info("LKM yüklendi: %s", name)
        return {"ok": True, "loaded": name}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def unload(name: str) -> dict:
    if name not in _MODULES:
        return {"ok": False, "error": "bilinmeyen modül"}
    if not _is_root():
        return {"ok": False, "error": "root gerekli"}
    if name not in _loaded():
        return {"ok": True, "already_unloaded": True, "name": name}
    try:
        r = subprocess.run(["rmmod", name], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return {"ok": False, "error": r.stderr.strip()}
        log.info("LKM kaldırıldı: %s", name)
        return {"ok": True, "unloaded": name}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _read_dev(path: str, max_bytes: int = 8192) -> str | None:
    try:
        with open(path, "r") as f:
            return f.read(max_bytes)
    except Exception:
        return None


def guard_alerts() -> dict:
    """oxware_guard anti-tamper alert sayacı + son alert (/dev/oxware_guard)."""
    if "oxware_guard" not in _loaded():
        return {"ok": True, "loaded": False,
                "reason": "oxware_guard yüklü değil"}
    raw = _read_dev(_DEV["oxware_guard"])
    if raw is None:
        return {"ok": False, "error": "cihaz okunamadı (root?)"}
    return {"ok": True, "loaded": True, "raw": raw.strip()}


def audit_events(max_bytes: int = 8192) -> dict:
    """oxware_audit yaşam-döngüsü kayıtları (/dev/oxware_audit)."""
    if "oxware_audit" not in _loaded():
        return {"ok": True, "loaded": False,
                "reason": "oxware_audit yüklü değil"}
    raw = _read_dev(_DEV["oxware_audit"], max_bytes)
    if raw is None:
        return {"ok": False, "error": "cihaz okunamadı (root?)"}
    return {"ok": True, "loaded": True, "events": raw.strip()}
