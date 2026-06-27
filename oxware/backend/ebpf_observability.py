# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""
OXware eBPF Kernel Observability
────────────────────────────────
Kernel-seviye, per-VM gözlemlenebilirlik — rakiplerde native olmayan
differentiator. QEMU/KVM süreçlerini kernelden bpftrace/bcc ile izler:
  - per-VM syscall sayımı (hangi syscall ne sıklıkta)
  - blok I/O gecikme histogramı (biolatency tarzı)
  - ağ akışı sayacı (mevcut XDP filtresiyle birlikte)

DÜRÜST KAPSAM: bpftrace/bcc + root + Linux gerekir. Yoksa fonksiyonlar
available=False + sebep döner — sahte metrik ÜRETİLMEZ. XDP attach/detach
mevcut kernel/ebpf/xdp_loader.py'ye delege edilir.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess

log = logging.getLogger("oxware.ebpf")

_XDP_OBJ = "/opt/oxware/kernel/ebpf/xdp_filter.o"


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _kernel_version() -> str:
    try:
        return subprocess.run(["uname", "-r"], capture_output=True, text=True,
                              timeout=3).stdout.strip()
    except Exception:
        return ""


def status() -> dict:
    """eBPF araç zinciri + XDP durumunu raporla (dürüst, sahte yok)."""
    bpftrace = _have("bpftrace")
    bcc = False
    try:
        import bcc  # type: ignore  # noqa: F401
        bcc = True
    except Exception:
        bcc = False
    return {
        "ok": True,
        "available": bool(bpftrace or bcc),
        "bpftrace": bpftrace,
        "bcc": bcc,
        "is_root": (os.geteuid() == 0) if hasattr(os, "geteuid") else False,
        "kernel": _kernel_version(),
        "xdp_object_compiled": os.path.exists(_XDP_OBJ),
        "reason": None if (bpftrace or bcc) else
                  "bpftrace/bcc kurulu değil — eBPF gözlemi devre dışı",
    }


def _vm_pid(vm_name_or_id: str) -> int | None:
    """Bir VM'in QEMU sürecinin PID'ini bul (libvirt 'guest=<name>' arg'ı)."""
    name = vm_name_or_id
    # UUID verildiyse virsh ile isme çevir
    try:
        if re.fullmatch(r"[0-9a-fA-F-]{36}", vm_name_or_id):
            r = subprocess.run(["virsh", "domname", vm_name_or_id],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                name = r.stdout.strip()
    except Exception:
        pass
    try:
        r = subprocess.run(["pgrep", "-f", f"guest={name},"],
                           capture_output=True, text=True, timeout=5)
        pids = [int(x) for x in r.stdout.split() if x.strip().isdigit()]
        return pids[0] if pids else None
    except Exception:
        return None


def _need_bpftrace() -> dict | None:
    if not _have("bpftrace"):
        return {"ok": False, "available": False,
                "error": "bpftrace yok — gözlem devre dışı"}
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return {"ok": False, "available": False,
                "error": "root gerekli (eBPF kernel probe)"}
    return None


def vm_syscalls(vm_id: str, seconds: int = 5) -> dict:
    """Bir VM'in QEMU sürecinin syscall dağılımını topla (bpftrace)."""
    gate = _need_bpftrace()
    if gate:
        return gate
    pid = _vm_pid(vm_id)
    if not pid:
        return {"ok": False, "error": "VM süreci (QEMU pid) bulunamadı"}
    seconds = max(1, min(60, int(seconds)))
    prog = (
        f"tracepoint:raw_syscalls:sys_enter /pid == {pid}/ "
        f"{{ @[probe] = count(); }} "
        f"interval:s:{seconds} {{ exit(); }}"
    )
    try:
        r = subprocess.run(["bpftrace", "-f", "json", "-e", prog],
                           capture_output=True, text=True, timeout=seconds + 15)
    except Exception as e:
        return {"ok": False, "error": f"bpftrace hatası: {e}"}
    counts = {}
    for line in r.stdout.splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("type") == "map":
            for _k, data in obj.get("data", {}).items():
                if isinstance(data, dict):
                    counts.update({kk: vv for kk, vv in data.items()})
    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:25]
    return {"ok": True, "available": True, "vm_id": vm_id, "pid": pid,
            "seconds": seconds, "syscalls": [{"name": k, "count": v} for k, v in top]}


def block_latency(seconds: int = 5) -> dict:
    """Host blok I/O gecikme histogramı (biolatency tarzı, bpftrace)."""
    gate = _need_bpftrace()
    if gate:
        return gate
    seconds = max(1, min(60, int(seconds)))
    prog = (
        "tracepoint:block:block_rq_issue { @start[args->dev, args->sector] = nsecs; } "
        "tracepoint:block:block_rq_complete /@start[args->dev, args->sector]/ "
        "{ @usecs = hist((nsecs - @start[args->dev, args->sector]) / 1000); "
        "delete(@start[args->dev, args->sector]); } "
        f"interval:s:{seconds} {{ exit(); }}"
    )
    try:
        r = subprocess.run(["bpftrace", "-e", prog],
                           capture_output=True, text=True, timeout=seconds + 15)
    except Exception as e:
        return {"ok": False, "error": f"bpftrace hatası: {e}"}
    # Histogram text çıktısını olduğu gibi döndür (insan-okur + grafiklenebilir).
    return {"ok": True, "available": True, "seconds": seconds,
            "histogram": r.stdout.strip()}


# ── XDP filtresi (mevcut loader'a delege) ────────────────────────────────────

def _xdp_loader():
    """kernel/ebpf/xdp_loader.py'yi import et (kurulu konumdan)."""
    import importlib.util
    for path in ("/opt/oxware/kernel/ebpf/xdp_loader.py",
                 os.path.join(os.path.dirname(__file__),
                              "..", "..", "kernel", "ebpf", "xdp_loader.py")):
        p = os.path.abspath(path)
        if os.path.exists(p):
            spec = importlib.util.spec_from_file_location("xdp_loader", p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


def xdp_list() -> dict:
    ld = _xdp_loader()
    if not ld:
        return {"ok": False, "error": "xdp_loader bulunamadı"}
    try:
        return {"ok": True, "interfaces": ld.list_interfaces()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def xdp_attach(iface: str) -> dict:
    ld = _xdp_loader()
    if not ld:
        return {"ok": False, "error": "xdp_loader bulunamadı"}
    try:
        return {"ok": bool(ld.attach(iface)), "iface": iface}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def xdp_detach(iface: str) -> dict:
    ld = _xdp_loader()
    if not ld:
        return {"ok": False, "error": "xdp_loader bulunamadı"}
    try:
        return {"ok": bool(ld.detach(iface)), "iface": iface}
    except Exception as e:
        return {"ok": False, "error": str(e)}
