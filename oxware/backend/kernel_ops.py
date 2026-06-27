# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""
OXware Host Kernel Ops
──────────────────────
Host kernel verimlilik + uptime ayarları:
  - zram   : sıkıştırılmış RAM swap (bellek baskısı altında ek kapasite)
  - zswap  : sayfa-cache sıkıştırma (swap önünde)
  - CPU power: scaling_governor + intel_pstate turbo (perf/güç dengesi)
  - livepatch: reboot'suz host kernel yama durumu (canonical-livepatch / kpatch)

Hepsi sysfs / standart araçlar üzerinden. Linux dışında veya yetki yoksa
available=False + sebep döner; sahte değer üretmez.
"""
from __future__ import annotations

import glob
import logging
import os
import shutil
import subprocess

log = logging.getLogger("oxware.kernel_ops")

_ZRAM_SYS = "/sys/block/zram0"
_ZSWAP_PARAMS = "/sys/module/zswap/parameters"
_CPU_GLOB = "/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor"
_NO_TURBO = "/sys/devices/system/cpu/intel_pstate/no_turbo"


def _read(path: str, default=None):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return default


def _write(path: str, value: str) -> bool:
    try:
        with open(path, "w") as f:
            f.write(value)
        return True
    except Exception as e:
        log.debug("write %s=%s başarısız: %s", path, value, e)
        return False


def _is_root() -> bool:
    return (os.geteuid() == 0) if hasattr(os, "geteuid") else False


# ── zram ─────────────────────────────────────────────────────────────────────

def zram_status() -> dict:
    if not os.path.isdir(_ZRAM_SYS):
        return {"ok": True, "available": False,
                "reason": "zram cihazı yok (modprobe zram gerekebilir)"}
    disksize = _read(f"{_ZRAM_SYS}/disksize", "0")
    try:
        size_mb = int(disksize) // (1024 * 1024)
    except Exception:
        size_mb = 0
    return {
        "ok": True, "available": True,
        "disksize_mb": size_mb,
        "comp_algorithm": _read(f"{_ZRAM_SYS}/comp_algorithm", ""),
        "orig_data_mb": _bytes_mb(_read(f"{_ZRAM_SYS}/mm_stat", "").split()[:1]),
        "compr_data_mb": _bytes_mb(_read(f"{_ZRAM_SYS}/mm_stat", "").split()[1:2]),
    }


def _bytes_mb(parts):
    try:
        return int(parts[0]) // (1024 * 1024)
    except Exception:
        return 0


def zram_configure(size_mb: int, algorithm: str = "zstd") -> dict:
    """zram swap'i (yeniden) yapılandır + swap olarak aktive et."""
    if not _is_root():
        return {"ok": False, "error": "root gerekli"}
    size_mb = max(0, int(size_mb))
    if algorithm not in ("lzo", "lzo-rle", "lz4", "zstd", "deflate"):
        return {"ok": False, "error": "geçersiz algoritma"}
    try:
        # modül + cihaz hazırla
        if not os.path.isdir(_ZRAM_SYS):
            subprocess.run(["modprobe", "zram"], check=True, timeout=10)
        # mevcut swap'i kapat + reset
        subprocess.run(["swapoff", "/dev/zram0"], capture_output=True, timeout=10)
        _write(f"{_ZRAM_SYS}/reset", "1")
        if size_mb == 0:
            return {"ok": True, "disabled": True}
        _write(f"{_ZRAM_SYS}/comp_algorithm", algorithm)
        _write(f"{_ZRAM_SYS}/disksize", str(size_mb * 1024 * 1024))
        subprocess.run(["mkswap", "/dev/zram0"], check=True, capture_output=True, timeout=10)
        subprocess.run(["swapon", "-p", "100", "/dev/zram0"], check=True,
                       capture_output=True, timeout=10)
        log.info("zram %sMB algo=%s aktif", size_mb, algorithm)
        return {"ok": True, "disksize_mb": size_mb, "comp_algorithm": algorithm}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── zswap ────────────────────────────────────────────────────────────────────

def zswap_status() -> dict:
    if not os.path.isdir(_ZSWAP_PARAMS):
        return {"ok": True, "available": False, "reason": "zswap derlenmemiş"}
    return {
        "ok": True, "available": True,
        "enabled": _read(f"{_ZSWAP_PARAMS}/enabled", "N") == "Y",
        "compressor": _read(f"{_ZSWAP_PARAMS}/compressor", ""),
        "zpool": _read(f"{_ZSWAP_PARAMS}/zpool", ""),
        "max_pool_percent": _read(f"{_ZSWAP_PARAMS}/max_pool_percent", ""),
    }


def zswap_configure(enabled: bool, compressor: str = "zstd",
                    max_pool_percent: int = 20) -> dict:
    if not _is_root():
        return {"ok": False, "error": "root gerekli"}
    if not os.path.isdir(_ZSWAP_PARAMS):
        return {"ok": False, "error": "zswap derlenmemiş"}
    _write(f"{_ZSWAP_PARAMS}/enabled", "Y" if enabled else "N")
    if enabled:
        _write(f"{_ZSWAP_PARAMS}/compressor", compressor)
        _write(f"{_ZSWAP_PARAMS}/max_pool_percent",
               str(max(1, min(50, int(max_pool_percent)))))
    return {"ok": True, **zswap_status()}


# ── CPU power ────────────────────────────────────────────────────────────────

def cpu_power_status() -> dict:
    govs = []
    for p in sorted(glob.glob(_CPU_GLOB)):
        govs.append(_read(p, "?"))
    avail = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors", "")
    no_turbo = _read(_NO_TURBO)
    return {
        "ok": True,
        "available": bool(govs),
        "governors": govs,
        "uniform": (len(set(govs)) <= 1),
        "current": (govs[0] if govs else None),
        "available_governors": avail.split() if avail else [],
        "turbo_supported": no_turbo is not None,
        "turbo_enabled": (no_turbo == "0") if no_turbo is not None else None,
    }


def cpu_set_governor(governor: str) -> dict:
    if not _is_root():
        return {"ok": False, "error": "root gerekli"}
    avail = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors", "")
    if avail and governor not in avail.split():
        return {"ok": False, "error": f"governor desteklenmiyor: {governor}"}
    n = 0
    for p in glob.glob(_CPU_GLOB):
        if _write(p, governor):
            n += 1
    if n == 0:
        return {"ok": False, "error": "hiçbir CPU yazılamadı (cpufreq yok?)"}
    log.info("governor=%s (%s CPU)", governor, n)
    return {"ok": True, "governor": governor, "cpus": n}


def cpu_set_turbo(enabled: bool) -> dict:
    if not _is_root():
        return {"ok": False, "error": "root gerekli"}
    if not os.path.exists(_NO_TURBO):
        return {"ok": False, "error": "intel_pstate turbo kontrolü yok"}
    # no_turbo = 0 => turbo açık
    _write(_NO_TURBO, "0" if enabled else "1")
    return {"ok": True, "turbo_enabled": enabled}


# ── Kernel livepatch ─────────────────────────────────────────────────────────

def livepatch_status() -> dict:
    """canonical-livepatch ya da kpatch durumunu raporla."""
    if shutil.which("canonical-livepatch"):
        try:
            r = subprocess.run(["canonical-livepatch", "status"],
                               capture_output=True, text=True, timeout=15)
            return {"ok": True, "available": True, "provider": "canonical-livepatch",
                    "status": r.stdout.strip() or r.stderr.strip()}
        except Exception as e:
            return {"ok": False, "provider": "canonical-livepatch", "error": str(e)}
    if shutil.which("kpatch"):
        try:
            r = subprocess.run(["kpatch", "list"], capture_output=True,
                               text=True, timeout=15)
            return {"ok": True, "available": True, "provider": "kpatch",
                    "status": r.stdout.strip()}
        except Exception as e:
            return {"ok": False, "provider": "kpatch", "error": str(e)}
    return {"ok": True, "available": False,
            "reason": "livepatch sağlayıcı yok (canonical-livepatch / kpatch kur)"}


def livepatch_apply(patch_path: str) -> dict:
    """Bir kpatch .ko modülünü canlı uygula (kpatch). Yol allowlist'li dizinde olmalı."""
    if not _is_root():
        return {"ok": False, "error": "root gerekli"}
    if not shutil.which("kpatch"):
        return {"ok": False, "error": "kpatch yok"}
    # Yol traversal'a karşı: yalnız /var/lib/oxware/livepatch altındaki dosyalar.
    base = "/var/lib/oxware/livepatch"
    real = os.path.realpath(patch_path)
    if not real.startswith(base + os.sep) or not real.endswith(".ko"):
        return {"ok": False, "error": f"patch {base} altında bir .ko olmalı"}
    if not os.path.exists(real):
        return {"ok": False, "error": "patch dosyası yok"}
    try:
        r = subprocess.run(["kpatch", "load", real], capture_output=True,
                           text=True, timeout=30)
        if r.returncode != 0:
            return {"ok": False, "error": r.stderr.strip()}
        return {"ok": True, "loaded": os.path.basename(real)}
    except Exception as e:
        return {"ok": False, "error": str(e)}
