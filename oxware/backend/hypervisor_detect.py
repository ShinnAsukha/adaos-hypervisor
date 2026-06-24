# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware stealth-hypervisor / blue-pill detection (defensive).

Host-side checks for a hidden hypervisor running *beneath* the OS (blue-pill /
nested VMX-root rootkit). No single check is perfect — a well-built stealth
hypervisor can hide the CPUID hypervisor bit — so this combines several
independent vectors, with TPM measured-boot drift being the strongest:

  1. CPUID hypervisor-present flag (/proc/cpuinfo) — set on a machine the
     operator believes is bare metal ⇒ something is virtualizing it.
  2. systemd-detect-virt — names the virtualization vendor if any.
  3. Secure Boot state (mokutil) — off when expected on is a tamper signal.
  4. TPM PCR measured-boot baseline + drift — a hypervisor inserted into the
     boot chain changes PCR[0-7]; compared against a trusted baseline this is
     hard to evade (PCR hashes can't lie).
  5. Coarse CPUID/VMEXIT timing probe — indicative only.

State: /var/lib/oxware/hvdetect_baseline.json
"""
from __future__ import annotations
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path

log = logging.getLogger("oxware.hvdetect")
_BASELINE = Path("/var/lib/oxware/hvdetect_baseline.json")


def _run(args, timeout=8):
    exe = shutil.which(args[0])
    if not exe:
        return None
    try:
        r = subprocess.run([exe] + args[1:], capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def _cpuid_hypervisor_flag() -> bool:
    try:
        txt = Path("/proc/cpuinfo").read_text(errors="ignore")
        return " hypervisor" in (" " + txt.replace("\n", " "))
    except Exception:
        return False


def _detect_virt() -> str:
    out = _run(["systemd-detect-virt"])
    return out or "none"


def _secure_boot() -> str:
    out = _run(["mokutil", "--sb-state"])
    if not out:
        return "unknown"
    low = out.lower()
    return "enabled" if "enabled" in low else ("disabled" if "disabled" in low else out[:40])


def _tpm_pcrs() -> dict | None:
    out = _run(["tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7"])
    if not out:
        return None
    pcrs = {}
    for line in out.splitlines():
        line = line.strip()
        # format: "  0 : 0xABC..."
        if ":" in line and line.split(":")[0].strip().isdigit():
            idx, val = line.split(":", 1)
            pcrs[idx.strip()] = val.strip()
    return pcrs or None


def _timing_probe() -> dict:
    """Coarse: time a tight loop of a privileged-ish operation. A heavy
    intercepting hypervisor inflates per-iteration time. Indicative only —
    pure-Python can't issue RDTSC/CPUID directly."""
    try:
        n = 200000
        t0 = time.perf_counter_ns()
        x = 0
        for _ in range(n):
            x ^= os.getpid()  # cheap syscall-free op; relative baseline anchor
        t1 = time.perf_counter_ns()
        ns_per = (t1 - t0) / n
        return {"ns_per_op": round(ns_per, 3), "note": "göreceli — yalnızca baseline ile kıyasla"}
    except Exception:
        return {"ns_per_op": None}


def scan() -> dict:
    hv_flag = _cpuid_hypervisor_flag()
    virt = _detect_virt()
    sb = _secure_boot()
    pcrs = _tpm_pcrs()
    timing = _timing_probe()

    base = None
    if _BASELINE.exists():
        try:
            base = json.loads(_BASELINE.read_text(encoding="utf-8"))
        except Exception:
            base = None

    warnings = []
    drift = None
    if base and base.get("pcrs") and pcrs:
        changed = [k for k, v in pcrs.items() if base["pcrs"].get(k) != v]
        drift = changed
        if changed:
            warnings.append(f"TPM PCR drift: {', '.join(changed)} — boot zinciri "
                            f"baseline'dan değişmiş (firmware/loader/hypervisor enjeksiyonu?)")
    if hv_flag and virt in ("none", "", None):
        warnings.append("CPUID 'hypervisor' biti AÇIK ama detect-virt 'none' — "
                        "gizli/transparan hypervisor olabilir (blue-pill).")
    if hv_flag:
        warnings.append(f"Bu makine bir hypervisor ALTINDA çalışıyor (vendor: {virt}). "
                        "Bare-metal bekleniyorsa bu bir kırmızı bayrak.")
    if sb == "disabled":
        warnings.append("Secure Boot KAPALI — boot-chain enjeksiyonuna açık.")
    if not pcrs:
        warnings.append("TPM okunamadı (tpm2-tools/TPM yok) — en güçlü tespit vektörü devre dışı.")

    clean = (not hv_flag) and sb != "disabled" and not (drift or [])
    return {
        "ok": True,
        "hypervisor_flag": hv_flag,
        "virt_vendor": virt,
        "secure_boot": sb,
        "tpm_available": bool(pcrs),
        "pcr_count": len(pcrs) if pcrs else 0,
        "baseline_set": bool(base),
        "pcr_drift": drift,
        "timing": timing,
        "warnings": warnings,
        "verdict": ("Temiz — gizli hypervisor belirtisi yok" if clean
                    else "DİKKAT — incelenmesi gereken belirti var"),
        "clean": clean,
        "note": ("Mükemmel bir blue-pill CPUID bitini gizleyebilir; en güvenilir "
                 "tespit TPM measured-boot drift + uzaktan attestation'dır."),
    }


def set_baseline() -> dict:
    pcrs = _tpm_pcrs()
    data = {"ts": time.time(), "pcrs": pcrs or {},
            "secure_boot": _secure_boot(), "virt": _detect_virt()}
    try:
        _BASELINE.parent.mkdir(parents=True, exist_ok=True)
        _BASELINE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception as e:
        return {"ok": False, "error": str(e)[:160]}
    return {"ok": True, "pcr_count": len(data["pcrs"]),
            "note": ("Baseline kaydedildi. Bundan sonra PCR drift bu noktaya "
                     "göre tespit edilir." if data["pcrs"]
                     else "TPM yok — baseline boş; drift tespiti çalışmaz.")}
