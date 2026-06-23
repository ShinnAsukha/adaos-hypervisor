# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware What-If capacity simulator.

"What happens if I add 10 VMs with 2 vCPU / 4 GB each?" — projects the impact
on CPU, RAM, power, cost and CO2 BEFORE you do it, using current live usage +
the host capacity + Green Mode's power profile + the carbon factor. Competitors
suggest right-sizing; none give a pre-flight what-if sandbox.

Estimates, clearly labeled. Read-only — changes nothing.
"""
from __future__ import annotations
import logging

log = logging.getLogger("oxware.whatif")
_USD_PER_KWH = 0.12


def _mod(name):
    try:
        return __import__(name)
    except Exception:
        try:
            return __import__(f"oxware.backend.{name}", fromlist=["*"])
        except Exception:
            return None


def simulate(add_vms: int, vcpus_each: int, ram_mb_each: int,
             overcommit_cpu: float = 3.0) -> dict:
    add_vms = max(0, min(int(add_vms or 0), 1000))
    vcpus_each = max(1, min(int(vcpus_each or 1), 128))
    ram_mb_each = max(64, min(int(ram_mb_each or 512), 1048576))

    sm = _mod("system_monitor")
    if not sm:
        return {"ok": False, "error": "system_monitor yok"}
    try:
        st = sm.get_system_stats()
        host = sm.get_host_info() if hasattr(sm, "get_host_info") else {}
        vmsum = sm.get_vm_summary() if hasattr(sm, "get_vm_summary") else {}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}

    cores = int(host.get("cpu_count") or host.get("cores") or
                st.get("cpu", {}).get("count") or 8)
    total_ram = float(st.get("memory", {}).get("total_mb") or 16384)
    used_ram = float(st.get("memory", {}).get("used_mb") or 0)
    cur_cpu = float(st.get("cpu", {}).get("percent") or 0)
    cur_vms = int(vmsum.get("total") or 0)

    # Projected RAM: linear add.
    add_ram = add_vms * ram_mb_each
    proj_ram = used_ram + add_ram
    proj_ram_pct = min(100.0, proj_ram / total_ram * 100) if total_ram else 0

    # Projected CPU: assume each new vCPU adds load proportional to current
    # per-vCPU usage, bounded by overcommit headroom.
    effective_cores = cores * overcommit_cpu
    cur_vcpu_load = (cur_cpu / 100.0) * effective_cores  # vCPU-equivalents busy
    add_vcpu = add_vms * vcpus_each
    # new VMs idle-ish at first; estimate 25% busy as a planning heuristic.
    proj_vcpu_load = cur_vcpu_load + add_vcpu * 0.25
    proj_cpu_pct = min(100.0, proj_vcpu_load / effective_cores * 100) if effective_cores else 0

    # Power / cost / CO2 via Green Mode profile.
    idle_w, peak_w, co2 = 150.0, 400.0, 0.4
    gm = _mod("green_mode")
    if gm and hasattr(gm, "get_config"):
        try:
            cfg = gm.get_config(); pp = cfg.get("power_profile_w", {})
            idle_w = float(pp.get("idle", idle_w)); peak_w = float(pp.get("peak", peak_w))
            co2 = float(cfg.get("co2_factor_kg_per_kwh", co2))
        except Exception:
            pass
    cur_w = idle_w + (peak_w - idle_w) * (cur_cpu / 100.0)
    proj_w = idle_w + (peak_w - idle_w) * (proj_cpu_pct / 100.0)
    kwh_month = proj_w * 24 * 30 / 1000.0

    fits = proj_ram_pct < 90 and proj_cpu_pct < 90
    warn = []
    if proj_ram_pct >= 90:
        warn.append(f"RAM %{proj_ram_pct:.0f} — yetersiz (eşik %90)")
    if proj_cpu_pct >= 90:
        warn.append(f"CPU %{proj_cpu_pct:.0f} — yetersiz (eşik %90)")
    if add_ram > (total_ram - used_ram):
        warn.append("Eklenen RAM mevcut boş RAM'i aşıyor (overcommit/swap riski)")

    return {
        "ok": True,
        "add": {"vms": add_vms, "vcpus_each": vcpus_each, "ram_mb_each": ram_mb_each},
        "host": {"cores": cores, "total_ram_mb": round(total_ram),
                 "overcommit_cpu": overcommit_cpu},
        "current": {"cpu_pct": round(cur_cpu, 1), "ram_pct": round(used_ram/total_ram*100, 1) if total_ram else 0,
                    "vms": cur_vms, "power_w": round(cur_w)},
        "projected": {"cpu_pct": round(proj_cpu_pct, 1), "ram_pct": round(proj_ram_pct, 1),
                      "vms": cur_vms + add_vms, "power_w": round(proj_w),
                      "energy_kwh_month": round(kwh_month, 1),
                      "cost_usd_month": round(kwh_month * _USD_PER_KWH, 2),
                      "co2_kg_month": round(kwh_month * co2, 1)},
        "fits": fits, "warnings": warn,
        "verdict": ("Sığar ✅" if fits else "Riskli/sığmaz ⚠️"),
        "note": "Tahmini — yeni VM'ler %25 yük varsayımı + mevcut canlı kullanım baz alınır.",
    }
