# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware carbon / energy footprint report (ESG).

Estimates electricity (kWh), cost, and CO2 over a period from the host power
profile and current utilization, plus the energy/CO2 already SAVED by Green
Mode. Numbers are estimates — clearly labeled as such — built on the same
power_profile_w + co2_factor the Green Mode module already uses, so the report
is consistent with the rest of the panel.
"""
from __future__ import annotations
import logging

log = logging.getLogger("oxware.carbon")
_USD_PER_KWH = 0.12  # default tariff; informational


def _mod(name):
    try:
        return __import__(name)
    except Exception:
        try:
            return __import__(f"oxware.backend.{name}", fromlist=["*"])
        except Exception:
            return None


def _node_count() -> int:
    for modname, fn in (("ha_manager", "list_nodes"), ("cluster_federation", "list_members")):
        m = _mod(modname)
        if m and hasattr(m, fn):
            try:
                n = len(getattr(m, fn)() or [])
                if n > 0:
                    return n
            except Exception:
                pass
    return 1


def _avg_cpu_pct() -> float:
    sm = _mod("system_monitor")
    if not sm:
        return 50.0
    try:
        return float(sm.get_system_stats().get("cpu", {}).get("percent", 50.0))
    except Exception:
        return 50.0


def report(days: int = 30) -> dict:
    days = max(1, min(int(days or 30), 365))
    gm = _mod("green_mode")
    idle_w, peak_w, co2_factor = 150.0, 400.0, 0.4
    if gm and hasattr(gm, "get_config"):
        try:
            cfg = gm.get_config()
            pp = cfg.get("power_profile_w", {})
            idle_w = float(pp.get("idle", idle_w))
            peak_w = float(pp.get("peak", peak_w))
            co2_factor = float(cfg.get("co2_factor_kg_per_kwh", co2_factor))
        except Exception:
            pass

    nodes = _node_count()
    util = max(0.0, min(_avg_cpu_pct() / 100.0, 1.0))
    per_node_w = idle_w + (peak_w - idle_w) * util
    total_w = per_node_w * nodes
    hours = days * 24
    kwh = total_w * hours / 1000.0
    co2_kg = kwh * co2_factor
    cost = kwh * _USD_PER_KWH

    saved = {"kwh": 0.0, "co2_kg": 0.0, "usd": 0.0}
    if gm and hasattr(gm, "analyze_savings_potential"):
        try:
            s = gm.analyze_savings_potential()
            weeks = days / 7.0
            saved["kwh"] = round(s.get("estimated_kwh_saved_per_week", 0.0) * weeks, 2)
            saved["co2_kg"] = round(s.get("estimated_co2_kg_saved_per_week", 0.0) * weeks, 2)
            saved["usd"] = round(s.get("estimated_usd_saved_per_week", 0.0) * weeks, 2)
        except Exception:
            pass

    # Relatable equivalents (rough public factors).
    trees = round(co2_kg / 21.0, 1)            # ~21 kg CO2/tree/year absorbed
    km_car = round(co2_kg / 0.12, 0)            # ~0.12 kg CO2/km avg car

    return {
        "ok": True,
        "period_days": days,
        "nodes": nodes,
        "avg_utilization_pct": round(util * 100, 1),
        "avg_power_w": round(total_w, 0),
        "energy_kwh": round(kwh, 1),
        "co2_kg": round(co2_kg, 1),
        "cost_usd": round(cost, 2),
        "saved_by_green_mode": saved,
        "equivalent": {"trees_year": trees, "car_km": km_car},
        "assumptions": {
            "idle_w": idle_w, "peak_w": peak_w,
            "co2_kg_per_kwh": co2_factor, "usd_per_kwh": _USD_PER_KWH,
            "note": "Tahmini — anlık ortalama CPU kullanımı baz alınır.",
        },
    }
