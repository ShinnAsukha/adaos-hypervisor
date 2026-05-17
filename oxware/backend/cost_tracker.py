"""OXware Cost Tracker — resource usage → estimated cost"""
import json, os
from pathlib import Path

_CFG_FILE = "/etc/oxware/cost_config.json"
_DEFAULTS = {"cpu_per_vcpu_hour": 0.01, "ram_per_gb_hour": 0.005,
             "disk_per_gb_month": 0.10, "currency": "USD"}

def get_config():
    try:
        p = Path(_CFG_FILE)
        if p.exists(): return {**_DEFAULTS, **json.loads(p.read_text())}
    except Exception: pass
    return dict(_DEFAULTS)

def save_config(**kwargs):
    cfg = get_config()
    for k in ("cpu_per_vcpu_hour", "ram_per_gb_hour", "disk_per_gb_month"):
        if k in kwargs:
            try: cfg[k] = float(kwargs[k])
            except Exception: pass
    if "currency" in kwargs: cfg["currency"] = str(kwargs["currency"])[:10]
    Path(_CFG_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(_CFG_FILE).write_text(json.dumps(cfg, indent=2))
    return cfg

def estimate_vm_cost(vm_id, vcpus, ram_mb, disk_gb, hours=720):
    cfg = get_config()
    vcpus = int(vcpus or 1); ram_gb = float(ram_mb or 1024) / 1024
    disk_gb = float(disk_gb or 10); hours = float(hours or 720)
    cpu_cost  = vcpus * cfg["cpu_per_vcpu_hour"] * hours
    ram_cost  = ram_gb * cfg["ram_per_gb_hour"] * hours
    disk_cost = disk_gb * cfg["disk_per_gb_month"] * (hours / 720)
    total = cpu_cost + ram_cost + disk_cost
    return {"vm_id": vm_id, "currency": cfg["currency"],
            "hourly": round(total / hours, 4),
            "monthly": round(total, 2),
            "breakdown": {"cpu": round(cpu_cost, 2),
                          "ram": round(ram_cost, 2),
                          "disk": round(disk_cost, 2)}}

def get_all_vm_costs(vms):
    results = [estimate_vm_cost(v.get("id",""), v.get("vcpus",1),
                                v.get("ram_mb",1024), v.get("disk_gb",10))
               for v in (vms or [])]
    total = sum(r["monthly"] for r in results)
    cfg = get_config()
    return {"vms": results, "total_monthly": round(total, 2), "currency": cfg["currency"]}
