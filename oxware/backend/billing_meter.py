#!/usr/bin/env python3
# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy. MIT License.
"""
Metered / hourly billing — dahili kullanım sayacı ve fatura satırı üretimi
─────────────────────────────────────────────────────────────────────────
Virtualizor'un "inbuilt hourly billing" özelliğinin karşılığı. OXware'de
`cost_tracker` (maliyet tahmini) ve `chargeback_engine` (geri-yansıtma) vardı,
ama gerçek fatura kesimi hep dış panele (WHMCS/WiseCP) bağımlıydı — saatlik
VPS satan barındırma firması için bu bir boşluktu.

Bu modül:
  * VM başına saatlik kullanım örneği toplar (açık/kapalı, vCPU, RAM, disk),
  * yalnızca VM AÇIKKEN geçen saatleri ücretlendirir (durdurulmuş VM'de
    çoğu sağlayıcı gibi sadece disk ücreti alınır),
  * dönem sonunda kalem kalem fatura satırı üretir.

Fiyatlandırma `/etc/oxware/billing_rates.json` (veya OXWARE_BILLING_RATES):
    {"currency":"USD","vcpu_hour":0.004,"gb_ram_hour":0.002,
     "gb_disk_hour":0.0002,"gb_disk_hour_stopped":0.0002,"ipv4_hour":0.0007}

Sayaç kayıtları JSONL: <data_dir>/billing/usage-YYYY-MM.jsonl
Sayaç toplayıcı idempotent — aynı saat dilimi iki kez yazılmaz.
"""

from __future__ import annotations

import os
import json
import time
import logging
import threading
from datetime import datetime, timezone

log = logging.getLogger("oxware.billing_meter")

_lock = threading.RLock()

DEFAULT_RATES = {
    "currency":             "USD",
    "vcpu_hour":            0.004,
    "gb_ram_hour":          0.002,
    "gb_disk_hour":         0.0002,
    "gb_disk_hour_stopped": 0.0002,   # durdurulmuş VM: sadece depolama
    "ipv4_hour":            0.0007,
}


def _data_dir() -> str:
    # Env ÖNCELİKLİ: aksi halde config importlanabildiği her ortamda (test/CI,
    # yan yana çalışan kurulumlar) OXWARE_DATA_DIR sessizce yok sayılıyordu.
    env = os.environ.get("OXWARE_BILLING_DIR") or os.environ.get("OXWARE_DATA_DIR")
    if env:
        return env
    try:
        import config
        return config.DATA_DIR
    except Exception:
        return "/var/lib/oxware"


def _rates_path() -> str:
    return os.environ.get("OXWARE_BILLING_RATES", "/etc/oxware/billing_rates.json")


def _usage_path(period: str) -> str:
    return os.path.join(_data_dir(), "billing", f"usage-{period}.jsonl")


def get_rates() -> dict:
    try:
        p = _rates_path()
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return {**DEFAULT_RATES, **(json.load(f) or {})}
    except (OSError, ValueError) as e:
        log.warning("billing_rates okunamadı (%s) — varsayılan tarife", e)
    return dict(DEFAULT_RATES)


def set_rates(**kwargs) -> dict:
    rates = get_rates()
    for k, v in kwargs.items():
        if k in DEFAULT_RATES:
            rates[k] = v
    p = _rates_path()
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rates, f, indent=2)
        os.replace(tmp, p)
        os.chmod(p, 0o600)
    except OSError as e:
        log.warning("billing_rates yazılamadı: %s", e)
    return rates


def _period(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), timezone.utc).strftime("%Y-%m")


def _hour_key(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), timezone.utc).strftime("%Y-%m-%dT%H")


# ── Sayaç toplama ─────────────────────────────────────────────────────────────

def _collect_samples(vm_lister=None) -> list:
    """Şu anki VM durumundan kullanım örnekleri üret."""
    vms = []
    if vm_lister is not None:
        vms = vm_lister() or []
    else:
        try:
            import vm_manager
            vms = vm_manager.list_vms() or []
        except Exception as e:
            log.warning("billing: VM listesi alınamadı: %s", e)
            return []

    hour = _hour_key()
    out = []
    for vm in vms:
        if not isinstance(vm, dict):
            continue
        state = (vm.get("state") or "").lower()
        running = state in ("running", "paused", "pmsuspended")
        out.append({
            "hour":      hour,
            "vm_id":     vm.get("id") or vm.get("uuid") or vm.get("name", ""),
            "vm_name":   vm.get("name", ""),
            "running":   running,
            "vcpus":     int(vm.get("vcpus") or 0),
            "ram_gb":    round(float(vm.get("memory_mb") or 0) / 1024, 3),
            "disk_gb":   float(vm.get("disk_gb") or 0),
            "ipv4":      int(vm.get("ipv4_count") or (1 if vm.get("ip") else 0)),
        })
    return out


def record_usage(vm_lister=None) -> dict:
    """Bir saatlik kullanım örneğini kaydet. Aynı saat için tekrar yazmaz."""
    samples = _collect_samples(vm_lister)
    if not samples:
        return {"ok": True, "recorded": 0, "reason": "no vms"}
    hour = samples[0]["hour"]
    path = _usage_path(_period())
    with _lock:
        # idempotency: bu saat zaten yazıldıysa atla
        try:
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    for line in f:
                        if f'"hour": "{hour}"' in line or f'"hour":"{hour}"' in line:
                            return {"ok": True, "recorded": 0, "reason": "already recorded", "hour": hour}
        except OSError:
            pass
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                for s in samples:
                    f.write(json.dumps(s, ensure_ascii=False) + "\n")
        except OSError as e:
            log.warning("kullanım kaydı yazılamadı: %s", e)
            return {"ok": False, "error": str(e)}
    return {"ok": True, "recorded": len(samples), "hour": hour}


# ── Faturalama ────────────────────────────────────────────────────────────────

def _line_cost(sample: dict, rates: dict) -> float:
    if sample.get("running"):
        c = (sample.get("vcpus", 0) * rates["vcpu_hour"]
             + sample.get("ram_gb", 0) * rates["gb_ram_hour"]
             + sample.get("disk_gb", 0) * rates["gb_disk_hour"]
             + sample.get("ipv4", 0) * rates["ipv4_hour"])
    else:
        # Durdurulmuş VM: hesaplama yok, yalnızca depolama (+ ayrılmış IP)
        c = (sample.get("disk_gb", 0) * rates["gb_disk_hour_stopped"]
             + sample.get("ipv4", 0) * rates["ipv4_hour"])
    return round(c, 6)


def invoice(period: str | None = None, vm_id: str | None = None) -> dict:
    """Dönem için kalem kalem fatura üret (varsayılan: içinde bulunulan ay)."""
    period = period or _period()
    rates = get_rates()
    path = _usage_path(period)
    per_vm: dict = {}
    total = 0.0
    rows = 0

    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    s = json.loads(line)
                except ValueError:
                    continue
                if vm_id and s.get("vm_id") != vm_id:
                    continue
                cost = _line_cost(s, rates)
                e = per_vm.setdefault(s.get("vm_id", "?"), {
                    "vm_id": s.get("vm_id", "?"), "vm_name": s.get("vm_name", ""),
                    "hours_running": 0, "hours_stopped": 0, "cost": 0.0,
                })
                if s.get("running"):
                    e["hours_running"] += 1
                else:
                    e["hours_stopped"] += 1
                e["cost"] = round(e["cost"] + cost, 6)
                total += cost
                rows += 1
    except FileNotFoundError:
        return {"ok": True, "period": period, "currency": rates["currency"],
                "lines": [], "total": 0.0, "samples": 0,
                "note": "bu dönem için kullanım kaydı yok"}
    except OSError as e:
        return {"ok": False, "error": str(e)}

    lines = sorted(per_vm.values(), key=lambda x: -x["cost"])
    for l in lines:
        l["cost"] = round(l["cost"], 4)
    return {
        "ok": True, "period": period, "currency": rates["currency"],
        "lines": lines, "total": round(total, 4), "samples": rows,
        "rates": rates,
    }


def periods() -> list:
    """Kullanım kaydı bulunan dönemler."""
    d = os.path.join(_data_dir(), "billing")
    try:
        return sorted(f[6:-6] for f in os.listdir(d)
                      if f.startswith("usage-") and f.endswith(".jsonl"))
    except OSError:
        return []


def start_meter(interval_sec: int = 3600) -> threading.Thread | None:
    """Saatlik sayaç thread'ini başlat."""
    def _loop():
        while True:
            try:
                record_usage()
            except Exception as e:                # pragma: no cover
                log.error("billing meter hatası: %s", e)
            time.sleep(max(60, interval_sec))
    t = threading.Thread(target=_loop, name="billing-meter", daemon=True)
    t.start()
    log.info("Faturalama sayacı başlatıldı (%ds)", interval_sec)
    return t


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(json.dumps({"rates": get_rates(), "periods": periods()},
                     indent=2, ensure_ascii=False))
