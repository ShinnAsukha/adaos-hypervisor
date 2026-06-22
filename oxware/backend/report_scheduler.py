# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware scheduled reports.

Builds operational reports (inventory / compliance / cost / audit) from data
OXware already collects, and delivers them on a schedule via the existing
notifications channels (Telegram / Discord / e-mail). On-demand send + a
weekly background sender.

State: /var/lib/oxware/report_schedules.json
"""
from __future__ import annotations
import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime

log = logging.getLogger("oxware.reports")
_STORE = "/var/lib/oxware/report_schedules.json"
_LOCK = threading.Lock()
_KINDS = ("inventory", "compliance", "cost", "audit")
_BG_STARTED = False


def _mod(name):
    try:
        return __import__(name)
    except Exception:
        try:
            return __import__(f"oxware.backend.{name}", fromlist=["*"])
        except Exception:
            return None


def _tbl(headers, rows):
    h = " | ".join(headers)
    sep = " | ".join("---" for _ in headers)
    body = "\n".join(" | ".join(str(c) for c in r) for r in rows)
    return f"| {h} |\n| {sep} |\n" + "\n".join(f"| {r} |" for r in body.split("\n") if r)


def generate(kind: str) -> dict:
    if kind not in _KINDS:
        return {"ok": False, "error": f"geçersiz tür ({', '.join(_KINDS)})"}
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    title = {"inventory": "Envanter", "compliance": "Uyumluluk",
             "cost": "Maliyet", "audit": "Denetim"}[kind]
    lines = [f"## OXware {title} Raporu", f"_{ts}_", ""]
    try:
        if kind == "inventory":
            vm = _mod("vm_manager")
            vms = vm.list_vms() if vm else []
            run = sum(1 for v in vms if v.get("state") == "running")
            lines.append(f"**Toplam VM:** {len(vms)} · **Çalışan:** {run}")
            rows = [[v["name"], v.get("state"), v.get("vcpus"), v.get("memory_mb")]
                    for v in vms[:50]]
            lines.append(_tbl(["VM", "Durum", "vCPU", "RAM(MB)"], rows) if rows else "VM yok")
        elif kind == "compliance":
            cs = _mod("compliance_scanner")
            data = {}
            for fn in ("get_summary", "summary", "scan", "get_status"):
                if cs and hasattr(cs, fn):
                    try:
                        data = getattr(cs, fn)(); break
                    except Exception:
                        pass
            lines.append("```json\n" + json.dumps(data, ensure_ascii=False, indent=2)[:1500] + "\n```")
        elif kind == "cost":
            for modn in ("cost_tracker", "chargeback_engine"):
                cm = _mod(modn)
                for fn in ("get_summary", "summary", "report", "get_costs"):
                    if cm and hasattr(cm, fn):
                        try:
                            lines.append("```json\n" + json.dumps(getattr(cm, fn)(), ensure_ascii=False, indent=2)[:1500] + "\n```")
                            break
                        except Exception:
                            pass
                else:
                    continue
                break
        elif kind == "audit":
            al = _mod("audit_log")
            logs = al.get_logs(limit=40) if al and hasattr(al, "get_logs") else []
            rows = [[l.get("timestamp", l.get("ts", "")), l.get("username"),
                     l.get("action"), l.get("resource_type", "")] for l in logs]
            lines.append(_tbl(["Zaman", "Kullanıcı", "Aksiyon", "Kaynak"], rows) if rows else "Kayıt yok")
    except Exception as e:
        lines.append(f"_Rapor üretim hatası: {str(e)[:160]}_")
    return {"ok": True, "kind": kind, "title": title, "report": "\n".join(lines)}


def send_now(kind: str, channel: str = "all") -> dict:
    rep = generate(kind)
    if not rep.get("ok"):
        return rep
    nt = _mod("notifications")
    if not nt or not hasattr(nt, "send_alert"):
        return {"ok": False, "error": "notifications modülü yok"}
    try:
        nt.send_alert(rep["report"][:3500], level="INFO", category="report",
                      details={"kind": kind})
        return {"ok": True, "sent": kind, "channel": channel}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


def _load():
    if not os.path.exists(_STORE):
        return {"schedules": []}
    try:
        return json.loads(open(_STORE, encoding="utf-8").read())
    except Exception:
        return {"schedules": []}


def _save(d):
    os.makedirs(os.path.dirname(_STORE), exist_ok=True)
    tmp = _STORE + ".tmp"
    open(tmp, "w", encoding="utf-8").write(json.dumps(d, indent=2, ensure_ascii=False))
    os.replace(tmp, _STORE)


def list_schedules():
    return _load()["schedules"]


def add_schedule(kind, interval_days=7, channel="all"):
    if kind not in _KINDS:
        return {"ok": False, "error": "geçersiz tür"}
    rec = {"id": "rs-" + uuid.uuid4().hex[:8], "kind": kind,
           "interval_days": max(1, min(int(interval_days), 90)),
           "channel": channel, "last_run": 0, "created": time.time()}
    with _LOCK:
        d = _load(); d["schedules"].append(rec); _save(d)
    return {"ok": True, "schedule": rec}


def delete_schedule(sid):
    with _LOCK:
        d = _load()
        d["schedules"] = [s for s in d["schedules"] if s["id"] != sid]
        _save(d)
    return {"ok": True, "id": sid}


def _loop():
    while True:
        try:
            now = time.time()
            for s in list_schedules():
                if now - s.get("last_run", 0) >= s["interval_days"] * 86400:
                    send_now(s["kind"], s.get("channel", "all"))
                    with _LOCK:
                        d = _load()
                        for x in d["schedules"]:
                            if x["id"] == s["id"]:
                                x["last_run"] = now
                        _save(d)
        except Exception as e:
            log.warning("report loop hata: %s", e)
        time.sleep(3600)


def start_background():
    global _BG_STARTED
    if _BG_STARTED:
        return
    _BG_STARTED = True
    threading.Thread(target=_loop, daemon=True, name="report-scheduler").start()
