# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware VM Flight Recorder + AI post-mortem ("black box").

An aircraft-style black box for VMs: it assembles the last N minutes of a VM's
metric history (from perf_history, already collected — no new sampling load)
and its events (from event_logger) into a single timeline, then on demand asks
the AI for a root-cause post-mortem ("CPU spike → memory pressure → OOM →
panic"). No competitor ships an auto post-mortem like this.

Reuses existing data — adds no background sampler.
"""
from __future__ import annotations
import logging
import time

log = logging.getLogger("oxware.flightrec")


def _mod(name):
    try:
        return __import__(name)
    except Exception:
        try:
            return __import__(f"oxware.backend.{name}", fromlist=["*"])
        except Exception:
            return None


def timeline(vm_id: str, period: str = "1h") -> dict:
    """Unified timeline: metric samples + events for a VM."""
    vm = _mod("vm_manager")
    name = vm_id
    try:
        if vm:
            name = vm.get_vm(vm_id).get("name", vm_id)
    except Exception:
        pass
    samples = []
    ph = _mod("perf_history")
    if ph and hasattr(ph, "get_vm_history"):
        try:
            samples = ph.get_vm_history(vm_id, period=period) or []
        except Exception:
            samples = []
    events = []
    ev = _mod("event_logger")
    if ev and hasattr(ev, "get_events"):
        secs = {"15m": 900, "30m": 1800, "1h": 3600, "6h": 21600,
                "24h": 86400}.get(period, 3600)
        try:
            events = ev.get_events(limit=100, vm_id=vm_id,
                                   since=time.time() - secs) or []
            if not events:  # some events log by name, not id
                events = [e for e in (ev.get_events(limit=200,
                          since=time.time() - secs) or [])
                          if name and name in str(e.get("message", ""))][:100]
        except Exception:
            events = []
    return {"ok": True, "vm": name, "period": period,
            "sample_count": len(samples), "event_count": len(events),
            "samples": samples[-300:], "events": events[-100:]}


def _summarize_samples(samples: list) -> str:
    """Compact textual trend for the AI (avoid dumping hundreds of points)."""
    if not samples:
        return "(metrik verisi yok)"
    def col(keys):
        vals = []
        for s in samples:
            for k in keys:
                v = s.get(k)
                if isinstance(v, (int, float)):
                    vals.append(v); break
        return vals
    cpu = col(["cpu", "cpu_percent"])
    mem = col(["mem", "memory", "memory_percent"])
    def stat(v):
        return f"min {min(v):.0f} / ort {sum(v)/len(v):.0f} / max {max(v):.0f}" if v else "—"
    last = samples[-1]
    return (f"Örnek sayısı: {len(samples)}\n"
            f"CPU%: {stat(cpu)}\nRAM%: {stat(mem)}\n"
            f"Son örnek: {last}")


def post_mortem(vm_id: str, agent_id: str = "", period: str = "1h") -> dict:
    """AI root-cause analysis over the recorded timeline."""
    agent = _mod("ai_agent")
    if not agent:
        return {"ok": False, "error": "ai_agent yok"}
    aid = agent_id
    if not aid:
        try:
            agents = agent.list_agents()
            aid = agents[0]["id"] if agents else ""
        except Exception:
            aid = ""
    if not aid:
        return {"ok": False, "error": "Yapılandırılmış AI ajanı yok"}
    tl = timeline(vm_id, period)
    ev_lines = "\n".join(
        f"[{e.get('level','?')}] {e.get('datetime', e.get('timestamp',''))}: "
        f"{e.get('message','')}" for e in tl["events"][-40:]) or "(olay yok)"
    prompt = (f"VM '{tl['vm']}' için kara-kutu kaydı (son {period}):\n\n"
              f"[Metrik özeti]\n{_summarize_samples(tl['samples'])}\n\n"
              f"[Olaylar]\n{ev_lines}\n\n"
              "Bir SRE gibi KÖK NEDEN otopsisi yap: ne oldu, neden, olay zinciri "
              "(ör. CPU spike → bellek baskısı → OOM → panik), ve önleme önerileri.")
    sysp = ("Sen kıdemli bir SRE'sin. VM kara-kutu verisinden kök-neden "
            "otopsisi üret. Türkçe, Markdown. Yapı: ## Özet, ## Olay Zinciri, "
            "## Kök Neden, ## Öneriler. Sadece verilenlere dayan, uydurma.")
    try:
        report = agent.query_agent_chat(aid, [{"role": "user", "content": prompt}], sysp)
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}
    return {"ok": True, "vm": tl["vm"], "period": period,
            "sample_count": tl["sample_count"], "event_count": tl["event_count"],
            "report": report}
