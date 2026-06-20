# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware AI Ops Insights.

On-demand AI summaries over the data OXware already collects:
  * summarize_events() — "what happened" digest of recent events (nightly
    summary, incident catch-up).
  * analyze_health()  — pulls anomalies + capacity forecast + live system
    state and asks the agent for a PRIORITIZED, advisory remediation list.

Advisory only: nothing is executed automatically. The operator reads the
suggestions and acts (existing runbooks / one-click actions). Reuses the
configured AI agents via ai_agent.query_agent_chat.
"""
from __future__ import annotations
import logging
import time

log = logging.getLogger("oxware.ai_insights")


def _mod(name):
    try:
        return __import__(name)
    except Exception:
        try:
            return __import__(f"oxware.backend.{name}", fromlist=["*"])
        except Exception:
            return None


_SYS_EVENTS = (
    "Sen OXware Hypervisor için kıdemli bir SRE asistanısın. Sana verilen "
    "olay kayıtlarını incele ve operatöre kısa bir DURUM ÖZETİ üret. Türkçe. "
    "Şu yapıda: ## Özet (1-2 cümle), ## Dikkat Gerektirenler (madde + neden), "
    "## Normal/Bilgi (kısa). Önemli değerleri **kalın** yap. Uydurma — sadece "
    "verilenlere dayan."
)
_SYS_HEALTH = (
    "Sen OXware Hypervisor için kıdemli bir SRE asistanısın. Sana anomali, "
    "kapasite tahmini ve canlı sistem durumu verilecek. ÖNCELİKLİ, uygulanabilir "
    "bir aksiyon listesi üret (advisory — sen çalıştırmıyorsun, operatör "
    "uygulayacak). Türkçe. Yapı: ## Risk Değerlendirmesi, ## Önerilen Aksiyonlar "
    "(öncelik sırasıyla, her biri: ne yapılmalı + neden + etki). Önemli yerleri "
    "**kalın**. Veri yoksa 'yeterli veri yok' de."
)


def _agent():
    a = _mod("ai_agent")
    return a


def _first_agent_id() -> str:
    a = _agent()
    if not a:
        return ""
    try:
        agents = a.list_agents()
        return agents[0]["id"] if agents else ""
    except Exception:
        return ""


def summarize_events(hours: int = 12, agent_id: str = "") -> dict:
    a = _agent()
    if not a:
        return {"ok": False, "error": "ai_agent yok"}
    aid = agent_id or _first_agent_id()
    if not aid:
        return {"ok": False, "error": "Yapılandırılmış AI ajanı yok"}
    ev = _mod("event_logger")
    if not ev:
        return {"ok": False, "error": "event_logger yok"}
    hours = max(1, min(int(hours or 12), 168))
    since = time.time() - hours * 3600
    events = ev.get_events(limit=200, since=since)
    if not events:
        return {"ok": True, "summary": f"Son {hours} saatte kayıtlı olay yok.",
                "event_count": 0, "agent_id": aid}
    lines = []
    for e in events[:120]:
        lines.append(f"[{e.get('level','?')}] {e.get('category','')}: "
                     f"{e.get('message','')}")
    prompt = (f"Son {hours} saatteki {len(events)} olay (en fazla 120 gösterildi):\n\n"
              + "\n".join(lines) + "\n\nBunları özetle.")
    try:
        summary = a.query_agent_chat(aid, [{"role": "user", "content": prompt}],
                                     _SYS_EVENTS)
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}
    return {"ok": True, "summary": summary, "event_count": len(events),
            "hours": hours, "agent_id": aid}


def analyze_health(agent_id: str = "") -> dict:
    a = _agent()
    if not a:
        return {"ok": False, "error": "ai_agent yok"}
    aid = agent_id or _first_agent_id()
    if not aid:
        return {"ok": False, "error": "Yapılandırılmış AI ajanı yok"}

    ctx_parts = []
    try:
        ctx_parts.append(a.live_system_context())
    except Exception:
        pass
    an = _mod("anomaly_detector")
    if an:
        try:
            anomalies = an.get_anomalies(limit=20)
            if anomalies:
                ctx_parts.append("\n[Anomaliler]\n" + "\n".join(
                    f"- {x.get('metric','?')}: {x.get('message', x)}"
                    for x in anomalies[:20]))
        except Exception:
            pass
    pl = _mod("ai_planner")
    if pl:
        try:
            cap = pl.predict_capacity(30)
            ctx_parts.append("\n[Kapasite tahmini 30g]\n" + str(cap)[:1500])
        except Exception:
            pass
        try:
            recs = pl.get_recommendations()
            ctx_parts.append("\n[Sistem önerileri]\n" + str(recs)[:1500])
        except Exception:
            pass
    context = "\n".join(p for p in ctx_parts if p) or "(veri yok)"
    prompt = ("Aşağıdaki duruma göre öncelikli aksiyon listesi üret:\n\n" + context)
    try:
        analysis = a.query_agent_chat(aid, [{"role": "user", "content": prompt}],
                                      _SYS_HEALTH)
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}
    return {"ok": True, "analysis": analysis, "agent_id": aid}
