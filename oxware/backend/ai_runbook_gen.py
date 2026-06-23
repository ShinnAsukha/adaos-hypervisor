# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware AI runbook generator — natural language → automation runbook.

"When CPU stays above 90% for 5 minutes, migrate the VM to node2" → the AI
drafts a runbook matching runbook_executor's schema (trigger.metric_regex +
steps). The draft is returned DISABLED for the operator to review and enable —
never auto-armed. Validated against the allowed step types before save.
"""
from __future__ import annotations
import json
import logging
import re
import uuid

log = logging.getLogger("oxware.runbookgen")
_STEP_TYPES = {"notify", "api_call", "shell", "vm_action"}


def _mod(name):
    try:
        return __import__(name)
    except Exception:
        try:
            return __import__(f"oxware.backend.{name}", fromlist=["*"])
        except Exception:
            return None


_SYS = (
    "Sen bir SRE otomasyon asistanısın. Kullanıcının doğal dil isteğini "
    "OXware runbook JSON'una çevir. SADECE JSON döndür, açıklama yazma.\n"
    "Şema: {\"name\": str, \"description\": str, \"trigger\": {\"metric_regex\": "
    "regex, \"min_z\": float, \"cooldown_sec\": int}, \"steps\": [ {\"type\": "
    "\"notify\"|\"vm_action\"|\"api_call\"|\"shell\", ...} ]}.\n"
    "notify: {type:notify, message}. vm_action: {type:vm_action, action: "
    "start|stop|reboot, extract_vm_id_from:\"metric_key\"}. metric_regex örnek: "
    "'^system\\\\.cpu$', '^vm\\\\..+\\\\.iops$'. Güvenli, minimal adımlar üret."
)


def generate(description: str, agent_id: str = "") -> dict:
    if not (description or "").strip():
        return {"ok": False, "error": "açıklama gerekli"}
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
    try:
        raw = agent.query_agent_chat(
            aid, [{"role": "user", "content": description}], _SYS)
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}

    # Extract JSON (model may wrap in code fences).
    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        return {"ok": False, "error": "AI geçerli JSON döndürmedi", "raw": raw[:500]}
    try:
        draft = json.loads(m.group(0))
    except Exception:
        return {"ok": False, "error": "JSON ayrıştırılamadı", "raw": raw[:500]}

    # Validate + sanitize.
    trig = draft.get("trigger") or {}
    if not isinstance(trig.get("metric_regex"), str):
        return {"ok": False, "error": "trigger.metric_regex eksik", "raw": raw[:500]}
    steps = [s for s in (draft.get("steps") or [])
             if isinstance(s, dict) and s.get("type") in _STEP_TYPES]
    if not steps:
        return {"ok": False, "error": "geçerli adım yok", "raw": raw[:500]}
    name = str(draft.get("name") or "ai-runbook")[:80]
    rb = {
        "id": "rb-ai-" + uuid.uuid4().hex[:8],
        "name": name,
        "description": str(draft.get("description") or description)[:300],
        "enabled": False,  # operator reviews + enables
        "source": "ai-generated",
        "trigger": {
            "metric_regex": trig["metric_regex"][:200],
            "min_z": float(trig.get("min_z", 3.0)),
            "cooldown_sec": int(trig.get("cooldown_sec", 600)),
        },
        "steps": steps[:10],
    }
    return {"ok": True, "draft": rb}


def save(rb: dict) -> dict:
    rbx = _mod("runbook_executor")
    if not rbx or not hasattr(rbx, "upsert_runbook"):
        return {"ok": False, "error": "runbook_executor yok"}
    if "id" not in rb:
        rb["id"] = "rb-ai-" + uuid.uuid4().hex[:8]
    rb["enabled"] = False  # always saved disabled; operator arms it explicitly
    try:
        rbx.upsert_runbook(rb)
        return {"ok": True, "id": rb["id"]}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}
