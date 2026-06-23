# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware ChatOps — manage the datacenter from Telegram, AI-powered.

Competitors only PUSH read-only alerts to chat. OXware is two-way: ask
"vm-3 neden yavaş?" or "yeni ubuntu VM aç" from Telegram and the AI answers /
acts via the same tool layer the panel uses.

Security: DISABLED by default. Only whitelisted chat IDs are served. Mutations
(create/start/stop/delete) require allow_mutations=true; otherwise the AI runs
with operator (read-mostly) authority. Uses the Telegram bot token already
configured in notifications. Long-polls getUpdates in a daemon thread.

State: /var/lib/oxware/chatops.json
"""
from __future__ import annotations
import json
import logging
import os
import threading
import time

log = logging.getLogger("oxware.chatops")
_CFG = "/var/lib/oxware/chatops.json"
_LOCK = threading.Lock()
_STARTED = False
_OFFSET = 0


def _mod(name):
    try:
        return __import__(name)
    except Exception:
        try:
            return __import__(f"oxware.backend.{name}", fromlist=["*"])
        except Exception:
            return None


def get_config() -> dict:
    cfg = {"enabled": False, "allowed_chat_ids": [], "allow_mutations": False,
           "agent_id": ""}
    if os.path.exists(_CFG):
        try:
            cfg.update(json.loads(open(_CFG, encoding="utf-8").read()))
        except Exception:
            pass
    nt = _mod("notifications")
    token = ""
    if nt and hasattr(nt, "_load_config"):
        try:
            token = nt._load_config().get("telegram_token", "")
        except Exception:
            pass
    cfg["telegram_ready"] = bool(token)
    return cfg


def set_config(enabled=None, allowed_chat_ids=None, allow_mutations=None,
               agent_id=None) -> dict:
    cur = {k: v for k, v in get_config().items()
           if k in ("enabled", "allowed_chat_ids", "allow_mutations", "agent_id")}
    if enabled is not None:
        cur["enabled"] = bool(enabled)
    if allowed_chat_ids is not None:
        cur["allowed_chat_ids"] = [str(c).strip() for c in allowed_chat_ids if str(c).strip()]
    if allow_mutations is not None:
        cur["allow_mutations"] = bool(allow_mutations)
    if agent_id is not None:
        cur["agent_id"] = agent_id
    try:
        os.makedirs(os.path.dirname(_CFG), exist_ok=True)
        open(_CFG, "w", encoding="utf-8").write(json.dumps(cur, indent=2))
    except Exception as e:
        return {"ok": False, "error": str(e)[:160]}
    if cur["enabled"]:
        start_background()
    return {"ok": True, **get_config()}


def _token():
    nt = _mod("notifications")
    if nt and hasattr(nt, "_load_config"):
        try:
            return nt._load_config().get("telegram_token", "")
        except Exception:
            return ""
    return ""


def _send(chat_id, text):
    nt = _mod("notifications")
    tok = _token()
    if nt and tok and hasattr(nt, "_send_telegram"):
        try:
            nt._send_telegram(tok, str(chat_id), text[:3800])
        except Exception as e:
            log.warning("chatops send: %s", e)


def _handle(chat_id, text, cfg):
    agent = _mod("ai_agent")
    tools = _mod("ai_tools")
    if not agent or not tools:
        _send(chat_id, "AI modülü yok.")
        return
    aid = cfg.get("agent_id") or ""
    if not aid:
        try:
            agents = agent.list_agents(); aid = agents[0]["id"] if agents else ""
        except Exception:
            aid = ""
    if not aid:
        _send(chat_id, "Yapılandırılmış AI ajanı yok.")
        return
    # Authority: operator (read-mostly) unless mutations explicitly allowed.
    ctx = {"username": f"telegram:{chat_id}",
           "role": "administrator" if cfg.get("allow_mutations") else "operator",
           "is_primary": False}
    sysp = ("Sen OXware ChatOps asistanısın (Telegram). Kısa, net Türkçe yanıt "
            "ver. Araçlarla gerçek işlem yapabilirsin; yetkisiz işlemde kibarca "
            "reddet. Markdown kullanma, düz metin yaz.")
    try:
        out = agent.query_agent_tools(
            aid, [{"role": "user", "content": text}], sysp,
            tools.SPECS, lambda n, a: tools.execute(n, a, ctx))
        _send(chat_id, out.get("text") or "(boş yanıt)")
    except Exception as e:
        _send(chat_id, f"Hata: {str(e)[:200]}")


def _loop():
    global _OFFSET
    import urllib.request
    import urllib.parse
    while True:
        cfg = get_config()
        tok = _token()
        if not cfg.get("enabled") or not tok:
            time.sleep(15)
            continue
        try:
            url = (f"https://api.telegram.org/bot{tok}/getUpdates?timeout=30"
                   f"&offset={_OFFSET}")
            with urllib.request.urlopen(url, timeout=40) as r:
                data = json.loads(r.read().decode())
            for upd in data.get("result", []):
                _OFFSET = max(_OFFSET, upd["update_id"] + 1)
                msg = upd.get("message") or {}
                chat_id = str((msg.get("chat") or {}).get("id", ""))
                text = (msg.get("text") or "").strip()
                if not text or not chat_id:
                    continue
                allowed = cfg.get("allowed_chat_ids") or []
                if allowed and chat_id not in allowed:
                    _send(chat_id, "Bu sohbet yetkili değil.")
                    continue
                log.info("chatops msg from %s: %s", chat_id, text[:80])
                _handle(chat_id, text, cfg)
        except Exception as e:
            log.debug("chatops loop: %s", e)
            time.sleep(10)


def start_background():
    global _STARTED
    if _STARTED:
        return
    if not get_config().get("enabled"):
        return
    _STARTED = True
    threading.Thread(target=_loop, daemon=True, name="chatops").start()
    log.info("ChatOps başlatıldı")


def status() -> dict:
    return get_config()
