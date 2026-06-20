# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware AI Chat — multi-conversation chat on top of configured AI agents.

Design goal: keep the server light. Conversations are persisted as a small
**text-only** transcript. Uploaded images are NEVER written to disk — they
are forwarded to the model only for the request in which they are sent, and
the stored history just records that an image was attached. This keeps the
state file tiny no matter how many screenshots a user pastes.

Each chat: {id, title, agent_id, created, updated, messages:[{role, content,
ts, has_image}]}. Per-chat agent selection is supported (agent_id per chat).

State: /var/lib/oxware/ai_chats.json
"""
from __future__ import annotations
import json
import os
import threading
import time
import uuid
from pathlib import Path

_STORE = Path("/var/lib/oxware/ai_chats.json")
_LOCK = threading.Lock()

_MAX_HISTORY = 16        # messages sent to the model (context window control)
_MAX_STORED = 400        # messages kept per chat on disk
_MAX_IMAGES = 6          # images per send
_MAX_IMG_LEN = 8_000_000  # ~6 MB decoded; reject larger to protect the model call


def _ai_agent():
    """Lazy import so this module loads on dev hosts lacking ai_agent deps."""
    try:
        from oxware.backend import ai_agent as a
        return a
    except Exception:
        try:
            import ai_agent as a
            return a
        except Exception:
            return None


def _load() -> dict:
    if not _STORE.exists():
        return {"chats": []}
    try:
        return json.loads(_STORE.read_text(encoding="utf-8"))
    except Exception:
        return {"chats": []}


def _save(d: dict) -> None:
    _STORE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _STORE.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, _STORE)


def _summary(chat: dict) -> dict:
    """Lightweight list entry (no message bodies)."""
    msgs = chat.get("messages", [])
    last = msgs[-1]["content"] if msgs else ""
    return {
        "id": chat["id"],
        "title": chat.get("title") or "Yeni sohbet",
        "agent_id": chat.get("agent_id"),
        "created": chat.get("created"),
        "updated": chat.get("updated"),
        "message_count": len(msgs),
        "preview": (last[:80] if last else ""),
    }


def list_chats() -> list:
    chats = _load().get("chats", [])
    chats.sort(key=lambda c: c.get("updated", 0), reverse=True)
    return [_summary(c) for c in chats]


def create_chat(title: str = "", agent_id: str = "") -> dict:
    now = time.time()
    chat = {
        "id": "chat-" + uuid.uuid4().hex[:10],
        "title": (title or "Yeni sohbet")[:120],
        "agent_id": agent_id or "",
        "created": now,
        "updated": now,
        "messages": [],
    }
    with _LOCK:
        d = _load()
        d["chats"].append(chat)
        _save(d)
    return chat


def get_chat(chat_id: str) -> dict | None:
    for c in _load().get("chats", []):
        if c["id"] == chat_id:
            return c
    return None


def update_chat(chat_id: str, title: str = None, agent_id: str = None) -> dict:
    with _LOCK:
        d = _load()
        for c in d["chats"]:
            if c["id"] == chat_id:
                if title is not None:
                    c["title"] = title[:120]
                if agent_id is not None:
                    c["agent_id"] = agent_id
                c["updated"] = time.time()
                _save(d)
                return {"ok": True, "chat": _summary(c)}
    return {"ok": False, "error": "not found"}


def delete_chat(chat_id: str) -> dict:
    with _LOCK:
        d = _load()
        new = [c for c in d["chats"] if c["id"] != chat_id]
        if len(new) == len(d["chats"]):
            return {"ok": False, "error": "not found"}
        d["chats"] = new
        _save(d)
    return {"ok": True, "id": chat_id}


_SYSTEM_PROMPT = (
    "Sen OXware Hypervisor için bir yapay zeka asistanısın. Türkçe, kısa ve "
    "net yanıt ver. Teknik terimleri doğru kullan. Görsel verildiğinde "
    "içeriğini analiz et.\n"
    "ARAÇLAR: Gerçekten işlem yapabilirsin. Kullanıcı bir şey isterse (VM "
    "oluştur/başlat/durdur/sil/listele, sistem durumu, golden image) shell "
    "komutu YAZMA — sağlanan araçları çağır ve gerçekten yap. İşi yaptıktan "
    "sonra sonucu özetle. VM silme gibi geri alınamaz işlemlerde önce "
    "kullanıcıdan onay iste; onaylarsa confirm=true ile çağır.\n"
    "BİÇİM: Sayısal/çok alanlı veriyi Markdown tablo ver (| sütun | + ayraç "
    "satırı). Önemli değerleri **kalın** yap. Yol/değer için `backtick`.\n"
    "YETKİ: Bazı bilgiler role bağlıdır. Kullanıcı oturumları, giriş IP'leri "
    "ve denetim (audit) kaydı YALNIZCA ana yöneticiye verilir; ilgili araç "
    "'denied' dönerse uydurma — kullanıcıya bu bilgiyi görme yetkisi "
    "olmadığını kibarca söyle.\n\n"
)


def send_message(chat_id: str, text: str, images: list = None,
                 agent_id: str = None, ctx: dict = None) -> dict:
    """Append the user message, call the selected agent with recent history
    (text + this turn's images), store the assistant reply. Images are not
    persisted — only the text transcript is."""
    text = (text or "").strip()
    images = images or []
    if not text and not images:
        return {"ok": False, "error": "boş mesaj"}
    if len(images) > _MAX_IMAGES:
        return {"ok": False, "error": f"en fazla {_MAX_IMAGES} görsel"}
    for img in images:
        if not isinstance(img, str) or len(img) > _MAX_IMG_LEN:
            return {"ok": False, "error": "görsel çok büyük"}

    agent = _ai_agent()
    if not agent:
        return {"ok": False, "error": "ai_agent modülü yüklenemedi"}

    with _LOCK:
        d = _load()
        chat = next((c for c in d["chats"] if c["id"] == chat_id), None)
        if not chat:
            return {"ok": False, "error": "sohbet bulunamadı"}
        if agent_id:
            chat["agent_id"] = agent_id
        use_agent = chat.get("agent_id")
        if not use_agent:
            return {"ok": False, "error": "Bu sohbet için bir AI ajanı seçin"}
        # Build model history from stored TEXT transcript (no past images).
        history = [{"role": m["role"], "content": m["content"]}
                   for m in chat["messages"][-_MAX_HISTORY:]]

    # Current turn carries the images (only place they appear).
    turn = {"role": "user", "content": text or "(görsel)", "images": images}
    model_messages = history + [turn]
    sys_prompt = _SYSTEM_PROMPT
    try:
        sys_prompt += agent.live_system_context()
    except Exception:
        pass

    # Tool-capable path: the assistant can actually operate OXware.
    tools_used = []
    try:
        try:
            import ai_tools
        except Exception:
            from oxware.backend import ai_tools  # type: ignore
        _ctx = ctx or {}
        out = agent.query_agent_tools(
            use_agent, model_messages, sys_prompt, ai_tools.SPECS,
            lambda n, a: ai_tools.execute(n, a, _ctx))
        reply = out.get("text", "")
        tools_used = out.get("tools_used", [])
    except Exception as e:
        # Fall back to plain chat if tool use is unavailable for this provider.
        try:
            reply = agent.query_agent_chat(use_agent, model_messages, sys_prompt)
        except Exception as e2:
            return {"ok": False, "error": str(e2 or e)[:300]}

    now = time.time()
    with _LOCK:
        d = _load()
        chat = next((c for c in d["chats"] if c["id"] == chat_id), None)
        if not chat:
            return {"ok": False, "error": "sohbet bulunamadı"}
        # Auto-title from the first user message.
        if not chat["messages"] and (text or images):
            chat["title"] = (text or "Görsel sohbeti")[:60]
        chat["messages"].append({"role": "user", "content": text,
                                 "ts": now, "has_image": bool(images)})
        chat["messages"].append({"role": "assistant", "content": reply,
                                 "ts": time.time(), "has_image": False})
        if len(chat["messages"]) > _MAX_STORED:
            chat["messages"] = chat["messages"][-_MAX_STORED:]
        chat["updated"] = time.time()
        if agent_id:
            chat["agent_id"] = agent_id
        _save(d)

    return {"ok": True, "reply": reply, "agent_id": use_agent,
            "tools_used": tools_used}
