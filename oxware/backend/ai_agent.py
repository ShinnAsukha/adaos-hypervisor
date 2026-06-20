"""
OXware Yapay Zeka Ajan Sistemi
─────────────────────────────
Her hypervisor için ayrı AI agent:
  - OpenRouter API (100+ model)
  - Anthropic Claude API
  - OpenAI API
  - Diğer OpenAI-uyumlu sağlayıcılar

Görevler:
  - Sistem metriklerini izle
  - Anomali tespit et
  - Olay özetleri üret
  - Uyarı mesajları yaz
  - Otomatik öneri sun

Yapılandırma: /etc/oxware/ai_agents.conf
"""

import os
import json
import time
import base64
import hashlib
import tempfile
import threading
import requests
from datetime import datetime
from typing import Optional
from pathlib import Path
import config
import event_logger
import notifications
import system_monitor

# ── OXW-2026-SEC-002 fix: AI_CONFIG_FILE path traversal guard ──────────────────
# Ortam değişkeninden gelen path normalize edilir ve sadece izin verilen
# dizinler altında kalması zorunlu kılınır. Aksi halde varsayılana düşülür.
_AI_CONFIG_DEFAULT  = "/etc/oxware/ai_agents.conf"
_AI_ALLOWED_ROOTS   = ("/etc/oxware", "/etc/adaos", "/var/lib/oxware", "/var/lib/adaos")

def _resolve_ai_config_path() -> str:
    raw = os.environ.get("OXWARE_AI_CONFIG", os.environ.get("ADAOS_AI_CONFIG", _AI_CONFIG_DEFAULT))
    try:
        norm = os.path.realpath(os.path.abspath(raw))
    except Exception:
        return _AI_CONFIG_DEFAULT
    # Sadece izin verilen kök dizinler altında olmalı + .conf/.json uzantısı
    if not any(norm == root or norm.startswith(root + os.sep) for root in _AI_ALLOWED_ROOTS):
        try:
            event_logger.warn(f"AI config path izinli dizin dışında, reddedildi: {raw}", category="security")
        except Exception:
            pass
        return _AI_CONFIG_DEFAULT
    if not norm.endswith((".conf", ".json")):
        return _AI_CONFIG_DEFAULT
    return norm

AI_CONFIG_FILE  = _resolve_ai_config_path()
AGENT_LOG_FILE  = os.path.join(config.LOG_DIR, "ai_agent.jsonl")
_agents: dict   = {}
_threads: dict  = {}
_stop_events: dict = {}            # agent_id → threading.Event (OXW-2026-SEC-003)
_running: bool  = False
_lock           = threading.RLock()  # _agents/_threads/_stop_events + config IO koruması

# ── OXW-2026-SEC-001 fix: API anahtarı şifrelemesi (at-rest) ───────────────────
# api_key değerleri diske "enc:" öneki ile Fernet şifreli yazılır.
# Anahtar /etc/oxware/.ai_key (0600) dosyasında tutulur, yoksa üretilir.
# Düz metin (eski) değerler okunabilir → otomatik migrate edilir.
_AI_KEY_FILE = "/etc/oxware/.ai_key"
_ENC_PREFIX  = "enc:"

try:
    from cryptography.fernet import Fernet as _Fernet
    _CRYPTO_OK = True
except Exception:
    _CRYPTO_OK = False

def _get_fernet():
    if not _CRYPTO_OK:
        return None
    try:
        if os.path.exists(_AI_KEY_FILE):
            with open(_AI_KEY_FILE, "rb") as f:
                key = f.read().strip()
        else:
            # SECRET_KEY'den deterministik anahtar türet (yedek), ya da rastgele üret
            seed = getattr(config, "SECRET_KEY", "") or ""
            if seed:
                key = base64.urlsafe_b64encode(hashlib.sha256(seed.encode()).digest())
            else:
                key = _Fernet.generate_key()
            os.makedirs(os.path.dirname(_AI_KEY_FILE), exist_ok=True)
            with open(_AI_KEY_FILE, "wb") as f:
                f.write(key)
            os.chmod(_AI_KEY_FILE, 0o600)
        return _Fernet(key)
    except Exception as e:
        try:
            event_logger.warn(f"AI key Fernet init hatası: {e}", category="security")
        except Exception:
            pass
        return None

def _encrypt_key(plaintext: str) -> str:
    if not plaintext or plaintext.startswith(_ENC_PREFIX):
        return plaintext
    f = _get_fernet()
    if not f:
        return plaintext  # crypto yoksa düz metin (geriye dönük uyum, 0600 dosya)
    try:
        return _ENC_PREFIX + f.encrypt(plaintext.encode()).decode()
    except Exception:
        return plaintext

def _decrypt_key(value: str) -> str:
    if not value or not value.startswith(_ENC_PREFIX):
        return value  # düz metin (eski) → olduğu gibi döndür
    f = _get_fernet()
    if not f:
        return ""
    try:
        return f.decrypt(value[len(_ENC_PREFIX):].encode()).decode()
    except Exception:
        return ""

# ── Provider şablonları ───────────────────────────────────────────────────────

PROVIDERS = {
    "openrouter": {
        "base_url":       "https://openrouter.ai/api/v1",
        "chat_endpoint":  "/chat/completions",
        "default_model":  "anthropic/claude-3-haiku",
        "headers_extra":  {"HTTP-Referer": "https://oxware-hypervisor.local"},
    },
    "anthropic": {
        "base_url":       "https://api.anthropic.com/v1",
        "chat_endpoint":  "/messages",
        "default_model":  "claude-haiku-4-5-20251001",
        "api_key_header": "x-api-key",
        "use_anthropic_sdk": True,
    },
    "openai": {
        "base_url":      "https://api.openai.com/v1",
        "chat_endpoint": "/chat/completions",
        "default_model": "gpt-4o-mini",
    },
    "ollama": {
        "base_url":      "http://localhost:11434/v1",
        "chat_endpoint": "/chat/completions",
        "default_model": "llama3",
    },
    "custom": {
        "base_url":      "",
        "chat_endpoint": "/chat/completions",
        "default_model": "gpt-4o",
    },
}


# ── Yapılandırma ──────────────────────────────────────────────────────────────

def _load_ai_config() -> dict:
    """Config oku — api_key alanları çözülür (decrypt). Thread-safe."""
    with _lock:
        if not os.path.exists(AI_CONFIG_FILE):
            return {"agents": {}, "global": {}}
        try:
            with open(AI_CONFIG_FILE) as f:
                data = json.load(f)
        except Exception:
            return {"agents": {}, "global": {}}
    # api_key alanlarını çöz (in-memory plaintext)
    for agent in data.get("agents", {}).values():
        if "api_key" in agent:
            agent["api_key"] = _decrypt_key(agent.get("api_key", ""))
    return data


def _save_ai_config(data: dict):
    """Config yaz — api_key şifrelenir, atomik (tmp + os.replace). Thread-safe."""
    # Şifreleme için kopya üzerinde çalış (in-memory plaintext'i bozma)
    import copy as _copy
    out = _copy.deepcopy(data)
    for agent in out.get("agents", {}).values():
        if "api_key" in agent:
            agent["api_key"] = _encrypt_key(agent.get("api_key", ""))
    with _lock:
        os.makedirs(os.path.dirname(AI_CONFIG_FILE), exist_ok=True)
        # OXW-2026-SEC-003: atomik yazma — tmp dosyaya yaz, sonra os.replace
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(AI_CONFIG_FILE), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(out, f, indent=2)
            os.chmod(tmp, 0o600)
            os.replace(tmp, AI_CONFIG_FILE)  # atomik
        except Exception:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
            raise


def list_agents() -> list:
    cfg = _load_ai_config()
    result = []
    for agent_id, agent in cfg.get("agents", {}).items():
        result.append({
            "id":       agent_id,
            "name":     agent.get("name", agent_id),
            "provider": agent.get("provider"),
            "model":    agent.get("model"),
            "enabled":  agent.get("enabled", True),
            "interval": agent.get("interval_minutes", 5),
            "running":  agent_id in _threads and _threads[agent_id].is_alive(),
            "tasks":    agent.get("tasks", []),
        })
    return result


def add_agent(
    agent_id: str,
    name: str,
    provider: str,
    api_key: str,
    model: str = None,
    base_url: str = None,
    interval_minutes: int = 5,
    tasks: list = None,
    alert_thresholds: dict = None,
    enabled: bool = True,
) -> dict:
    cfg = _load_ai_config()

    prov = PROVIDERS.get(provider, PROVIDERS["custom"])
    agent = {
        "name":               name,
        "provider":           provider,
        "api_key":            api_key,
        "model":              model or prov["default_model"],
        "base_url":           base_url or prov["base_url"],
        "interval_minutes":   interval_minutes,
        "tasks":              tasks or ["monitor", "events", "alerts"],
        "alert_thresholds": alert_thresholds or {
            "cpu_percent":    85,
            "memory_percent": 90,
            "disk_percent":   80,
        },
        "enabled":  enabled,
        "created":  time.time(),
    }
    # OXW-2026-SEC-003: read-modify-write tek lock altında (lost-update önler)
    with _lock:
        cfg["agents"][agent_id] = agent
        _save_ai_config(cfg)

    if enabled:
        start_agent(agent_id)

    return {"id": agent_id, **agent}


def delete_agent(agent_id: str):
    stop_agent(agent_id)
    with _lock:
        cfg = _load_ai_config()
        cfg["agents"].pop(agent_id, None)
        _save_ai_config(cfg)


def update_agent(agent_id: str, updates: dict) -> dict:
    with _lock:
        cfg = _load_ai_config()
        if agent_id not in cfg["agents"]:
            raise KeyError(f"Agent bulunamadı: {agent_id}")
        cfg["agents"][agent_id].update(updates)
        _save_ai_config(cfg)
        _enabled = cfg["agents"][agent_id].get("enabled", True)
    # Yeniden başlat (lock dışında — start/stop kendi lock'unu alır)
    stop_agent(agent_id)
    if _enabled:
        start_agent(agent_id)
    return cfg["agents"][agent_id]


# ── AI API çağrıları ──────────────────────────────────────────────────────────

def _call_openrouter_openai(agent: dict, prompt: str, system_prompt: str = "") -> str:
    url = agent["base_url"].rstrip("/") + PROVIDERS.get(agent["provider"], PROVIDERS["custom"])["chat_endpoint"]
    headers = {
        "Authorization": f"Bearer {agent['api_key']}",
        "Content-Type":  "application/json",
    }
    # OpenRouter ek başlıklar
    if agent.get("provider") == "openrouter":
        headers["HTTP-Referer"] = "https://oxware-hypervisor.local"
        headers["X-Title"] = "OXware Hypervisor"

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    body = {
        "model":       agent["model"],
        "messages":    messages,
        "max_tokens":  800,
        "temperature": 0.3,
    }

    r = requests.post(url, headers=headers, json=body, timeout=30)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()


def _call_anthropic(agent: dict, prompt: str, system_prompt: str = "") -> str:
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key":         agent["api_key"],
        "anthropic-version": "2023-06-01",
        "Content-Type":      "application/json",
    }
    body = {
        "model":      agent["model"],
        "max_tokens": 800,
        "messages":   [{"role": "user", "content": prompt}],
    }
    if system_prompt:
        body["system"] = system_prompt

    r = requests.post(url, headers=headers, json=body, timeout=30)
    r.raise_for_status()
    return r.json()["content"][0]["text"].strip()


def query_agent(agent_id: str, prompt: str, system_prompt: str = "") -> str:
    """Bir agent'a doğrudan soru sor."""
    cfg = _load_ai_config()
    agent = cfg["agents"].get(agent_id)
    if not agent:
        raise KeyError(f"Agent bulunamadı: {agent_id}")

    provider = agent.get("provider", "openrouter")
    if provider == "anthropic":
        return _call_anthropic(agent, prompt, system_prompt)
    else:
        return _call_openrouter_openai(agent, prompt, system_prompt)


# ── İzleme görevi ─────────────────────────────────────────────────────────────

def _build_system_context() -> str:
    """Sistem durumunu AI için özet metin olarak hazırla."""
    try:
        stats = system_monitor.get_system_stats()
        vm_sum = system_monitor.get_vm_summary()
        host = system_monitor.get_host_info()

        return (
            f"[OXware Hypervisor Sistem Durumu]\n"
            f"Host: {host.get('hostname')} | OS: {host.get('os')}\n"
            f"CPU: %{stats['cpu']['percent']:.1f} | "
            f"RAM: %{stats['memory']['percent']:.1f} "
            f"({stats['memory']['used_mb']}/{stats['memory']['total_mb']} MB)\n"
            f"Swap: %{stats['swap']['percent']:.1f}\n"
            f"VM: {vm_sum['running']} çalışıyor / {vm_sum['total']} toplam\n"
            f"Yük: {stats['cpu']['load_avg']['1min']} (1dk) "
            f"{stats['cpu']['load_avg']['5min']} (5dk)\n"
            f"Disk R/W: {stats['disk_io']['read_mb']}/{stats['disk_io']['write_mb']} MB\n"
            f"Ağ ↓/↑: {stats['network']['bytes_recv_mb']}/{stats['network']['bytes_sent_mb']} MB\n"
            f"Zaman: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
    except Exception as e:
        return f"[Sistem bilgisi alınamadı: {e}]"


def _agent_monitor_cycle(agent_id: str, agent: dict):
    """Tek bir izleme döngüsü."""
    tasks = agent.get("tasks", ["monitor"])
    thresholds = agent.get("alert_thresholds", {})
    system_ctx = _build_system_context()

    SYSTEM_PROMPT = (
        "Sen OXware Hypervisor için bir sistem izleme yapay zekasısın. "
        "Türkçe yanıt ver. Kısa ve net ol. Teknik terimler kullan. "
        "Sorun varsa '⚠️ UYARI:' ile başla. Normal ise '✓' ile başla."
    )

    results = {}

    # Görev 1: Sistem izleme analizi
    if "monitor" in tasks:
        try:
            prompt = (
                f"Aşağıdaki hypervisor sistem durumunu analiz et. "
                f"Dikkat çekici anormal bir durum var mı? "
                f"Varsa ne yapılmalı?\n\n{system_ctx}"
            )
            analysis = query_agent(agent_id, prompt, SYSTEM_PROMPT)
            results["monitor"] = analysis

            # Kritik eşikler aşıldıysa bildir
            stats = system_monitor.get_system_stats()
            cpu  = stats["cpu"]["percent"]
            ram  = stats["memory"]["percent"]
            disk_write = stats["disk_io"]["write_mb"]

            alerts_fired = []
            if cpu  > thresholds.get("cpu_percent", 85):
                alerts_fired.append(f"CPU: %{cpu:.1f}")
            if ram  > thresholds.get("memory_percent", 90):
                alerts_fired.append(f"RAM: %{ram:.1f}")

            if alerts_fired:
                notifications.send_alert(
                    f"[AI Agent: {agent.get('name')}] Kaynak uyarısı: {', '.join(alerts_fired)}\nAI Analizi: {analysis[:200]}",
                    level="WARNING",
                    category="ai",
                    details={"agent": agent_id, "analysis": analysis[:500]},
                )

        except Exception as e:
            results["monitor_error"] = str(e)

    # Görev 2: Olay özeti
    if "events" in tasks:
        try:
            import event_logger as ev
            recent = ev.get_events(limit=20, since=time.time() - 3600)
            if recent:
                events_text = "\n".join(
                    f"[{e['level']}] {e['category']}: {e['message']}"
                    for e in recent[:15]
                )
                prompt = (
                    f"Son 1 saatteki {len(recent)} olayı incele ve özetle.\n\n"
                    f"{events_text}\n\nBu olaylar hakkında kısa değerlendirme yap."
                )
                summary = query_agent(agent_id, prompt, SYSTEM_PROMPT)
                results["events_summary"] = summary
        except Exception as e:
            results["events_error"] = str(e)

    # Sonucu kaydet
    log_entry = {
        "timestamp":  time.time(),
        "datetime":   datetime.now().isoformat(),
        "agent_id":   agent_id,
        "agent_name": agent.get("name"),
        "results":    results,
    }
    with open(AGENT_LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

    event_logger.info(
        f"AI Agent '{agent.get('name')}' izleme tamamlandı",
        category="ai",
        details={"agent_id": agent_id, "tasks": list(results.keys())},
    )

    return results


def _agent_thread(agent_id: str, stop_event: threading.Event):
    """Agent thread döngüsü — threading.Event ile temiz durdurma (OXW-2026-SEC-003)."""
    while not stop_event.is_set():
        cfg = _load_ai_config()
        agent = cfg["agents"].get(agent_id)
        if not agent or not agent.get("enabled", True):
            break

        try:
            _agent_monitor_cycle(agent_id, agent)
        except Exception as e:
            event_logger.error(
                f"AI Agent '{agent_id}' hata: {e}",
                category="ai",
            )

        interval = agent.get("interval_minutes", 5) * 60
        # Event.wait ile bekle — stop_event set olunca anında uyanır (sleep yerine)
        if stop_event.wait(timeout=interval):
            break


def start_agent(agent_id: str):
    global _running
    with _lock:
        _running = True
        existing = _threads.get(agent_id)
        if existing and existing.is_alive():
            return  # Zaten çalışıyor
        ev = threading.Event()
        _stop_events[agent_id] = ev
        t = threading.Thread(target=_agent_thread, args=(agent_id, ev), daemon=True, name=f"ai-agent-{agent_id}")
        t.start()
        _threads[agent_id] = t
    event_logger.info(f"AI Agent başlatıldı: {agent_id}", category="ai")


def stop_agent(agent_id: str):
    """Agent thread'ini Event ile temiz durdur."""
    with _lock:
        ev = _stop_events.pop(agent_id, None)
        if ev:
            ev.set()
        _threads.pop(agent_id, None)
    event_logger.info(f"AI Agent durduruldu: {agent_id}", category="ai")


def start_all_agents():
    """Servis başlangıcında tüm aktif agentları başlat."""
    global _running
    _running = True
    cfg = _load_ai_config()
    for agent_id, agent in cfg.get("agents", {}).items():
        if agent.get("enabled", True):
            start_agent(agent_id)


def stop_all_agents():
    global _running
    with _lock:
        _running = False
        for ev in _stop_events.values():
            ev.set()
        _stop_events.clear()
        _threads.clear()


def get_agent_logs(agent_id: str = None, limit: int = 50) -> list:
    logs = []
    if not os.path.exists(AGENT_LOG_FILE):
        return logs
    with open(AGENT_LOG_FILE) as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                if agent_id and entry.get("agent_id") != agent_id:
                    continue
                logs.append(entry)
            except Exception:
                pass
    return sorted(logs, key=lambda x: x.get("timestamp", 0), reverse=True)[:limit]


# ── Çok turlu sohbet + görsel (vision) ─────────────────────────────────────────
# query_agent tek-tur/metin. Sohbet penceresi için çok turlu + görsel desteği.
# Görseller diske yazılmaz; yalnız bu istekte modele iletilir (sunucu hafif kalır).

def _split_data_url(s: str):
    """data:image/png;base64,XXXX → (media_type, base64). Düz base64 → png varsay."""
    if not s:
        return "image/png", ""
    if s.startswith("data:"):
        try:
            head, b64 = s.split(",", 1)
            mt = head[5:].split(";")[0] or "image/png"
            return mt, b64
        except Exception:
            return "image/png", ""
    return "image/png", s


def _call_anthropic_chat(agent: dict, messages: list, system_prompt: str,
                         max_tokens: int) -> str:
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key":         agent["api_key"],
        "anthropic-version": "2023-06-01",
        "Content-Type":      "application/json",
    }
    out = []
    for m in messages:
        imgs = m.get("images") or []
        if imgs:
            blocks = []
            for img in imgs:
                mt, data = _split_data_url(img)
                if data:
                    blocks.append({"type": "image", "source": {
                        "type": "base64", "media_type": mt, "data": data}})
            if m.get("content"):
                blocks.append({"type": "text", "text": m["content"]})
            out.append({"role": m["role"], "content": blocks or m.get("content", "")})
        else:
            out.append({"role": m["role"], "content": m.get("content", "")})
    body = {"model": agent["model"], "max_tokens": max_tokens, "messages": out}
    if system_prompt:
        body["system"] = system_prompt
    r = requests.post(url, headers=headers, json=body, timeout=60)
    r.raise_for_status()
    return r.json()["content"][0]["text"].strip()


def _call_openai_chat(agent: dict, messages: list, system_prompt: str,
                      max_tokens: int) -> str:
    url = agent["base_url"].rstrip("/") + PROVIDERS.get(
        agent["provider"], PROVIDERS["custom"])["chat_endpoint"]
    headers = {
        "Authorization": f"Bearer {agent['api_key']}",
        "Content-Type":  "application/json",
    }
    if agent.get("provider") == "openrouter":
        headers["HTTP-Referer"] = "https://oxware-hypervisor.local"
        headers["X-Title"] = "OXware Hypervisor"
    out = []
    if system_prompt:
        out.append({"role": "system", "content": system_prompt})
    for m in messages:
        imgs = m.get("images") or []
        if imgs:
            parts = []
            if m.get("content"):
                parts.append({"type": "text", "text": m["content"]})
            for img in imgs:
                u = img if img.startswith("data:") else "data:image/png;base64," + img
                parts.append({"type": "image_url", "image_url": {"url": u}})
            out.append({"role": m["role"], "content": parts})
        else:
            out.append({"role": m["role"], "content": m.get("content", "")})
    body = {"model": agent["model"], "messages": out,
            "max_tokens": max_tokens, "temperature": 0.4}
    r = requests.post(url, headers=headers, json=body, timeout=60)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()


def query_agent_chat(agent_id: str, messages: list, system_prompt: str = "",
                     max_tokens: int = 1024) -> str:
    """Çok turlu sohbet. messages: [{role, content, images?}]. Görsel destekli."""
    cfg = _load_ai_config()
    agent = cfg["agents"].get(agent_id)
    if not agent:
        raise KeyError(f"Agent bulunamadı: {agent_id}")
    if agent.get("provider") == "anthropic":
        return _call_anthropic_chat(agent, messages, system_prompt, max_tokens)
    return _call_openai_chat(agent, messages, system_prompt, max_tokens)


def live_system_context() -> str:
    """Sohbet için canlı sistem özeti (system prompt'a gömülür)."""
    return _build_system_context()


# ── Araç kullanımı (tool use / function calling) ────────────────────────────
# Asistanın gerçekten işlem yapabilmesi için: model bir araç çağırır, biz
# sunucuda çalıştırır, sonucu geri veririz; model nihai yanıtı üretene kadar
# döngü sürer. Hem Anthropic hem OpenAI-uyumlu sağlayıcılar desteklenir.

def _anthropic_msg(m: dict) -> dict:
    imgs = m.get("images") or []
    if imgs:
        blocks = []
        for img in imgs:
            mt, data = _split_data_url(img)
            if data:
                blocks.append({"type": "image", "source": {
                    "type": "base64", "media_type": mt, "data": data}})
        if m.get("content"):
            blocks.append({"type": "text", "text": m["content"]})
        return {"role": m["role"], "content": blocks or m.get("content", "")}
    return {"role": m["role"], "content": m.get("content", "")}


def _call_anthropic_tools(agent, messages, system_prompt, tools, executor,
                          max_rounds, max_tokens):
    import json as _json
    url = "https://api.anthropic.com/v1/messages"
    headers = {"x-api-key": agent["api_key"],
               "anthropic-version": "2023-06-01",
               "Content-Type": "application/json"}
    a_tools = [{"name": t["name"], "description": t["description"],
                "input_schema": t["parameters"]} for t in tools]
    convo = [_anthropic_msg(m) for m in messages]
    used = []
    for _ in range(max_rounds):
        body = {"model": agent["model"], "max_tokens": max_tokens,
                "messages": convo, "tools": a_tools}
        if system_prompt:
            body["system"] = system_prompt
        r = requests.post(url, headers=headers, json=body, timeout=90)
        r.raise_for_status()
        data = r.json()
        blocks = data.get("content", [])
        if data.get("stop_reason") == "tool_use":
            convo.append({"role": "assistant", "content": blocks})
            results = []
            for b in blocks:
                if b.get("type") == "tool_use":
                    used.append(b.get("name"))
                    res = executor(b.get("name"), b.get("input") or {})
                    results.append({"type": "tool_result",
                                    "tool_use_id": b.get("id"),
                                    "content": _json.dumps(res, ensure_ascii=False)})
            convo.append({"role": "user", "content": results})
            continue
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        return {"text": text.strip(), "tools_used": used}
    return {"text": "(Araç döngüsü sınırına ulaşıldı.)", "tools_used": used}


def _call_openai_tools(agent, messages, system_prompt, tools, executor,
                       max_rounds, max_tokens):
    import json as _json
    url = agent["base_url"].rstrip("/") + PROVIDERS.get(
        agent["provider"], PROVIDERS["custom"])["chat_endpoint"]
    headers = {"Authorization": f"Bearer {agent['api_key']}",
               "Content-Type": "application/json"}
    if agent.get("provider") == "openrouter":
        headers["HTTP-Referer"] = "https://oxware-hypervisor.local"
        headers["X-Title"] = "OXware Hypervisor"
    o_tools = [{"type": "function", "function": {
        "name": t["name"], "description": t["description"],
        "parameters": t["parameters"]}} for t in tools]
    convo = []
    if system_prompt:
        convo.append({"role": "system", "content": system_prompt})
    for m in messages:
        imgs = m.get("images") or []
        if imgs:
            parts = []
            if m.get("content"):
                parts.append({"type": "text", "text": m["content"]})
            for img in imgs:
                u = img if img.startswith("data:") else "data:image/png;base64," + img
                parts.append({"type": "image_url", "image_url": {"url": u}})
            convo.append({"role": m["role"], "content": parts})
        else:
            convo.append({"role": m["role"], "content": m.get("content", "")})
    used = []
    for _ in range(max_rounds):
        body = {"model": agent["model"], "messages": convo,
                "tools": o_tools, "max_tokens": max_tokens, "temperature": 0.3}
        r = requests.post(url, headers=headers, json=body, timeout=90)
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        calls = msg.get("tool_calls") or []
        if calls:
            convo.append(msg)
            for c in calls:
                fn = c.get("function", {})
                used.append(fn.get("name"))
                try:
                    args = _json.loads(fn.get("arguments") or "{}")
                except Exception:
                    args = {}
                res = executor(fn.get("name"), args)
                convo.append({"role": "tool", "tool_call_id": c.get("id"),
                              "content": _json.dumps(res, ensure_ascii=False)})
            continue
        return {"text": (msg.get("content") or "").strip(), "tools_used": used}
    return {"text": "(Araç döngüsü sınırına ulaşıldı.)", "tools_used": used}


def query_agent_tools(agent_id: str, messages: list, system_prompt: str,
                      tools: list, executor, max_rounds: int = 6,
                      max_tokens: int = 1500) -> dict:
    """Araç kullanımı ile sohbet. Dönüş: {text, tools_used}."""
    cfg = _load_ai_config()
    agent = cfg["agents"].get(agent_id)
    if not agent:
        raise KeyError(f"Agent bulunamadı: {agent_id}")
    if agent.get("provider") == "anthropic":
        return _call_anthropic_tools(agent, messages, system_prompt, tools,
                                     executor, max_rounds, max_tokens)
    return _call_openai_tools(agent, messages, system_prompt, tools,
                              executor, max_rounds, max_tokens)


def ask_agent_about_vm(agent_id: str, vm_id: str, question: str) -> str:
    """Belirli bir VM hakkında AI'ya soru sor."""
    try:
        import vm_manager
        vm = vm_manager.get_vm(vm_id)
        stats = vm_manager.get_vm_stats(vm_id)
        ctx = (
            f"VM Bilgisi:\n"
            f"Ad: {vm['name']}\n"
            f"Durum: {vm['state']}\n"
            f"CPU: {vm['vcpus']} vCPU\n"
            f"Bellek: {vm['memory_mb']} MB\n"
            f"Diskler: {', '.join(d['device'] for d in vm['disks'])}\n"
            f"İstatistikler: {json.dumps(stats, ensure_ascii=False, indent=2)}\n\n"
            f"Soru: {question}"
        )
    except Exception as e:
        ctx = f"VM bilgisi alınamadı ({e})\nSoru: {question}"

    return query_agent(agent_id, ctx)
