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
import threading
import requests
from datetime import datetime
from typing import Optional
from pathlib import Path
import config
import event_logger
import notifications
import system_monitor

AI_CONFIG_FILE  = os.environ.get("OXWARE_AI_CONFIG", os.environ.get("ADAOS_AI_CONFIG", "/etc/oxware/ai_agents.conf"))
AGENT_LOG_FILE  = os.path.join(config.LOG_DIR, "ai_agent.jsonl")
_agents: dict   = {}
_threads: dict  = {}
_running: bool  = False

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
    if not os.path.exists(AI_CONFIG_FILE):
        return {"agents": {}, "global": {}}
    try:
        with open(AI_CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {"agents": {}, "global": {}}


def _save_ai_config(data: dict):
    os.makedirs(os.path.dirname(AI_CONFIG_FILE), exist_ok=True)
    with open(AI_CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(AI_CONFIG_FILE, 0o600)


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
    cfg["agents"][agent_id] = agent
    _save_ai_config(cfg)

    if enabled:
        start_agent(agent_id)

    return {"id": agent_id, **agent}


def delete_agent(agent_id: str):
    stop_agent(agent_id)
    cfg = _load_ai_config()
    cfg["agents"].pop(agent_id, None)
    _save_ai_config(cfg)


def update_agent(agent_id: str, updates: dict) -> dict:
    cfg = _load_ai_config()
    if agent_id not in cfg["agents"]:
        raise KeyError(f"Agent bulunamadı: {agent_id}")
    cfg["agents"][agent_id].update(updates)
    _save_ai_config(cfg)
    # Yeniden başlat
    stop_agent(agent_id)
    if cfg["agents"][agent_id].get("enabled", True):
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


def _agent_thread(agent_id: str):
    """Agent thread döngüsü."""
    while _running:
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
        # interval süre boyunca _running kontrolü yaparak bekle
        end = time.time() + interval
        while _running and time.time() < end:
            time.sleep(5)


def start_agent(agent_id: str):
    global _running
    _running = True
    if agent_id in _threads and _threads[agent_id].is_alive():
        return  # Zaten çalışıyor
    t = threading.Thread(target=_agent_thread, args=(agent_id,), daemon=True, name=f"ai-agent-{agent_id}")
    t.start()
    _threads[agent_id] = t
    event_logger.info(f"AI Agent başlatıldı: {agent_id}", category="ai")


def stop_agent(agent_id: str):
    # Thread kendiliğinden durur (_running False veya agent disabled olduğunda)
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
    _running = False


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
