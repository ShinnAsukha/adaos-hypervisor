"""
AdaOS Bildirim Sistemi
─────────────────────
Telegram Bot ve Discord Webhook üzerinden uyarı gönderir.
Yapılandırma: /etc/adaos/notifications.conf
"""

import os
import json
import time
import threading
import requests
from datetime import datetime
from pathlib import Path

NOTIF_CONFIG = os.environ.get("OXWARE_NOTIF_CONFIG", os.environ.get("ADAOS_NOTIF_CONFIG", "/etc/oxware/notifications.conf"))
NOTIF_QUEUE_FILE = "/var/lib/oxware/notif_queue.json"

_queue_lock = threading.Lock()
_config_cache = {}
_config_mtime = 0


def _load_config() -> dict:
    global _config_cache, _config_mtime

    if not os.path.exists(NOTIF_CONFIG):
        return {}

    mtime = os.path.getmtime(NOTIF_CONFIG)
    if mtime == _config_mtime:
        return _config_cache

    cfg = {}
    with open(NOTIF_CONFIG) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip().lower()] = v.strip()

    _config_cache = cfg
    _config_mtime = mtime
    return cfg


def save_notif_config(
    telegram_token: str = None,
    telegram_chat_id: str = None,
    discord_webhook: str = None,
    min_level: str = "WARNING",
    hostname_tag: str = None,
):
    """Bildirim yapılandırmasını kaydet."""
    os.makedirs(os.path.dirname(NOTIF_CONFIG), exist_ok=True)

    existing = _load_config()
    updates = {}
    if telegram_token:    updates["telegram_token"]    = telegram_token
    if telegram_chat_id:  updates["telegram_chat_id"]  = telegram_chat_id
    if discord_webhook:   updates["discord_webhook"]   = discord_webhook
    if min_level:         updates["min_level"]          = min_level
    if hostname_tag:      updates["hostname_tag"]       = hostname_tag

    merged = {**existing, **updates}

    lines = [
        "# AdaOS Bildirim Yapılandırması",
        "# Bu dosyayı düzenleyerek bildirim ayarlarını değiştirin",
        "",
    ]
    for k, v in merged.items():
        lines.append(f"{k.upper()} = {v}")

    Path(NOTIF_CONFIG).write_text("\n".join(lines) + "\n")
    os.chmod(NOTIF_CONFIG, 0o600)
    global _config_mtime
    _config_mtime = 0  # Cache'i geçersiz kıl


def get_notif_config() -> dict:
    cfg = _load_config()
    return {
        "telegram_enabled":   bool(cfg.get("telegram_token") and cfg.get("telegram_chat_id")),
        "discord_enabled":    bool(cfg.get("discord_webhook")),
        "min_level":          cfg.get("min_level", "WARNING"),
        "hostname_tag":       cfg.get("hostname_tag", ""),
        "telegram_chat_id":   cfg.get("telegram_chat_id", ""),
        "discord_webhook_set": bool(cfg.get("discord_webhook")),
    }


# ── Telegram ─────────────────────────────────────────────────────────────────

def _send_telegram(token: str, chat_id: str, text: str) -> bool:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        r = requests.post(url, json={
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }, timeout=10)
        return r.status_code == 200
    except Exception as e:
        print(f"[notifications] Telegram hatası: {e}")
        return False


# ── Discord ───────────────────────────────────────────────────────────────────

def _send_discord(webhook_url: str, title: str, description: str, color: int = 0xFF0000) -> bool:
    try:
        r = requests.post(webhook_url, json={
            "embeds": [{
                "title": title,
                "description": description,
                "color": color,
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {"text": "OXware Hypervisor"},
            }]
        }, timeout=10)
        return r.status_code in (200, 204)
    except Exception as e:
        print(f"[notifications] Discord hatası: {e}")
        return False


# ── Ana gönderici ─────────────────────────────────────────────────────────────

LEVEL_EMOJI = {
    "DEBUG":    "🔍",
    "INFO":     "ℹ️",
    "WARNING":  "⚠️",
    "ERROR":    "🔴",
    "CRITICAL": "🚨",
}

LEVEL_COLORS = {
    "DEBUG":    0x808080,
    "INFO":     0x00D4FF,
    "WARNING":  0xFFAA00,
    "ERROR":    0xFF4444,
    "CRITICAL": 0xFF0000,
}

LEVEL_ORDER = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def send_alert(
    message: str,
    level: str = "WARNING",
    category: str = "system",
    details: dict = None,
    vm_id: str = None,
) -> dict:
    """Tüm aktif kanallara uyarı gönder."""
    cfg = _load_config()
    if not cfg:
        return {"sent": False, "reason": "Bildirim yapılandırması yok"}

    min_level = cfg.get("min_level", "WARNING").upper()
    if LEVEL_ORDER.index(level.upper()) < LEVEL_ORDER.index(min_level):
        return {"sent": False, "reason": f"Seviye {level} < minimum {min_level}"}

    hostname = cfg.get("hostname_tag") or _get_hostname()
    emoji = LEVEL_EMOJI.get(level.upper(), "⚡")
    ts = datetime.now().strftime("%d.%m.%Y %H:%M:%S")

    # Telegram mesajı
    tg_text = (
        f"{emoji} <b>OXware Hypervisor Uyarısı</b>\n"
        f"─────────────────────\n"
        f"🖥️ <b>Host:</b> {hostname}\n"
        f"📂 <b>Kategori:</b> {category}\n"
        f"⚡ <b>Seviye:</b> {level.upper()}\n"
        f"📝 <b>Mesaj:</b> {message}\n"
    )
    if vm_id:
        tg_text += f"🔑 <b>VM:</b> <code>{vm_id[:12]}</code>\n"
    if details:
        for k, v in list(details.items())[:5]:
            tg_text += f"  • {k}: {v}\n"
    tg_text += f"\n🕐 {ts}"

    results = {}

    # Telegram
    tg_token = cfg.get("telegram_token")
    tg_chat  = cfg.get("telegram_chat_id")
    if tg_token and tg_chat:
        results["telegram"] = _send_telegram(tg_token, tg_chat, tg_text)

    # Discord
    dc_webhook = cfg.get("discord_webhook")
    if dc_webhook:
        dc_desc = (
            f"**Host:** `{hostname}`\n"
            f"**Kategori:** {category}\n"
            f"**Mesaj:** {message}\n"
        )
        if vm_id:
            dc_desc += f"**VM:** `{vm_id[:12]}`\n"
        if details:
            for k, v in list(details.items())[:5]:
                dc_desc += f"**{k}:** {v}\n"
        dc_desc += f"\n{ts}"
        results["discord"] = _send_discord(
            dc_webhook,
            f"{emoji} OXware: {level.upper()} — {category}",
            dc_desc,
            LEVEL_COLORS.get(level.upper(), 0xFF0000),
        )

    sent_count = sum(1 for v in results.values() if v)
    return {
        "sent": sent_count > 0,
        "results": results,
        "channels": sent_count,
    }


def test_notification() -> dict:
    """Test bildirimi gönder."""
    return send_alert(
        message="Bu bir test bildirimidir. OXware bildirim sistemi çalışıyor.",
        level="INFO",
        category="system",
        details={"test": True, "timestamp": datetime.now().isoformat()},
    )


def _get_hostname() -> str:
    try:
        import socket
        return socket.gethostname()
    except Exception:
        return "oxware-hypervisor"


# ── Otomatik uyarı gönderme ───────────────────────────────────────────────────

def notify_vm_state_change(vm_name: str, vm_id: str, old_state: str, new_state: str):
    """VM durum değişikliğinde bildirim."""
    level = "ERROR" if new_state in ("crashed", "shutdown") else "INFO"
    send_alert(
        message=f"VM '{vm_name}' durumu değişti: {old_state} → {new_state}",
        level=level,
        category="vm",
        vm_id=vm_id,
        details={"vm_name": vm_name, "old_state": old_state, "new_state": new_state},
    )


def notify_resource_alert(resource: str, value: float, threshold: float):
    """Kaynak kullanımı uyarısı."""
    level = "CRITICAL" if value > 95 else "WARNING"
    send_alert(
        message=f"{resource} kullanımı yüksek: %{value:.1f} (eşik: %{threshold:.0f})",
        level=level,
        category="system",
        details={"resource": resource, "value": f"{value:.1f}%", "threshold": f"{threshold:.0f}%"},
    )


def notify_provision_complete(vm_name: str, vm_id: str, ip: str, password: str):
    """Yeni VM kurulumu tamamlandı bildirimi."""
    send_alert(
        message=f"Yeni VM hazır: {vm_name}",
        level="INFO",
        category="provision",
        vm_id=vm_id,
        details={"vm": vm_name, "ip": ip, "password": "***gizli***"},
    )
