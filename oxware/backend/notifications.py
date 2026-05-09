"""
AdaOS Bildirim Sistemi
─────────────────────
Telegram Bot, Discord Webhook ve E-posta üzerinden uyarı gönderir.
Yapılandırma: /etc/oxware/notifications.conf
"""

import os
import json
import time
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from datetime import datetime
from pathlib import Path

try:
    import logging as _logging
    log = _logging.getLogger("oxware.notifications")
except Exception:
    log = None

NOTIF_CONFIG     = os.environ.get("OXWARE_NOTIF_CONFIG", os.environ.get("ADAOS_NOTIF_CONFIG", "/etc/oxware/notifications.conf"))
NOTIF_QUEUE_FILE = "/var/lib/oxware/notif_queue.json"
EMAIL_CONFIG     = "/etc/oxware/email_config.json"

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
    email_cfg = get_email_config()
    return {
        "telegram_enabled":    bool(cfg.get("telegram_token") and cfg.get("telegram_chat_id")),
        "discord_enabled":     bool(cfg.get("discord_webhook")),
        "email_enabled":       email_cfg.get("enabled", False),
        "min_level":           cfg.get("min_level", "WARNING"),
        "hostname_tag":        cfg.get("hostname_tag", ""),
        "telegram_chat_id":    cfg.get("telegram_chat_id", ""),
        "discord_webhook_set": bool(cfg.get("discord_webhook")),
    }


# ── Email ─────────────────────────────────────────────────────────────────────

def get_email_config() -> dict:
    """Email yapılandırmasını oku."""
    try:
        if os.path.exists(EMAIL_CONFIG):
            with open(EMAIL_CONFIG) as f:
                cfg = json.load(f)
            return {
                "smtp_host":  cfg.get("smtp_host", ""),
                "smtp_port":  cfg.get("smtp_port", 587),
                "username":   cfg.get("username", ""),
                "password":   "***" if cfg.get("password") else "",
                "from_addr":  cfg.get("from_addr", ""),
                "use_tls":    cfg.get("use_tls", True),
                "enabled":    cfg.get("enabled", False),
            }
    except Exception as e:
        if log:
            log.warning("Email config yükleme hatası: %s", e)
    return {"smtp_host": "", "smtp_port": 587, "username": "", "password": "",
            "from_addr": "", "use_tls": True, "enabled": False}


def _load_full_email_config() -> dict:
    """Şifre dahil tam email config."""
    try:
        if os.path.exists(EMAIL_CONFIG):
            with open(EMAIL_CONFIG) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_email_config(
    smtp_host: str,
    smtp_port: int,
    username: str,
    password: str,
    from_addr: str,
    use_tls: bool = True,
) -> dict:
    """Email SMTP yapılandırmasını kaydet."""
    try:
        cfg = {
            "smtp_host":  smtp_host,
            "smtp_port":  int(smtp_port),
            "username":   username,
            "password":   password,
            "from_addr":  from_addr,
            "use_tls":    bool(use_tls),
            "enabled":    True,
            "updated_at": datetime.now().isoformat(),
        }
        os.makedirs(os.path.dirname(EMAIL_CONFIG), exist_ok=True)
        with open(EMAIL_CONFIG, "w") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        try:
            os.chmod(EMAIL_CONFIG, 0o600)
        except Exception:
            pass
        return {"success": True, "smtp_host": smtp_host, "from_addr": from_addr}
    except Exception as e:
        if log:
            log.error("save_email_config hatası: %s", e)
        return {"success": False, "error": str(e)}


def send_email(
    to: str,
    subject: str,
    body: str,
    html: bool = False,
) -> bool:
    """E-posta gönder. Başarı durumunda True döndürür."""
    try:
        cfg = _load_full_email_config()
        if not cfg:
            if log:
                log.warning("Email yapılandırması bulunamadı.")
            return False

        smtp_host = cfg.get("smtp_host", "")
        smtp_port = int(cfg.get("smtp_port", 587))
        username  = cfg.get("username", "")
        password  = cfg.get("password", "")
        from_addr = cfg.get("from_addr", username)
        use_tls   = cfg.get("use_tls", True)

        if not smtp_host:
            if log:
                log.warning("SMTP host tanımlı değil.")
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = from_addr
        msg["To"]      = to

        content_type = "html" if html else "plain"
        msg.attach(MIMEText(body, content_type, "utf-8"))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()
            if username and password:
                server.login(username, password)
            server.sendmail(from_addr, [to], msg.as_string())

        if log:
            log.info("Email gönderildi: %s → %s", subject, to)
        return True

    except Exception as e:
        if log:
            log.error("send_email hatası: %s", e)
        print(f"[notifications] Email hatası: {e}")
        return False


def test_email(to: str) -> dict:
    """Test e-postası gönder."""
    hostname = _get_hostname()
    subject = f"OXware Test E-postası — {hostname}"
    body = (
        f"Bu bir OXware Hypervisor test e-postasıdır.\n\n"
        f"Host: {hostname}\n"
        f"Tarih: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n\n"
        "Email bildirimleri başarıyla yapılandırılmıştır."
    )
    success = send_email(to=to, subject=subject, body=body)
    return {
        "success": success,
        "to": to,
        "message": "Test e-postası gönderildi." if success else "Gönderim başarısız.",
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
    import urllib.request, urllib.error
    payload = json.dumps({
        "username": "OXware Hypervisor",
        "avatar_url": "https://raw.githubusercontent.com/ShinnAsukha/oxware-hypervisor/main/oxware/frontend/static/img/sadeceikon.png",
        "embeds": [{
            "title": title,
            "description": description,
            "color": color,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "footer": {"text": "OXware Hypervisor"},
        }]
    }).encode("utf-8")

    try:
        # requests ile dene
        r = requests.post(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if r.status_code in (200, 204):
            return True
        log.warning("Discord webhook yanıtı: %s %s", r.status_code, r.text[:200])
        return False
    except Exception:
        pass

    # urllib fallback
    try:
        req = urllib.request.Request(webhook_url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 204)
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
    channels: list = None,
) -> dict:
    """Aktif kanallara uyarı gönder.

    channels: ["telegram", "discord", "email"] — None ise tüm aktif kanallara gönderir.
    """
    cfg = _load_config()
    if not cfg:
        return {"sent": False, "reason": "Bildirim yapılandırması yok"}

    min_level = cfg.get("min_level", "WARNING").upper()
    if LEVEL_ORDER.index(level.upper()) < LEVEL_ORDER.index(min_level):
        return {"sent": False, "reason": f"Seviye {level} < minimum {min_level}"}

    # Hangi kanallar aktif olacak
    use_all = channels is None
    use_telegram = use_all or "telegram" in channels
    use_discord  = use_all or "discord" in channels
    use_email    = use_all or "email" in channels

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
    if use_telegram:
        tg_token = cfg.get("telegram_token")
        tg_chat  = cfg.get("telegram_chat_id")
        if tg_token and tg_chat:
            results["telegram"] = _send_telegram(tg_token, tg_chat, tg_text)

    # Discord
    if use_discord:
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

    # Email
    if use_email:
        email_cfg = _load_full_email_config()
        if email_cfg and email_cfg.get("enabled") and email_cfg.get("smtp_host"):
            to_addr = email_cfg.get("username") or email_cfg.get("from_addr", "")
            if to_addr:
                subject = f"[OXware] {emoji} {level.upper()} — {category}"
                # Düz metin gövde
                body_lines = [
                    f"OXware Hypervisor Uyarısı",
                    f"",
                    f"Host:      {hostname}",
                    f"Kategori:  {category}",
                    f"Seviye:    {level.upper()}",
                    f"Mesaj:     {message}",
                ]
                if vm_id:
                    body_lines.append(f"VM:        {vm_id}")
                if details:
                    body_lines.append("")
                    for k, v in list(details.items())[:5]:
                        body_lines.append(f"  {k}: {v}")
                body_lines += ["", f"Tarih: {ts}"]
                results["email"] = send_email(
                    to=to_addr,
                    subject=subject,
                    body="\n".join(body_lines),
                )

    sent_count = sum(1 for v in results.values() if v)
    return {
        "sent": sent_count > 0,
        "results": results,
        "channels": sent_count,
    }


def test_notification(channel: str = None) -> dict:
    """Test bildirimi gönder — seviye kısıtlamasını bypass eder."""
    cfg = _load_config()
    results = {}
    hostname = cfg.get("hostname_tag") or _get_hostname()

    if channel == "telegram" or channel is None:
        token = cfg.get("telegram_token")
        chat = cfg.get("telegram_chat_id")
        if token and chat:
            msg = (f"✅ <b>OXware Test Bildirimi</b>\n"
                   f"🖥️ Host: {hostname}\n"
                   f"🕐 {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n"
                   f"Telegram bildirimleri çalışıyor!")
            results["telegram"] = _send_telegram(token, chat, msg)

    if channel == "discord" or channel is None:
        webhook = cfg.get("discord_webhook")
        if webhook:
            results["discord"] = _send_discord(
                webhook,
                "✅ OXware Test Bildirimi",
                f"**Host:** `{hostname}`\n**Zaman:** {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\nDiscord bildirimleri çalışıyor!",
                0x00D4FF
            )

    return {"sent": bool(results), "results": results}


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
