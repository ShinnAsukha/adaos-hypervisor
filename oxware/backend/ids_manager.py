"""
OXware IDS Manager
──────────────────
Suricata tabanlı IDS/IPS yönetimi.
Suricata kurulu değilse: get_status {"available": False} döndürür.
"""

import json
import logging
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timedelta

log = logging.getLogger("oxware.ids")

SURICATA_CONF = "/etc/suricata/suricata.yaml"
RULES_DIR     = "/var/lib/suricata/rules"
EVE_LOG       = "/var/log/suricata/eve.json"
IDS_CONFIG    = "/var/lib/oxware/ids_config.json"
CUSTOM_RULES  = os.path.join(RULES_DIR, "custom.rules")

_lock = threading.Lock()


# ── Yardımcı ──────────────────────────────────────────────────────────────────

def _ensure_dir(path: str):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass


def _run(*cmd, timeout: int = 30) -> tuple:
    """subprocess.run. (stdout, stderr, returncode) döndür."""
    try:
        r = subprocess.run(
            list(cmd),
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except FileNotFoundError:
        return "", f"Komut bulunamadı: {cmd[0]}", 127
    except Exception as e:
        return "", str(e), -1


def _systemctl(action: str, service: str = "suricata") -> tuple:
    return _run("systemctl", action, service, timeout=30)


def is_available() -> bool:
    """Suricata kurulu mu?"""
    try:
        _, _, rc = _run("suricata", "--version")
        return rc == 0
    except Exception:
        return False


def _get_version() -> str:
    try:
        stdout, _, rc = _run("suricata", "--version")
        if rc == 0 and stdout:
            return stdout.splitlines()[0].strip()
    except Exception:
        pass
    return "unknown"


def _count_rules() -> int:
    """Kural dosyalarındaki toplam kural sayısını say."""
    try:
        total = 0
        if os.path.isdir(RULES_DIR):
            for fname in os.listdir(RULES_DIR):
                if fname.endswith(".rules"):
                    fpath = os.path.join(RULES_DIR, fname)
                    try:
                        with open(fpath) as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith("#"):
                                    total += 1
                    except Exception:
                        pass
        return total
    except Exception:
        return 0


def _is_active() -> bool:
    """suricata servis aktif mi?"""
    try:
        stdout, _, rc = _run("systemctl", "is-active", "suricata")
        return stdout.strip() == "active"
    except Exception:
        return False


# ── Durum ve Config ───────────────────────────────────────────────────────────

def get_status() -> dict:
    """IDS genel durumunu döndür."""
    try:
        avail = is_available()
        if not avail:
            return {"available": False}

        cfg   = get_config()
        today = datetime.now().strftime("%Y-%m-%dT")
        alerts_today = 0

        if os.path.exists(EVE_LOG):
            try:
                with open(EVE_LOG) as f:
                    for line in f:
                        try:
                            entry = json.loads(line)
                            if (entry.get("event_type") == "alert"
                                    and entry.get("timestamp", "").startswith(today)):
                                alerts_today += 1
                        except Exception:
                            pass
            except Exception:
                pass

        return {
            "available": True,
            "active": _is_active(),
            "version": _get_version(),
            "rules_count": _count_rules(),
            "alerts_today": alerts_today,
            "interface": cfg.get("interface", "any"),
        }
    except Exception as e:
        log.error("get_status hatası: %s", e)
        return {"available": False, "error": str(e)}


def get_config() -> dict:
    """IDS yapılandırmasını oku."""
    try:
        if os.path.exists(IDS_CONFIG):
            with open(IDS_CONFIG) as f:
                cfg = json.load(f)
            cfg.setdefault("interface", "any")
            cfg.setdefault("home_net", "192.168.0.0/16")
            cfg.setdefault("enabled", True)
            return cfg
    except Exception as e:
        log.warning("IDS config yükleme hatası: %s", e)
    return {"interface": "any", "home_net": "192.168.0.0/16", "enabled": True}


def update_config(
    interface: str = None,
    home_net: str = None,
    enabled: bool = None,
) -> dict:
    """IDS yapılandırmasını güncelle."""
    try:
        cfg = get_config()
        if interface is not None:
            cfg["interface"] = interface
        if home_net is not None:
            cfg["home_net"] = home_net
        if enabled is not None:
            cfg["enabled"] = bool(enabled)
        cfg["updated_at"] = datetime.now().isoformat()
        _ensure_dir(IDS_CONFIG)
        with _lock:
            with open(IDS_CONFIG, "w") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
        return cfg
    except Exception as e:
        log.error("update_config hatası: %s", e)
        return {"error": str(e)}


# ── Servis Kontrolü ───────────────────────────────────────────────────────────

def start() -> dict:
    """Suricata'yı başlat."""
    try:
        if not is_available():
            return {"success": False, "error": "Suricata kurulu değil."}
        stdout, stderr, rc = _systemctl("start")
        success = rc == 0
        if success:
            log.info("Suricata başlatıldı.")
        else:
            log.error("Suricata başlatılamadı: %s", stderr)
        return {"success": success, "message": stderr or "Başlatıldı."}
    except Exception as e:
        log.error("start hatası: %s", e)
        return {"success": False, "error": str(e)}


def stop() -> dict:
    """Suricata'yı durdur."""
    try:
        if not is_available():
            return {"success": False, "error": "Suricata kurulu değil."}
        _, stderr, rc = _systemctl("stop")
        success = rc == 0
        log.info("Suricata durduruldu." if success else "Suricata durdurulamadı.")
        return {"success": success, "message": stderr or "Durduruldu."}
    except Exception as e:
        log.error("stop hatası: %s", e)
        return {"success": False, "error": str(e)}


def restart() -> dict:
    """Suricata'yı yeniden başlat."""
    try:
        if not is_available():
            return {"success": False, "error": "Suricata kurulu değil."}
        _, stderr, rc = _systemctl("restart")
        success = rc == 0
        return {"success": success, "message": stderr or "Yeniden başlatıldı."}
    except Exception as e:
        log.error("restart hatası: %s", e)
        return {"success": False, "error": str(e)}


def reload_rules() -> dict:
    """Kuralları güncelle ve Suricata'yı yeniden yükle."""
    try:
        if not is_available():
            return {"success": False, "error": "Suricata kurulu değil."}

        # suricata-update
        out, err, rc = _run("suricata-update", timeout=120)
        if rc != 0:
            log.warning("suricata-update başarısız: %s", err)

        # reload
        _, err2, rc2 = _systemctl("reload")
        success = rc2 == 0
        return {
            "success": success,
            "update_output": out,
            "reload_error": err2 if not success else None,
        }
    except Exception as e:
        log.error("reload_rules hatası: %s", e)
        return {"success": False, "error": str(e)}


# ── Alert Okuma ───────────────────────────────────────────────────────────────

def get_alerts(
    limit: int = 100,
    severity: int = None,
    since_hours: int = 24,
) -> list:
    """EVE JSON log'undan alert'leri oku ve filtrele."""
    try:
        if not os.path.exists(EVE_LOG):
            return []

        cutoff = (datetime.now() - timedelta(hours=since_hours)).isoformat()
        alerts = []

        with open(EVE_LOG) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("event_type") != "alert":
                        continue
                    ts = entry.get("timestamp", "")
                    if ts < cutoff:
                        continue
                    alert_info = entry.get("alert", {})
                    if severity is not None and alert_info.get("severity") != severity:
                        continue
                    alerts.append({
                        "ts":        ts,
                        "src_ip":    entry.get("src_ip", ""),
                        "dest_ip":   entry.get("dest_ip", ""),
                        "src_port":  entry.get("src_port"),
                        "dest_port": entry.get("dest_port"),
                        "proto":     entry.get("proto", ""),
                        "alert": {
                            "signature": alert_info.get("signature", ""),
                            "severity":  alert_info.get("severity", 3),
                            "category":  alert_info.get("category", ""),
                        },
                    })
                except Exception:
                    pass

        return list(reversed(alerts))[:limit]
    except Exception as e:
        log.error("get_alerts hatası: %s", e)
        return []


def get_alert_summary() -> dict:
    """Son 24 saatteki alert özeti."""
    try:
        alerts = get_alerts(limit=10000, since_hours=24)
        by_severity: dict = {}
        sig_counts: dict  = {}

        for a in alerts:
            sev = a["alert"].get("severity", 3)
            by_severity[sev] = by_severity.get(sev, 0) + 1
            sig = a["alert"].get("signature", "unknown")
            sig_counts[sig] = sig_counts.get(sig, 0) + 1

        top_sigs = sorted(sig_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_24h": len(alerts),
            "by_severity": by_severity,
            "top_signatures": [{"signature": s, "count": c} for s, c in top_sigs],
        }
    except Exception as e:
        log.error("get_alert_summary hatası: %s", e)
        return {"total_24h": 0, "by_severity": {}, "top_signatures": [], "error": str(e)}


# ── Özel Kurallar ─────────────────────────────────────────────────────────────

def add_custom_rule(rule_text: str) -> dict:
    """Özel kural ekle."""
    try:
        rule_text = rule_text.strip()
        if not rule_text:
            return {"success": False, "error": "Kural metni boş."}

        _ensure_dir(CUSTOM_RULES)
        with _lock:
            # Mevcut kuralları oku, yineleme kontrolü
            existing_rules = []
            if os.path.exists(CUSTOM_RULES):
                with open(CUSTOM_RULES) as f:
                    existing_rules = f.read().splitlines()

            if rule_text in existing_rules:
                return {"success": False, "error": "Kural zaten mevcut."}

            with open(CUSTOM_RULES, "a") as f:
                f.write(rule_text + "\n")

        log.info("Özel kural eklendi: %.60s...", rule_text)
        return {"success": True, "rule": rule_text}
    except Exception as e:
        log.error("add_custom_rule hatası: %s", e)
        return {"success": False, "error": str(e)}


def list_custom_rules() -> list:
    """Tüm özel kuralları listele."""
    try:
        if not os.path.exists(CUSTOM_RULES):
            return []
        with open(CUSTOM_RULES) as f:
            rules = []
            for i, line in enumerate(f, start=1):
                line = line.strip()
                if line and not line.startswith("#"):
                    rules.append({"rule_id": i, "rule": line})
            return rules
    except Exception as e:
        log.error("list_custom_rules hatası: %s", e)
        return []


def delete_custom_rule(rule_id: int) -> dict:
    """rule_id numaralı satırı (1-indexed) sil."""
    try:
        if not os.path.exists(CUSTOM_RULES):
            return {"success": False, "error": "Kural dosyası yok."}

        with _lock:
            with open(CUSTOM_RULES) as f:
                lines = f.readlines()

            # rule_id gerçek satır numarası değil, yorum olmayan satırların sırası
            non_comment_idx = []
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    non_comment_idx.append(i)

            if rule_id < 1 or rule_id > len(non_comment_idx):
                return {"success": False, "error": f"Geçersiz rule_id: {rule_id}"}

            target_line_idx = non_comment_idx[rule_id - 1]
            deleted_rule = lines[target_line_idx].strip()
            del lines[target_line_idx]

            with open(CUSTOM_RULES, "w") as f:
                f.writelines(lines)

        log.info("Özel kural silindi: rule_id=%d", rule_id)
        return {"success": True, "deleted_rule": deleted_rule}
    except Exception as e:
        log.error("delete_custom_rule hatası: %s", e)
        return {"success": False, "error": str(e)}
