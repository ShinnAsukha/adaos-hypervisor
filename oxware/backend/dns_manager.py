"""
dns_manager.py — dnsmasq DNS/DHCP yönetimi (OXware Hypervisor)
"""

import subprocess
import json
import logging
import os
import re
import threading
import time

log = logging.getLogger("oxware.dns")

HOSTS_FILE = "/etc/oxware-hosts"
LEASES_FILE = "/var/lib/misc/dnsmasq.leases"
DNSMASQ_CONF = "/etc/dnsmasq.d/oxware.conf"

_lock = threading.Lock()

# ---------------------------------------------------------------------------
# İç yardımcılar
# ---------------------------------------------------------------------------

def _run(*cmd):
    """subprocess.run çalıştırır; hata fırlatmaz."""
    try:
        result = subprocess.run(
            list(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            log.warning("Komut başarısız [%d]: %s | stderr: %s",
                        result.returncode, " ".join(cmd), result.stderr.strip())
        return result
    except FileNotFoundError:
        log.error("Komut bulunamadı: %s", cmd[0])
        return None
    except Exception as exc:
        log.exception("_run hatası: %s", exc)
        return None


def _ensure_hosts_file():
    """HOSTS_FILE yoksa oluşturur."""
    if not os.path.exists(HOSTS_FILE):
        try:
            with open(HOSTS_FILE, "w", encoding="utf-8") as f:
                f.write("# OXware DNS Hosts\n")
        except OSError as exc:
            log.error("Hosts dosyası oluşturulamadı: %s", exc)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_status():
    """dnsmasq'ın çalışıp çalışmadığını ve temel bilgileri döner."""
    try:
        result = _run("systemctl", "is-active", "dnsmasq")
        active = result is not None and result.stdout.strip() == "active"

        # pid ve port bilgisi
        pid = None
        port = 53
        pid_result = _run("pidof", "dnsmasq")
        if pid_result and pid_result.returncode == 0:
            pid = pid_result.stdout.strip()

        return {
            "active": active,
            "service": "dnsmasq",
            "pid": pid,
            "port": port,
            "hosts_file": HOSTS_FILE,
            "conf_file": DNSMASQ_CONF,
        }
    except Exception as exc:
        log.exception("get_status hatası: %s", exc)
        return {"active": False, "error": str(exc)}


def list_hosts():
    """
    HOSTS_FILE parse eder.
    Dönüş: [{"ip": str, "hostname": str, "comment": str}, ...]
    """
    _ensure_hosts_file()
    hosts = []
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    # Yorum satırını bir sonraki host'a ata
                    continue
                # Inline comment varsa ayır
                comment = ""
                if "#" in line:
                    parts = line.split("#", 1)
                    line = parts[0].strip()
                    comment = parts[1].strip()

                tokens = line.split()
                if len(tokens) >= 2:
                    hosts.append({
                        "ip": tokens[0],
                        "hostname": tokens[1],
                        "aliases": tokens[2:] if len(tokens) > 2 else [],
                        "comment": comment,
                    })
    except OSError as exc:
        log.error("Hosts dosyası okunamadı: %s", exc)
    return hosts


def add_host(ip, hostname, comment=""):
    """HOSTS_FILE'a kayıt ekler ve dnsmasq'ı yeniden yükler."""
    with _lock:
        try:
            _ensure_hosts_file()

            # Aynı hostname varsa güncelle
            hosts = list_hosts()
            existing = [h for h in hosts if h["hostname"] == hostname]
            if existing:
                delete_host(hostname)

            line = f"{ip}\t{hostname}"
            if comment:
                line += f"\t# {comment}"
            line += "\n"

            with open(HOSTS_FILE, "a", encoding="utf-8") as f:
                f.write(line)

            log.info("Host eklendi: %s -> %s", ip, hostname)
            reload()
            return {"success": True, "ip": ip, "hostname": hostname}
        except OSError as exc:
            log.error("Host eklenemedi: %s", exc)
            return {"success": False, "error": str(exc)}


def delete_host(hostname):
    """HOSTS_FILE'dan hostname kaydını kaldırır ve dnsmasq'ı yeniden yükler."""
    with _lock:
        try:
            if not os.path.exists(HOSTS_FILE):
                return {"success": False, "error": "Hosts dosyası bulunamadı"}

            with open(HOSTS_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()

            new_lines = []
            removed = 0
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("#") or not stripped:
                    new_lines.append(line)
                    continue
                tokens = stripped.split("#")[0].split()
                if len(tokens) >= 2 and hostname in tokens[1:] + [tokens[1]]:
                    removed += 1
                    continue
                new_lines.append(line)

            with open(HOSTS_FILE, "w", encoding="utf-8") as f:
                f.writelines(new_lines)

            log.info("Host silindi: %s (%d satır)", hostname, removed)
            reload()
            return {"success": True, "removed_count": removed}
        except OSError as exc:
            log.error("Host silinemedi: %s", exc)
            return {"success": False, "error": str(exc)}


def list_leases():
    """
    DHCP lease dosyasını parse eder.
    Dönüş: [{"mac": str, "ip": str, "hostname": str, "expires": int}, ...]
    """
    leases = []
    try:
        if not os.path.exists(LEASES_FILE):
            log.warning("Leases dosyası bulunamadı: %s", LEASES_FILE)
            return []

        with open(LEASES_FILE, "r", encoding="utf-8") as f:
            for line in f:
                tokens = line.strip().split()
                if len(tokens) >= 4:
                    leases.append({
                        "expires": int(tokens[0]) if tokens[0].isdigit() else tokens[0],
                        "mac": tokens[1],
                        "ip": tokens[2],
                        "hostname": tokens[3] if tokens[3] != "*" else "",
                        "client_id": tokens[4] if len(tokens) > 4 else "",
                    })
    except OSError as exc:
        log.error("Leases dosyası okunamadı: %s", exc)
    return leases


def get_config():
    """DNSMASQ_CONF dosyasını okur ve parse eder."""
    try:
        if not os.path.exists(DNSMASQ_CONF):
            return {"exists": False, "path": DNSMASQ_CONF, "settings": {}}

        settings = {}
        with open(DNSMASQ_CONF, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, val = line.partition("=")
                    settings[key.strip()] = val.strip()
                else:
                    settings[line] = True

        return {"exists": True, "path": DNSMASQ_CONF, "settings": settings}
    except OSError as exc:
        log.error("Config okunamadı: %s", exc)
        return {"exists": False, "error": str(exc)}


def update_config(upstream_dns=None, domain=None, dhcp_range=None, dhcp_enabled=None):
    """
    DNSMASQ_CONF'u günceller.
    Parametreler None ise mevcut değer korunur.
    """
    with _lock:
        try:
            os.makedirs(os.path.dirname(DNSMASQ_CONF), exist_ok=True)

            current = get_config()
            settings = current.get("settings", {})

            if upstream_dns is not None:
                settings["server"] = upstream_dns
            if domain is not None:
                settings["domain"] = domain
            if dhcp_range is not None:
                settings["dhcp-range"] = dhcp_range
            if dhcp_enabled is not None:
                if not dhcp_enabled:
                    settings.pop("dhcp-range", None)

            lines = ["# OXware dnsmasq config — auto-generated\n"]
            for key, val in settings.items():
                if val is True:
                    lines.append(f"{key}\n")
                else:
                    lines.append(f"{key}={val}\n")

            with open(DNSMASQ_CONF, "w", encoding="utf-8") as f:
                f.writelines(lines)

            log.info("dnsmasq config güncellendi")

            # systemd-resolved kalıcı DNS — reboot'ta sıfırlanmasın
            if upstream_dns is not None:
                try:
                    dns_list = upstream_dns if isinstance(upstream_dns, list) else [upstream_dns]
                    dns_str = " ".join(dns_list)
                    resolved_conf = "/etc/systemd/resolved.conf.d/oxware.conf"
                    os.makedirs(os.path.dirname(resolved_conf), exist_ok=True)
                    with open(resolved_conf, "w") as _rf:
                        _rf.write(f"[Resolve]\nDNS={dns_str}\n")
                    import subprocess as _sp
                    _sp.run(["systemctl", "restart", "systemd-resolved"],
                            capture_output=True, timeout=10)
                    log.info("systemd-resolved DNS güncellendi: %s", dns_str)
                except Exception as _re:
                    log.warning("resolved.conf güncellenemedi: %s", _re)

            return {"success": True, "settings": settings}
        except OSError as exc:
            log.error("Config güncellenemedi: %s", exc)
            return {"success": False, "error": str(exc)}


def reload():
    """dnsmasq servisini yeniden yükler."""
    log.info("dnsmasq yeniden yükleniyor")
    result = _run("systemctl", "reload", "dnsmasq")
    if result is None:
        # systemctl yoksa SIGHUP gönder
        _run("killall", "-HUP", "dnsmasq")
        return {"success": True, "method": "SIGHUP"}
    return {
        "success": result.returncode == 0,
        "stderr": result.stderr.strip(),
    }


def get_stats():
    """
    dnsmasq stats socket üzerinden istatistikleri alır.
    Erişim yoksa boş dict döner.
    """
    try:
        # dnsmasq log tabanlı stats için SIGUSR1 sinyali gönder
        result = _run("killall", "-USR1", "dnsmasq")
        if result is None or result.returncode != 0:
            return {}

        # Logdan son satırları oku (journalctl veya /var/log/syslog)
        log_result = _run("journalctl", "-u", "dnsmasq", "--no-pager", "-n", "20")
        stats = {}
        if log_result and log_result.returncode == 0:
            for line in log_result.stdout.splitlines():
                if "queries forwarded" in line:
                    m = re.search(r"queries forwarded (\d+)", line)
                    if m:
                        stats["queries_forwarded"] = int(m.group(1))
                if "queries answered locally" in line:
                    m = re.search(r"queries answered locally (\d+)", line)
                    if m:
                        stats["queries_local"] = int(m.group(1))
                if "cache size" in line:
                    m = re.search(r"cache size (\d+)", line)
                    if m:
                        stats["cache_size"] = int(m.group(1))

        return stats
    except Exception as exc:
        log.warning("get_stats hatası: %s", exc)
        return {}


# Alias'lar
def add_dns_record(hostname, ip):
    """add_host alias."""
    return add_host(ip, hostname)


def delete_dns_record(hostname):
    """delete_host alias."""
    return delete_host(hostname)
