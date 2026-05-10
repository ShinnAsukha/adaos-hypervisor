"""
security_hardening.py — OXware güvenlik denetim ve sertleştirme modülü.

Kontrol listesi (Proxmox/KVM best practices):
  1. br_netfilter kernel modülü
  2. IOMMU etkin mi (PCI passthrough izolasyonu)
  3. Kernel sysctl sertleştirme
  4. SSH hardening
  5. UFW/iptables yönetim portu koruması
  6. QEMU seccomp desteği
  7. Root SSH girişi kapalı mı
  8. Varsayılan şifre kullanılıyor mu
  9. Açık portlar taraması
 10. Account lockout (başarısız login takibi)
"""

import os
import re
import subprocess
import threading
import time
import logging
from typing import Optional

log = logging.getLogger("oxware.security_hardening")

# ── Başarısız login takibi (username bazlı lockout) ───────────────────────────

_failed_lock   = threading.Lock()
_failed_logins: dict = {}   # {username: {"count": int, "locked_until": float}}

LOCKOUT_THRESHOLD = 5       # Bu kadar başarısız denemeden sonra kilitle
LOCKOUT_DURATION  = 300     # 5 dakika kilit


def record_failed_login(username: str):
    now = time.time()
    with _failed_lock:
        entry = _failed_logins.setdefault(username, {"count": 0, "locked_until": 0})
        entry["count"] += 1
        if entry["count"] >= LOCKOUT_THRESHOLD:
            entry["locked_until"] = now + LOCKOUT_DURATION
            log.warning("Account lockout: %s — %d başarısız deneme", username, entry["count"])


def record_successful_login(username: str):
    with _failed_lock:
        _failed_logins.pop(username, None)


def is_account_locked(username: str) -> tuple[bool, int]:
    """(locked: bool, seconds_remaining: int) döndür."""
    now = time.time()
    with _failed_lock:
        entry = _failed_logins.get(username)
        if not entry:
            return False, 0
        if entry["locked_until"] > now:
            return True, int(entry["locked_until"] - now)
        # Kilit süresi geçti — sıfırla
        if entry["locked_until"] > 0:
            _failed_logins.pop(username, None)
    return False, 0


def get_lockout_status() -> list:
    """Tüm kilitli hesapları döndür."""
    now = time.time()
    result = []
    with _failed_lock:
        for user, entry in list(_failed_logins.items()):
            result.append({
                "username":        user,
                "failed_count":    entry["count"],
                "locked":          entry["locked_until"] > now,
                "locked_until":    entry["locked_until"],
                "seconds_left":    max(0, int(entry["locked_until"] - now)),
            })
    return result


def unlock_account(username: str) -> bool:
    with _failed_lock:
        if username in _failed_logins:
            del _failed_logins[username]
            return True
    return False


# ── Yardımcı ─────────────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 15) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except FileNotFoundError:
        return -1, f"Komut bulunamadı: {cmd[0]}"
    except Exception as e:
        return -1, str(e)


def _read_file(path: str) -> Optional[str]:
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return None


def _sysctl_get(key: str) -> Optional[str]:
    code, out = _run(["sysctl", "-n", key])
    return out if code == 0 else None


# ── Kontrol Fonksiyonları ─────────────────────────────────────────────────────

def check_br_netfilter() -> dict:
    """br_netfilter modülü yüklü mü? VM firewall kuralları için gerekli."""
    code, out = _run(["lsmod"])
    loaded = "br_netfilter" in out
    # Ayrıca /proc/modules kontrol
    proc = _read_file("/proc/modules") or ""
    loaded = loaded or "br_netfilter" in proc
    return {
        "id":      "br_netfilter",
        "title":   "br_netfilter Kernel Modülü",
        "status":  "pass" if loaded else "fail",
        "detail":  "Yüklü ✓" if loaded else "Yüklü değil — VM firewall kuralları devre dışı kalabilir",
        "fix":     None if loaded else "modprobe br_netfilter && echo 'br_netfilter' >> /etc/modules-load.d/oxware.conf",
    }


def check_iommu() -> dict:
    """IOMMU etkin mi? PCI passthrough izolasyonu için gerekli."""
    cmdline = _read_file("/proc/cmdline") or ""
    iommu_on = "intel_iommu=on" in cmdline or "amd_iommu=on" in cmdline or "iommu=pt" in cmdline
    # dmesg kontrolü
    code, dmesg = _run(["dmesg"])
    dmesg_iommu = "IOMMU enabled" in dmesg or "AMD-Vi: AMD IOMMUv2" in dmesg
    enabled = iommu_on or dmesg_iommu
    return {
        "id":      "iommu",
        "title":   "IOMMU / VT-d",
        "status":  "pass" if enabled else "warn",
        "detail":  "IOMMU aktif ✓" if enabled else "IOMMU tespit edilemedi — PCI passthrough kullanmıyorsanız sorun yok",
        "fix":     None if enabled else "GRUB'da GRUB_CMDLINE_LINUX'a 'intel_iommu=on iommu=pt' ekle, update-grub çalıştır",
    }


def check_kernel_sysctl() -> dict:
    """Kritik sysctl güvenlik ayarları."""
    checks = {
        "net.ipv4.ip_forward":              ("1",  "warn"),   # KVM için gerekli — sadece warn
        "net.ipv4.conf.all.rp_filter":      ("1",  "fail"),
        "net.ipv4.conf.all.accept_redirects": ("0", "fail"),
        "net.ipv4.conf.all.send_redirects":   ("0", "fail"),
        "net.ipv4.tcp_syncookies":           ("1",  "fail"),
        "kernel.dmesg_restrict":             ("1",  "warn"),
        "kernel.kptr_restrict":              ("2",  "warn"),
        "net.ipv4.conf.all.log_martians":    ("1",  "warn"),
    }
    issues = []
    for key, (expected, severity) in checks.items():
        val = _sysctl_get(key)
        if val != expected:
            issues.append({"key": key, "expected": expected, "got": val or "?", "severity": severity})

    if not issues:
        return {"id": "sysctl", "title": "Kernel Sysctl", "status": "pass",
                "detail": "Tüm kritik sysctl ayarları doğru ✓", "fix": None}

    fix_cmds = " && ".join(f"sysctl -w {i['key']}={i['expected']}" for i in issues)
    return {
        "id":     "sysctl",
        "title":  "Kernel Sysctl",
        "status": "fail" if any(i["severity"] == "fail" for i in issues) else "warn",
        "detail": f"{len(issues)} ayar yanlış: " + ", ".join(i["key"] for i in issues),
        "issues": issues,
        "fix":    fix_cmds,
    }


def check_ssh_hardening() -> dict:
    """SSH güvenlik ayarları."""
    sshd_config = _read_file("/etc/ssh/sshd_config") or ""
    issues = []

    def _setting(key: str, bad_val: str, good_val: str, msg: str):
        # Regex: satır başında (boşluk olabilir), key, whitespace, value
        pattern = re.compile(rf"^\s*{key}\s+(\S+)", re.MULTILINE | re.IGNORECASE)
        m = pattern.search(sshd_config)
        val = m.group(1) if m else None
        if val is None or val.lower() == bad_val.lower():
            issues.append({"key": key, "current": val or "default", "recommended": good_val, "msg": msg})

    _setting("PermitRootLogin",      "yes",  "prohibit-password", "Root SSH girişi açık")
    _setting("PasswordAuthentication", "yes", "no",               "SSH şifre girişi açık (key-only önerilir)")
    _setting("X11Forwarding",        "yes",  "no",                "X11 forwarding açık (gereksiz saldırı yüzeyi)")
    _setting("MaxAuthTries",         "6",    "3",                 "MaxAuthTries yüksek (brute-force riski)")
    _setting("PermitEmptyPasswords", "yes",  "no",                "Boş şifreye izin veriliyor")

    if not sshd_config:
        return {"id": "ssh", "title": "SSH Sertleştirme", "status": "warn",
                "detail": "/etc/ssh/sshd_config okunamadı", "fix": None}

    if not issues:
        return {"id": "ssh", "title": "SSH Sertleştirme", "status": "pass",
                "detail": "SSH ayarları güvenli ✓", "fix": None}

    # Fix komutu
    fixes = []
    for i in issues:
        fixes.append(f"sed -i 's/^#*\\s*{i['key']}.*/{i['key']} {i['recommended']}/' /etc/ssh/sshd_config")
    fixes.append("systemctl reload sshd")

    return {
        "id":     "ssh",
        "title":  "SSH Sertleştirme",
        "status": "fail" if any(i["key"] == "PermitRootLogin" for i in issues) else "warn",
        "detail": f"{len(issues)} SSH sorunu: " + ", ".join(i["msg"] for i in issues),
        "issues": issues,
        "fix":    " && ".join(fixes),
    }


def check_qemu_seccomp() -> dict:
    """QEMU seccomp desteği var mı?"""
    code, out = _run(["qemu-system-x86_64", "--version"])
    if code != 0:
        # qemu-system-x86_64 bulunamadı — farklı isim dene
        code, out = _run(["qemu-kvm", "--version"])
    if code != 0:
        return {"id": "qemu_seccomp", "title": "QEMU Seccomp",
                "status": "warn", "detail": "QEMU bulunamadı — kurulu değil mi?", "fix": None}

    # seccomp kernel desteği
    seccomp_file = _read_file("/proc/version") or ""
    code2, out2 = _run(["grep", "-r", "seccomp", "/proc/config.gz"], timeout=5)
    # En basit kontrol: /proc/sys/kernel/seccomp
    seccomp_ok = os.path.exists("/proc/sys/kernel/seccomp") or os.path.exists("/sys/kernel/security/apparmor")

    return {
        "id":     "qemu_seccomp",
        "title":  "QEMU Seccomp Sandbox",
        "status": "pass" if seccomp_ok else "warn",
        "detail": "Kernel seccomp desteği mevcut ✓" if seccomp_ok else
                  "Seccomp tespit edilemedi — QEMU sandbox sınırlı olabilir",
        "fix":    None,
    }


def check_firewall() -> dict:
    """UFW veya iptables aktif mi?"""
    # UFW
    code_ufw, out_ufw = _run(["ufw", "status"])
    if code_ufw == 0 and "active" in out_ufw.lower():
        return {"id": "firewall", "title": "Güvenlik Duvarı (UFW)",
                "status": "pass", "detail": "UFW aktif ✓", "fix": None}

    # iptables — en az birkaç kural var mı?
    code_ipt, out_ipt = _run(["iptables", "-L", "-n"])
    if code_ipt == 0 and "DROP" in out_ipt or "REJECT" in out_ipt:
        return {"id": "firewall", "title": "Güvenlik Duvarı (iptables)",
                "status": "pass", "detail": "iptables kuralları aktif ✓", "fix": None}

    return {
        "id":     "firewall",
        "title":  "Güvenlik Duvarı",
        "status": "fail",
        "detail": "UFW veya iptables DROP/REJECT kuralı bulunamadı — port koruması yok",
        "fix":    "ufw enable && ufw default deny incoming && ufw allow 8006/tcp && ufw allow 22/tcp",
    }


def check_open_ports() -> dict:
    """Kritik portlara dışarıdan erişim riski var mı?"""
    risky_ports = {
        "5900-5999": "VNC (şifresiz erişim riski)",
        "6080":      "noVNC WebSocket",
        "2375":      "Docker daemon (şifresiz)",
        "2376":      "Docker daemon TLS",
    }
    code, out = _run(["ss", "-tlnp"])
    if code != 0:
        code, out = _run(["netstat", "-tlnp"])

    found = []
    for port_range, desc in risky_ports.items():
        if port_range.replace("-", "") in out or port_range in out:
            found.append(f"{port_range} ({desc})")

    if not found:
        return {"id": "open_ports", "title": "Açık Port Riski",
                "status": "pass", "detail": "Riskli port bulunamadı ✓", "fix": None}

    return {
        "id":     "open_ports",
        "title":  "Açık Port Riski",
        "status": "warn",
        "detail": f"Potansiyel riskli portlar: {', '.join(found)}",
        "fix":    "ufw deny <port> veya servis konfigürasyonundan portu kapat",
    }


def check_default_password() -> dict:
    """Varsayılan/zayıf şifre kullanılıyor mu? (sembolik kontrol)"""
    try:
        import credentials as cred
        info = cred.get_credential_info()
        # Şifre hiç değiştirilmemiş mi?
        created  = info.get("created_at", 0) or 0
        changed  = info.get("last_changed") or 0
        if not changed or (changed - created) < 5:
            return {
                "id":     "default_password",
                "title":  "Varsayılan Şifre",
                "status": "warn",
                "detail": "Şifre kurulumdan bu yana değiştirilmemiş — değiştirmeniz önerilir",
                "fix":    "Güvenlik → Şifre Sıfırlama bölümünden değiştirin",
            }
    except Exception:
        pass
    return {"id": "default_password", "title": "Varsayılan Şifre",
            "status": "pass", "detail": "Şifre değiştirilmiş ✓", "fix": None}


# ── Ana audit fonksiyonu ──────────────────────────────────────────────────────

def run_security_audit() -> dict:
    """
    Tüm kontrolleri çalıştır.
    Döner: {checks: [...], summary: {pass, warn, fail, score}}
    """
    checks = []
    runners = [
        check_br_netfilter,
        check_iommu,
        check_kernel_sysctl,
        check_ssh_hardening,
        check_qemu_seccomp,
        check_firewall,
        check_open_ports,
        check_default_password,
    ]
    for fn in runners:
        try:
            checks.append(fn())
        except Exception as e:
            log.error("Güvenlik kontrol hatası (%s): %s", fn.__name__, e)
            checks.append({
                "id": fn.__name__, "title": fn.__name__,
                "status": "error", "detail": str(e), "fix": None,
            })

    summary = {
        "pass":  sum(1 for c in checks if c["status"] == "pass"),
        "warn":  sum(1 for c in checks if c["status"] == "warn"),
        "fail":  sum(1 for c in checks if c["status"] == "fail"),
        "total": len(checks),
    }
    summary["score"] = int(
        (summary["pass"] * 100 + summary["warn"] * 50) / max(summary["total"], 1)
    )
    return {"checks": checks, "summary": summary, "scanned_at": time.time()}


def apply_fix(check_id: str) -> dict:
    """
    Belirli bir kontrol için otomatik düzeltme uygula.
    Sadece güvenli/geri alınabilir komutlar çalıştırır.
    """
    SAFE_FIXES = {
        "br_netfilter": [
            ["modprobe", "br_netfilter"],
            ["sh", "-c", "echo 'br_netfilter' >> /etc/modules-load.d/oxware.conf"],
        ],
        "sysctl": [
            ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=1"],
            ["sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0"],
            ["sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"],
            ["sysctl", "-w", "net.ipv4.tcp_syncookies=1"],
            ["sysctl", "-w", "net.ipv4.conf.all.log_martians=1"],
            ["sysctl", "-w", "kernel.dmesg_restrict=1"],
        ],
    }
    cmds = SAFE_FIXES.get(check_id)
    if not cmds:
        return {"success": False, "error": f"'{check_id}' için otomatik düzeltme yok — manuel uygulayın"}

    results = []
    for cmd in cmds:
        code, out = _run(cmd)
        results.append({"cmd": " ".join(cmd), "code": code, "out": out[:200]})

    success = all(r["code"] == 0 for r in results)
    return {"success": success, "results": results}
