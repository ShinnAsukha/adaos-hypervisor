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


# ── Yeni Kontroller ───────────────────────────────────────────────────────────

def check_ksm() -> dict:
    """KSM (Kernel Samepage Merging) — cross-VM bellek yan kanal riski."""
    ksm_run = _read_file("/sys/kernel/mm/ksm/run")
    if ksm_run is None or ksm_run == "0":
        return {"id": "ksm", "title": "KSM Bellek Dedup",
                "status": "pass", "detail": "KSM kapalı ✓ — cross-VM side-channel riski yok", "fix": None}
    # KSM açık — VM sayısını kontrol et
    code, vms = _run(["virsh", "list", "--all", "--name"])
    vm_count = len([v for v in vms.splitlines() if v.strip()]) if code == 0 else 2
    if vm_count > 1:
        return {
            "id":     "ksm",
            "title":  "KSM Bellek Dedup",
            "status": "warn",
            "detail": f"KSM açık ve {vm_count} VM var — çok kiracılı ortamda cross-VM bellek sızıntısı riski (CVE-class)",
            "fix":    "echo 0 > /sys/kernel/mm/ksm/run && echo 'w /sys/kernel/mm/ksm/run - - - - 0' > /etc/tmpfiles.d/ksm-disable.conf",
        }
    return {"id": "ksm", "title": "KSM Bellek Dedup",
            "status": "pass", "detail": "KSM açık ama tek VM — risk düşük ✓", "fix": None}


def check_l2_isolation() -> dict:
    """Bridge L2 izolasyonu — ARP spoofing ve MAC sahteciliği koruması."""
    issues = []
    for key, expected in [
        ("net.bridge.bridge-nf-call-iptables", "1"),
        ("net.bridge.bridge-nf-call-ip6tables", "1"),
    ]:
        val = _sysctl_get(key)
        if val != expected:
            issues.append(key)

    code, out = _run(["ebtables", "-L"])
    ebtables_ok = (code == 0 and len(out) > 20)

    if not issues and ebtables_ok:
        return {"id": "l2_isolation", "title": "L2 Ağ İzolasyonu",
                "status": "pass", "detail": "Bridge L2 filtering aktif ✓", "fix": None}

    fix = ("modprobe br_netfilter && "
           "sysctl -w net.bridge.bridge-nf-call-iptables=1 && "
           "sysctl -w net.bridge.bridge-nf-call-ip6tables=1")
    return {
        "id":     "l2_isolation",
        "title":  "L2 Ağ İzolasyonu",
        "status": "warn",
        "detail": f"Bridge filtering eksik: {', '.join(issues) if issues else 'ebtables kuralı yok'} — ARP spoofing riski",
        "fix":    fix,
    }


def check_nested_virt() -> dict:
    """Nested sanallaştırma — L2 hypervisor kaçış riski."""
    intel = _read_file("/sys/module/kvm_intel/parameters/nested")
    amd   = _read_file("/sys/module/kvm_amd/parameters/nested")
    enabled = (intel in ("1", "Y")) or (amd in ("1", "Y"))
    if not enabled:
        return {"id": "nested_virt", "title": "Nested Sanallaştırma",
                "status": "pass", "detail": "Nested virtualization kapalı ✓", "fix": None}
    vendor = "intel" if intel in ("1", "Y") else "amd"
    return {
        "id":     "nested_virt",
        "title":  "Nested Sanallaştırma",
        "status": "warn",
        "detail": "Nested virtualization aktif — VM içi hypervisor kaçış riski (corCTF 2024 PoC mevcut)",
        "fix":    f"echo 'options kvm_{vendor} nested=0' >> /etc/modprobe.d/kvm-hardening.conf",
    }


def check_vm_devices() -> dict:
    """VM'lerde riskli sanal cihaz kontrolü (floppy, 9p, audio)."""
    code, xml_list = _run(["virsh", "list", "--all", "--name"])
    if code != 0:
        return {"id": "vm_devices", "title": "VM Cihaz Güvenliği",
                "status": "warn", "detail": "virsh erişilemedi", "fix": None}
    vms = [v.strip() for v in xml_list.splitlines() if v.strip()]
    if not vms:
        return {"id": "vm_devices", "title": "VM Cihaz Güvenliği",
                "status": "pass", "detail": "Aktif VM yok ✓", "fix": None}
    risky = []
    for vm in vms[:10]:
        code2, xml = _run(["virsh", "dumpxml", vm])
        if code2 != 0:
            continue
        xml_lower = xml.lower()
        if "floppy" in xml_lower or "<disk.*fd" in xml_lower:
            risky.append(f"{vm}:floppy")
        if "<filesystem type='mount'" in xml_lower or "9p" in xml_lower:
            risky.append(f"{vm}:9p/virtfs")
    if not risky:
        return {"id": "vm_devices", "title": "VM Cihaz Güvenliği",
                "status": "pass", "detail": "Riskli sanal cihaz bulunamadı ✓", "fix": None}
    return {
        "id":     "vm_devices",
        "title":  "VM Cihaz Güvenliği",
        "status": "warn",
        "detail": f"Riskli sanal cihazlar: {', '.join(risky[:5])} — hypervisor kaçış yüzeyi",
        "fix":    "VM konfigürasyonundan floppy/9p cihazlarını kaldırın: virsh edit <vm>",
    }


def check_cert_expiry() -> dict:
    """SSL sertifika geçerlilik tarihi kontrolü."""
    import datetime
    cert_paths = ["/etc/oxware/ssl/oxware.crt", "/etc/ssl/oxware/oxware.crt",
                  "/etc/oxware/ssl/server.crt"]
    cert_file = next((p for p in cert_paths if os.path.exists(p)), None)
    if not cert_file:
        return {"id": "cert_expiry", "title": "SSL Sertifika",
                "status": "warn", "detail": "SSL sertifika dosyası bulunamadı", "fix": None}
    code, out = _run(["openssl", "x509", "-in", cert_file, "-noout", "-enddate"])
    if code != 0:
        return {"id": "cert_expiry", "title": "SSL Sertifika",
                "status": "warn", "detail": f"Sertifika okunamadı: {out[:80]}", "fix": None}
    try:
        date_str = out.split("=", 1)[1].strip()
        exp = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (exp - datetime.datetime.utcnow()).days
        renew_cmd = (f"openssl req -x509 -nodes -days 3650 -newkey rsa:2048 "
                     f"-keyout {cert_file.replace('.crt','.key')} -out {cert_file} "
                     f"-subj '/CN=oxware' && systemctl restart oxware")
        if days_left < 0:
            return {"id": "cert_expiry", "title": "SSL Sertifika", "status": "fail",
                    "detail": f"Sertifika {abs(days_left)} gün önce sona erdi!", "fix": renew_cmd}
        if days_left < 30:
            return {"id": "cert_expiry", "title": "SSL Sertifika", "status": "warn",
                    "detail": f"Sertifika {days_left} gün içinde sona eriyor", "fix": renew_cmd}
        return {"id": "cert_expiry", "title": "SSL Sertifika",
                "status": "pass", "detail": f"Sertifika geçerli, {days_left} gün kaldı ✓", "fix": None}
    except Exception as e:
        return {"id": "cert_expiry", "title": "SSL Sertifika",
                "status": "warn", "detail": f"Sertifika tarihi ayrıştırılamadı: {e}", "fix": None}


def check_cve_exposure() -> dict:
    """NVD API üzerinden son QEMU/KVM CVE'lerini sorgula."""
    import datetime, urllib.request, json
    try:
        end   = datetime.datetime.utcnow()
        start = end - datetime.timedelta(days=90)
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch=QEMU%20KVM"
            f"&pubStartDate={start.strftime('%Y-%m-%dT00:00:00.000')}"
            f"&pubEndDate={end.strftime('%Y-%m-%dT23:59:59.999')}"
            f"&cvssV3Severity=HIGH"
            f"&resultsPerPage=5"
        )
        req = urllib.request.Request(url, headers={"User-Agent": "OXware/2.1"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", [])
        if total == 0:
            return {"id": "cve_exposure", "title": "KVM/QEMU CVE İzleme",
                    "status": "pass", "detail": "Son 90 günde kritik CVE bulunamadı ✓", "fix": None}
        cve_list = []
        for v in vulns[:3]:
            cve_id = v.get("cve", {}).get("id", "?")
            desc   = (v.get("cve", {}).get("descriptions") or [{}])[0].get("value", "")[:80]
            cve_list.append(f"{cve_id}: {desc}")
        return {
            "id":     "cve_exposure",
            "title":  "KVM/QEMU CVE İzleme",
            "status": "warn",
            "detail": f"Son 90 günde {total} yüksek CVE: {cve_list[0] if cve_list else ''}",
            "fix":    "apt-get update && apt-get upgrade -y qemu-kvm qemu-system-x86 libvirt-daemon-system",
            "cves":   cve_list,
        }
    except Exception as e:
        log.warning("CVE sorgusu başarısız: %s", e)
        return {"id": "cve_exposure", "title": "KVM/QEMU CVE İzleme",
                "status": "warn", "detail": f"CVE sorgusu yapılamadı (ağ?): {str(e)[:60]}", "fix": None}


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
        check_ksm,
        check_l2_isolation,
        check_nested_virt,
        check_vm_devices,
        check_cert_expiry,
        check_cve_exposure,
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
            ["sysctl", "-w", "kernel.kptr_restrict=2"],
            # Kalıcı yap
            ["sh", "-c", "cat >> /etc/sysctl.d/99-oxware.conf << 'EOF'\n"
                          "net.ipv4.conf.all.rp_filter=1\n"
                          "net.ipv4.conf.all.accept_redirects=0\n"
                          "net.ipv4.conf.all.send_redirects=0\n"
                          "net.ipv4.tcp_syncookies=1\n"
                          "net.ipv4.conf.all.log_martians=1\n"
                          "kernel.dmesg_restrict=1\n"
                          "kernel.kptr_restrict=2\n"
                          "EOF"],
        ],
        "ksm": [
            ["sh", "-c", "echo 0 > /sys/kernel/mm/ksm/run"],
            ["sh", "-c", "echo 'w /sys/kernel/mm/ksm/run - - - - 0' > /etc/tmpfiles.d/ksm-disable.conf"],
        ],
        "l2_isolation": [
            ["modprobe", "br_netfilter"],
            ["sysctl", "-w", "net.bridge.bridge-nf-call-iptables=1"],
            ["sysctl", "-w", "net.bridge.bridge-nf-call-ip6tables=1"],
            ["sh", "-c", "echo 'net.bridge.bridge-nf-call-iptables=1' >> /etc/sysctl.d/99-oxware-bridge.conf"],
        ],
        # SSH: Sadece güvenli değişiklikler — PasswordAuthentication/PermitRootLogin dokunulmaz
        "ssh_hardening": [
            ["sh", "-c", "grep -q '^X11Forwarding' /etc/ssh/sshd_config && sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config || echo 'X11Forwarding no' >> /etc/ssh/sshd_config"],
            ["sh", "-c", "grep -q '^MaxAuthTries' /etc/ssh/sshd_config && sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config || echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config"],
            ["sh", "-c", "grep -q '^PermitEmptyPasswords' /etc/ssh/sshd_config && sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config || echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config"],
            ["sh", "-c", "grep -q '^LoginGraceTime' /etc/ssh/sshd_config && sed -i 's/^LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config || echo 'LoginGraceTime 30' >> /etc/ssh/sshd_config"],
            ["sh", "-c", "systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true"],
        ],
        # Docker 2375: TCP socket kapat, UNIX socket güvenli kıl
        "docker_2375": [
            ["sh", "-c", "[ -S /var/run/docker.sock ] && chmod 660 /var/run/docker.sock 2>/dev/null || true"],
            ["sh", "-c", "mkdir -p /etc/systemd/system/docker.service.d && printf '[Service]\\nExecStart=\\nExecStart=/usr/bin/dockerd' > /etc/systemd/system/docker.service.d/no-tcp.conf 2>/dev/null || true"],
            ["systemctl", "daemon-reload"],
            ["sh", "-c", "systemctl restart docker 2>/dev/null || true"],
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


# ── Periyodik Denetim + AI Uyarısı ───────────────────────────────────────────

_last_audit_result: dict = {}
_audit_sched_lock  = threading.Lock()


def run_scheduled_audit() -> dict:
    """
    Güvenlik denetimi çalıştır, değişiklikleri tespit et, bildirim gönder.
    Yeni fail/warn ortaya çıkarsa Telegram/Discord'a AI uyarısı gider.
    """
    global _last_audit_result
    result = run_security_audit()
    new_issues = []

    with _audit_sched_lock:
        old_statuses = {c["id"]: c["status"] for c in _last_audit_result.get("checks", [])}
        for check in result.get("checks", []):
            prev = old_statuses.get(check["id"])
            if prev in ("pass", None) and check["status"] in ("fail", "warn"):
                new_issues.append(check)
        _last_audit_result = result

    summary = result.get("summary", {})
    score    = summary.get("score", 0)
    fails    = summary.get("fail", 0)
    warns    = summary.get("warn", 0)

    try:
        import notifications as _notif

        if new_issues:
            details = {c["title"]: c["detail"][:80] for c in new_issues[:5]}
            _notif.send_alert(
                message=f"🔴 Güvenlik denetimi: {len(new_issues)} YENİ sorun tespit edildi! Puan: {score}/100",
                level="ERROR",
                category="security",
                details=details,
            )
            log.warning("Yeni güvenlik sorunları bildirildi: %s", [c["id"] for c in new_issues])
        elif fails > 0:
            details = {c["title"]: c["detail"][:80]
                       for c in result.get("checks", []) if c["status"] == "fail"}
            _notif.send_alert(
                message=f"⚠️ Güvenlik denetimi: {fails} açık sorun, {warns} uyarı. Puan: {score}/100",
                level="WARNING",
                category="security",
                details=details,
            )
    except Exception as e:
        log.warning("Güvenlik bildirimi gönderilemedi: %s", e)

    return result


def start_audit_scheduler(interval_hours: int = 24):
    """Arka planda periyodik güvenlik denetimi başlat."""
    def _loop():
        time.sleep(120)   # 2 dk başlangıç gecikmesi
        while True:
            try:
                log.info("Periyodik güvenlik denetimi başlatılıyor...")
                run_scheduled_audit()
                log.info("Periyodik güvenlik denetimi tamamlandı.")
            except Exception as e:
                log.error("Periyodik denetim hatası: %s", e)
            time.sleep(interval_hours * 3600)

    t = threading.Thread(target=_loop, daemon=True, name="oxware-security-audit")
    t.start()
    log.info("Güvenlik denetimi zamanlayıcısı başlatıldı (%dh aralık)", interval_hours)
