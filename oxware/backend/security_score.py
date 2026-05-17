"""OXware Security Score — per-VM and host security assessment"""
import subprocess, logging
from datetime import datetime, timedelta

log = logging.getLogger("security_score")

GRADES = [(90,"A"),(75,"B"),(60,"C"),(40,"D"),(0,"F")]

def _grade(score):
    for threshold, grade in GRADES:
        if score >= threshold: return grade
    return "F"

def score_vm(vm_id, vm_info: dict):
    score = 100
    issues = []
    recs   = []

    ssh_port = int(vm_info.get("ssh_port", 22))
    if ssh_port == 22:
        score -= 10; issues.append("SSH varsayılan port 22 kullanıyor")
        recs.append("SSH portunu 2222-65535 arasına taşıyın")

    if vm_info.get("root_login"):
        score -= 20; issues.append("SSH root girişi etkin")
        recs.append("PermitRootLogin no yapın, sudo kullanın")

    if vm_info.get("password_auth", True):
        score -= 5; issues.append("SSH şifre kimlik doğrulaması etkin")
        recs.append("Anahtar tabanlı auth kullanın, PasswordAuthentication no yapın")

    cve_count = min(int(vm_info.get("cve_count", 0)), 6)
    if cve_count:
        deduct = cve_count * 5
        score -= deduct; issues.append(f"{cve_count} bilinen CVE tespit edildi")
        recs.append("Sistemi güncelleyin: apt upgrade")

    if not vm_info.get("has_recent_snapshot"):
        score -= 5; issues.append("Son 30 günde snapshot yok")
        recs.append("Düzenli snapshot alın")

    if not vm_info.get("has_firewall_rules"):
        score -= 10; issues.append("Güvenlik duvarı kuralı yok")
        recs.append("VM için firewall kuralları ekleyin")
    else:
        score += 10

    score = max(0, min(100, score))
    return {"vm_id": vm_id, "score": score, "grade": _grade(score),
            "issues": issues, "recommendations": recs,
            "checked_at": datetime.now().isoformat()}

def score_all_vms(vms: list):
    results = []
    for vm in (vms or []):
        vm_id = vm.get("id", ""); vm_name = vm.get("name", vm_id)
        info = {"ssh_port": 22, "root_login": False, "password_auth": True,
                "cve_count": 0, "has_recent_snapshot": False, "has_firewall_rules": False}
        try:
            result = score_vm(vm_id, info)
            result["vm_name"] = vm_name
            results.append(result)
        except Exception as e:
            log.error("score_vm %s: %s", vm_id, e)
    return sorted(results, key=lambda x: x["score"])

def get_host_score():
    score = 100; issues = []; recs = []
    try:
        r = subprocess.run(["which","fail2ban-client"],capture_output=True)
        if r.returncode != 0:
            score -= 15; issues.append("fail2ban kurulu değil")
            recs.append("apt install fail2ban")
    except Exception: pass
    try:
        r = subprocess.run(["ufw","status"],capture_output=True,text=True,timeout=5)
        if "inactive" in r.stdout.lower():
            score -= 20; issues.append("UFW güvenlik duvarı devre dışı")
            recs.append("ufw enable")
    except Exception: pass
    try:
        r = subprocess.run(["apt","list","--upgradable"],capture_output=True,text=True,
                           timeout=30,check=False)
        upgradable = len([l for l in r.stdout.splitlines() if "/" in l])
        if upgradable > 20:
            score -= 15; issues.append(f"{upgradable} güncelleme bekliyor")
            recs.append("apt upgrade")
        elif upgradable > 0:
            score -= 5; issues.append(f"{upgradable} güncelleme bekliyor")
    except Exception: pass
    score = max(0, min(100, score))
    return {"score": score, "grade": _grade(score), "issues": issues,
            "recommendations": recs, "checked_at": datetime.now().isoformat()}
