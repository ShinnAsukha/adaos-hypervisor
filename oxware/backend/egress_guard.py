#!/usr/bin/env python3
# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy. MIT License.
"""
OXware Egress Guard — merkezi dışa-çıkış kilidi (Katman 1)
──────────────────────────────────────────────────────────
Amaç: host'tan izinsiz hiçbir bilgi dışarı çıkmasın. Socket seviyesinde
çalışır; requests / urllib / boto3 / ldap3 / paramiko / anthropic SDK —
hepsi eninde sonunda socket.connect() çağırdığı için tek noktadan denetlenir.

Politika (deny-by-default):
  - Loopback (127/8, ::1) ve özel ağlar (RFC1918, fc00::/7, fe80::/10,
    169.254/16, 100.64/10 CGNAT) → HER ZAMAN izinli. Hipervizör'ün LAN
    üzerindeki SSH/LDAP/libvirt/node trafiği kırılmasın diye.
  - Public internet → allowlist'te değilse REDDEDİLİR ve audit'e yazılır.
  - AF_UNIX (libvirt qemu:///system) → dokunulmaz.

Modlar (OXWARE_EGRESS_MODE / config [egress] mode):
  - monitor  : bloklama, sadece logla    (VARSAYILAN — güncelleme/marketplace
               gibi giden çağrıları kırmaz; neyin çıktığını görürsün)
  - enforce  : dışarıyı blokla + logla   (bilinçli kilit; allowlist gerekir)
  - off      : guard devre dışı
Dark Site açıkken egress otomatik enforce'a çekilir (dark_site.apply()).

eventlet NOTU: bu modül eventlet import edilmeden ÖNCE install() edilmeli.
Böylece eventlet.green.socket, zaten sarmalanmış primitifleri "original"
olarak yakalar ve koruma yeşil socket'lerde de geçerli olur.
"""

import os
import sys
import json
import time
import socket as _socket
import logging
import ipaddress
import threading

log = logging.getLogger("oxware.egress")

# ── Durum ─────────────────────────────────────────────────────────────────────
_installed = False
_lock = threading.Lock()

MODE = "enforce"            # enforce | monitor | off
ALLOW_PRIVATE = True        # özel/loopback ağlara her zaman izin
AUDIT = True                # reddedilen (ve izinli-dış) denemeleri JSONL'e yaz
_ALLOW_HOSTS: set = set()   # allowlist: hostname son-ekleri (ör. "github.com")
_ALLOW_NETS: list = []      # allowlist: ipaddress.ip_network nesneleri
_AUDIT_PATH = "/var/log/oxware/egress.jsonl"

# hostname → son çözülen IP eşlemesi (connect() log'unda isim gösterebilmek için)
_resolved: dict = {}
_resolved_lock = threading.Lock()

# Orijinal (sarmalanmamış) referanslar
_orig_getaddrinfo = _socket.getaddrinfo
_orig_connect = _socket.socket.connect
_orig_connect_ex = _socket.socket.connect_ex


# ── Politika değerlendirme ─────────────────────────────────────────────────────

def _is_private_ip(ip_obj) -> bool:
    return (
        ip_obj.is_loopback
        or ip_obj.is_private
        or ip_obj.is_link_local
        or ip_obj.is_multicast          # yerel keşif (mDNS/SSDP) — dışarı gitmez
        or ip_obj in ipaddress.ip_network("100.64.0.0/10")   # CGNAT / Tailscale
        or (ip_obj.version == 6 and ip_obj in ipaddress.ip_network("fc00::/7"))
    )


def _host_allowed(host: str) -> bool:
    if not host:
        return False
    h = host.lower().rstrip(".")
    for suf in _ALLOW_HOSTS:
        if h == suf or h.endswith("." + suf):
            return True
    return False


def _ip_allowed_by_net(ip_obj) -> bool:
    for net in _ALLOW_NETS:
        if ip_obj.version == net.version and ip_obj in net:
            return True
    return False


def _decide(ip_str: str, host_hint: str = "") -> tuple:
    """(allowed: bool, reason: str) döndür."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.split("%")[0])   # scope-id at
    except ValueError:
        return True, "non-ip"          # AF_UNIX vb. — konumuz değil
    if ALLOW_PRIVATE and _is_private_ip(ip_obj):
        return True, "private"
    if _ip_allowed_by_net(ip_obj):
        return True, "allow-net"
    if host_hint and _host_allowed(host_hint):
        return True, "allow-host"
    return False, "external-denied"


# ── Audit ──────────────────────────────────────────────────────────────────────

def _audit(decision: str, reason: str, host: str, ip: str, port) -> None:
    if not AUDIT:
        return
    rec = {
        "ts": round(time.time(), 3),
        "decision": decision,          # allow | block
        "reason": reason,
        "host": host or "",
        "ip": ip or "",
        "port": port,
        "mode": MODE,
    }
    try:
        os.makedirs(os.path.dirname(_AUDIT_PATH), exist_ok=True)
        with open(_AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass   # log yazılamıyorsa sessizce geç — bloklama kararını etkilemez


def _blocked_error(host: str, ip: str, port) -> OSError:
    target = host or ip
    msg = ("OXware egress-guard: dış bağlantı reddedildi -> %s:%s "
           "(allowlist'e ekleyin: [egress] allow=...)" % (target, port))
    log.warning(msg)
    return OSError(_socket.errno.ENETUNREACH if hasattr(_socket, "errno") else 101, msg)


# ── Sarmalayıcılar ─────────────────────────────────────────────────────────────

def _cache_hostnames(results, hostname: str) -> None:
    """Çözülen TÜM adresleri isim ipucu olarak önbelleğe al.

    SEC/bug: eskiden yalnızca results[0] önbelleğe alınıyordu. create_connection
    listedeki adresleri sırayla dener; ilk adres (çoğu kez AAAA) başarısız olup
    sonraki A kaydına düşünce host_hint bulunamıyor ve ALLOWLIST'TEKİ host
    bloklanıyordu. Ayrıca clear() yerine en eski kayıtlar atılır (uçuştaki
    bağlantıların ipucu kaybolmasın).
    """
    if not hostname or not results:
        return
    with _resolved_lock:
        for r in results:
            try:
                _resolved[r[4][0]] = hostname
            except (IndexError, TypeError):
                continue
        while len(_resolved) > 4096:
            try:
                _resolved.pop(next(iter(_resolved)))
            except (StopIteration, KeyError):
                break


def _guarded_getaddrinfo(host, port, *args, **kwargs):
    hostname = host if isinstance(host, str) else ""
    # SEC: isim çözümlemesini KARARDAN ÖNCE yapma. Aksi halde
    # `<gizli-veri>.attacker.tld` sorgusu UDP/53 ile dışarı çıkar ve enforce
    # modunda bile canlı bir DNS exfil kanalı kalır. Allowlist'te olmayan bir
    # isim için hiç sorgu göndermiyoruz.
    if MODE == "enforce" and hostname and not _host_allowed(hostname):
        try:
            ipaddress.ip_address(hostname)      # IP-literal ise aşağıda IP'ye göre karar verilir
        except ValueError:
            _audit("block", "dns-not-allowlisted", hostname, "", port)
            raise _socket.gaierror(
                _socket.EAI_FAIL if hasattr(_socket, "EAI_FAIL") else -4,
                "OXware egress-guard: '%s' allowlist'te değil, DNS sorgusu yapılmadı" % hostname)

    results = _orig_getaddrinfo(host, port, *args, **kwargs)
    _cache_hostnames(results, hostname)
    if MODE == "off":
        return results
    # Çözülen adreslerden en az biri izinliyse geçir (connect asıl kapıdır)
    for fam, _t, _p, _c, sockaddr in results:
        ip = sockaddr[0]
        allowed, reason = _decide(ip, hostname)
        if allowed:
            return results
    # Hiçbiri izinli değil
    ip0 = results[0][4][0] if results else ""
    if MODE == "monitor":
        _audit("allow", "monitor", hostname, ip0, port)
        return results
    _audit("block", "external-denied", hostname, ip0, port)
    raise _socket.gaierror(_socket.EAI_FAIL if hasattr(_socket, "EAI_FAIL") else -4,
                           "OXware egress-guard: '%s' dış ada çözülüyor, reddedildi" % hostname)


def _check_sockaddr(address):
    """connect/connect_ex ortak kontrolü. Bloklanacaksa OSError fırlatır."""
    if MODE == "off" or not isinstance(address, (tuple, list)) or len(address) < 2:
        return
    ip = str(address[0])
    port = address[1]
    with _resolved_lock:
        host_hint = _resolved.get(ip, "")

    # SEC (bypass): connect(("evil.tld", 443)) tamamen geçerli bir çağrı ve
    # address[0] IP'ye parse edilemediği için _decide "non-ip" deyip İZİN
    # veriyordu; ad çözümü C tarafında yapılıp yamalı getaddrinfo'yu da
    # atlıyordu. Artık isim adresleri burada çözülüp politikadan geçiriliyor.
    try:
        ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        if not _host_allowed(ip):
            if MODE == "monitor":
                _audit("allow", "monitor", ip, "", port)
                return
            _audit("block", "hostname-denied", ip, "", port)
            raise _blocked_error(ip, "", port)
        # Allowlist'teki isim: çözülen adreslerden en az biri politikayı geçmeli
        try:
            infos = _orig_getaddrinfo(ip, port)
        except Exception:
            return                      # çözülemiyorsa zaten bağlanamaz
        _cache_hostnames(infos, ip)
        for r in infos:
            if _decide(r[4][0], ip)[0]:
                return
        if MODE == "monitor":
            _audit("allow", "monitor", ip, "", port)
            return
        _audit("block", "hostname-denied", ip, "", port)
        raise _blocked_error(ip, "", port)

    allowed, reason = _decide(ip, host_hint)
    if allowed:
        return
    if MODE == "monitor":
        _audit("allow", "monitor", host_hint, ip, port)
        return
    _audit("block", "external-denied", host_hint, ip, port)
    raise _blocked_error(host_hint, ip, port)


def _guarded_connect(self, address):
    _check_sockaddr(address)
    return _orig_connect(self, address)


def _guarded_connect_ex(self, address):
    try:
        _check_sockaddr(address)
    except OSError:
        # connect_ex hata fırlatmaz, errno döner
        return _socket.errno.ENETUNREACH if hasattr(_socket, "errno") else 101
    return _orig_connect_ex(self, address)


# ── Kurulum ────────────────────────────────────────────────────────────────────

def _load_policy() -> None:
    global MODE, ALLOW_PRIVATE, AUDIT, _ALLOW_HOSTS, _ALLOW_NETS, _AUDIT_PATH
    mode = os.environ.get("OXWARE_EGRESS_MODE", "").strip().lower()
    allow_raw = os.environ.get("OXWARE_EGRESS_ALLOW", "")
    allow_priv = os.environ.get("OXWARE_EGRESS_ALLOW_PRIVATE", "")
    audit_env = os.environ.get("OXWARE_EGRESS_AUDIT", "")
    log_dir = os.environ.get("OXWARE_LOG_DIR", "")

    # config.py varsa oradan da oku (env öncelikli)
    try:
        import config as _cfg
        mode = mode or getattr(_cfg, "EGRESS_MODE", "")
        if not allow_raw:
            allow_raw = ",".join(getattr(_cfg, "EGRESS_ALLOW", []) or [])
        if not allow_priv:
            allow_priv = str(getattr(_cfg, "EGRESS_ALLOW_PRIVATE", True))
        if not audit_env:
            audit_env = str(getattr(_cfg, "EGRESS_AUDIT", True))
        if not log_dir:
            log_dir = getattr(_cfg, "LOG_DIR", "")
    except Exception:
        pass

    MODE = mode if mode in ("enforce", "monitor", "off") else "monitor"
    ALLOW_PRIVATE = str(allow_priv).strip().lower() not in ("0", "false", "no", "off")
    AUDIT = str(audit_env).strip().lower() not in ("0", "false", "no", "off")
    if log_dir:
        _AUDIT_PATH = os.path.join(log_dir, "egress.jsonl")

    hosts, nets = set(), []
    for item in str(allow_raw).replace(";", ",").split(","):
        item = item.strip().lower().rstrip(".")
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            hosts.add(item)          # hostname son-eki
    _ALLOW_HOSTS = hosts
    _ALLOW_NETS = nets


def install() -> bool:
    """Egress guard'ı kur. eventlet import'undan ÖNCE çağır. Idempotent."""
    global _installed
    with _lock:
        if _installed:
            return True
        _load_policy()
        if MODE == "off":
            log.info("egress-guard: mod=off — kurulum atlandı")
            _installed = True
            return True
        _socket.getaddrinfo = _guarded_getaddrinfo
        _socket.socket.connect = _guarded_connect
        _socket.socket.connect_ex = _guarded_connect_ex
        _installed = True
        log.warning("egress-guard AKTİF: mod=%s allow_private=%s "
                    "allowlist_hosts=%d allowlist_nets=%d audit=%s",
                    MODE, ALLOW_PRIVATE, len(_ALLOW_HOSTS), len(_ALLOW_NETS), AUDIT)
        return True


def is_offline() -> bool:
    """Katman 2 için: guard gerçekten dışarıyı blokluyor mu?"""
    return _installed and MODE == "enforce"


def status() -> dict:
    return {
        "installed": _installed,
        "mode": MODE,
        "allow_private": ALLOW_PRIVATE,
        "allow_hosts": sorted(_ALLOW_HOSTS),
        "allow_nets": [str(n) for n in _ALLOW_NETS],
        "audit": AUDIT,
        "audit_path": _AUDIT_PATH,
    }


if __name__ == "__main__":
    # Hızlı manuel test: python egress_guard.py [host]
    logging.basicConfig(level=logging.INFO)
    install()
    print(json.dumps(status(), indent=2, ensure_ascii=False))
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    try:
        s = _socket.create_connection((target, 80), timeout=3)
        print("BAĞLANDI (beklenmiyor):", target)
        s.close()
    except Exception as e:
        print("BLOKLANDI/başarısız (beklenen):", type(e).__name__, e)
