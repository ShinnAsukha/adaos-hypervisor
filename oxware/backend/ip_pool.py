"""
AdaOS IP Havuzu Yöneticisi
─────────────────────────
IP aralığı tanımlayın, VM'lere otomatik IP atayın.
Veri: /var/lib/adaos/ip_pool.json
"""

import os
import json
import time
import ipaddress
import threading
from pathlib import Path
import config

POOL_FILE = os.path.join(config.DATA_DIR, "ip_pool.json")
_lock = threading.Lock()


def _load() -> dict:
    if os.path.exists(POOL_FILE):
        with open(POOL_FILE) as f:
            return json.load(f)
    return {
        "pools": {},
        "assignments": {},   # ip -> {vm_id, vm_name, assigned_at, mac}
    }


def _save(data: dict):
    os.makedirs(os.path.dirname(POOL_FILE), exist_ok=True)
    with open(POOL_FILE, "w") as f:
        json.dump(data, f, indent=2)


def create_pool(
    name: str,
    network: str,                  # örn: "192.168.100.0/24"
    gateway: str,
    dns: list = None,
    start_ip: str = None,          # Havuz başlangıcı (None = network+10)
    end_ip: str = None,            # Havuz sonu (None = broadcast-1)
    reserved: list = None,         # Bu IP'leri dışarıda bırak
    libvirt_network: str = "default",  # Libvirt ağ adı (virsh net-update için)
) -> dict:
    net = ipaddress.IPv4Network(network, strict=False)
    hosts = list(net.hosts())

    if not hosts:
        raise ValueError("Geçersiz ağ aralığı")

    if start_ip:
        start = ipaddress.IPv4Address(start_ip)
    else:
        start = hosts[9] if len(hosts) > 10 else hosts[0]

    if end_ip:
        end = ipaddress.IPv4Address(end_ip)
    else:
        end = hosts[-1]

    if ipaddress.IPv4Address(gateway) not in net:
        raise ValueError("Gateway ağ dışında")

    pool_data = {
        "name": name,
        "network": network,
        "gateway": gateway,
        "dns": dns or ["8.8.8.8", "1.1.1.1"],
        "start_ip": str(start),
        "end_ip": str(end),
        "reserved": reserved or [gateway],
        "libvirt_network": libvirt_network or "default",
        "created_at": time.time(),
    }

    with _lock:
        data = _load()
        data["pools"][name] = pool_data
        _save(data)

    return pool_data


def delete_pool(name: str):
    with _lock:
        data = _load()
        if name not in data["pools"]:
            raise KeyError(f"Havuz bulunamadı: {name}")
        del data["pools"][name]
        _save(data)


def list_pools() -> list:
    data = _load()
    result = []
    for name, pool in data["pools"].items():
        total = _pool_capacity(pool)
        used  = _pool_used(name, data)
        result.append({
            **pool,
            "total_ips": total,
            "used_ips":  used,
            "free_ips":  total - used,
        })
    return result


def _pool_capacity(pool: dict) -> int:
    try:
        start = int(ipaddress.IPv4Address(pool["start_ip"]))
        end   = int(ipaddress.IPv4Address(pool["end_ip"]))
        reserved = len(pool.get("reserved", []))
        return max(0, end - start + 1 - reserved)
    except Exception:
        return 0


def _pool_used(pool_name: str, data: dict) -> int:
    return sum(
        1 for a in data["assignments"].values()
        if a.get("pool") == pool_name
    )


def _pool_ips(pool: dict) -> list:
    start = ipaddress.IPv4Address(pool["start_ip"])
    end   = ipaddress.IPv4Address(pool["end_ip"])
    reserved = set(pool.get("reserved", []))
    ips = []
    current = start
    while int(current) <= int(end):
        if str(current) not in reserved:
            ips.append(str(current))
        current = ipaddress.IPv4Address(int(current) + 1)
    return ips


def allocate_ip(pool_name: str, vm_id: str, vm_name: str, mac: str = None) -> dict:
    """Havuzdan boş IP tahsis et."""
    with _lock:
        data = _load()
        pool = data["pools"].get(pool_name)
        if not pool:
            raise KeyError(f"Havuz bulunamadı: {pool_name}")

        assigned_ips = {ip for ip, a in data["assignments"].items() if a.get("pool") == pool_name}
        available = [ip for ip in _pool_ips(pool) if ip not in assigned_ips]

        if not available:
            raise RuntimeError(f"Havuzda boş IP yok: {pool_name}")

        ip = available[0]
        data["assignments"][ip] = {
            "vm_id":       vm_id,
            "vm_name":     vm_name,
            "pool":        pool_name,
            "mac":         mac or "",
            "assigned_at": time.time(),
            "gateway":     pool["gateway"],
            "dns":         pool["dns"],
            "network":     pool["network"],
        }
        _save(data)

    return {
        "ip":              ip,
        "gateway":         pool["gateway"],
        "dns":             pool["dns"],
        "network":         pool["network"],
        "netmask":         str(ipaddress.IPv4Network(pool["network"], strict=False).netmask),
        "prefix":          ipaddress.IPv4Network(pool["network"], strict=False).prefixlen,
        "libvirt_network": pool.get("libvirt_network", "default"),
    }


def release_ip(vm_id: str):
    """VM'in IP'sini serbest bırak."""
    with _lock:
        data = _load()
        to_del = [ip for ip, a in data["assignments"].items() if a.get("vm_id") == vm_id]
        for ip in to_del:
            del data["assignments"][ip]
        _save(data)
    return to_del


def get_vm_ip(vm_id: str) -> str | None:
    data = _load()
    for ip, a in data["assignments"].items():
        if a.get("vm_id") == vm_id:
            return ip
    return None


def get_vm_assignment(vm_id: str) -> dict | None:
    """VM'e ait tam IP atamasını döndür (ip, mac, network, gateway dahil)."""
    data = _load()
    for ip, a in data["assignments"].items():
        if a.get("vm_id") == vm_id:
            return {"ip": ip, **a}
    return None


def list_assignments(pool_name: str = None) -> list:
    data = _load()
    result = []
    for ip, a in data["assignments"].items():
        if pool_name and a.get("pool") != pool_name:
            continue
        result.append({"ip": ip, **a})
    return result


def release_by_mac(mac: str) -> list:
    """MAC adresine göre IP'yi serbest bırak."""
    with _lock:
        data = _load()
        to_del = [ip for ip, a in data["assignments"].items() if a.get("mac") == mac]
        for ip in to_del:
            del data["assignments"][ip]
        _save(data)
    return to_del


def lock_ip(ip: str, locked: bool = True) -> bool:
    """IP atamasını kilitle veya kilidi aç."""
    with _lock:
        data = _load()
        if ip not in data["assignments"]:
            raise KeyError(f"Atama bulunamadı: {ip}")
        data["assignments"][ip]["locked"] = locked
        _save(data)
    return locked


def reassign_ip(mac: str, new_ip: str) -> dict:
    """MAC adresine ait IP'yi yeni IP ile değiştir."""
    with _lock:
        data = _load()
        old_ip = None
        for ip, a in data["assignments"].items():
            if a.get("mac") == mac:
                old_ip = ip
                break
        if not old_ip:
            raise KeyError(f"MAC bulunamadı: {mac}")
        # Yeni IP zaten atanmış mı?
        if new_ip in data["assignments"]:
            raise ValueError(f"IP zaten kullanımda: {new_ip}")
        entry = data["assignments"].pop(old_ip)
        entry["ip"] = new_ip
        data["assignments"][new_ip] = entry
        _save(data)
    return {"old_ip": old_ip, "new_ip": new_ip}


def update_pool(name: str, gateway: str = None, start_ip: str = None, end_ip: str = None, dns: list = None) -> dict:
    """Mevcut havuzu güncelle."""
    with _lock:
        data = _load()
        pool = data["pools"].get(name)
        if not pool:
            raise KeyError(f"Havuz bulunamadı: {name}")
        if gateway:
            pool["gateway"] = gateway
        if start_ip:
            pool["start_ip"] = start_ip
        if end_ip:
            pool["end_ip"] = end_ip
        if dns:
            pool["dns"] = dns if isinstance(dns, list) else dns.split(",")
        _save(data)
    return pool


def manual_assign(ip: str, mac: str, vm_name: str = "", pool_name: str = "", vm_id: str = "") -> dict:
    """Manuel IP ataması ekle."""
    with _lock:
        data = _load()
        pool = data["pools"].get(pool_name, {})
        data["assignments"][ip] = {
            "vm_id":       vm_id or mac,
            "vm_name":     vm_name,
            "pool":        pool_name,
            "mac":         mac,
            "assigned_at": time.time(),
            "source":      "oxware",
            "state":       "bound",
            "gateway":     pool.get("gateway", ""),
            "dns":         pool.get("dns", []),
            "network":     pool.get("network", ""),
        }
        _save(data)
    return {"ip": ip, "mac": mac, "vm": vm_name, "pool": pool_name}


def get_all_stats() -> dict:
    """Tüm havuzlar toplamı istatistik."""
    data = _load()
    total_cap = sum(_pool_capacity(p) for p in data["pools"].values())
    total_used = len(data["assignments"])
    locked = sum(1 for a in data["assignments"].values() if a.get("locked", False))
    return {
        "total": total_cap,
        "bound": total_used,
        "released": total_cap - total_used,
        "locked": locked,
        "pools": len(data["pools"]),
    }


def get_pool_stats(pool_name: str) -> dict:
    data = _load()
    pool = data["pools"].get(pool_name)
    if not pool:
        raise KeyError(pool_name)
    total = _pool_capacity(pool)
    used  = _pool_used(pool_name, data)
    return {
        "name":    pool_name,
        "total":   total,
        "used":    used,
        "free":    total - used,
        "percent": round(used / total * 100, 1) if total else 0,
    }
