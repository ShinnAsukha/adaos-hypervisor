"""
AdaOS Topoloji Haritası Veri Toplayıcı
Hypervisor → Ağlar → VM'ler hiyerarşik yapısını döndürür.
"""

import subprocess
import socket
import json
import os
import time
import libvirt
import xml.etree.ElementTree as ET
import config
import ip_pool as ip_pool_mgr
import system_monitor


def _conn():
    return libvirt.open(config.LIBVIRT_URI)


def _interface_stats(iface: str) -> dict:
    try:
        r = subprocess.run(
            ["ip", "-s", "link", "show", iface],
            capture_output=True, text=True, timeout=3,
        )
        rx = tx = 0
        lines = r.stdout.splitlines()
        for i, ln in enumerate(lines):
            if "RX:" in ln and i + 1 < len(lines):
                rx = int(lines[i + 1].split()[0])
            if "TX:" in ln and i + 1 < len(lines):
                tx = int(lines[i + 1].split()[0])
        return {"rx_bytes": rx, "tx_bytes": tx}
    except Exception:
        return {"rx_bytes": 0, "tx_bytes": 0}


def _get_vm_ip_from_pool(vm_id: str) -> str | None:
    return ip_pool_mgr.get_vm_ip(vm_id)


def _get_vm_ip_from_arp(mac: str) -> str | None:
    if not mac:
        return None
    try:
        r = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            if mac.lower() in line.lower():
                return line.split()[0]
    except Exception:
        pass
    return None


def _get_vm_ip_from_dhcp_leases(mac: str) -> str | None:
    """libvirt DHCP lease'lerinden IP al."""
    if not mac:
        return None
    try:
        conn = _conn()
        for net in conn.listAllNetworks():
            if net.isActive():
                try:
                    leases = net.DHCPLeases()
                    for lease in leases:
                        if lease.get("mac", "").lower() == mac.lower():
                            conn.close()
                            return lease.get("ipaddr")
                except Exception:
                    pass
        conn.close()
    except Exception:
        pass
    return None


def _parse_vm_xml(xml_str: str) -> dict:
    try:
        root = ET.fromstring(xml_str)
        disks = []
        for d in root.findall(".//disk[@device='disk']/source"):
            path = d.get("file", "")
            if path:
                try:
                    size_gb = round(os.path.getsize(path) / 1073741824, 1)
                except Exception:
                    size_gb = 0
                disks.append({"path": path, "size_gb": size_gb})

        nics = []
        for iface in root.findall(".//interface"):
            mac_el = iface.find("mac")
            src_el = iface.find("source")
            nics.append({
                "mac":     mac_el.get("address", "") if mac_el is not None else "",
                "network": (src_el.get("network") or src_el.get("bridge", "")) if src_el is not None else "",
                "type":    iface.get("type", ""),
            })

        vnc_el = root.find(".//graphics[@type='vnc']")
        vnc_port = int(vnc_el.get("port", -1)) if vnc_el is not None else -1

        mem_el = root.find("memory")
        mem_mb = int(mem_el.text) // 1024 if mem_el is not None else 0

        vcpu_el = root.find("vcpu")
        vcpus = int(vcpu_el.text) if vcpu_el is not None else 0

        return {"disks": disks, "nics": nics, "vnc_port": vnc_port, "memory_mb": mem_mb, "vcpus": vcpus}
    except Exception:
        return {"disks": [], "nics": [], "vnc_port": -1, "memory_mb": 0, "vcpus": 0}


STATE_MAP = {
    libvirt.VIR_DOMAIN_NOSTATE:  "unknown",
    libvirt.VIR_DOMAIN_RUNNING:  "running",
    libvirt.VIR_DOMAIN_BLOCKED:  "blocked",
    libvirt.VIR_DOMAIN_PAUSED:   "paused",
    libvirt.VIR_DOMAIN_SHUTDOWN: "shutdown",
    libvirt.VIR_DOMAIN_SHUTOFF:  "stopped",
    libvirt.VIR_DOMAIN_CRASHED:  "crashed",
    libvirt.VIR_DOMAIN_PMSUSPENDED: "suspended",
}


def get_topology() -> dict:
    """Tam topoloji haritasını döndür."""

    # ── Host bilgisi ──────────────────────────────────────────────────────────
    host = system_monitor.get_host_info()
    stats = system_monitor.get_system_stats()

    try:
        host_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        host_ip = "127.0.0.1"

    node = {
        "type":     "hypervisor",
        "id":       "host",
        "name":     host.get("hostname", "adaos-host"),
        "ip":       host_ip,
        "os":       host.get("os", ""),
        "cpu_pct":  stats["cpu"]["percent"],
        "ram_pct":  stats["memory"]["percent"],
        "ram_used": stats["memory"]["used_mb"],
        "ram_total":stats["memory"]["total_mb"],
        "uptime":   host.get("uptime", ""),
        "kvm":      host.get("kvm_available", False),
        "status":   "online",
        "networks": [],
    }

    try:
        conn = _conn()
    except Exception as e:
        node["error"] = str(e)
        return node

    try:
        # ── Ağlar ─────────────────────────────────────────────────────────────
        all_networks = {}  # network_name → network_node

        for net in conn.listAllNetworks():
            xml_str = net.XMLDesc()
            root = ET.fromstring(xml_str)

            ip_el = root.find("ip")
            forward = root.find("forward")
            dhcp_range = root.find(".//dhcp/range")

            bridge = ""
            try:
                bridge = net.bridgeName() if net.isActive() else ""
            except Exception:
                pass

            net_stats = _interface_stats(bridge) if bridge else {}

            net_node = {
                "type":         "network",
                "id":           net.UUIDString(),
                "name":         net.name(),
                "bridge":       bridge,
                "active":       bool(net.isActive()),
                "autostart":    bool(net.autostart()),
                "forward_mode": forward.get("mode", "isolated") if forward is not None else "isolated",
                "gateway":      ip_el.get("address", "") if ip_el is not None else "",
                "netmask":      ip_el.get("netmask", "") if ip_el is not None else "",
                "dhcp_start":   dhcp_range.get("start", "") if dhcp_range is not None else "",
                "dhcp_end":     dhcp_range.get("end", "") if dhcp_range is not None else "",
                "rx_bytes":     net_stats.get("rx_bytes", 0),
                "tx_bytes":     net_stats.get("tx_bytes", 0),
                "vms":          [],
            }

            all_networks[net.name()] = net_node

        # ── VM'ler ────────────────────────────────────────────────────────────
        for dom in conn.listAllDomains():
            try:
                state, _ = dom.state()
                xml_str   = dom.XMLDesc()
                parsed    = _parse_vm_xml(xml_str)
                info      = dom.info()

                vm_state = STATE_MAP.get(state, "unknown")
                vm_id    = dom.UUIDString()

                # IP adresini bul (öncelik sırası)
                ip_addr = _get_vm_ip_from_pool(vm_id)

                if not ip_addr and parsed["nics"]:
                    primary_mac = parsed["nics"][0]["mac"]
                    ip_addr = (
                        _get_vm_ip_from_dhcp_leases(primary_mac) or
                        _get_vm_ip_from_arp(primary_mac)
                    )

                # CPU kullanım yüzdesi
                cpu_pct = 0.0
                try:
                    if dom.isActive():
                        cpu_stats = dom.getCPUStats(True)
                        if cpu_stats:
                            cpu_pct = round(cpu_stats[0].get("cpu_time", 0) / 1e9 / info[3] * 100, 1)
                            cpu_pct = min(cpu_pct, 100.0)
                except Exception:
                    pass

                vm_node = {
                    "type":       "vm",
                    "id":         vm_id,
                    "name":       dom.name(),
                    "state":      vm_state,
                    "active":     vm_state == "running",
                    "ip":         ip_addr or "",
                    "vcpus":      info[3],
                    "memory_mb":  info[1] // 1024,
                    "cpu_pct":    cpu_pct,
                    "vnc_port":   parsed["vnc_port"],
                    "disks":      parsed["disks"],
                    "nics":       parsed["nics"],
                    "autostart":  bool(dom.autostart()),
                }

                # Bu VM'i ağına ekle
                placed = False
                for nic in parsed["nics"]:
                    net_name = nic.get("network", "")
                    if net_name in all_networks:
                        all_networks[net_name]["vms"].append(vm_node)
                        placed = True
                        break

                if not placed:
                    # Ağ bulunamadıysa "default"a ekle ya da yeni bir "unknown" ağı yarat
                    if "default" in all_networks:
                        all_networks["default"]["vms"].append(vm_node)
                    else:
                        if "_unassigned" not in all_networks:
                            all_networks["_unassigned"] = {
                                "type": "network", "id": "_unassigned",
                                "name": "Ağsız VM'ler", "bridge": "",
                                "active": False, "autostart": False,
                                "forward_mode": "none", "gateway": "",
                                "vms": [],
                            }
                        all_networks["_unassigned"]["vms"].append(vm_node)

            except Exception:
                continue

        node["networks"] = list(all_networks.values())

    finally:
        conn.close()

    # ── IP Havuzları ──────────────────────────────────────────────────────────
    try:
        node["ip_pools"] = ip_pool_mgr.list_pools()
    except Exception:
        node["ip_pools"] = []

    node["timestamp"] = time.time()
    return node
