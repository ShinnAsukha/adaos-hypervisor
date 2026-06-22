# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware network mode detection + per-VM IP audit.

Explains WHY VM IPs sometimes look wrong and surfaces the real address.

- NAT / routed / isolated networks: libvirt's own dnsmasq hands out the
  addresses, so libvirt DHCP leases are authoritative — the panel shows the
  correct per-VM IP.
- Bridge networks: VMs sit on the physical LAN and get their address from an
  EXTERNAL DHCP server. libvirt has no lease table for them, so DHCP-based
  lookups fall back to a wrong/host-looking value. The real address must come
  from the QEMU guest agent. This module detects the mode and reports both the
  libvirt-reported IP and the guest-agent IP per VM so the truth is visible.
"""
from __future__ import annotations
import logging

log = logging.getLogger("oxware.net_detect")


def _mod(name):
    try:
        return __import__(name)
    except Exception:
        try:
            return __import__(f"oxware.backend.{name}", fromlist=["*"])
        except Exception:
            return None


_MODE_INFO = {
    "nat": {
        "label": "NAT",
        "ip_source": "libvirt-lease",
        "explain": "VM'ler host arkasında özel IP alır (libvirt dnsmasq DHCP). "
                   "libvirt lease tablosu var → panel doğru IP gösterir.",
        "ok": True,
    },
    "route": {
        "label": "Routed",
        "ip_source": "libvirt-lease",
        "explain": "Yönlendirilmiş ağ; libvirt dnsmasq DHCP verir. Panel IP'yi "
                   "lease'den doğru okur.",
        "ok": True,
    },
    "bridge": {
        "label": "Bridge (harici DHCP)",
        "ip_source": "guest-agent",
        "explain": "VM'ler fiziksel LAN'da; IP'yi HARİCİ DHCP sunucusu verir. "
                   "libvirt lease tutmaz → DHCP'ye bakan görünüm yanlış/host IP "
                   "gösterebilir. Gerçek IP guest-agent'tan alınır.",
        "ok": False,
    },
    "isolated": {
        "label": "İzole",
        "ip_source": "libvirt-lease",
        "explain": "Dış bağlantı yok. DHCP tanımlıysa libvirt dnsmasq verir.",
        "ok": True,
    },
    "open": {
        "label": "Open",
        "ip_source": "guest-agent",
        "explain": "Açık mod; filtreleme yok. IP kaynağına göre guest-agent "
                   "önerilir.",
        "ok": False,
    },
}


def analyze_networks() -> dict:
    nm = _mod("network_manager")
    if not nm:
        return {"ok": False, "error": "network_manager yok"}
    out = []
    for n in nm.list_networks():
        mode = (n.get("forward_mode") or "isolated").lower()
        info = _MODE_INFO.get(mode, _MODE_INFO["isolated"])
        dhcp = n.get("dhcp")
        out.append({
            "name": n.get("name"),
            "mode": mode,
            "label": info["label"],
            "dhcp_enabled": bool(dhcp),
            "dhcp_range": (f"{dhcp.get('start','')}–{dhcp.get('end','')}"
                          if dhcp else "—"),
            "ip_source": info["ip_source"],
            "explain": info["explain"],
            "reliable_panel_ip": info["ok"],
        })
    return {"ok": True, "networks": out}


def _libvirt_ip(vm) -> str:
    for net in (vm.get("networks") or []):
        if net.get("ip"):
            return net["ip"]
    return ""


def _net_mode_map():
    nm = _mod("network_manager")
    m = {}
    if nm:
        try:
            for n in nm.list_networks():
                m[n.get("name")] = (n.get("forward_mode") or "isolated").lower()
        except Exception:
            pass
    return m


def vm_ip_audit() -> dict:
    """Per-VM: libvirt-reported IP vs real guest-agent IP, with the network
    mode — so bridge/DHCP mismatches are obvious."""
    vm = _mod("vm_manager")
    if not vm:
        return {"ok": False, "error": "vm_manager yok"}
    modes = _net_mode_map()
    rows = []
    for v in vm.list_vms():
        if v.get("state") != "running":
            continue
        nets = v.get("networks") or []
        netname = nets[0].get("network") if nets else ""
        mode = modes.get(netname, "?")
        lvip = _libvirt_ip(v)
        agent_ip = ""
        try:
            gi = vm.get_guest_agent_info(v["id"])
            for ifc in gi.get("interfaces", []):
                for a in ifc.get("ips", []):
                    if a.get("type") == "ipv4" and not a["ip"].startswith("127."):
                        agent_ip = a["ip"]; break
                if agent_ip:
                    break
        except Exception:
            pass
        real = agent_ip or lvip
        rows.append({
            "vm": v["name"], "network": netname, "mode": mode,
            "panel_ip": lvip or "—", "agent_ip": agent_ip or "—",
            "real_ip": real or "—",
            "mismatch": bool(agent_ip and lvip and agent_ip != lvip),
            "ip_source": ("guest-agent" if mode == "bridge" else "libvirt-lease"),
        })
    return {"ok": True, "vms": rows}
