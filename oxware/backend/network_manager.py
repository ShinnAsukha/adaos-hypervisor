import libvirt
import xml.etree.ElementTree as ET
import subprocess
import config

LIBVIRT_URI = config.LIBVIRT_URI


def _connect():
    return libvirt.open(LIBVIRT_URI)


def list_networks():
    conn = _connect()
    nets = []
    try:
        for net in conn.listAllNetworks():
            xml_str = net.XMLDesc()
            root = ET.fromstring(xml_str)

            forward = root.find("forward")
            ip_el = root.find("ip")
            dhcp_el = root.find(".//dhcp/range") if ip_el is not None else None

            nets.append({
                "uuid": net.UUIDString(),
                "name": net.name(),
                "active": bool(net.isActive()),
                "autostart": bool(net.autostart()),
                "bridge": net.bridgeName() if net.isActive() else "",
                "forward_mode": forward.get("mode", "nat") if forward is not None else "isolated",
                "ip": ip_el.get("address", "") if ip_el is not None else "",
                "netmask": ip_el.get("netmask", "") if ip_el is not None else "",
                "dhcp": {
                    "start": dhcp_el.get("start", "") if dhcp_el is not None else "",
                    "end": dhcp_el.get("end", "") if dhcp_el is not None else "",
                } if dhcp_el is not None else None,
            })
    finally:
        conn.close()
    return nets


def create_network(name, forward_mode="nat", bridge_name=None,
                   ip_address="192.168.100.1", netmask="255.255.255.0",
                   dhcp_start="192.168.100.100", dhcp_end="192.168.100.200",
                   bridge_iface=None):

    # Bridge modu: fiziksel arayüze direkt bridge — libvirt DHCP/IP yok
    if forward_mode == "bridge":
        iface = bridge_iface or "enp1s0"
        xml = f"""<network>
  <name>{name}</name>
  <forward mode='bridge'/>
  <bridge name='{iface}'/>
</network>"""
        conn = _connect()
        try:
            net = conn.networkDefineXML(xml)
            net.setAutostart(1)
            net.create()
            return {"uuid": net.UUIDString(), "name": name, "status": "created", "mode": "bridge"}
        finally:
            conn.close()

    if not bridge_name:
        bridge_name = f"virbr-{name[:8]}"

    forward_xml = ""
    if forward_mode in ("nat", "route"):
        forward_xml = f"<forward mode='{forward_mode}'/>"

    xml = f"""<network>
  <name>{name}</name>
  {forward_xml}
  <bridge name='{bridge_name}' stp='on' delay='0'/>
  <ip address='{ip_address}' netmask='{netmask}'>
    <dhcp>
      <range start='{dhcp_start}' end='{dhcp_end}'/>
    </dhcp>
  </ip>
</network>"""

    conn = _connect()
    try:
        net = conn.networkDefineXML(xml)
        net.setAutostart(1)
        net.create()
        return {"uuid": net.UUIDString(), "name": name, "status": "created"}
    finally:
        conn.close()


def delete_network(net_uuid):
    conn = _connect()
    try:
        try:
            net = conn.networkLookupByUUIDString(net_uuid)
        except libvirt.libvirtError:
            net = conn.networkLookupByName(net_uuid)

        if net.isActive():
            net.destroy()
        net.undefine()
        return {"status": "deleted"}
    finally:
        conn.close()


def start_network(net_uuid):
    conn = _connect()
    try:
        net = conn.networkLookupByUUIDString(net_uuid)
        net.create()
        return {"status": "started"}
    finally:
        conn.close()


def stop_network(net_uuid):
    conn = _connect()
    try:
        net = conn.networkLookupByUUIDString(net_uuid)
        net.destroy()
        return {"status": "stopped"}
    finally:
        conn.close()


def set_network_autostart(net_uuid, enabled: bool):
    conn = _connect()
    try:
        net = conn.networkLookupByUUIDString(net_uuid)
        net.setAutostart(1 if enabled else 0)
        return {"ok": True, "autostart": enabled}
    finally:
        conn.close()

def get_network_info(net_uuid):
    """Get detailed info for a single network."""
    conn = _connect()
    try:
        net = conn.networkLookupByUUIDString(net_uuid)
        import xml.etree.ElementTree as ET
        root = ET.fromstring(net.XMLDesc(0))
        ip_el = root.find("ip")
        dhcp_el = ip_el.find("dhcp") if ip_el is not None else None
        range_el = dhcp_el.find("range") if dhcp_el is not None else None
        return {
            "name": net.name(),
            "uuid": net_uuid,
            "active": bool(net.isActive()),
            "autostart": bool(net.autostart()),
            "bridge": net.bridgeName() if net.isActive() else "",
            "mode": root.findtext("forward/@mode") or (root.find("forward").get("mode") if root.find("forward") is not None else "nat"),
            "gateway": ip_el.get("address") if ip_el is not None else None,
            "netmask": ip_el.get("netmask") if ip_el is not None else None,
            "dhcp_start": range_el.get("start") if range_el is not None else None,
            "dhcp_end": range_el.get("end") if range_el is not None else None,
        }
    finally:
        conn.close()


def get_host_interfaces():
    result = subprocess.run(
        ["ip", "-j", "addr"],
        capture_output=True, text=True
    )
    interfaces = []
    try:
        import json
        ifaces = json.loads(result.stdout)
        for iface in ifaces:
            addrs = [
                a["local"]
                for a in iface.get("addr_info", [])
                if a.get("family") == "inet"
            ]
            interfaces.append({
                "name": iface.get("ifname", ""),
                "state": iface.get("operstate", "UNKNOWN").lower(),
                "mac": iface.get("address", ""),
                "addresses": addrs,
                "flags": iface.get("flags", []),
                "mtu": iface.get("mtu", 1500),
            })
    except Exception:
        pass
    return interfaces
