"""
OXware DVS Manager — Distributed Virtual Switch.
Manages cluster-wide OVS bridge configs stored in /var/lib/oxware/dvs_config.json.
Each DVS spans multiple nodes via VXLAN tunnels.
"""
import json, uuid, subprocess, logging, threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("oxware.dvs")
_DVS_FILE = Path("/var/lib/oxware/dvs_configs.json")
_lock = threading.Lock()


def _load():
    try:
        if _DVS_FILE.exists():
            return json.loads(_DVS_FILE.read_text())
    except Exception:
        pass
    return []


def _save(data):
    _DVS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _DVS_FILE.write_text(json.dumps(data, indent=2))


def list_dvs():
    with _lock:
        return _load()


def create_dvs(name, description="", vlan_id=0, mtu=1500, uplinks=None, nodes=None):
    """Create a new Distributed vSwitch definition."""
    dvs = {
        "id": str(uuid.uuid4()),
        "name": str(name).strip(),
        "description": str(description).strip(),
        "vlan_id": int(vlan_id),
        "mtu": int(mtu),
        "uplinks": uplinks or [],
        "nodes": nodes or [],
        "port_groups": [],
        "status": "created",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with _lock:
        all_dvs = _load()
        all_dvs.append(dvs)
        _save(all_dvs)
    return dvs


def delete_dvs(dvs_id):
    with _lock:
        all_dvs = _load()
        new_dvs = [d for d in all_dvs if d["id"] != dvs_id]
        if len(new_dvs) == len(all_dvs):
            return False
        _save(new_dvs)
    return True


def add_port_group(dvs_id, pg_name, vlan_id=0, pg_type="vm"):
    with _lock:
        all_dvs = _load()
        for dvs in all_dvs:
            if dvs["id"] == dvs_id:
                pg = {
                    "id": str(uuid.uuid4()),
                    "name": pg_name,
                    "vlan_id": int(vlan_id),
                    "type": pg_type,
                }
                dvs.setdefault("port_groups", []).append(pg)
                _save(all_dvs)
                return pg
    return None


def delete_port_group(dvs_id, pg_id):
    with _lock:
        all_dvs = _load()
        for dvs in all_dvs:
            if dvs["id"] == dvs_id:
                pgs = dvs.get("port_groups", [])
                new = [p for p in pgs if p.get("id") != pg_id]
                if len(new) != len(pgs):
                    dvs["port_groups"] = new
                    _save(all_dvs)
                    return True
    return False


_TEAMING = ("active-backup", "balance-slb", "balance-tcp", "lacp")


def set_uplinks(dvs_id, uplinks, teaming_mode="active-backup"):
    """Set the uplink pNIC list + NIC-teaming (bond) mode for a DVS."""
    if teaming_mode not in _TEAMING:
        teaming_mode = "active-backup"
    with _lock:
        all_dvs = _load()
        for dvs in all_dvs:
            if dvs["id"] == dvs_id:
                dvs["uplinks"] = [str(u).strip() for u in (uplinks or []) if str(u).strip()]
                dvs["teaming_mode"] = teaming_mode
                _save(all_dvs)
                return dvs
    return None


def add_node(dvs_id, node_ip):
    """Associate a cluster node with this DVS."""
    with _lock:
        all_dvs = _load()
        for dvs in all_dvs:
            if dvs["id"] == dvs_id:
                if node_ip not in dvs.get("nodes", []):
                    dvs.setdefault("nodes", []).append(node_ip)
                    _save(all_dvs)
                    return True
    return False


def get_ovs_bridges():
    """List OVS bridges on this host."""
    try:
        r = subprocess.run(["ovs-vsctl", "list-br"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            bridges = [b.strip() for b in r.stdout.strip().splitlines() if b.strip()]
            result = []
            for br in bridges:
                ports_r = subprocess.run(
                    ["ovs-vsctl", "list-ports", br],
                    capture_output=True, text=True, timeout=5
                )
                ports = [p.strip() for p in ports_r.stdout.strip().splitlines() if p.strip()]
                result.append({"name": br, "ports": ports})
            return result
    except FileNotFoundError:
        return []
    except Exception as e:
        log.warning("get_ovs_bridges: %s", e)
        return []


def create_vxlan_tunnel(bridge, remote_ip, vni=100):
    """Create VXLAN tunnel to a remote node for DVS spanning."""
    try:
        iface = f"vxlan{vni}"
        cmds = [
            ["ovs-vsctl", "add-port", bridge, iface],
            ["ovs-vsctl", "set", "interface", iface, "type=vxlan",
             f"options:remote_ip={remote_ip}", f"options:key={vni}"],
        ]
        for cmd in cmds:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if r.returncode != 0 and "already exists" not in r.stderr:
                return {"ok": False, "error": r.stderr.strip()}
        return {"ok": True, "interface": iface, "vni": vni, "remote": remote_ip}
    except Exception as e:
        return {"ok": False, "error": str(e)}
