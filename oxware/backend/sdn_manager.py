"""
OXware SDN Manager
──────────────────
Software Defined Networking — Open vSwitch (OVS) tabanlı ağ yönetimi.
OVS yüklü değilse: get_status {"ovs_available": False} döndürür.
"""

import json
import logging
import os
import subprocess
import threading
import uuid
from datetime import datetime

log = logging.getLogger("oxware.sdn")

SDN_NETWORKS_FILE = "/var/lib/oxware/sdn_networks.json"
_lock = threading.Lock()


# ── Yardımcı ──────────────────────────────────────────────────────────────────

def _ensure_dir(path: str):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass


def _run(*cmd, timeout: int = 15) -> tuple:
    """subprocess.run ile komut çalıştır. (stdout, stderr, returncode) döndür."""
    try:
        r = subprocess.run(
            list(cmd),
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except FileNotFoundError:
        return "", f"Komut bulunamadı: {cmd[0]}", 127
    except Exception as e:
        return "", str(e), -1


def _ovs_available() -> bool:
    """OVS kurulu mu kontrol et."""
    try:
        _, _, rc = _run("ovs-vsctl", "--version")
        return rc == 0
    except Exception:
        return False


def _err_no_ovs() -> dict:
    return {"error": "OVS not installed", "ovs_available": False}


# ── SDN Networks Dosyası ──────────────────────────────────────────────────────

def _load_networks() -> list:
    try:
        if os.path.exists(SDN_NETWORKS_FILE):
            with open(SDN_NETWORKS_FILE) as f:
                return json.load(f)
    except Exception as e:
        log.warning("SDN networks yükleme hatası: %s", e)
    return []


def _save_networks(data: list):
    _ensure_dir(SDN_NETWORKS_FILE)
    try:
        with open(SDN_NETWORKS_FILE, "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log.error("SDN networks kaydetme hatası: %s", e)


# ── OVS Durumu ────────────────────────────────────────────────────────────────

def get_status() -> dict:
    """OVS genel durumunu döndür."""
    try:
        if not _ovs_available():
            return {"ovs_available": False}

        stdout, _, _ = _run("ovs-vsctl", "--version")
        version = stdout.splitlines()[0] if stdout else "unknown"

        bridges = list_bridges()

        return {
            "ovs_available": True,
            "version": version,
            "bridges": bridges,
            "bridge_count": len(bridges),
        }
    except Exception as e:
        log.error("get_status hatası: %s", e)
        return {"ovs_available": False, "error": str(e)}


def list_bridges() -> list:
    """Tüm OVS bridge'leri listele."""
    try:
        if not _ovs_available():
            return []
        stdout, _, rc = _run("ovs-vsctl", "list-br")
        if rc != 0 or not stdout:
            return []
        return [b.strip() for b in stdout.splitlines() if b.strip()]
    except Exception as e:
        log.error("list_bridges hatası: %s", e)
        return []


def create_bridge(
    name: str,
    fail_mode: str = "standalone",
    datapath_type: str = "system",
) -> dict:
    """Yeni OVS bridge oluştur."""
    try:
        if not _ovs_available():
            return _err_no_ovs()

        _, stderr, rc = _run("ovs-vsctl", "add-br", name)
        if rc != 0:
            return {"success": False, "error": stderr}

        # fail_mode
        if fail_mode:
            _run("ovs-vsctl", "set-fail-mode", name, fail_mode)
        # datapath_type
        if datapath_type and datapath_type != "system":
            _run("ovs-vsctl", "set", "bridge", name, f"datapath_type={datapath_type}")

        log.info("Bridge oluşturuldu: %s", name)
        return {"success": True, "bridge": name, "fail_mode": fail_mode, "datapath_type": datapath_type}
    except Exception as e:
        log.error("create_bridge hatası: %s", e)
        return {"success": False, "error": str(e)}


def delete_bridge(name: str) -> dict:
    """OVS bridge'i sil."""
    try:
        if not _ovs_available():
            return _err_no_ovs()
        _, stderr, rc = _run("ovs-vsctl", "del-br", name)
        if rc != 0:
            return {"success": False, "error": stderr}
        log.info("Bridge silindi: %s", name)
        return {"success": True, "bridge": name}
    except Exception as e:
        log.error("delete_bridge hatası: %s", e)
        return {"success": False, "error": str(e)}


def add_port(
    bridge: str,
    port_name: str,
    tag: int = None,
    type_: str = None,
) -> dict:
    """Bridge'e port ekle."""
    try:
        if not _ovs_available():
            return _err_no_ovs()

        cmd = ["ovs-vsctl", "add-port", bridge, port_name]
        _, stderr, rc = _run(*cmd)
        if rc != 0:
            return {"success": False, "error": stderr}

        # VLAN tag
        if tag is not None:
            _run("ovs-vsctl", "set", "port", port_name, f"tag={tag}")
        # Port tipi (internal, patch, vxlan vs.)
        if type_:
            _run("ovs-vsctl", "set", "interface", port_name, f"type={type_}")

        log.info("Port eklendi: %s → %s", port_name, bridge)
        return {"success": True, "bridge": bridge, "port": port_name, "tag": tag, "type": type_}
    except Exception as e:
        log.error("add_port hatası: %s", e)
        return {"success": False, "error": str(e)}


def del_port(bridge: str, port_name: str) -> dict:
    """Bridge'den port sil."""
    try:
        if not _ovs_available():
            return _err_no_ovs()
        _, stderr, rc = _run("ovs-vsctl", "del-port", bridge, port_name)
        if rc != 0:
            return {"success": False, "error": stderr}
        log.info("Port silindi: %s ← %s", port_name, bridge)
        return {"success": True, "bridge": bridge, "port": port_name}
    except Exception as e:
        log.error("del_port hatası: %s", e)
        return {"success": False, "error": str(e)}


def list_ports(bridge: str) -> list:
    """Bridge'deki portları listele."""
    try:
        if not _ovs_available():
            return []
        stdout, _, rc = _run("ovs-vsctl", "list-ports", bridge)
        if rc != 0 or not stdout:
            return []
        return [p.strip() for p in stdout.splitlines() if p.strip()]
    except Exception as e:
        log.error("list_ports hatası: %s", e)
        return []


def set_controller(bridge: str, controller_url: str) -> dict:
    """OpenFlow controller bağla (örn: tcp:127.0.0.1:6653)."""
    try:
        if not _ovs_available():
            return _err_no_ovs()
        _, stderr, rc = _run("ovs-vsctl", "set-controller", bridge, controller_url)
        if rc != 0:
            return {"success": False, "error": stderr}
        log.info("Controller ayarlandı: %s → %s", bridge, controller_url)
        return {"success": True, "bridge": bridge, "controller": controller_url}
    except Exception as e:
        log.error("set_controller hatası: %s", e)
        return {"success": False, "error": str(e)}


def del_controller(bridge: str) -> dict:
    """Bridge'den controller kaldır."""
    try:
        if not _ovs_available():
            return _err_no_ovs()
        _, stderr, rc = _run("ovs-vsctl", "del-controller", bridge)
        if rc != 0:
            return {"success": False, "error": stderr}
        return {"success": True, "bridge": bridge}
    except Exception as e:
        log.error("del_controller hatası: %s", e)
        return {"success": False, "error": str(e)}


# ── SDN Network (yüksek seviye) ────────────────────────────────────────────────

def create_sdn_network(
    name: str,
    subnet: str,
    gateway: str,
    vlan_id: int = None,
) -> dict:
    """OVS bridge + libvirt network tanımı oluştur ve kaydet."""
    try:
        if not _ovs_available():
            return _err_no_ovs()

        network_id = str(uuid.uuid4())
        bridge_name = f"sdn-{name[:12]}"

        # OVS bridge oluştur
        br_result = create_bridge(bridge_name)
        if not br_result.get("success"):
            return {"success": False, "error": f"Bridge oluşturulamadı: {br_result.get('error')}"}

        # VLAN internal port
        if vlan_id is not None:
            add_port(bridge_name, f"{bridge_name}-vlan", tag=vlan_id, type_="internal")

        # libvirt network XML tanımı (basit)
        net_xml = f"""<network>
  <name>{name}</name>
  <uuid>{network_id}</uuid>
  <forward mode='bridge'/>
  <bridge name='{bridge_name}'/>
  <virtualport type='openvswitch'/>
</network>"""

        _, stderr, rc = _run(
            "virsh", "net-define", "/dev/stdin",
            timeout=10
        )
        # Not: stdin ile geçiremiyorsak geçici dosya kullan
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as tmp:
                tmp.write(net_xml)
                tmp_path = tmp.name
            _run("virsh", "net-define", tmp_path)
            _run("virsh", "net-start", name)
            _run("virsh", "net-autostart", name)
            os.unlink(tmp_path)
        except Exception as xe:
            log.debug("libvirt network tanımı atlandı: %s", xe)

        # Kaydet
        network = {
            "id": network_id,
            "name": name,
            "bridge": bridge_name,
            "subnet": subnet,
            "gateway": gateway,
            "vlan_id": vlan_id,
            "created_at": datetime.now().isoformat(),
        }
        with _lock:
            networks = _load_networks()
            networks.append(network)
            _save_networks(networks)

        log.info("SDN network oluşturuldu: %s (%s)", name, network_id)
        return {"success": True, "network": network}
    except Exception as e:
        log.error("create_sdn_network hatası: %s", e)
        return {"success": False, "error": str(e)}


def list_sdn_networks() -> list:
    """Kayıtlı SDN ağlarını listele."""
    try:
        with _lock:
            return _load_networks()
    except Exception as e:
        log.error("list_sdn_networks hatası: %s", e)
        return []


def delete_sdn_network(network_id: str) -> dict:
    """SDN ağını sil."""
    try:
        with _lock:
            networks = _load_networks()
            target = next((n for n in networks if n["id"] == network_id), None)
            if not target:
                return {"success": False, "error": "Ağ bulunamadı."}

            bridge_name = target.get("bridge", "")
            net_name    = target.get("name", "")

            # libvirt network kaldır
            if net_name:
                _run("virsh", "net-destroy", net_name)
                _run("virsh", "net-undefine", net_name)

            # OVS bridge kaldır
            if bridge_name and _ovs_available():
                delete_bridge(bridge_name)

            new_list = [n for n in networks if n["id"] != network_id]
            _save_networks(new_list)

        log.info("SDN network silindi: %s", network_id)
        return {"success": True, "deleted_id": network_id}
    except Exception as e:
        log.error("delete_sdn_network hatası: %s", e)
        return {"success": False, "error": str(e)}


def get_flow_table(bridge: str) -> dict:
    """OVS flow tablosunu döndür."""
    try:
        if not _ovs_available():
            return _err_no_ovs()
        stdout, stderr, rc = _run("ovs-ofctl", "dump-flows", bridge)
        if rc != 0:
            return {"success": False, "error": stderr}
        flows = [line.strip() for line in stdout.splitlines() if line.strip()]
        return {"success": True, "bridge": bridge, "flows": flows, "count": len(flows)}
    except Exception as e:
        log.error("get_flow_table hatası: %s", e)
        return {"success": False, "error": str(e)}
