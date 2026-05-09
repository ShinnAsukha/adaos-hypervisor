"""
vlan_manager.py — VLAN network yönetimi (Linux bridge + libvirt) (OXware Hypervisor)
Root yetkisi gerekir.
"""

import subprocess
import json
import logging
import os
import threading
import uuid
import re

log = logging.getLogger("oxware.vlan")

VLANS_FILE = "/var/lib/oxware/vlans.json"

_lock = threading.Lock()

# ---------------------------------------------------------------------------
# İç yardımcılar
# ---------------------------------------------------------------------------

def _run(*cmd):
    """subprocess.run çalıştırır; hata fırlatmaz."""
    try:
        result = subprocess.run(
            list(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            log.warning("Komut başarısız [%d]: %s | stderr: %s",
                        result.returncode, " ".join(cmd), result.stderr.strip())
        return result
    except FileNotFoundError:
        log.error("Komut bulunamadı: %s", cmd[0])
        return None
    except Exception as exc:
        log.exception("_run hatası: %s", exc)
        return None


def _load():
    """VLANS_FILE'dan vlan listesini yükler."""
    try:
        os.makedirs(os.path.dirname(VLANS_FILE), exist_ok=True)
        if not os.path.exists(VLANS_FILE):
            return {}
        with open(VLANS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log.error("VLANS_FILE okunamadı: %s", exc)
        return {}


def _save(data):
    """Vlan listesini VLANS_FILE'a kaydeder."""
    try:
        os.makedirs(os.path.dirname(VLANS_FILE), exist_ok=True)
        with open(VLANS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except OSError as exc:
        log.error("VLANS_FILE yazılamadı: %s", exc)
        raise


def _libvirt_network_xml(vlan_id, name, bridge_name):
    """libvirt network tanım XML'ini döner."""
    return f"""<network>
  <name>vlan{vlan_id}-{name}</name>
  <uuid>{uuid.uuid4()}</uuid>
  <forward mode='bridge'/>
  <bridge name='{bridge_name}'/>
  <vlan tag='{vlan_id}'>
    <trunk>no</trunk>
  </vlan>
</network>"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_vlans():
    """
    VLANS_FILE + ip link show ile enriched vlan listesini döner.
    """
    try:
        vlans = _load()

        # ip link show type vlan ile aktif olanları bul
        active_ifaces = set()
        result = _run("ip", "-j", "link", "show", "type", "vlan")
        if result and result.returncode == 0:
            try:
                iface_data = json.loads(result.stdout)
                for iface in iface_data:
                    active_ifaces.add(iface.get("ifname", ""))
            except (json.JSONDecodeError, TypeError):
                pass

        enriched = []
        for vid, vlan in vlans.items():
            entry = dict(vlan)
            iface_name = vlan.get("iface_name", "")
            entry["active"] = iface_name in active_ifaces
            enriched.append(entry)

        return enriched
    except Exception as exc:
        log.exception("list_vlans hatası: %s", exc)
        return []


def create_vlan(parent_iface, vlan_id, name, ip_address=None, gateway=None):
    """
    VLAN arayüzü oluşturur, libvirt network tanımlar ve VLANS_FILE'a kaydeder.
    """
    with _lock:
        try:
            vlan_id = int(vlan_id)
            iface_name = f"{parent_iface}.{vlan_id}"
            bridge_name = f"br-vlan{vlan_id}"

            # ip link add
            r = _run("ip", "link", "add", "link", parent_iface,
                     "name", iface_name, "type", "vlan", "id", str(vlan_id))
            if r is None or r.returncode != 0:
                return {"success": False, "error": f"VLAN arayüzü oluşturulamadı: {r.stderr.strip() if r else 'komut yok'}"}

            # ip link set up
            _run("ip", "link", "set", iface_name, "up")

            # ip addr add (opsiyonel)
            if ip_address:
                _run("ip", "addr", "add", ip_address, "dev", iface_name)

            # libvirt bridge ve network
            _run("ip", "link", "add", "name", bridge_name, "type", "bridge")
            _run("ip", "link", "set", iface_name, "master", bridge_name)
            _run("ip", "link", "set", bridge_name, "up")

            # libvirt network XML oluştur ve tanımla
            xml = _libvirt_network_xml(vlan_id, name, bridge_name)
            xml_path = f"/tmp/oxware_vlan_{vlan_id}.xml"
            try:
                with open(xml_path, "w", encoding="utf-8") as f:
                    f.write(xml)
                _run("virsh", "net-define", xml_path)
                _run("virsh", "net-start", f"vlan{vlan_id}-{name}")
                _run("virsh", "net-autostart", f"vlan{vlan_id}-{name}")
            except OSError as exc:
                log.warning("libvirt network tanımlanamadı: %s", exc)

            # VLANS_FILE'a kaydet
            vlans = _load()
            vlans[str(vlan_id)] = {
                "vlan_id": vlan_id,
                "name": name,
                "parent_iface": parent_iface,
                "iface_name": iface_name,
                "bridge_name": bridge_name,
                "ip_address": ip_address,
                "gateway": gateway,
                "libvirt_network": f"vlan{vlan_id}-{name}",
            }
            _save(vlans)

            log.info("VLAN oluşturuldu: %s (id=%d)", iface_name, vlan_id)
            return {
                "success": True,
                "vlan_id": vlan_id,
                "iface_name": iface_name,
                "bridge_name": bridge_name,
            }
        except Exception as exc:
            log.exception("create_vlan hatası: %s", exc)
            return {"success": False, "error": str(exc)}


def delete_vlan(vlan_id):
    """VLAN arayüzünü ve libvirt network'ü siler."""
    with _lock:
        try:
            vlan_id = int(vlan_id)
            vlans = _load()
            vlan = vlans.get(str(vlan_id))

            if not vlan:
                return {"success": False, "error": "VLAN bulunamadı"}

            iface_name = vlan.get("iface_name", f"*.{vlan_id}")
            bridge_name = vlan.get("bridge_name", f"br-vlan{vlan_id}")
            libvirt_net = vlan.get("libvirt_network", "")

            # libvirt network kaldır
            if libvirt_net:
                _run("virsh", "net-destroy", libvirt_net)
                _run("virsh", "net-undefine", libvirt_net)

            # Bridge ve vlan arayüzünü kaldır
            _run("ip", "link", "set", bridge_name, "down")
            _run("ip", "link", "del", bridge_name)
            _run("ip", "link", "del", iface_name)

            vlans.pop(str(vlan_id), None)
            _save(vlans)

            log.info("VLAN silindi: %d", vlan_id)
            return {"success": True, "vlan_id": vlan_id}
        except Exception as exc:
            log.exception("delete_vlan hatası: %s", exc)
            return {"success": False, "error": str(exc)}


def get_vlan(vlan_id):
    """Belirtilen VLAN bilgisini döner."""
    try:
        vlans = _load()
        vlan = vlans.get(str(vlan_id))
        if not vlan:
            return {"success": False, "error": "VLAN bulunamadı"}
        return {"success": True, "vlan": vlan}
    except Exception as exc:
        log.exception("get_vlan hatası: %s", exc)
        return {"success": False, "error": str(exc)}


def list_interfaces():
    """
    ip link show parse eder; mevcut arayüzleri listeler.
    """
    try:
        result = _run("ip", "-j", "link", "show")
        if result is None or result.returncode != 0:
            return []

        try:
            ifaces = json.loads(result.stdout)
            return [
                {
                    "name": iface.get("ifname"),
                    "type": iface.get("link_type"),
                    "state": iface.get("operstate"),
                    "mac": iface.get("address"),
                    "flags": iface.get("flags", []),
                }
                for iface in ifaces
            ]
        except (json.JSONDecodeError, TypeError):
            # Fallback: text parse
            interfaces = []
            for line in result.stdout.splitlines():
                m = re.match(r"\d+: (\S+):", line)
                if m:
                    interfaces.append({"name": m.group(1).rstrip("@")})
            return interfaces
    except Exception as exc:
        log.exception("list_interfaces hatası: %s", exc)
        return []


def attach_vm_to_vlan(vm_id, vlan_id):
    """VM'i VLAN'a bağlar (virsh attach-interface)."""
    try:
        vlans = _load()
        vlan = vlans.get(str(vlan_id))
        if not vlan:
            return {"success": False, "error": "VLAN bulunamadı"}

        network_name = vlan.get("libvirt_network", f"vlan{vlan_id}")
        result = _run("virsh", "attach-interface", str(vm_id),
                      "--type", "network",
                      "--source", network_name,
                      "--model", "virtio",
                      "--config", "--live")

        if result is None:
            return {"success": False, "error": "virsh bulunamadı"}

        success = result.returncode == 0
        log.info("VM %s VLAN %d'e bağlandı: %s", vm_id, vlan_id, success)
        return {
            "success": success,
            "vm_id": vm_id,
            "vlan_id": vlan_id,
            "stderr": result.stderr.strip(),
        }
    except Exception as exc:
        log.exception("attach_vm_to_vlan hatası: %s", exc)
        return {"success": False, "error": str(exc)}


def detach_vm_from_vlan(vm_id, vlan_id):
    """VM'i VLAN'dan ayırır (virsh detach-interface)."""
    try:
        vlans = _load()
        vlan = vlans.get(str(vlan_id))
        network_name = vlan.get("libvirt_network", f"vlan{vlan_id}") if vlan else f"vlan{vlan_id}"

        result = _run("virsh", "detach-interface", str(vm_id),
                      "--type", "network",
                      "--config", "--live")

        if result is None:
            return {"success": False, "error": "virsh bulunamadı"}

        success = result.returncode == 0
        log.info("VM %s VLAN %d'den ayrıldı: %s", vm_id, vlan_id, success)
        return {
            "success": success,
            "vm_id": vm_id,
            "vlan_id": vlan_id,
            "stderr": result.stderr.strip(),
        }
    except Exception as exc:
        log.exception("detach_vm_from_vlan hatası: %s", exc)
        return {"success": False, "error": str(exc)}


def get_vlan_stats(vlan_id):
    """ip -s link show ile VLAN arayüz istatistiklerini döner."""
    try:
        vlans = _load()
        vlan = vlans.get(str(vlan_id))
        if not vlan:
            return {"success": False, "error": "VLAN bulunamadı"}

        iface_name = vlan.get("iface_name", f"*.{vlan_id}")

        result = _run("ip", "-j", "-s", "link", "show", iface_name)
        if result is None or result.returncode != 0:
            return {"success": False, "error": "Arayüz bulunamadı"}

        try:
            data = json.loads(result.stdout)
            if data:
                stats = data[0].get("stats64", data[0].get("stats", {}))
                return {
                    "success": True,
                    "iface": iface_name,
                    "rx_bytes": stats.get("rx", {}).get("bytes", 0),
                    "tx_bytes": stats.get("tx", {}).get("bytes", 0),
                    "rx_packets": stats.get("rx", {}).get("packets", 0),
                    "tx_packets": stats.get("tx", {}).get("packets", 0),
                    "rx_errors": stats.get("rx", {}).get("errors", 0),
                    "tx_errors": stats.get("tx", {}).get("errors", 0),
                }
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            log.warning("Stats JSON parse hatası: %s", exc)

        return {"success": True, "iface": iface_name, "raw": result.stdout}
    except Exception as exc:
        log.exception("get_vlan_stats hatası: %s", exc)
        return {"success": False, "error": str(exc)}
