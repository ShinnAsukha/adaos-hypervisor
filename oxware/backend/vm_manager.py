import libvirt
import xml.etree.ElementTree as ET
import subprocess
import os
import time
import json
import uuid
import logging
import threading
import config

_log = logging.getLogger("oxware.vm_manager")

LIBVIRT_URI = config.LIBVIRT_URI

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

_VNC_REGISTRY_FILE = os.path.join(config.DATA_DIR, "vnc_registry.json")

# ISO kurulum monitörleri: vm_uuid → Thread
_install_monitors: dict = {}


def _monitor_install(vm_uuid: str, vm_name: str, on_complete=None):
    """
    ISO ile kurulan VM'i izle.
    Kurulum bitip VM kapanınca:
      1. CDROM'u XML'den kaldır
      2. Boot order → hd (disk)
      3. VM'i yeniden başlat
    """
    log = logging.getLogger("oxware.install_monitor")
    log.info("Kurulum monitörü başladı: %s (%s)", vm_name, vm_uuid)

    was_running = False
    timeout    = 7200   # 2 saat max
    elapsed    = 0

    while elapsed < timeout:
        try:
            conn = _connect()
            try:
                dom   = conn.lookupByUUIDString(vm_uuid)
                state, _ = dom.state()
                running   = (state == libvirt.VIR_DOMAIN_RUNNING)

                if running:
                    was_running = True
                elif was_running and not running:
                    # VM çalışıyordu → durdu = kurulum tamamlandı
                    log.info("Kurulum bitti: %s — cdrom eject, boot=hd, başlatılıyor", vm_name)

                    xml_str = dom.XMLDesc(0)
                    root    = ET.fromstring(xml_str)

                    # cdrom disk elementlerini kaldır
                    devices = root.find("devices")
                    if devices is not None:
                        for disk in list(devices.findall("disk")):
                            if disk.get("device") == "cdrom":
                                devices.remove(disk)

                    # boot order → sadece hd
                    os_el = root.find("os")
                    if os_el is not None:
                        for b in list(os_el.findall("boot")):
                            os_el.remove(b)
                        boot_el = ET.SubElement(os_el, "boot")
                        boot_el.set("dev", "hd")

                    # on_reboot → restart (kurulum sırasında destroy'du)
                    for tag in ("on_reboot",):
                        el = root.find(tag)
                        if el is not None:
                            el.text = "restart"

                    new_xml = ET.tostring(root, encoding="unicode")

                    conn2 = _connect()
                    try:
                        conn2.defineXML(new_xml)          # kalıcı kaydet
                        dom2 = conn2.lookupByUUIDString(vm_uuid)
                        # Yarım kalmış state'i temizle — force stop sonra start
                        try:
                            dom2.destroy()
                        except Exception:
                            pass
                        time.sleep(2)
                        dom2.create()                     # diskten boot
                        log.info("VM diskten boot ile yeniden başlatıldı: %s", vm_name)
                    finally:
                        conn2.close()

                    # Callback: NAT sync vs. için çağır
                    if on_complete:
                        try:
                            threading.Thread(
                                target=on_complete,
                                args=(vm_uuid, vm_name),
                                daemon=True,
                                name=f"post-install-{vm_name}"
                            ).start()
                        except Exception as _cb_err:
                            log.warning("on_complete callback hatası: %s", _cb_err)

                    break   # monitör işi bitti
            finally:
                conn.close()
        except Exception as ex:
            log.warning("Install monitor hata (%s): %s", vm_name, ex)

        time.sleep(5)
        elapsed += 5

    _install_monitors.pop(vm_uuid, None)
    log.info("Kurulum monitörü durdu: %s", vm_name)


def _connect():
    return libvirt.open(LIBVIRT_URI)


def _load_vnc_registry():
    if os.path.exists(_VNC_REGISTRY_FILE):
        with open(_VNC_REGISTRY_FILE) as f:
            return json.load(f)
    return {}


def _save_vnc_registry(reg):
    with open(_VNC_REGISTRY_FILE, "w") as f:
        json.dump(reg, f, indent=2)


def _next_vnc_port():
    reg = _load_vnc_registry()
    used = set(reg.values())
    for p in range(config.VNC_START, config.VNC_END + 1):
        if p not in used:
            return p
    raise RuntimeError("Boş VNC portu bulunamadı")


def _get_domain_stats(dom):
    try:
        state, reason = dom.state()
        info = dom.info()
        mem_used = info[2]
        mem_total = info[1]
        cpu_time = info[4]
        return {
            "state": STATE_MAP.get(state, "unknown"),
            "cpu_time": cpu_time,
            "memory_used_kb": mem_used,
            "memory_max_kb": mem_total,
        }
    except Exception:
        return {"state": "unknown", "cpu_time": 0, "memory_used_kb": 0, "memory_max_kb": 0}


def _parse_disk_info(xml_str):
    disks = []
    try:
        root = ET.fromstring(xml_str)
        for disk in root.findall(".//disk[@type='file'][@device='disk']"):
            source = disk.find("source")
            target = disk.find("target")
            if source is not None and target is not None:
                disks.append({
                    "path": source.get("file", ""),
                    "device": target.get("dev", ""),
                    "bus": target.get("bus", ""),
                })
    except Exception:
        pass
    return disks


def _parse_net_info(xml_str):
    interfaces = []
    try:
        root = ET.fromstring(xml_str)
        for iface in root.findall(".//interface"):
            mac = iface.find("mac")
            source = iface.find("source")
            target = iface.find("target")
            interfaces.append({
                "mac": mac.get("address", "") if mac is not None else "",
                "network": source.get("network", source.get("bridge", "")) if source is not None else "",
                "device": target.get("dev", "") if target is not None else "",
                "type": iface.get("type", ""),
            })
    except Exception:
        pass
    return interfaces


def _parse_vnc_port(xml_str):
    try:
        root = ET.fromstring(xml_str)
        graphics = root.find(".//graphics[@type='vnc']")
        if graphics is not None:
            port = graphics.get("port", "-1")
            return int(port)
    except Exception:
        pass
    return -1


def list_vms():
    conn = _connect()
    vms = []
    try:
        for dom in conn.listAllDomains():
            stats = _get_domain_stats(dom)
            xml_str = dom.XMLDesc()
            disks = _parse_disk_info(xml_str)
            nets = _parse_net_info(xml_str)
            vnc_port = _parse_vnc_port(xml_str)

            info = dom.info()
            vms.append({
                "id": dom.UUIDString(),
                "name": dom.name(),
                "state": stats["state"],
                "vcpus": info[3],
                "memory_mb": info[1] // 1024,
                "memory_max_mb": info[1] // 1024,
                "cpu_time": stats["cpu_time"],
                "disks": disks,
                "networks": nets,
                "vnc_port": vnc_port,
                "autostart": bool(dom.autostart()),
            })
    finally:
        conn.close()
    return vms


def get_vm(vm_id):
    conn = _connect()
    try:
        try:
            dom = conn.lookupByUUIDString(vm_id)
        except libvirt.libvirtError:
            dom = conn.lookupByName(vm_id)

        stats = _get_domain_stats(dom)
        xml_str = dom.XMLDesc()
        disks = _parse_disk_info(xml_str)
        nets = _parse_net_info(xml_str)
        vnc_port = _parse_vnc_port(xml_str)
        info = dom.info()

        return {
            "id": dom.UUIDString(),
            "name": dom.name(),
            "state": stats["state"],
            "vcpus": info[3],
            "memory_mb": info[1] // 1024,
            "cpu_time": stats["cpu_time"],
            "disks": disks,
            "networks": nets,
            "vnc_port": vnc_port,
            "autostart": bool(dom.autostart()),
            "xml": xml_str,
        }
    finally:
        conn.close()


def _generate_mac() -> str:
    """QEMU prefix (52:54:00) ile rastgele MAC üret."""
    return '52:54:00:{:02x}:{:02x}:{:02x}'.format(*os.urandom(3))


def _flush_dnsmasq_lease(mac: str):
    """dnsmasq lease dosyasından MAC'e ait dynamic lease'i sil + HUP gönder."""
    lease_files = [
        "/var/lib/libvirt/dnsmasq/default.leases",
        "/var/lib/misc/dnsmasq.leases",
    ]
    for lf in lease_files:
        if not os.path.exists(lf):
            continue
        try:
            with open(lf) as f:
                lines = f.readlines()
            new_lines = [l for l in lines if mac.lower() not in l.lower()]
            if len(new_lines) != len(lines):
                with open(lf, "w") as f:
                    f.writelines(new_lines)
                _log.info("Lease silindi: %s → %s", mac, lf)
        except Exception as e:
            _log.warning("Lease silinemedi %s: %s", lf, e)
    # dnsmasq'a HUP gönder — lease dosyasını yeniden yüklesin
    try:
        subprocess.run(["kill", "-HUP", "$(pgrep dnsmasq)"],
                       shell=True, capture_output=True, timeout=5)
        subprocess.run(["pkill", "-HUP", "dnsmasq"],
                       capture_output=True, timeout=5)
    except Exception:
        pass


def add_dhcp_host(network: str, mac: str, ip: str, hostname: str = "") -> bool:
    """Libvirt ağına static DHCP kaydı ekle (MAC→IP). dnsmasq anında görür."""
    host_xml = f'<host mac="{mac}" ip="{ip}"'
    if hostname:
        host_xml += f' name="{hostname}"'
    host_xml += '/>'

    # Önce aynı MAC için var olan eski kayıtları temizle
    try:
        dump = subprocess.run(
            ["virsh", "net-dumpxml", network],
            capture_output=True, text=True, timeout=10
        )
        import xml.etree.ElementTree as _ET
        root = _ET.fromstring(dump.stdout)
        for host in root.findall(".//dhcp/host"):
            if host.get("mac", "").lower() == mac.lower():
                old_ip = host.get("ip", "")
                if old_ip != ip:
                    old_xml = f'<host mac="{mac}" ip="{old_ip}"/>'
                    subprocess.run(
                        ["virsh", "net-update", network, "delete", "ip-dhcp-host",
                         old_xml, "--live", "--config"],
                        capture_output=True, timeout=10
                    )
                    _log.info("Eski DHCP entry silindi: %s → %s", mac, old_ip)
    except Exception as _ce:
        _log.warning("Eski entry temizleme hatası: %s", _ce)

    # Eski dynamic lease'i de sil
    _flush_dnsmasq_lease(mac)

    try:
        r = subprocess.run(
            ["virsh", "net-update", network, "add", "ip-dhcp-host",
             host_xml, "--live", "--config"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            _log.info("DHCP host eklendi: %s → %s (%s)", mac, ip, network)
            return True
        if "already exists" in r.stderr.lower() or "already" in r.stdout.lower():
            _log.info("DHCP host zaten mevcut: %s → %s", mac, ip)
            return True
        _log.warning("DHCP host eklenemedi: %s", r.stderr.strip())
        return False
    except Exception as e:
        _log.warning("add_dhcp_host hata: %s", e)
        return False


def remove_dhcp_host(network: str, mac: str, ip: str) -> bool:
    """Libvirt ağından static DHCP kaydını sil."""
    host_xml = f'<host mac="{mac}" ip="{ip}"/>'
    try:
        r = subprocess.run(
            ["virsh", "net-update", network, "delete", "ip-dhcp-host",
             host_xml, "--live", "--config"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            _log.info("DHCP host silindi: %s → %s (%s)", mac, ip, network)
            return True
        _log.warning("DHCP host silinemedi: %s", r.stderr.strip())
        return False
    except Exception as e:
        _log.warning("remove_dhcp_host hata: %s", e)
        return False


def create_vm(name, memory_mb, vcpus, disk_gb, iso_path=None,
              network="default", disk_format="qcow2", os_variant="generic",
              boot_order="cdrom,hd", mac: str = None, disk_bus: str = "sata",
              cpu_mode: str = "host-model"):

    vm_uuid  = str(uuid.uuid4())
    vm_mac   = mac or _generate_mac()          # stable MAC for DHCP static entry
    disk_path = os.path.join(config.DISK_DIR, f"{name}.qcow2")
    vnc_port = _next_vnc_port()
    disk_dev = "vda" if disk_bus == "virtio" else "sda"

    # Windows tespiti: ISO adı veya os_variant "win" içeriyorsa
    _iso_name = os.path.basename(iso_path or "").lower()
    is_windows = (
        "win" in _iso_name or "windows" in _iso_name or
        "win" in os_variant.lower()
    )
    nic_model = "e1000" if is_windows else "virtio"

    os.makedirs(config.DISK_DIR, exist_ok=True)

    # Disk oluştur
    subprocess.run(
        ["qemu-img", "create", "-f", disk_format, disk_path, f"{disk_gb}G"],
        check=True, capture_output=True
    )

    # XML şablonu
    cpu_check = "none" if cpu_mode == "host-passthrough" else "partial"
    cpu_model_xml = "" if cpu_mode == "host-passthrough" else "    <model fallback='allow'/>"
    # cdrom her zaman sata/sdb — disk ile çakışmaz (virtio vda, sata sda)
    cdrom_dev = "sdb"
    iso_block = ""
    if iso_path and os.path.exists(iso_path):
        iso_block = f"""
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='{iso_path}'/>
      <target dev='{cdrom_dev}' bus='sata'/>
      <readonly/>
    </disk>"""

    boot_xml = "".join(
        f"<boot dev='{dev}'/>"
        for dev in boot_order.split(",")
    )

    xml = f"""<domain type='kvm'>
  <name>{name}</name>
  <uuid>{vm_uuid}</uuid>
  <memory unit='MiB'>{memory_mb}</memory>
  <currentMemory unit='MiB'>{memory_mb}</currentMemory>
  <vcpu placement='static'>{vcpus}</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-6.2'>hvm</type>
    {boot_xml}
  </os>
  <features>
    <acpi/>
    <apic/>
    <vmport state='off'/>{"" if not is_windows else """
    <hyperv mode='custom'>
      <relaxed state='on'/>
      <vapic state='on'/>
      <spinlocks state='on' retries='8191'/>
      <vpindex state='on'/>
      <synic state='on'/>
      <stimer state='on'/>
      <reset state='on'/>
    </hyperv>"""}
  </features>
  <cpu mode='{cpu_mode}' check='{cpu_check}'>
{cpu_model_xml}
  </cpu>
  <clock offset='{"localtime" if is_windows else "utc"}'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>{'destroy' if iso_path and os.path.exists(iso_path) else 'restart'}</on_reboot>
  <on_crash>destroy</on_crash>
  <pm>
    <suspend-to-mem enabled='no'/>
    <suspend-to-disk enabled='no'/>
  </pm>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='{disk_format}' cache='none' io='native'/>
      <source file='{disk_path}'/>
      <target dev='{disk_dev}' bus='{disk_bus}'/>
    </disk>{iso_block}
    <interface type='network'>
      <mac address='{vm_mac}' />
      <source network='{network}'/>
      <model type='{nic_model}'/>
    </interface>
    <serial type='pty'>
      <target type='isa-serial' port='0'>
        <model name='isa-serial'/>
      </target>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <channel type='unix'>
      <target type='virtio' name='org.qemu.guest_agent.0'/>
    </channel>
    <input type='mouse' bus='ps2'/>
    <input type='keyboard' bus='ps2'/>
    <graphics type='vnc' port='{vnc_port}' autoport='no' listen='0.0.0.0' keymap='tr'>
      <listen type='address' address='0.0.0.0'/>
    </graphics>
    <sound model='ich9'>
    </sound>
    <video>
      <model type='virtio' heads='1' primary='yes'/>
    </video>
    <memballoon model='virtio'>
    </memballoon>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
  </devices>
</domain>"""

    conn = _connect()
    try:
        dom = conn.defineXML(xml)
        dom.setAutostart(1)   # host restart'ta VM otomatik başlasın
        reg = _load_vnc_registry()
        reg[vm_uuid] = vnc_port
        _save_vnc_registry(reg)

        # ISO varsa kurulum monitörü başlat (otomatik eject + boot fix)
        if iso_path and os.path.exists(iso_path):
            t = threading.Thread(
                target=_monitor_install,
                args=(vm_uuid, name),
                daemon=True,
                name=f"install-monitor-{name}"
            )
            _install_monitors[vm_uuid] = t
            t.start()

        return {"id": vm_uuid, "name": name, "vnc_port": vnc_port, "mac": vm_mac}
    finally:
        conn.close()


def start_vm(vm_id):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        if dom.isActive():
            return {"status": "already_running"}
        dom.create()
        return {"status": "started"}
    finally:
        conn.close()


def stop_vm(vm_id, force=False):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        if not dom.isActive():
            return {"status": "already_stopped"}
        if force:
            dom.destroy()
            return {"status": "forced_stop"}
        dom.shutdown()
        return {"status": "shutting_down"}
    finally:
        conn.close()


def reboot_vm(vm_id, force=False):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        if not dom.isActive():
            raise ValueError("VM çalışmıyor")
        if force:
            dom.reset(0)
        else:
            dom.reboot(0)
        return {"status": "rebooting"}
    finally:
        conn.close()


def pause_vm(vm_id):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        dom.suspend()
        return {"status": "paused"}
    finally:
        conn.close()


def resume_vm(vm_id):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        dom.resume()
        return {"status": "resumed"}
    finally:
        conn.close()


def delete_vm(vm_id, delete_disk=True):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)

        if dom.isActive():
            dom.destroy()
            time.sleep(1)

        xml_str = dom.XMLDesc()
        disks = _parse_disk_info(xml_str)

        dom.undefineFlags(
            libvirt.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE |
            libvirt.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA
        )

        if delete_disk:
            for disk in disks:
                path = disk.get("path", "")
                if path and os.path.exists(path):
                    os.remove(path)

        reg = _load_vnc_registry()
        reg.pop(vm_id, None)
        _save_vnc_registry(reg)

        return {"status": "deleted"}
    finally:
        conn.close()


def get_vm_stats(vm_id):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        if not dom.isActive():
            return {"state": "stopped"}

        info = dom.info()
        stats = dom.getCPUStats(True)[0]

        # Disk I/O
        disk_stats = {}
        xml_str = dom.XMLDesc()
        for disk in _parse_disk_info(xml_str):
            dev = disk.get("device", "vda")
            try:
                rd, wr = dom.blockStats(dev)[:2], dom.blockStats(dev)[2:4]
                disk_stats[dev] = {"read_bytes": rd[0], "write_bytes": wr[0]}
            except Exception:
                pass

        # Ağ istatistikleri
        net_stats = {}
        for iface in _parse_net_info(xml_str):
            dev = iface.get("device", "")
            if dev:
                try:
                    ns = dom.interfaceStats(dev)
                    net_stats[dev] = {
                        "rx_bytes": ns[0], "tx_bytes": ns[4],
                        "rx_packets": ns[1], "tx_packets": ns[5],
                    }
                except Exception:
                    pass

        return {
            "state": STATE_MAP.get(info[0], "unknown"),
            "cpu_time_ns": stats.get("cpu_time", 0),
            "memory_kb": info[1],
            "vcpus": info[3],
            "disk_stats": disk_stats,
            "net_stats": net_stats,
        }
    finally:
        conn.close()


def set_autostart(vm_id, enabled):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        dom.setAutostart(1 if enabled else 0)
        return {"autostart": enabled}
    finally:
        conn.close()


def take_snapshot(vm_id, snap_name, description=""):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        xml = f"""<domainsnapshot>
  <name>{snap_name}</name>
  <description>{description}</description>
</domainsnapshot>"""
        dom.snapshotCreateXML(xml, 0)
        return {"status": "snapshot_created", "name": snap_name}
    finally:
        conn.close()


def list_snapshots(vm_id):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        snaps = []
        for snap in dom.listAllSnapshots():
            xml_str = snap.getXMLDesc()
            root = ET.fromstring(xml_str)
            created_el = root.find("creationTime")
            snaps.append({
                "name": snap.getName(),
                "created": int(created_el.text) if created_el is not None else 0,
                "description": (root.findtext("description") or ""),
                "current": snap.isCurrent(),
            })
        return snaps
    finally:
        conn.close()


def revert_snapshot(vm_id, snap_name):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        snap = dom.snapshotLookupByName(snap_name)
        dom.revertToSnapshot(snap)
        return {"status": "reverted", "snapshot": snap_name}
    finally:
        conn.close()


def delete_snapshot(vm_id, snap_name):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        snap = dom.snapshotLookupByName(snap_name)
        snap.delete()
        return {"status": "deleted", "snapshot": snap_name}
    finally:
        conn.close()


# ── Hardware Tuning & Hot-Plug ─────────────────────────────────────────────────

def get_hardware_config(vm_id: str) -> dict:
    """VM'nin tam donanım yapılandırmasını döndür (CPU modu, nested virt, NIC'ler, diskler)."""
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        xml_str = dom.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
        root = ET.fromstring(xml_str)
        state_val, _ = dom.state()
        running = (state_val == libvirt.VIR_DOMAIN_RUNNING)

        # CPU
        vcpu_el = root.find("vcpu")
        vcpu_max     = int(vcpu_el.text) if vcpu_el is not None else 1
        vcpu_current = int(vcpu_el.get("current", vcpu_max)) if vcpu_el is not None else vcpu_max
        cpu_el   = root.find("cpu")
        cpu_mode = cpu_el.get("mode", "custom") if cpu_el is not None else "custom"
        nested   = False
        if cpu_el is not None:
            for feat in cpu_el.findall("feature"):
                if feat.get("name") in ("vmx", "svm") and feat.get("policy") == "require":
                    nested = True
                    break

        # Memory
        mem_el     = root.find("memory")
        mem_max_kb = int(mem_el.text) if mem_el is not None else 0
        cur_el     = root.find("currentMemory")
        mem_cur_kb = int(cur_el.text) if cur_el is not None else mem_max_kb

        # Disks (include cdrom so frontend can show eject button)
        disks = []
        for disk in root.findall(".//disk"):
            dev_type = disk.get("device", "disk")   # "disk" or "cdrom"
            if dev_type not in ("disk", "cdrom"):
                continue
            src  = disk.find("source")
            tgt  = disk.find("target")
            drv  = disk.find("driver")
            disks.append({
                "path":        src.get("file", "") if src is not None else "",
                "target":      tgt.get("dev", "")  if tgt is not None else "",
                "bus":         tgt.get("bus", "")  if tgt is not None else "",
                "format":      drv.get("type", "raw") if drv is not None else "raw",
                "device_type": dev_type,
            })

        # NICs
        nics = []
        for iface in root.findall(".//interface"):
            mac_el  = iface.find("mac")
            src_el  = iface.find("source")
            mdl_el  = iface.find("model")
            nics.append({
                "mac":     mac_el.get("address", "") if mac_el is not None else "",
                "network": src_el.get("network", src_el.get("bridge", "")) if src_el is not None else "",
                "model":   mdl_el.get("type", "virtio") if mdl_el is not None else "virtio",
                "type":    iface.get("type", "network"),
            })

        return {
            "running":      running,
            "vcpu_max":     vcpu_max,
            "vcpu_current": vcpu_current,
            "mem_max_mb":   mem_max_kb // 1024,
            "mem_current_mb": mem_cur_kb // 1024,
            "cpu_mode":     cpu_mode,
            "nested_virt":  nested,
            "disks":        disks,
            "nics":         nics,
        }
    finally:
        conn.close()


def hot_set_vcpus(vm_id: str, count: int) -> dict:
    """Çalışan VM'de vCPU sayısını canlı değiştir."""
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        state_val, _ = dom.state()
        running = (state_val == libvirt.VIR_DOMAIN_RUNNING)
        flags = libvirt.VIR_DOMAIN_VCPU_CONFIG
        if running:
            flags |= libvirt.VIR_DOMAIN_VCPU_LIVE
        dom.setVcpusFlags(count, flags)
        return {"ok": True, "vcpus": count, "live": running}
    finally:
        conn.close()


def hot_set_memory(vm_id: str, mb: int) -> dict:
    """Çalışan VM'de RAM'i balloon ile canlı değiştir (max değerini aşamaz)."""
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        state_val, _ = dom.state()
        running = (state_val == libvirt.VIR_DOMAIN_RUNNING)
        kb = mb * 1024
        flags = libvirt.VIR_DOMAIN_MEM_CONFIG
        if running:
            flags |= libvirt.VIR_DOMAIN_MEM_LIVE
        dom.setMemoryFlags(kb, flags)
        return {"ok": True, "memory_mb": mb, "live": running}
    finally:
        conn.close()


def set_cpu_mode(vm_id: str, mode: str) -> dict:
    """CPU modunu değiştir (host-passthrough/host-model/custom). Restart gerekli."""
    valid = {"host-passthrough", "host-model", "custom"}
    if mode not in valid:
        raise ValueError(f"Geçersiz CPU modu: {mode}")
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        xml_str = dom.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
        root = ET.fromstring(xml_str)
        cpu_el = root.find("cpu")
        if cpu_el is None:
            cpu_el = ET.SubElement(root, "cpu")
        cpu_el.set("mode", mode)
        if mode == "host-passthrough":
            cpu_el.set("check", "none")
        new_xml = ET.tostring(root, encoding="unicode")
        conn.defineXML(new_xml)
        return {"ok": True, "cpu_mode": mode, "restart_required": True}
    finally:
        conn.close()


def set_nested_virt(vm_id: str, enabled: bool) -> dict:
    """Nested virtualization (vmx/svm) aç/kapat. Restart gerekli."""
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        xml_str = dom.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
        root = ET.fromstring(xml_str)
        cpu_el = root.find("cpu")
        if cpu_el is None:
            cpu_el = ET.SubElement(root, "cpu")

        # Host CPU flag gerekiyor
        if enabled and cpu_el.get("mode") not in ("host-passthrough", "host-model"):
            cpu_el.set("mode", "host-passthrough")
            cpu_el.set("check", "none")

        # Mevcut vmx/svm feature'ları temizle
        for feat in cpu_el.findall("feature"):
            if feat.get("name") in ("vmx", "svm"):
                cpu_el.remove(feat)

        if enabled:
            # vmx (Intel) ve svm (AMD) ikisini de ekle — hypervisor hangisini destekliyorsa kullanır
            for fname in ("vmx", "svm"):
                feat_el = ET.SubElement(cpu_el, "feature")
                feat_el.set("policy", "require")
                feat_el.set("name", fname)

        new_xml = ET.tostring(root, encoding="unicode")
        conn.defineXML(new_xml)
        return {"ok": True, "nested_virt": enabled, "restart_required": True}
    finally:
        conn.close()


def hot_attach_disk(vm_id: str, disk_path: str, bus: str = "virtio") -> dict:
    """Yeni disk hot-attach et. VM çalışıyorsa canlı, değilse config'e yazar."""
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        state_val, _ = dom.state()
        running = (state_val == libvirt.VIR_DOMAIN_RUNNING)

        # Hedef aygıt adı bul (vda,vdb,... veya sda,sdb,...)
        prefix = "vd" if bus == "virtio" else "sd"
        existing = set()
        xml_str = dom.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
        root = ET.fromstring(xml_str)
        for tgt in root.findall(".//disk/target"):
            existing.add(tgt.get("dev", ""))
        letter = "a"
        while f"{prefix}{letter}" in existing:
            letter = chr(ord(letter) + 1)
        dev = f"{prefix}{letter}"

        disk_xml = f"""<disk type='file' device='disk'>
  <driver name='qemu' type='qcow2' cache='none'/>
  <source file='{disk_path}'/>
  <target dev='{dev}' bus='{bus}'/>
</disk>"""

        flags = libvirt.VIR_DOMAIN_AFFECT_CONFIG
        if running:
            flags |= libvirt.VIR_DOMAIN_AFFECT_LIVE
        dom.attachDeviceFlags(disk_xml, flags)
        return {"ok": True, "target": dev, "path": disk_path, "live": running}
    finally:
        conn.close()


def hot_detach_disk(vm_id: str, target_dev: str) -> dict:
    """Disk hot-detach et (hedef aygıt adına göre, örn. vdb)."""
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        state_val, _ = dom.state()
        running = (state_val == libvirt.VIR_DOMAIN_RUNNING)

        xml_str = dom.XMLDesc()
        root = ET.fromstring(xml_str)
        disk_el = None
        for disk in root.findall(".//disk[@device='disk']"):
            tgt = disk.find("target")
            if tgt is not None and tgt.get("dev") == target_dev:
                disk_el = disk
                break
        if disk_el is None:
            raise ValueError(f"Disk bulunamadı: {target_dev}")

        disk_xml = ET.tostring(disk_el, encoding="unicode")
        flags = libvirt.VIR_DOMAIN_AFFECT_CONFIG
        if running:
            flags |= libvirt.VIR_DOMAIN_AFFECT_LIVE
        dom.detachDeviceFlags(disk_xml, flags)
        return {"ok": True, "target": target_dev, "live": running}
    finally:
        conn.close()


def hot_attach_nic(vm_id: str, network: str = "default", model: str = "virtio") -> dict:
    """Yeni NIC hot-attach et."""
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        state_val, _ = dom.state()
        running = (state_val == libvirt.VIR_DOMAIN_RUNNING)

        # Rastgele MAC üret
        import random
        mac = "52:54:00:%02x:%02x:%02x" % (random.randint(0,255), random.randint(0,255), random.randint(0,255))
        nic_xml = f"""<interface type='network'>
  <mac address='{mac}'/>
  <source network='{network}'/>
  <model type='{model}'/>
</interface>"""

        flags = libvirt.VIR_DOMAIN_AFFECT_CONFIG
        if running:
            flags |= libvirt.VIR_DOMAIN_AFFECT_LIVE
        dom.attachDeviceFlags(nic_xml, flags)
        return {"ok": True, "mac": mac, "network": network, "model": model, "live": running}
    finally:
        conn.close()


def hot_detach_nic(vm_id: str, mac: str) -> dict:
    """NIC hot-detach et (MAC adresine göre)."""
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        state_val, _ = dom.state()
        running = (state_val == libvirt.VIR_DOMAIN_RUNNING)

        xml_str = dom.XMLDesc()
        root = ET.fromstring(xml_str)
        iface_el = None
        for iface in root.findall(".//interface"):
            mac_el = iface.find("mac")
            if mac_el is not None and mac_el.get("address", "").lower() == mac.lower():
                iface_el = iface
                break
        if iface_el is None:
            raise ValueError(f"NIC bulunamadı: {mac}")

        iface_xml = ET.tostring(iface_el, encoding="unicode")
        flags = libvirt.VIR_DOMAIN_AFFECT_CONFIG
        if running:
            flags |= libvirt.VIR_DOMAIN_AFFECT_LIVE
        dom.detachDeviceFlags(iface_xml, flags)
        return {"ok": True, "mac": mac, "live": running}
    finally:
        conn.close()


def create_extra_disk(vm_id: str, size_gb: int, fmt: str = "qcow2") -> str:
    """Yeni boş disk oluştur ve yolunu döndür (hot-attach için)."""
    vm = get_vm(vm_id)
    disk_name = f"{vm['name']}-extra-{int(time.time())}.{fmt}"
    disk_path = os.path.join(config.DISK_DIR, disk_name)
    subprocess.run(
        ["qemu-img", "create", "-f", fmt, disk_path, f"{size_gb}G"],
        check=True, capture_output=True
    )
    return disk_path


def clone_vm(vm_id, new_name):
    source = get_vm(vm_id)
    src_disk = source["disks"][0]["path"] if source["disks"] else None

    if not src_disk:
        raise ValueError("Kaynak VM diski bulunamadı")

    new_disk = os.path.join(config.DISK_DIR, f"{new_name}.qcow2")
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-b", src_disk, "-F", "qcow2", new_disk],
        check=True, capture_output=True
    )

    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        xml_str = dom.XMLDesc()
        root = ET.fromstring(xml_str)

        root.find("name").text = new_name
        import uuid as _uuid
        root.find("uuid").text = str(_uuid.uuid4())

        for source_el in root.findall(".//disk[@device='disk']/source"):
            source_el.set("file", new_disk)

        vnc_port = _next_vnc_port()
        for g in root.findall(".//graphics[@type='vnc']"):
            g.set("port", str(vnc_port))

        new_xml = ET.tostring(root, encoding="unicode")
        new_dom = conn.defineXML(new_xml)

        reg = _load_vnc_registry()
        reg[new_dom.UUIDString()] = vnc_port
        _save_vnc_registry(reg)

        return {"id": new_dom.UUIDString(), "name": new_name, "cloned_from": vm_id}
    finally:
        conn.close()
