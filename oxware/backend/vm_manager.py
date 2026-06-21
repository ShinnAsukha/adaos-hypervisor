import libvirt
import xml.etree.ElementTree as ET
import subprocess
import os
import time
import json
import uuid
import random
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
_STATIC_IP_FILE    = os.path.join(config.DATA_DIR, "vm_static_ips.json")
_STATIC_IP_LOCK    = threading.Lock()


def _load_static_ips() -> dict:
    """Load MAC→IP mapping for manually assigned static IPs."""
    try:
        if os.path.exists(_STATIC_IP_FILE):
            with open(_STATIC_IP_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_vm_static_ip(mac: str, ip: str) -> None:
    """Persist a static IP for a VM MAC so it shows in the VM list."""
    with _STATIC_IP_LOCK:
        data = _load_static_ips()
        data[mac.lower()] = ip
        try:
            with open(_STATIC_IP_FILE, "w") as f:
                json.dump(data, f)
        except Exception as e:
            _log.warning("Static IP kaydedilemedi: %s", e)


def clear_vm_static_ip(mac: str) -> None:
    """Remove a stored static IP (on VM delete)."""
    with _STATIC_IP_LOCK:
        data = _load_static_ips()
        data.pop(mac.lower(), None)
        try:
            with open(_STATIC_IP_FILE, "w") as f:
                json.dump(data, f)
        except Exception:
            pass

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

                    # cdrom disk elementlerini kaldır — yalnızca kurucu ISO (sdb).
                    # cloud-init ISO (sdc) bırakılır: VM ilk boot'unda cloud-init okur.
                    devices = root.find("devices")
                    if devices is not None:
                        for disk in list(devices.findall("disk")):
                            if disk.get("device") == "cdrom":
                                target = disk.find("target")
                                dev = target.get("dev", "") if target is not None else ""
                                if dev != "sdc":   # sdc = cidata ISO, koru
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

# Alias — app.py calls vm_manager._libvirt_conn()
_libvirt_conn = _connect


# ── list_vms() short-TTL cache (3 s) ─────────────────────────────────────────
# Dashboard polls every 8 s; avoid a full libvirt scan + XMLDesc on every tick.
_LIST_CACHE = {"data": None, "ts": 0.0}
_LIST_CACHE_TTL = 3.0
_LIST_CACHE_LOCK = threading.Lock()


def _invalidate_list_cache():
    """Call after any mutation (create/delete/start/stop) to bust the cache."""
    with _LIST_CACHE_LOCK:
        _LIST_CACHE["data"] = None


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


def _get_host_disk_type(file_path: str) -> str:
    """
    Backing dosyasının bulunduğu host disk türünü tespit et.
    Döner: 'nvme' | 'ssd' | 'hdd' | 'virtual' | 'unknown'
    """
    try:
        import stat as _stat
        # Dosyanın bulunduğu block device'i bul (df ile)
        r = subprocess.run(
            ["df", "--output=source", file_path],
            capture_output=True, text=True, timeout=5
        )
        lines = r.stdout.strip().splitlines()
        if len(lines) < 2:
            return "unknown"
        dev = lines[1].strip()
        # /dev/sda1 → sda, /dev/nvme0n1p1 → nvme0n1, /dev/mapper/... → skip
        import re as _re
        m = _re.match(r"/dev/(nvme\w+|sd\w+|vd\w+|hd\w+|xvd\w+)", dev)
        if not m:
            return "virtual"
        dev_name = _re.sub(r"p?\d+$", "", m.group(1))  # strip partition number
        # NVMe
        if dev_name.startswith("nvme"):
            return "nvme"
        # rotational: 0=SSD, 1=HDD
        rot_path = f"/sys/block/{dev_name}/queue/rotational"
        if os.path.exists(rot_path):
            with open(rot_path) as f:
                rotational = f.read().strip()
            return "hdd" if rotational == "1" else "ssd"
        # virtio/xen virtual disk
        if dev_name.startswith(("vd", "xvd")):
            return "virtual"
    except Exception:
        pass
    return "unknown"


def _parse_disk_info(xml_str):
    disks = []
    try:
        root = ET.fromstring(xml_str)
        for disk in root.findall(".//disk[@type='file'][@device='disk']"):
            source = disk.find("source")
            target = disk.find("target")
            if source is not None and target is not None:
                _fpath = source.get("file", "")
                _cap_gb = 0.0
                try:
                    if _fpath and os.path.isfile(_fpath):
                        # Use qemu-img virtual-size (what guest sees), NOT os.path.getsize
                        # which returns sparse/compressed actual size for qcow2 thin disks.
                        _qi = subprocess.run(
                            ["qemu-img", "info", "--output=json", _fpath],
                            capture_output=True, text=True, timeout=5
                        )
                        if _qi.returncode == 0:
                            _virt = json.loads(_qi.stdout).get("virtual-size", 0)
                            if _virt > 0:
                                _cap_gb = round(_virt / (1024 ** 3), 2)
                        if _cap_gb == 0:
                            # Fallback: raw file size
                            _cap_gb = round(os.path.getsize(_fpath) / (1024 ** 3), 2)
                except Exception:
                    try:
                        _cap_gb = round(os.path.getsize(_fpath) / (1024 ** 3), 2)
                    except Exception:
                        pass
                bus = target.get("bus", "")
                # Detect underlying host disk type
                disk_type = _get_host_disk_type(_fpath) if _fpath else "unknown"
                disks.append({
                    "path":        _fpath,
                    "device":      target.get("dev", ""),
                    "bus":         bus,
                    "disk_type":   disk_type,   # nvme|ssd|hdd|virtual|unknown
                    "capacity_gb": _cap_gb,
                })
    except Exception:
        pass
    return disks


def _get_dhcp_ip_for_mac(network: str, mac: str) -> str:
    """
    virsh net-dhcp-leases <network> çıktısından MAC'e karşılık gelen IP'yi döner.
    Windows VM'lerde guest agent olmadan IP tespiti için kullanılır.
    """
    if not network or not mac:
        return ""
    try:
        r = subprocess.run(
            ["virsh", "net-dhcp-leases", network],
            capture_output=True, text=True, timeout=5
        )
        mac_lower = mac.lower()
        for line in r.stdout.splitlines():
            if mac_lower in line.lower():
                # Satır: <expiry>  <mac>  <proto>  <ip/prefix>  <hostname>  <clientid>
                parts = line.split()
                for part in parts:
                    if "/" in part and "." in part:          # ipv4/prefix
                        return part.split("/")[0]
                    if ":" not in part and "." in part and part.count(".") == 3:
                        return part                           # bare IP (no prefix)
    except Exception:
        pass
    # Fallback: manually saved static IPs (for bridge VMs where dnsmasq is bypassed)
    static_ips = _load_static_ips()
    return static_ips.get(mac.lower(), "")


def _parse_net_info(xml_str, resolve_ip: bool = False):
    interfaces = []
    try:
        root = ET.fromstring(xml_str)
        for iface in root.findall(".//interface"):
            mac    = iface.find("mac")
            source = iface.find("source")
            target = iface.find("target")
            mac_addr = mac.get("address", "") if mac is not None else ""
            network  = source.get("network", source.get("bridge", "")) if source is not None else ""
            ip_addr  = ""
            if resolve_ip and mac_addr and network:
                ip_addr = _get_dhcp_ip_for_mac(network, mac_addr)
            interfaces.append({
                "mac":     mac_addr,
                "network": network,
                "device":  target.get("dev", "") if target is not None else "",
                "type":    iface.get("type", ""),
                "ip":      ip_addr,
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
    now = time.monotonic()
    with _LIST_CACHE_LOCK:
        if _LIST_CACHE["data"] is not None and (now - _LIST_CACHE["ts"]) < _LIST_CACHE_TTL:
            return list(_LIST_CACHE["data"])   # return a shallow copy

    conn = _connect()
    vms = []
    try:
        for dom in conn.listAllDomains():
            stats   = _get_domain_stats(dom)
            xml_str = dom.XMLDesc()
            disks   = _parse_disk_info(xml_str)
            nets    = _parse_net_info(xml_str)
            vnc_port = _parse_vnc_port(xml_str)
            info    = dom.info()
            vms.append({
                "id":            dom.UUIDString(),
                "name":          dom.name(),
                "state":         stats["state"],
                "vcpus":         info[3],
                "memory_mb":     info[1] // 1024,
                "memory_max_mb": info[1] // 1024,
                "cpu_time":      stats["cpu_time"],
                "disks":         disks,
                "networks":      nets,
                "vnc_port":      vnc_port,
                "autostart":     bool(dom.autostart()),
            })
    finally:
        conn.close()

    with _LIST_CACHE_LOCK:
        _LIST_CACHE["data"] = vms
        _LIST_CACHE["ts"]   = time.monotonic()
    return list(vms)


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
        nets = _parse_net_info(xml_str, resolve_ip=True)   # DHCP lease lookup for IP
        vnc_port = _parse_vnc_port(xml_str)
        info = dom.info()

        return {
            "id": dom.UUIDString(),
            "name": dom.name(),
            "state": stats["state"],
            "vcpus": info[3],
            "memory_mb": info[1] // 1024,
            "memory_used_mb": stats["memory_used_kb"] // 1024,
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
        subprocess.run(["pkill", "-HUP", "dnsmasq"],
                       capture_output=True, timeout=5)
    except Exception:
        pass


def add_dhcp_host(network: str, mac: str, ip: str, hostname: str = "") -> bool:
    """Libvirt ağına static DHCP kaydı ekle (MAC→IP). dnsmasq anında görür."""
    import html as _html
    host_xml = f'<host mac="{_html.escape(mac, quote=True)}" ip="{_html.escape(ip, quote=True)}"'
    if hostname:
        host_xml += f' name="{_html.escape(hostname, quote=True)}"'
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


def _sha512_crypt_pure(password: str, salt: str = None) -> str:
    """
    Pure-Python SHA-512 crypt per Drepper spec (https://www.akkadia.org/docs/SHA-crypt.txt).
    Used when openssl and Python crypt module are both unavailable.
    Always succeeds — no external dependencies.
    """
    import hashlib as _hl, os as _os

    _B64 = ('./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            'abcdefghijklmnopqrstuvwxyz')

    def _to64(v, n):
        s = ''
        for _ in range(n):
            s += _B64[v & 0x3f]
            v >>= 6
        return s

    if salt is None:
        salt = ''.join(_B64[b & 0x3f] for b in _os.urandom(16))
    salt = salt[:16]

    pw = password.encode()
    sa = salt.encode()

    # --- Step 1-5: Digest A ---
    da = _hl.sha512(pw + sa)
    db = _hl.sha512(pw + sa + pw).digest()   # Digest B

    # Append bytes from B for each char of password (step 4)
    n = len(pw)
    while n > 0:
        da.update(db if n >= 64 else db[:n])
        n -= 64

    # Process bits of password length (step 5)
    n = len(pw)
    while n:
        da.update(db if (n & 1) else pw)
        n >>= 1
    da = da.digest()

    # --- Step 6: Digest P ---
    dp = _hl.sha512()
    for _ in range(len(pw)):
        dp.update(pw)
    dp = dp.digest()
    p_str = (dp * (len(pw) // 64 + 1))[:len(pw)]

    # --- Step 7: Digest S ---
    ds = _hl.sha512()
    for _ in range(16 + da[0]):
        ds.update(sa)
    s_str = ds.digest()[:len(sa)]

    # --- Step 8: 5000 rounds ---
    c = da
    for i in range(5000):
        dc = _hl.sha512()
        dc.update(p_str if (i & 1) else c)
        if i % 3: dc.update(s_str)
        if i % 7: dc.update(p_str)
        dc.update(c if (i & 1) else p_str)
        c = dc.digest()

    # --- Step 9: SHA-512 specific byte interleaving ---
    out = (
        _to64((c[ 0]<<16)|(c[21]<<8)|c[42], 4) +
        _to64((c[22]<<16)|(c[43]<<8)|c[ 1], 4) +
        _to64((c[44]<<16)|(c[ 2]<<8)|c[23], 4) +
        _to64((c[ 3]<<16)|(c[24]<<8)|c[45], 4) +
        _to64((c[25]<<16)|(c[46]<<8)|c[ 4], 4) +
        _to64((c[47]<<16)|(c[ 5]<<8)|c[26], 4) +
        _to64((c[ 6]<<16)|(c[27]<<8)|c[48], 4) +
        _to64((c[28]<<16)|(c[49]<<8)|c[ 7], 4) +
        _to64((c[50]<<16)|(c[ 8]<<8)|c[29], 4) +
        _to64((c[ 9]<<16)|(c[30]<<8)|c[51], 4) +
        _to64((c[31]<<16)|(c[52]<<8)|c[10], 4) +
        _to64((c[53]<<16)|(c[11]<<8)|c[32], 4) +
        _to64((c[12]<<16)|(c[33]<<8)|c[54], 4) +
        _to64((c[34]<<16)|(c[55]<<8)|c[13], 4) +
        _to64((c[56]<<16)|(c[14]<<8)|c[35], 4) +
        _to64((c[15]<<16)|(c[36]<<8)|c[57], 4) +
        _to64((c[37]<<16)|(c[58]<<8)|c[16], 4) +
        _to64((c[59]<<16)|(c[17]<<8)|c[38], 4) +
        _to64((c[18]<<16)|(c[39]<<8)|c[60], 4) +
        _to64((c[40]<<16)|(c[61]<<8)|c[19], 4) +
        _to64((c[62]<<16)|(c[20]<<8)|c[41], 4) +
        _to64(c[63], 2)
    )
    return f"$6${salt}${out}"


def _build_cidata_iso_python(iso_path: str, ci_dir: str, has_network_config: bool) -> str | None:
    """
    Pure-Python minimal ISO 9660 writer for cloud-init NoCloud.
    No external tools required.
    Volume label 'cidata', files: meta-data, user-data, network-config.

    ISO 9660 layout:
      Sectors  0-15: system area (unused)
      Sector  16:    Primary Volume Descriptor
      Sector  17:    Volume Descriptor Set Terminator
      Sector  18:    L-Type Path Table (padded to 1 sector)
      Sector  19:    M-Type Path Table (padded to 1 sector)
      Sector  20:    Root Directory (1 sector)
      Sector 21+:    File data
    """
    import struct as _st
    import math   as _math
    import os     as _os
    import time   as _time

    SEC = 2048

    # ── helpers ───────────────────────────────────────────────────────────────
    def b16(n):   # both-endian 16-bit → 4 bytes
        return _st.pack('<H', n) + _st.pack('>H', n)

    def b32(n):   # both-endian 32-bit → 8 bytes
        return _st.pack('<I', n) + _st.pack('>I', n)

    def le32(n):
        return _st.pack('<I', n)

    def be32(n):
        return _st.pack('>I', n)

    def pad_sec(data: bytes) -> bytes:
        rem = len(data) % SEC
        return data + b'\x00' * (SEC - rem if rem else 0)

    def dt7() -> bytes:  # 7-byte directory record timestamp
        t = _time.localtime()
        return bytes([t.tm_year - 1900, t.tm_mon, t.tm_mday,
                      t.tm_hour, t.tm_min, t.tm_sec, 0])

    def dt17() -> bytes:  # 17-byte PVD timestamp (unspecified)
        return b'0000000000000000\x00'

    def dir_rec(name: bytes, extent: int, size: int, is_dir: bool = False) -> bytes:
        """Build one ISO 9660 directory record (fixed-width field writes)."""
        nl = len(name)
        rl = 33 + nl
        if rl & 1:
            rl += 1   # must be even
        r = bytearray(rl)
        r[0]    = rl
        r[1]    = 0                                  # ext attr len
        r[2:10] = b32(extent)                        # location (both-endian 32)
        r[10:18]= b32(size)                          # data length (both-endian 32)
        r[18:25]= dt7()                              # recording date
        r[25]   = 0x02 if is_dir else 0x00           # flags
        # r[26]=interleave unit, r[27]=interleave gap → 0
        r[28:32]= b16(1)                             # volume sequence number (both-endian 16 = 4 bytes)
        r[32]   = nl
        r[33:33+nl] = name
        return bytes(r)

    # ── collect files ─────────────────────────────────────────────────────────
    # ISO 9660 level-1: uppercase, hyphens OK in practice; cloud-init reads
    # by content using the volume label, so filenames just need to be present.
    FILE_NAMES = [
        ("meta-data",     "META-DATA;1"),
        ("user-data",     "USER-DATA;1"),
    ]
    if has_network_config:
        FILE_NAMES.append(("network-config", "NETWORK-CONFIG;1"))

    files = []   # (iso_name_bytes, raw_data)
    for real_name, iso_name in FILE_NAMES:
        fp = _os.path.join(ci_dir, real_name)
        if _os.path.exists(fp):
            with open(fp, "rb") as _f:
                files.append((iso_name.encode("ascii"), _f.read()))

    if not files:
        return None

    # ── sector layout ─────────────────────────────────────────────────────────
    L_PATH_SECTOR  = 18
    M_PATH_SECTOR  = 19
    ROOT_DIR_SEC   = 20
    FILE_START_SEC = 21

    extents = []   # (iso_name_bytes, data, sector)
    cur = FILE_START_SEC
    for name_b, data in files:
        extents.append((name_b, data, cur))
        cur += max(1, _math.ceil(len(data) / SEC))
    total_sectors = cur

    # ── minimal path table (root only, 10 bytes) ─────────────────────────────
    def _pt_entry(sector_fn) -> bytes:
        e = bytearray(10)
        e[0] = 1                                     # len of dir id
        e[1] = 0                                     # ext attr len
        return bytes(e)   # filled below per endianness

    # L-type path table (little-endian sector)
    l_pt = bytearray(10)
    l_pt[0] = 1                                      # dir id length
    l_pt[1] = 0                                      # ext attr
    _st.pack_into('<I', l_pt, 2, ROOT_DIR_SEC)       # extent LE
    _st.pack_into('<H', l_pt, 6, 1)                  # parent dir num
    l_pt[8] = 0                                      # dir identifier (root)
    l_pt[9] = 0                                      # padding

    # M-type path table (big-endian sector)
    m_pt = bytearray(10)
    m_pt[0] = 1
    m_pt[1] = 0
    _st.pack_into('>I', m_pt, 2, ROOT_DIR_SEC)       # extent BE
    _st.pack_into('>H', m_pt, 6, 1)
    m_pt[8] = 0
    m_pt[9] = 0

    # ── root directory sector ─────────────────────────────────────────────────
    dot    = dir_rec(b'\x00', ROOT_DIR_SEC, SEC, is_dir=True)
    dotdot = dir_rec(b'\x01', ROOT_DIR_SEC, SEC, is_dir=True)
    root_dir = bytearray(dot + dotdot)
    for name_b, data, sect in extents:
        rec = dir_rec(name_b, sect, len(data), is_dir=False)
        if len(root_dir) + len(rec) > SEC:
            break
        root_dir.extend(rec)

    # ── Primary Volume Descriptor (exactly 2048 bytes) ────────────────────────
    pvd = bytearray(SEC)
    # Use struct.pack_into throughout to avoid bytearray resize bugs
    pvd[0]    = 1                                    # PVD type
    pvd[1:6]  = b'CD001'
    pvd[6]    = 1                                    # version
    pvd[7]    = 0                                    # unused
    pvd[8:40] = b' ' * 32                            # system identifier
    pvd[40:72]= (b'cidata' + b' ' * 26)              # volume identifier (32 bytes)
    # bytes 72-79: unused
    pvd[80:88] = b32(total_sectors)                  # volume space size
    # bytes 88-119: unused (escape seqs)
    pvd[120:124] = b16(1)                            # volume set size        (both16 = 4 bytes)
    pvd[124:128] = b16(1)                            # volume sequence number (both16 = 4 bytes)
    pvd[128:132] = b16(SEC)                          # logical block size     (both16 = 4 bytes)
    pvd[132:140] = b32(10)                           # path table size        (both32 = 8 bytes)
    pvd[140:144] = le32(L_PATH_SECTOR)               # L path table location
    pvd[144:148] = le32(0)                           # optional L path table (none)
    pvd[148:152] = be32(M_PATH_SECTOR)               # M path table location
    pvd[152:156] = be32(0)                           # optional M path table (none)
    # Root directory record at offset 156 (34 bytes)
    root_dr = dir_rec(b'\x00', ROOT_DIR_SEC, SEC, is_dir=True)
    pvd[156:190] = root_dr[:34]
    pvd[190:318] = b' ' * 128                        # volume set identifier
    pvd[318:446] = b' ' * 128                        # publisher identifier
    pvd[446:574] = b' ' * 128                        # data preparer identifier
    pvd[574:702] = b' ' * 128                        # application identifier
    pvd[702:739] = b' ' * 37                         # copyright file id
    pvd[739:776] = b' ' * 37                         # abstract file id
    pvd[776:813] = b' ' * 37                         # bibliographic file id
    pvd[813:830] = dt17()                            # creation date
    pvd[830:847] = dt17()                            # modification date
    pvd[847:864] = dt17()                            # expiration date
    pvd[864:881] = dt17()                            # effective date
    pvd[881]     = 1                                 # file structure version

    # ── Volume Descriptor Set Terminator ─────────────────────────────────────
    vdst = bytearray(SEC)
    vdst[0]   = 255
    vdst[1:6] = b'CD001'
    vdst[6]   = 1

    # ── Write ISO ────────────────────────────────────────────────────────────
    with open(iso_path, "wb") as _fp:
        _fp.write(b'\x00' * (16 * SEC))              # system area
        _fp.write(bytes(pvd))                        # sector 16: PVD
        _fp.write(bytes(vdst))                       # sector 17: VDST
        _fp.write(pad_sec(bytes(l_pt)))              # sector 18: L path table
        _fp.write(pad_sec(bytes(m_pt)))              # sector 19: M path table
        _fp.write(pad_sec(bytes(root_dir)))          # sector 20: root dir
        for _, data, _ in extents:
            _fp.write(pad_sec(data))                 # sectors 21+: files

    _log.info("cloud-init ISO oluşturuldu (Python ISO 9660 fallback): %s", iso_path)
    return iso_path


def _build_cloud_init_iso(vm_name: str, ci: dict) -> str | None:
    """
    cloud-init NoCloud ISO oluştur.
    ci dict anahtarları:
      user, password, ssh_key, hostname, user_data (opsiyonel)
      static_ip, gateway, netmask, dns (bridge/doğrudan IP için opsiyonel)
    Yol döndürür veya None.
    """
    import shutil as _sh, tempfile as _tf
    try:
        ci_dir = _tf.mkdtemp(prefix=f"ci-{vm_name}-")
        hostname = ci.get("hostname") or vm_name

        # Sanitize: newline injection would break YAML structure
        def _safe(s: str) -> str:
            return s.replace("\r", "").replace("\n", "")

        safe_user     = _safe(ci.get("user", "") or "")
        safe_hostname = _safe(hostname)
        safe_password = _safe(ci.get("password", "") or "")
        safe_ssh_key  = _safe(ci.get("ssh_key", "") or "")

        # meta-data — unique instance-id forces cloud-init to re-run on every attach
        meta = f"instance-id: {vm_name}-{int(time.time())}\nlocal-hostname: {safe_hostname}\n"

        # user-data YAML
        lines = ["#cloud-config"]
        # Always enable SSH password auth (disabled by default on Ubuntu cloud images)
        lines.append("ssh_pwauth: true")

        # Generate SHA-512 password hash (most reliable for cloud-init passwd: field)
        def _hash_password(pw: str) -> str:
            """SHA-512 shadow hash. Always returns a valid hash — never None."""
            # 1. openssl passwd -6 <pw>  (direct arg, most reliable)
            try:
                r = subprocess.run(
                    ["openssl", "passwd", "-6", pw],
                    capture_output=True, text=True, timeout=5
                )
                h = r.stdout.strip()
                if h and h.startswith("$6$"):
                    return h
            except Exception:
                pass
            # 2. openssl passwd -6 -stdin
            try:
                r = subprocess.run(
                    ["openssl", "passwd", "-6", "-stdin"],
                    input=pw, capture_output=True, text=True, timeout=5
                )
                h = r.stdout.strip()
                if h and h.startswith("$6$"):
                    return h
            except Exception:
                pass
            # 3. Python crypt module (available in Python < 3.13)
            try:
                import crypt as _crypt
                return _crypt.crypt(pw, _crypt.mksalt(_crypt.METHOD_SHA512))
            except Exception:
                pass
            # 4. Pure-Python SHA-512 crypt (always succeeds)
            return _sha512_crypt_pure(pw)

        # Top-level password: directive — sets DEFAULT user (ubuntu) password.
        # Most reliable method, works on all cloud-init versions regardless of
        # users: stanza. MUST come before users: stanza in the YAML.
        if safe_password:
            lines.append(f"password: {safe_password}")

        if safe_user:
            hashed_pw = _hash_password(safe_password) if safe_password else None

            # CRITICAL: '- default' must be first — without it cloud-init REPLACES
            # all pre-installed users (ubuntu) instead of adding to them.
            # This was the root cause of "Login incorrect" on Ubuntu cloud images.
            user_lines = [
                "users:",
                "  - default",
            ]
            is_default_user = safe_user.lower() in ("ubuntu", "debian", "centos",
                                                      "fedora", "ec2-user", "cloud-user")
            if not is_default_user:
                # Custom username — add as a second user alongside the default
                user_lines.extend([
                    f"  - name: {safe_user}",
                    "    sudo: ALL=(ALL) NOPASSWD:ALL",
                    "    shell: /bin/bash",
                    "    groups: users,sudo",
                ])
                if safe_password:
                    user_lines.append("    lock_passwd: false")
                    if hashed_pw:
                        user_lines.append(f"    passwd: '{hashed_pw}'")
                if safe_ssh_key:
                    user_lines.append("    ssh_authorized_keys:")
                    user_lines.append(f"      - {safe_ssh_key}")
            else:
                # Username IS the default cloud user — patch via default entry
                if safe_ssh_key:
                    user_lines.extend([
                        f"  - name: {safe_user}",
                        "    sudo: ALL=(ALL) NOPASSWD:ALL",
                        "    lock_passwd: false",
                        "    ssh_authorized_keys:",
                        f"      - {safe_ssh_key}",
                    ])
            lines.append("\n".join(user_lines))

            if safe_password:
                # chpasswd: covers all users explicitly (cloud-init 22.3+ format)
                # type: text = plain password, cloud-init hashes internally
                chpasswd_entries = (
                    f"    - name: ubuntu\n      password: {safe_password}\n      type: text"
                )
                if not is_default_user:
                    chpasswd_entries += (
                        f"\n    - name: {safe_user}\n      password: {safe_password}\n      type: text"
                    )
                chpasswd_entries += (
                    f"\n    - name: root\n      password: {safe_password}\n      type: text"
                )
                lines.append(
                    f"chpasswd:\n"
                    f"  expire: false\n"
                    f"  users:\n"
                    f"{chpasswd_entries}"
                )

                # runcmd: absolute last resort — runs after ALL cloud-init modules
                _pw_q = safe_password.replace("'", "'\\''")
                runcmd_cmds = [
                    f"printf 'ubuntu:{_pw_q}\\nroot:{_pw_q}\\n' | chpasswd 2>/dev/null || true",
                    f"passwd -u ubuntu 2>/dev/null || true",
                    f"passwd -u root 2>/dev/null || true",
                ]
                if not is_default_user:
                    runcmd_cmds.insert(1,
                        f"printf '{safe_user}:{_pw_q}\\n' | chpasswd 2>/dev/null || true"
                    )
                    runcmd_cmds.insert(2,
                        f"passwd -u {safe_user} 2>/dev/null || true"
                    )
                runcmd_yaml = "runcmd:\n" + "\n".join(f"  - \"{c}\"" for c in runcmd_cmds)
                lines.append(runcmd_yaml)

        elif safe_ssh_key:
            lines.append(f"ssh_authorized_keys:\n  - {safe_ssh_key}")

        if ci.get("user_data"):
            lines.append(ci["user_data"].strip())

        user_data = "\n".join(lines) + "\n"

        # network-config: statik IP atanacaksa (bridge/passthrough ağlar için)
        static_ip  = _safe(ci.get("static_ip", "") or "")
        gateway    = _safe(ci.get("gateway", "") or "")
        netmask    = _safe(ci.get("netmask", "") or "")
        dns_list   = ci.get("dns") or ["8.8.8.8", "1.1.1.1"]
        prefix     = ci.get("prefix", "")

        iface = _safe(ci.get("interface", "") or "eth0") or "eth0"

        network_config_str = None
        if static_ip and gateway:
            # Prefix hesapla
            if not prefix and netmask:
                try:
                    import ipaddress as _ipa
                    prefix = str(ipaddress.IPv4Network(f"0.0.0.0/{netmask}", strict=False).prefixlen)
                except Exception:
                    prefix = "24"
            if not prefix:
                prefix = "24"
            dns_yaml = "\n".join(f"      - {d}" for d in dns_list)
            network_config_str = f"""version: 2
ethernets:
  {iface}:
    dhcp4: false
    addresses:
      - {static_ip}/{prefix}
    gateway4: {gateway}
    nameservers:
      addresses:
{dns_yaml}
"""

        with open(os.path.join(ci_dir, "meta-data"), "w") as f:
            f.write(meta)
        with open(os.path.join(ci_dir, "user-data"), "w") as f:
            f.write(user_data)
        if network_config_str:
            with open(os.path.join(ci_dir, "network-config"), "w") as f:
                f.write(network_config_str)

        iso_path = os.path.join(config.DISK_DIR, f"ci-{vm_name}.iso")

        # cloud-localds supports network-config natively
        # genisoimage/mkisofs: include network-config file manually
        nc_path = os.path.join(ci_dir, "network-config")
        nc_args = [nc_path] if network_config_str else []

        # Auto-install genisoimage if none of the tools available
        import shutil as _sh2
        if not (_sh2.which("genisoimage") or _sh2.which("mkisofs") or _sh2.which("cloud-localds")):
            _log.info("cloud-init araçları bulunamadı, genisoimage kuruluyor...")
            subprocess.run(
                ["apt-get", "install", "-y", "-qq", "genisoimage"],
                capture_output=True, timeout=120
            )

        for cmd in (
            ["genisoimage", "-output", iso_path, "-volid", "cidata", "-joliet", "-rock",
             os.path.join(ci_dir, "user-data"), os.path.join(ci_dir, "meta-data")] + nc_args,
            ["mkisofs", "-output", iso_path, "-volid", "cidata", "-joliet", "-rock",
             os.path.join(ci_dir, "user-data"), os.path.join(ci_dir, "meta-data")] + nc_args,
            ["cloud-localds", iso_path,
             os.path.join(ci_dir, "user-data"), os.path.join(ci_dir, "meta-data")] +
            (["--network-config", nc_path] if network_config_str else []),
        ):
            r = subprocess.run(cmd, capture_output=True)
            if r.returncode == 0 and os.path.exists(iso_path):
                _sh.rmtree(ci_dir, ignore_errors=True)
                return iso_path

        # Pure-Python fallback: minimal ISO 9660 with "cidata" label
        # Works for cloud-init NoCloud — no external tools needed
        try:
            _py_iso = _build_cidata_iso_python(iso_path, ci_dir, network_config_str)
            if _py_iso:
                _sh.rmtree(ci_dir, ignore_errors=True)
                return _py_iso
        except Exception as _pie:
            _log.warning("Python ISO fallback hatası: %s", _pie)

        _sh.rmtree(ci_dir, ignore_errors=True)
        _log.warning("cloud-init ISO oluşturulamadı (genisoimage/mkisofs/cloud-localds bulunamadı)")
        return None
    except Exception as e:
        _log.error("_build_cloud_init_iso hatası: %s", e)
        return None


# ── Cloud Image URL map ───────────────────────────────────────────────────────
_CLOUD_IMAGE_URLS: dict[str, str] = {
    "ubuntu22.04": "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
    "ubuntu20.04": "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img",
    "ubuntu24.04": "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
    "debian12":    "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2",
    "debian11":    "https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2",
    "rocky9":      "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2",
    "alma9":       "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2",
}
_CLOUD_CACHE_DIR = "/var/lib/libvirt/images"


def _prepare_cloud_image(os_variant: str, disk_gb: int, dest_path: str) -> None:
    """
    Cloud image'ı hazırla:
      1. Cache'de varsa kullan (/var/lib/libvirt/images/{os_variant}-cloud.qcow2)
      2. Yoksa indir (wget)
      3. qemu-img convert ile dest_path'e kopyala (bağımsız qcow2)
      4. dest_path'i disk_gb'ye resize et
    """
    url = _CLOUD_IMAGE_URLS.get(os_variant)
    if not url:
        raise ValueError(f"Cloud image desteklenmiyor: {os_variant}. "
                         "Desteklenenler: " + ", ".join(_CLOUD_IMAGE_URLS.keys()))

    cache_path = os.path.join(_CLOUD_CACHE_DIR, f"{os_variant}-cloud.qcow2")
    os.makedirs(_CLOUD_CACHE_DIR, exist_ok=True)

    if not os.path.exists(cache_path):
        _log.info("Cloud image indiriliyor: %s → %s", url, cache_path)
        tmp_dl = cache_path + ".downloading"
        try:
            subprocess.run(
                ["wget", "-q", "--show-progress", "-O", tmp_dl, url],
                check=True, timeout=3600
            )
            os.rename(tmp_dl, cache_path)
        except Exception as e:
            try:
                os.unlink(tmp_dl)
            except Exception:
                pass
            raise RuntimeError(f"Cloud image indirilemedi ({url}): {e}") from e
    else:
        _log.info("Cloud image cache'den kullanılıyor: %s", cache_path)

    # Bağımsız kopyayı oluştur (convert — backing file bağımlılığı yok)
    _log.info("Cloud image kopyalanıyor → %s", dest_path)
    subprocess.run(
        ["qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", cache_path, dest_path],
        check=True, capture_output=True, timeout=600
    )

    # İstenilen boyuta resize et
    img_info = subprocess.run(
        ["qemu-img", "info", "--output=json", dest_path],
        capture_output=True, text=True
    )
    try:
        import json as _j
        _vsize_bytes = _j.loads(img_info.stdout).get("virtual-size", 0)
        _vsize_gb    = _vsize_bytes / (1024 ** 3)
    except Exception:
        _vsize_gb = 0

    if disk_gb > _vsize_gb:
        subprocess.run(
            ["qemu-img", "resize", dest_path, f"{disk_gb}G"],
            check=True, capture_output=True
        )
        _log.info("Cloud image resize edildi → %dG", disk_gb)


def create_vm(name, memory_mb, vcpus, disk_gb, iso_path=None,
              network="default", disk_format="qcow2", os_variant="generic",
              boot_order="cdrom,hd", mac: str = None, disk_bus: str = "sata",
              cpu_mode: str = "host-model", cloud_init: dict = None,
              use_cloud_image: bool = False,
              template_id: str = None, clone_type: str = "linked"):

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

    # Cloud-init ISO (optional)
    ci_iso_path = None
    if cloud_init and not is_windows:
        ci_iso_path = _build_cloud_init_iso(name, cloud_init)

    # Disk oluştur
    if template_id:
        # Linked clone veya full clone şablondan
        import sys as _sys
        _tpl_dir = os.path.join(os.path.dirname(__file__))
        if _tpl_dir not in _sys.path:
            _sys.path.insert(0, _tpl_dir)
        try:
            import template_manager as _tplmgr
            _tpl_disk = _tplmgr._disk_path(template_id)
        except Exception:
            _tpl_disk = os.path.join("/var/lib/oxware/templates", template_id, "disk.qcow2")
        if not os.path.exists(_tpl_disk):
            raise ValueError(f"Şablon diski bulunamadı: {_tpl_disk}")
        if clone_type == "full":
            subprocess.run(
                ["qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", _tpl_disk, disk_path],
                check=True, capture_output=True, timeout=7200
            )
        else:  # linked (default) — instant copy-on-write
            subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", "-b", _tpl_disk, "-F", "qcow2", disk_path],
                check=True, capture_output=True
            )
        if not iso_path:
            boot_order = "hd"
        disk_format = "qcow2"
    elif use_cloud_image:
        # Cloud image'dan bağımsız disk kopyası oluştur + resize
        _prepare_cloud_image(os_variant, disk_gb, disk_path)
        # Cloud image ile ISO boot'a gerek yok — disk'ten boot et
        if not iso_path:
            boot_order = "hd"
    else:
        subprocess.run(
            ["qemu-img", "create", "-f", disk_format, disk_path, f"{disk_gb}G"],
            check=True, capture_output=True
        )

    # XML şablonu — kullanıcı girdilerini XML attribute injection'dan koru
    import html as _html
    network = _html.escape(network, quote=True)

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

    ci_block = ""
    if ci_iso_path and os.path.exists(ci_iso_path):
        ci_block = f"""
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='{ci_iso_path}'/>
      <target dev='sdc' bus='sata'/>
      <readonly/>
    </disk>"""

    boot_xml = "".join(
        f"<boot dev='{dev}'/>"
        for dev in boot_order.split(",")
    )

    clock_offset = "localtime" if is_windows else "utc"
    hyperv_xml = """
    <hyperv mode='custom'>
      <relaxed state='on'/>
      <vapic state='on'/>
      <spinlocks state='on' retries='8191'/>
      <vpindex state='on'/>
      <synic state='on'/>
      <reset state='on'/>
    </hyperv>""" if is_windows else ""

    # Optional OXware firmware boot splash (additive fw_cfg; safe no-op when
    # disabled or image missing).
    try:
        import boot_splash as _bsplash
        _splash_ns, _splash_cmd = _bsplash.domain_inject()
        _splash_bootmenu = _bsplash.os_bootmenu_xml()
    except Exception:
        _splash_ns, _splash_cmd, _splash_bootmenu = "", "", ""

    xml = f"""<domain type='kvm'{_splash_ns}>
  <name>{name}</name>
  <uuid>{vm_uuid}</uuid>
  <memory unit='MiB'>{memory_mb}</memory>
  <currentMemory unit='MiB'>{memory_mb}</currentMemory>
  <vcpu placement='static'>{vcpus}</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-6.2'>hvm</type>
    {boot_xml}{_splash_bootmenu}
  </os>
  <features>
    <acpi/>
    <apic/>
    <vmport state='off'/>{hyperv_xml}
  </features>
  <cpu mode='{cpu_mode}' check='{cpu_check}'>
{cpu_model_xml}
  </cpu>
  <clock offset='{clock_offset}'>
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
    </disk>{iso_block}{ci_block}
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
      <model type='vga' vram='16384' heads='1' primary='yes'/>
    </video>
    <memballoon model='virtio'>
    </memballoon>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
  </devices>{_splash_cmd}
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

        _invalidate_list_cache()
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
        _invalidate_list_cache()
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
            _invalidate_list_cache()
            return {"status": "forced_stop"}
        dom.shutdown()
        _invalidate_list_cache()
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
        _invalidate_list_cache()
        return {"status": "rebooting"}
    finally:
        conn.close()


def pause_vm(vm_id):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        dom.suspend()
        _invalidate_list_cache()
        return {"status": "paused"}
    finally:
        conn.close()


def resume_vm(vm_id):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        dom.resume()
        _invalidate_list_cache()
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

        # cloud-init ISO adını VM adından türet
        try:
            _vm_name_el = ET.fromstring(xml_str).findtext("name") or ""
        except Exception:
            _vm_name_el = ""

        dom.undefineFlags(
            libvirt.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE |
            libvirt.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA
        )

        if delete_disk:
            for disk in disks:
                path = disk.get("path", "")
                if path and os.path.exists(path):
                    os.remove(path)

        # cloud-init ISO temizle
        if _vm_name_el:
            _ci_iso = os.path.join(config.DISK_DIR, f"ci-{_vm_name_el}.iso")
            if os.path.exists(_ci_iso):
                try:
                    os.remove(_ci_iso)
                except Exception:
                    pass

        reg = _load_vnc_registry()
        reg.pop(vm_id, None)
        _save_vnc_registry(reg)
        _invalidate_list_cache()
        return {"status": "deleted"}
    finally:
        conn.close()


def get_vm_stats(vm_id):
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        if not dom.isActive():
            return {"state": "stopped"}

        info      = dom.info()
        cpu_stats = dom.getCPUStats(True)[0]

        # Parse XML once for both disk device names and net interface names
        xml_str = dom.XMLDesc()
        try:
            _root = ET.fromstring(xml_str)
        except Exception:
            _root = None

        # Disk I/O — single blockStats call per device
        disk_stats = {}
        if _root is not None:
            for disk_el in _root.findall(".//disk[@type='file'][@device='disk']"):
                tgt = disk_el.find("target")
                if tgt is not None:
                    dev = tgt.get("dev", "")
                    if dev:
                        try:
                            bs = dom.blockStats(dev)  # single call: [rd_req, rd_bytes, wr_req, wr_bytes, ...]
                            disk_stats[dev] = {"read_bytes": bs[1], "write_bytes": bs[3]}
                        except Exception:
                            pass

        # Net stats
        net_stats = {}
        if _root is not None:
            for iface_el in _root.findall(".//interface"):
                tgt = iface_el.find("target")
                if tgt is not None:
                    dev = tgt.get("dev", "")
                    if dev:
                        try:
                            ns = dom.interfaceStats(dev)
                            net_stats[dev] = {
                                "rx_bytes":   ns[0], "tx_bytes":   ns[4],
                                "rx_packets": ns[1], "tx_packets": ns[5],
                            }
                        except Exception:
                            pass

        # ── Real guest RAM usage via virtio-balloon stats ──────────────────
        # info[2] = current balloon size (allocated, NOT actual guest usage)
        # info[1] = max configured memory
        # If balloon driver is installed in guest, memoryStats() provides real data:
        #   "available" = total memory visible to guest OS
        #   "unused"    = free memory in guest OS
        #   "rss"       = QEMU process RSS on host (always present)
        mem_stats = {}
        try:
            mem_stats = dom.memoryStats()
        except Exception:
            pass

        _avail_kb = mem_stats.get("available", 0)
        _unused_kb = mem_stats.get("unused", 0)
        _rss_kb   = mem_stats.get("rss", 0)

        if _avail_kb > 0 and "unused" in mem_stats:
            # Balloon driver reports real guest usage
            _used_kb = _avail_kb - _unused_kb
            _max_kb  = _avail_kb
        elif _rss_kb > 0:
            # No balloon driver — use QEMU RSS as best approximation
            _used_kb = _rss_kb
            _max_kb  = info[1]
        else:
            # No data at all — show 0 (better than always 100%)
            _used_kb = 0
            _max_kb  = info[1]

        return {
            "state":         STATE_MAP.get(info[0], "unknown"),
            "cpu_time_ns":   cpu_stats.get("cpu_time", 0),
            "memory_kb":     _used_kb,
            "max_memory_kb": _max_kb,
            "balloon_kb":    info[2],   # raw balloon allocation (for diagnostics)
            "vcpus":         info[3],
            "disk_stats":    disk_stats,
            "net_stats":     net_stats,
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
    """
    VM vCPU sayısını değiştir.
    - count <= maxvcpus → canlı (live) + config güncelleme.
    - count > maxvcpus  → VM durdur → XML maxvcpus güncelle → redefine → yeniden başlat.
    """
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        state_val, _ = dom.state()
        running = (state_val == libvirt.VIR_DOMAIN_RUNNING)

        # Mevcut maxvcpus — inactive XML'den oku
        xml_str = dom.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
        root = ET.fromstring(xml_str)
        vcpu_el = root.find("vcpu")
        cur_max = int(vcpu_el.text or "1") if vcpu_el is not None else 1

        if count > cur_max:
            # maxvcpus aşıldı — offline XML güncelleme gerekli
            was_running = running
            if running:
                dom.destroy()
                time.sleep(1)

            if vcpu_el is not None:
                vcpu_el.text = str(count)
                vcpu_el.set("current", str(count))
            else:
                vcpu_el = ET.SubElement(root, "vcpu")
                vcpu_el.text = str(count)
                vcpu_el.set("current", str(count))

            new_xml = ET.tostring(root, encoding="unicode")
            conn.defineXML(new_xml)

            restarted = False
            if was_running:
                try:
                    dom2 = conn.lookupByUUIDString(vm_id)
                    dom2.create()
                    restarted = True
                except Exception:
                    pass

            return {"ok": True, "vcpus": count, "live": False,
                    "restarted": restarted,
                    "message": "maxvcpus aşıldı — VM yeniden başlatıldı" if restarted else "maxvcpus aşıldı — VM durduruldu, elle başlatın"}
        else:
            # count <= maxvcpus — live hotplug
            flags = libvirt.VIR_DOMAIN_VCPU_CONFIG
            if running:
                flags |= libvirt.VIR_DOMAIN_VCPU_LIVE
            dom.setVcpusFlags(count, flags)
            return {"ok": True, "vcpus": count, "live": running}
    finally:
        conn.close()


def hot_set_memory(vm_id: str, mb: int) -> dict:
    """
    VM RAM değiştir.
    - Azaltma: balloon ile canlı (VM çalışırken anında).
    - Artırma: maxmemory değeri aşıldığında VM durdur → XML güncelle → yeniden başlat.
    """
    conn = _connect()
    try:
        dom = conn.lookupByUUIDString(vm_id)
        state_val, _ = dom.state()
        running = (state_val == libvirt.VIR_DOMAIN_RUNNING)
        kb = mb * 1024

        # Mevcut max memory (KiB) — inactive XML'den oku (güvenilir)
        xml_str = dom.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
        root = ET.fromstring(xml_str)
        mem_el  = root.find("memory")
        cur_el  = root.find("currentMemory")

        if mem_el is not None:
            unit = mem_el.get("unit", "KiB")
            raw  = int(mem_el.text or "0")
            if unit in ("MiB", "mib"):
                cur_max_kb = raw * 1024
            elif unit in ("GiB", "gib"):
                cur_max_kb = raw * 1024 * 1024
            else:
                cur_max_kb = raw
        else:
            cur_max_kb = 0

        if kb > cur_max_kb:
            # RAM artırma: maxmemory değiştirilmeli → offline işlem gerekli
            was_running = running
            if running:
                dom.destroy()   # force stop
                time.sleep(1)

            # <memory> ve <currentMemory> güncelle
            if mem_el is not None:
                mem_el.text = str(kb)
                mem_el.set("unit", "KiB")
            else:
                mem_el = ET.SubElement(root, "memory")
                mem_el.text = str(kb)
                mem_el.set("unit", "KiB")

            if cur_el is not None:
                cur_el.text = str(kb)
                cur_el.set("unit", "KiB")
            else:
                cur_el = ET.SubElement(root, "currentMemory")
                cur_el.text = str(kb)
                cur_el.set("unit", "KiB")

            new_xml = ET.tostring(root, encoding="unicode")
            conn.defineXML(new_xml)

            restarted = False
            if was_running:
                time.sleep(1)
                dom2 = conn.lookupByUUIDString(vm_id)
                dom2.create()
                restarted = True

            _invalidate_list_cache()
            return {
                "ok": True, "memory_mb": mb, "live": False,
                "restarted": restarted,
                "message": ("VM RAM artırıldı ve yeniden başlatıldı." if restarted
                            else "RAM artırıldı (VM zaten durduydu).")
            }
        else:
            # RAM azaltma: balloon ile canlı değiştir
            flags = libvirt.VIR_DOMAIN_MEM_CONFIG
            if running:
                flags |= libvirt.VIR_DOMAIN_MEM_LIVE
            dom.setMemoryFlags(kb, flags)
            _invalidate_list_cache()
            return {
                "ok": True, "memory_mb": mb, "live": running,
                "restarted": False,
                "message": "RAM balloon ile güncellendi."
            }
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

        # IDE/SATA hotplug desteklemez — çalışan VM'e virtio kullan
        if running and bus in ("ide", "sata"):
            bus = "virtio"

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
        mac = _generate_mac()
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
    """Full independent clone — qemu-img convert (not backing-file snapshot).
    Clone disk is self-contained; original can be deleted without affecting clone."""
    source = get_vm(vm_id)
    src_disk = source["disks"][0]["path"] if source["disks"] else None

    if not src_disk:
        raise ValueError("Kaynak VM diski bulunamadı")
    if not os.path.isfile(src_disk):
        raise ValueError(f"Kaynak disk dosyası bulunamadı: {src_disk}")

    conn = _connect()
    try:
        import uuid as _uuid

        def _name_exists(conn, name):
            try:
                conn.lookupByName(name)
                return True
            except Exception:
                return False

        final_name = new_name
        if _name_exists(conn, new_name):
            counter = 2
            while _name_exists(conn, f"{new_name}-{counter}"):
                counter += 1
            final_name = f"{new_name}-{counter}"

        new_disk = os.path.join(config.DISK_DIR, f"{final_name}.qcow2")

        # Full independent copy — not a backing-file snapshot
        subprocess.run(
            ["qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", src_disk, new_disk],
            check=True, capture_output=True,
            timeout=7200   # 2h max for large disks
        )

        dom = conn.lookupByUUIDString(vm_id)
        xml_str = dom.XMLDesc()
        root = ET.fromstring(xml_str)

        root.find("name").text = final_name
        root.find("uuid").text = str(_uuid.uuid4())

        # Update disk source to new disk
        for source_el in root.findall(".//disk[@device='disk']/source"):
            source_el.set("file", new_disk)

        # Eject cloud-init CD-ROM so clone doesn't re-run cloud-init on first boot
        for disk_el in root.findall(".//disk[@device='cdrom']"):
            src_el = disk_el.find("source")
            if src_el is not None and "cloud-init" in (src_el.get("file", "") or "").lower():
                disk_el.remove(src_el)

        # Assign new unique VNC port
        vnc_port = _next_vnc_port()
        for g in root.findall(".//graphics[@type='vnc']"):
            g.set("port", str(vnc_port))

        # Assign fresh random MAC addresses to avoid conflicts with original VM
        for iface_el in root.findall(".//interface"):
            mac_el = iface_el.find("mac")
            if mac_el is not None:
                new_mac = "52:54:00:%02x:%02x:%02x" % (
                    random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)
                )
                mac_el.set("address", new_mac)

        new_xml = ET.tostring(root, encoding="unicode")
        new_dom = conn.defineXML(new_xml)

        reg = _load_vnc_registry()
        reg[new_dom.UUIDString()] = vnc_port
        _save_vnc_registry(reg)
        _invalidate_list_cache()

        return {"id": new_dom.UUIDString(), "name": final_name, "cloned_from": vm_id,
                "disk": new_disk}
    finally:
        conn.close()


# ── QEMU Guest Agent ──────────────────────────────────────────────────────────

def _qemu_agent_cmd(vm_name: str, execute: str, arguments: dict = None, timeout: int = 5):
    """virsh qemu-agent-command wrapper. None döner hata/timeout durumunda."""
    import json as _json
    cmd_obj = {"execute": execute}
    if arguments:
        cmd_obj["arguments"] = arguments
    try:
        r = subprocess.run(
            ["virsh", "qemu-agent-command", vm_name,
             _json.dumps(cmd_obj), "--timeout", str(timeout)],
            capture_output=True, text=True, timeout=timeout + 3
        )
        if r.returncode != 0:
            return None
        parsed = _json.loads(r.stdout)
        return parsed.get("return")
    except Exception:
        return None


def get_guest_agent_info(vm_id: str) -> dict:
    """
    QEMU guest agent üzerinden VM içinden bilgi topla.
    Döner: {status, version, hostname, os, interfaces, filesystems}
    """
    # VM adını bul
    conn = _connect()
    try:
        try:
            dom = conn.lookupByUUIDString(vm_id)
        except libvirt.libvirtError:
            dom = conn.lookupByName(vm_id)
        vm_name = dom.name()
        state   = dom.info()[0]
    finally:
        conn.close()

    result = {
        "status":      "unavailable",
        "version":     None,
        "hostname":    None,
        "os":          None,
        "interfaces":  [],
        "filesystems": [],
    }

    # VM çalışmıyorsa agent yoktur
    if state != libvirt.VIR_DOMAIN_RUNNING:
        result["status"] = "vm_stopped"
        return result

    # Ping — agent canlı mı?
    ping = _qemu_agent_cmd(vm_name, "guest-ping", timeout=3)
    if ping is None:
        return result  # unavailable
    result["status"] = "running"

    # Agent sürümü
    info = _qemu_agent_cmd(vm_name, "guest-info")
    if info and isinstance(info, dict):
        result["version"] = info.get("version")

    # Hostname
    hn = _qemu_agent_cmd(vm_name, "guest-get-host-name")
    if hn and isinstance(hn, dict):
        result["hostname"] = hn.get("host-name")

    # OS bilgisi
    os_info = _qemu_agent_cmd(vm_name, "guest-get-osinfo")
    if os_info and isinstance(os_info, dict):
        result["os"] = {
            "id":      os_info.get("id"),
            "name":    os_info.get("name"),
            "version": os_info.get("version-id"),
            "kernel":  os_info.get("kernel-version"),
            "machine": os_info.get("machine"),
        }

    # Ağ arayüzleri + IP'ler (DHCP'den daha doğru)
    net_ifaces = _qemu_agent_cmd(vm_name, "guest-network-get-interfaces")
    if net_ifaces and isinstance(net_ifaces, list):
        result["interfaces"] = [
            {
                "name": iface.get("name"),
                "mac":  iface.get("hardware-address"),
                "ips":  [
                    {
                        "ip":     addr.get("ip-address"),
                        "prefix": addr.get("prefix"),
                        "type":   addr.get("ip-address-type"),
                    }
                    for addr in iface.get("ip-addresses", [])
                ],
            }
            for iface in net_ifaces
            if iface.get("name") != "lo"
        ]

    # Dosya sistemi kullanımı
    fs_info = _qemu_agent_cmd(vm_name, "guest-get-fsinfo")
    if fs_info and isinstance(fs_info, list):
        result["filesystems"] = [
            {
                "mountpoint":  f.get("mountpoint"),
                "total_bytes": f.get("total-bytes"),
                "used_bytes":  f.get("used-bytes"),
                "fs_type":     f.get("type"),
                "name":        f.get("name"),
            }
            for f in fs_info
            if f.get("total-bytes") and f.get("mountpoint")
        ]

    return result


def get_guest_agent_status(vm_id: str) -> str:
    """Hızlı durum kontrolü: 'running' | 'unavailable' | 'vm_stopped'."""
    conn = _connect()
    try:
        try:
            dom = conn.lookupByUUIDString(vm_id)
        except libvirt.libvirtError:
            dom = conn.lookupByName(vm_id)
        vm_name = dom.name()
        state   = dom.info()[0]
    finally:
        conn.close()

    if state != libvirt.VIR_DOMAIN_RUNNING:
        return "vm_stopped"
    ping = _qemu_agent_cmd(vm_name, "guest-ping", timeout=2)
    return "running" if ping is not None else "unavailable"
