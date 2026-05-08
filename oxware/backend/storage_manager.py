import libvirt
import xml.etree.ElementTree as ET
import subprocess
import os
import config

LIBVIRT_URI = config.LIBVIRT_URI


def _connect():
    return libvirt.open(LIBVIRT_URI)


def list_pools():
    conn = _connect()
    pools = []
    try:
        for pool in conn.listAllStoragePools():
            xml_str = pool.XMLDesc()
            root = ET.fromstring(xml_str)
            path_el = root.find(".//path")

            try:
                info = pool.info()
                capacity = info[1]
                allocation = info[2]
                available = info[3]
            except Exception:
                capacity = allocation = available = 0

            pools.append({
                "uuid": pool.UUIDString(),
                "name": pool.name(),
                "active": bool(pool.isActive()),
                "autostart": bool(pool.autostart()),
                "type": root.get("type", "dir"),
                "path": path_el.text if path_el is not None else "",
                "capacity_gb": round(capacity / (1024**3), 2),
                "allocation_gb": round(allocation / (1024**3), 2),
                "available_gb": round(available / (1024**3), 2),
            })
    finally:
        conn.close()
    return pools


def create_pool(name, path, pool_type="dir"):
    os.makedirs(path, exist_ok=True)

    xml = f"""<pool type='{pool_type}'>
  <name>{name}</name>
  <target>
    <path>{path}</path>
  </target>
</pool>"""

    conn = _connect()
    try:
        pool = conn.storagePoolDefineXML(xml)
        pool.build(0)
        pool.setAutostart(1)
        pool.create()
        return {"uuid": pool.UUIDString(), "name": name, "status": "created"}
    finally:
        conn.close()


def delete_pool(pool_uuid, delete_files=False):
    conn = _connect()
    try:
        try:
            pool = conn.storagePoolLookupByUUIDString(pool_uuid)
        except libvirt.libvirtError:
            pool = conn.storagePoolLookupByName(pool_uuid)

        if pool.isActive():
            pool.destroy()

        if delete_files:
            pool.delete(0)

        pool.undefine()
        return {"status": "deleted"}
    finally:
        conn.close()


def list_volumes(pool_uuid):
    conn = _connect()
    try:
        try:
            pool = conn.storagePoolLookupByUUIDString(pool_uuid)
        except libvirt.libvirtError:
            pool = conn.storagePoolLookupByName(pool_uuid)

        pool.refresh()
        volumes = []
        for vol in pool.listAllVolumes():
            xml_str = vol.XMLDesc()
            root = ET.fromstring(xml_str)
            fmt = root.find(".//format")

            try:
                info = vol.info()
                capacity = info[1]
                allocation = info[2]
            except Exception:
                capacity = allocation = 0

            volumes.append({
                "key": vol.key(),
                "name": vol.name(),
                "path": vol.path(),
                "format": fmt.get("type", "raw") if fmt is not None else "raw",
                "capacity_gb": round(capacity / (1024**3), 2),
                "allocation_gb": round(allocation / (1024**3), 2),
            })
        return volumes
    finally:
        conn.close()


def create_volume(pool_uuid, name, size_gb, vol_format="qcow2"):
    xml = f"""<volume type='file'>
  <name>{name}.{vol_format}</name>
  <capacity unit='GiB'>{size_gb}</capacity>
  <target>
    <format type='{vol_format}'/>
  </target>
</volume>"""

    conn = _connect()
    try:
        try:
            pool = conn.storagePoolLookupByUUIDString(pool_uuid)
        except libvirt.libvirtError:
            pool = conn.storagePoolLookupByName(pool_uuid)

        vol = pool.createXML(xml, 0)
        return {"name": vol.name(), "path": vol.path(), "status": "created"}
    finally:
        conn.close()


def delete_volume(pool_uuid, vol_name):
    conn = _connect()
    try:
        try:
            pool = conn.storagePoolLookupByUUIDString(pool_uuid)
        except libvirt.libvirtError:
            pool = conn.storagePoolLookupByName(pool_uuid)

        vol = pool.storageVolLookupByName(vol_name)
        vol.delete()
        return {"status": "deleted"}
    finally:
        conn.close()


def upload_iso(file_path, dest_name=None):
    if not dest_name:
        dest_name = os.path.basename(file_path)

    dest = os.path.join(config.ISO_DIR, dest_name)
    os.makedirs(config.ISO_DIR, exist_ok=True)

    if file_path != dest:
        import shutil
        shutil.copy2(file_path, dest)

    return {"name": dest_name, "path": dest, "size": os.path.getsize(dest)}


def list_isos():
    isos = []
    if os.path.exists(config.ISO_DIR):
        for f in os.listdir(config.ISO_DIR):
            if f.lower().endswith(".iso"):
                path = os.path.join(config.ISO_DIR, f)
                isos.append({
                    "name": f,
                    "path": path,
                    "size_mb": round(os.path.getsize(path) / (1024**2), 1),
                })
    return isos


def delete_iso(name):
    path = os.path.join(config.ISO_DIR, name)
    if os.path.exists(path):
        os.remove(path)
        return {"status": "deleted"}
    raise FileNotFoundError(f"ISO bulunamadı: {name}")


def get_disk_usage():
    result = subprocess.run(
        ["df", "-h", "--output=source,fstype,size,used,avail,pcent,target"],
        capture_output=True, text=True
    )
    lines = result.stdout.strip().split("\n")
    disks = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 7:
            disks.append({
                "device": parts[0],
                "fstype": parts[1],
                "size": parts[2],
                "used": parts[3],
                "avail": parts[4],
                "percent": parts[5],
                "mount": parts[6],
            })
    return disks


def get_block_devices():
    """Return physical block devices via lsblk (disk + part level)."""
    import json as _json
    try:
        r = subprocess.run(
            ["lsblk", "-J", "-b", "-o",
             "NAME,MODEL,SIZE,TYPE,MOUNTPOINT,FSTYPE,HOTPLUG,ROTA,STATE,SERIAL,VENDOR"],
            capture_output=True, text=True, timeout=10
        )
        data = _json.loads(r.stdout)
    except Exception:
        return []

    # df -B1 for used/available per mountpoint
    df_map = {}
    try:
        df = subprocess.run(
            ["df", "-B1", "--output=source,used,avail,pcent"],
            capture_output=True, text=True
        )
        for line in df.stdout.strip().split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 4:
                df_map[parts[0]] = {
                    "used_bytes":  int(parts[1]),
                    "avail_bytes": int(parts[2]),
                    "percent":     parts[3],
                }
    except Exception:
        pass

    def _parse(devices, parent=None):
        result = []
        for d in devices:
            name     = d.get("name", "")
            dev_path = f"/dev/{name}"
            size_b   = int(d.get("size") or 0)
            mnt      = d.get("mountpoint") or ""
            dtype    = d.get("type", "")
            df_info  = df_map.get(dev_path, df_map.get(mnt, {}))

            entry = {
                "device":      dev_path,
                "name":        name,
                "model":       (d.get("model") or d.get("vendor") or "").strip(),
                "serial":      (d.get("serial") or "").strip(),
                "size_bytes":  size_b,
                "size":        _fmt_bytes(size_b),
                "type":        dtype,
                "mountpoint":  mnt,
                "fstype":      d.get("fstype") or "",
                "removable":   bool(d.get("hotplug")),
                "rotational":  bool(d.get("rota")),
                "state":       d.get("state") or ("mounted" if mnt else "available"),
                "used_bytes":  df_info.get("used_bytes", 0),
                "avail_bytes": df_info.get("avail_bytes", 0),
                "percent":     df_info.get("percent", ""),
                "parent":      parent,
                "children":    [],
            }

            if d.get("children"):
                entry["children"] = _parse(d["children"], parent=name)

            result.append(entry)
        return result

    raw = data.get("blockdevices", [])
    # Only disks + partitions at top level
    return _parse(raw)


def _fmt_bytes(b):
    if b == 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"
