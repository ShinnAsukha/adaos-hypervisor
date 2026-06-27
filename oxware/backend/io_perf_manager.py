# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""
OXware VM I/O Performance Manager
─────────────────────────────────
Kernel-yolu VM I/O performans ayarları — Proxmox paritesi:
  - iothreads  : dedike I/O thread sayısı (<domain><iothreads>)
  - disk aio   : native | threads | io_uring  (+ cache, queues/multiqueue)
  - net queues : virtio-net multiqueue (<interface><driver queues=N>)
  - vhost      : net backend vhost (kernel) aç/kapat

Değişiklikler kalıcı (inactive) XML'e yazılır; çoğu canlı değiştirilemez,
bu yüzden restart_required=True döner. Tüm fonksiyonlar libvirt yoksa /
domain bulunamazsa düzgün hata döner, çökmez.
"""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

log = logging.getLogger("oxware.io_perf")

try:
    import libvirt  # type: ignore
    _HAS_LIBVIRT = True
except Exception:  # pragma: no cover - dev/Windows
    libvirt = None
    _HAS_LIBVIRT = False

_VALID_AIO = ("native", "threads", "io_uring")
_VALID_CACHE = ("none", "writeback", "writethrough", "directsync", "unsafe")


def _connect():
    if not _HAS_LIBVIRT:
        raise RuntimeError("libvirt yok")
    import config
    return libvirt.open(config.LIBVIRT_URI)


def _lookup(conn, vm_id):
    try:
        return conn.lookupByUUIDString(vm_id)
    except Exception:
        return conn.lookupByName(vm_id)


def _inactive_xml(dom) -> ET.Element:
    flags = libvirt.VIR_DOMAIN_XML_INACTIVE
    return ET.fromstring(dom.XMLDesc(flags))


def get_io_config(vm_id: str) -> dict:
    """VM'in mevcut I/O yapılandırmasını oku (iothreads + disk + net)."""
    if not _HAS_LIBVIRT:
        return {"ok": False, "error": "libvirt yok", "available": False}
    conn = None
    try:
        conn = _connect()
        dom = _lookup(conn, vm_id)
        root = _inactive_xml(dom)
        iothreads = root.findtext("iothreads") or "0"
        disks = []
        for d in root.findall("./devices/disk"):
            if d.get("device") not in (None, "disk"):
                continue
            drv = d.find("driver")
            tgt = d.find("target")
            disks.append({
                "target": (tgt.get("dev") if tgt is not None else None),
                "bus": (tgt.get("bus") if tgt is not None else None),
                "aio": (drv.get("io") if drv is not None else None),
                "cache": (drv.get("cache") if drv is not None else None),
                "iothread": (drv.get("iothread") if drv is not None else None),
                "queues": (drv.get("queues") if drv is not None else None),
            })
        nets = []
        for n in root.findall("./devices/interface"):
            mac = n.find("mac")
            drv = n.find("driver")
            nets.append({
                "mac": (mac.get("address") if mac is not None else None),
                "model": (n.find("model").get("type") if n.find("model") is not None else None),
                "backend": (drv.get("name") if drv is not None else None),
                "queues": (drv.get("queues") if drv is not None else None),
            })
        return {"ok": True, "available": True, "vm_id": vm_id,
                "iothreads": int(iothreads), "disks": disks, "interfaces": nets}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _redefine(dom, root) -> None:
    conn = dom.connect()
    conn.defineXML(ET.tostring(root, encoding="unicode"))


def set_iothreads(vm_id: str, count: int) -> dict:
    """Domain iothread havuzunu ayarla. 0 = kaldır."""
    count = max(0, int(count))
    if not _HAS_LIBVIRT:
        return {"ok": False, "error": "libvirt yok"}
    conn = None
    try:
        conn = _connect()
        dom = _lookup(conn, vm_id)
        root = _inactive_xml(dom)
        el = root.find("iothreads")
        if count == 0:
            if el is not None:
                root.remove(el)
        else:
            if el is None:
                el = ET.SubElement(root, "iothreads")
            el.text = str(count)
        _redefine(dom, root)
        log.info("iothreads=%s vm=%s", count, vm_id)
        return {"ok": True, "iothreads": count, "restart_required": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def set_disk_perf(vm_id: str, target: str, aio: str = None, cache: str = None,
                  iothread: int = None, queues: int = None) -> dict:
    """Bir diskin sürücü performans ayarlarını değiştir.

    target  : disk hedefi (vda, sda…)
    aio     : native|threads|io_uring  (io_uring = en yeni kernel yolu)
    cache   : none|writeback|…
    iothread: bu diski şu iothread'e bağla (>=1). 0/None = kaldır.
    queues  : virtio-blk multiqueue kuyruk sayısı.
    """
    if not _HAS_LIBVIRT:
        return {"ok": False, "error": "libvirt yok"}
    if aio is not None and aio not in _VALID_AIO:
        return {"ok": False, "error": f"aio geçersiz (izinli: {_VALID_AIO})"}
    if cache is not None and cache not in _VALID_CACHE:
        return {"ok": False, "error": f"cache geçersiz (izinli: {_VALID_CACHE})"}
    conn = None
    try:
        conn = _connect()
        dom = _lookup(conn, vm_id)
        root = _inactive_xml(dom)
        disk = None
        for d in root.findall("./devices/disk"):
            tgt = d.find("target")
            if tgt is not None and tgt.get("dev") == target:
                disk = d
                break
        if disk is None:
            return {"ok": False, "error": f"disk bulunamadı: {target}"}
        drv = disk.find("driver")
        if drv is None:
            drv = ET.SubElement(disk, "driver")
            drv.set("name", "qemu")
            drv.set("type", "qcow2")
        # io_uring + native, cache='none' ile uyumludur; cache verilmezse
        # native/io_uring için güvenli varsayılan 'none' uygula.
        if aio is not None:
            drv.set("io", aio)
            if cache is None and drv.get("cache") is None and aio in ("native", "io_uring"):
                drv.set("cache", "none")
        if cache is not None:
            drv.set("cache", cache)
        if iothread is not None:
            if int(iothread) <= 0:
                drv.attrib.pop("iothread", None)
            else:
                drv.set("iothread", str(int(iothread)))
        if queues is not None:
            if int(queues) <= 1:
                drv.attrib.pop("queues", None)
            else:
                drv.set("queues", str(int(queues)))
        _redefine(dom, root)
        log.info("disk perf vm=%s target=%s aio=%s cache=%s iothread=%s q=%s",
                 vm_id, target, aio, cache, iothread, queues)
        return {"ok": True, "target": target, "restart_required": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def set_net_multiqueue(vm_id: str, mac: str, queues: int,
                       vhost: bool = True) -> dict:
    """virtio-net multiqueue + vhost backend ayarla.

    queues : 1 = multiqueue kapalı. >1 = N kuyruk (vCPU sayısına eşit önerilir).
    vhost  : True = kernel vhost-net backend (yüksek throughput).
    """
    if not _HAS_LIBVIRT:
        return {"ok": False, "error": "libvirt yok"}
    queues = max(1, int(queues))
    conn = None
    try:
        conn = _connect()
        dom = _lookup(conn, vm_id)
        root = _inactive_xml(dom)
        iface = None
        for n in root.findall("./devices/interface"):
            m = n.find("mac")
            if m is not None and (m.get("address") or "").lower() == (mac or "").lower():
                iface = n
                break
        if iface is None:
            return {"ok": False, "error": f"NIC bulunamadı: {mac}"}
        model = iface.find("model")
        if model is None or model.get("type") != "virtio":
            return {"ok": False, "error": "multiqueue yalnız virtio NIC'te"}
        drv = iface.find("driver")
        if drv is None:
            drv = ET.SubElement(iface, "driver")
        if queues <= 1:
            drv.attrib.pop("queues", None)
        else:
            drv.set("queues", str(queues))
        drv.set("name", "vhost" if vhost else "qemu")
        _redefine(dom, root)
        log.info("net mq vm=%s mac=%s queues=%s vhost=%s", vm_id, mac, queues, vhost)
        return {"ok": True, "mac": mac, "queues": queues, "vhost": vhost,
                "restart_required": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def recommend(vm_id: str) -> dict:
    """vCPU/disk sayısına göre güvenli öneri üret (uygulamaz, sadece önerir)."""
    cfg = get_io_config(vm_id)
    if not cfg.get("ok"):
        return cfg
    n_disks = len(cfg.get("disks", []))
    recs = {
        "iothreads": max(1, min(4, n_disks)),
        "disk_aio": "io_uring",
        "disk_cache": "none",
        "net_queues": "vCPU sayısına eşit (örn. 4)",
        "vhost": True,
        "note": "io_uring + dedike iothread = en düşük gecikme. Uygulamadan "
                "önce VM'i kapatmak gerekir (restart_required).",
    }
    return {"ok": True, "vm_id": vm_id, "recommendations": recs}
