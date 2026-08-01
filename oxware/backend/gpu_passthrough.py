#!/usr/bin/env python3
# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy. MIT License.
"""
GPU Passthrough Wizard — tam-GPU VFIO passthrough'u otomatikleştirir
────────────────────────────────────────────────────────────────────
Kullanıcı IOMMU / VFIO / kernel parametre / ACS override ile uğraşmasın.
Wizard akışı:

  1. iommu_status()          → IOMMU açık mı? (intel/amd, kernel cmdline)
  2. list_passthrough_gpus() → GPU'lar + IOMMU grubu + grup üyeleri + sürücü
  3. preflight(pci)          → hazır mı? her kontrol pass/fail + düzeltme ipucu
  4. generate_plan(pci)      → tam remediation (kernel cmdline, modprobe, reboot)
  5. bind_vfio(pci)          → GPU'yu host sürücüsünden alıp vfio-pci'ye bağla
  6. attach_to_vm(vm, pci)   → <hostdev> PCI olarak VM'e ekle (+ ses fonksiyonu)

vGPU (paylaşımlı mdev) için vgpu_manager.py'ye bakın — bu modül TAM GPU'yu
tek VM'e verir (VFIO passthrough). Linux + root + libvirt gerektirir;
diğer ortamlarda güvenli/boş döner.
"""

import os
import re
import subprocess
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import libvirt
except ImportError:  # pragma: no cover
    libvirt = None

log = logging.getLogger("gpu_passthrough")

PCI_DEVICES = Path("/sys/bus/pci/devices")
IOMMU_GROUPS = Path("/sys/kernel/iommu_groups")


# ── Düşük seviye /sys okuyucular ───────────────────────────────────────────────

def _read(p, default=""):
    try:
        return Path(p).read_text().strip()
    except Exception:
        return default


def _pci_ids(addr: str) -> tuple:
    """(vendor_id, device_id) hex without 0x, ör. ('10de','2204')."""
    v = _read(PCI_DEVICES / addr / "vendor").replace("0x", "")
    d = _read(PCI_DEVICES / addr / "device").replace("0x", "")
    return v, d


def _current_driver(addr: str) -> str:
    link = PCI_DEVICES / addr / "driver"
    try:
        if link.exists():
            return os.path.basename(os.readlink(link))
    except Exception:
        pass
    return ""


def _iommu_group(addr: str) -> str:
    link = PCI_DEVICES / addr / "iommu_group"
    try:
        if link.exists():
            return os.path.basename(os.readlink(link))
    except Exception:
        pass
    return ""


def _group_members(group: str) -> list:
    if not group:
        return []
    gdir = IOMMU_GROUPS / group / "devices"
    try:
        return sorted(p.name for p in gdir.iterdir())
    except Exception:
        return []


def _lspci_map() -> dict:
    """addr -> {'name','driver','class'} via lspci -Dnnk (best-effort)."""
    out = {}
    try:
        r = subprocess.run(["lspci", "-Dnnk"], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return out
        cur = None
        for line in r.stdout.splitlines():
            if not line.startswith("\t") and line.strip():
                addr = line.split()[0]
                out[addr] = {"name": line[len(addr):].strip(), "driver": "", "class": ""}
                cur = addr
            elif cur and "Kernel driver in use:" in line:
                out[cur]["driver"] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    return out


# ── 1. IOMMU durumu ────────────────────────────────────────────────────────────

def iommu_status() -> dict:
    cmdline = _read("/proc/cmdline")
    groups_present = IOMMU_GROUPS.exists() and any(IOMMU_GROUPS.iterdir()) \
        if IOMMU_GROUPS.exists() else False
    cpu = _read("/proc/cpuinfo")
    vendor = "intel" if "GenuineIntel" in cpu else ("amd" if "AuthenticAMD" in cpu else "unknown")
    has_flag = ("intel_iommu=on" in cmdline) or ("amd_iommu=on" in cmdline) or ("iommu=pt" in cmdline)
    return {
        "enabled": bool(groups_present),
        "cpu_vendor": vendor,
        "kernel_cmdline_has_iommu": has_flag,
        "iommu_groups_present": bool(groups_present),
        "kernel_cmdline": cmdline,
    }


# ── 2. Passthrough'a uygun GPU listesi ─────────────────────────────────────────

def _is_gpu_class(addr: str) -> bool:
    cls = _read(PCI_DEVICES / addr / "class")   # 0x030000 = VGA, 0x030200 = 3D
    return cls.startswith("0x0300") or cls.startswith("0x0302")


def _audio_companion(addr: str, group_members: list) -> str:
    """Aynı slot'taki ses fonksiyonunu bul (GPU 65:00.0 -> ses 65:00.1)."""
    base = addr.rsplit(".", 1)[0]
    for m in group_members:
        if m != addr and m.startswith(base):
            cls = _read(PCI_DEVICES / m / "class")
            if cls.startswith("0x0403") or cls.startswith("0x0401"):   # audio
                return m
    return ""


def list_passthrough_gpus() -> list:
    out = []
    if not PCI_DEVICES.exists():
        return out
    names = _lspci_map()
    for dev in sorted(PCI_DEVICES.iterdir()):
        addr = dev.name
        if not _is_gpu_class(addr):
            continue
        group = _iommu_group(addr)
        members = _group_members(group)
        vid, did = _pci_ids(addr)
        driver = _current_driver(addr)
        audio = _audio_companion(addr, members)
        # Grup "temiz" = sadece GPU (+ ses fonksiyonu) var, başka aygıt yok.
        extra = [m for m in members if m != addr and m != audio]
        out.append({
            "pci": addr,
            "name": names.get(addr, {}).get("name", ""),
            "vendor_id": vid,
            "device_id": did,
            "ids": f"{vid}:{did}",
            "iommu_group": group,
            "group_members": members,
            "audio_companion": audio,
            "current_driver": driver,
            "bound_to_vfio": driver == "vfio-pci",
            "group_clean": len(extra) == 0,
            "group_extra_devices": extra,
        })
    return out


# ── 3. Preflight kontrolleri ───────────────────────────────────────────────────

def preflight(pci: str) -> dict:
    checks = []

    def add(id_, ok, sev, msg, fix=""):
        checks.append({"id": id_, "ok": bool(ok), "severity": sev, "msg": msg, "fix": fix})

    iommu = iommu_status()
    add("iommu_enabled", iommu["enabled"], "critical",
        "IOMMU %s" % ("etkin" if iommu["enabled"] else "KAPALI"),
        "" if iommu["enabled"] else "Kernel cmdline'a %s_iommu=on iommu=pt ekleyin, reboot."
        % iommu["cpu_vendor"])

    gpu = next((g for g in list_passthrough_gpus() if g["pci"] == pci), None)
    if not gpu:
        add("gpu_found", False, "critical", "GPU %s bulunamadı" % pci,
            "list_passthrough_gpus() ile geçerli PCI adresi seçin.")
        return {"pci": pci, "ready": False, "checks": checks, "gpu": None}

    add("gpu_found", True, "info", "GPU: %s" % (gpu["name"] or pci))
    add("vfio_modules", _vfio_modules_loaded(), "warning",
        "vfio-pci modülü %s" % ("yüklü" if _vfio_modules_loaded() else "yüklü değil"),
        "" if _vfio_modules_loaded() else "modprobe vfio-pci  (veya generate_plan uygula)")
    add("iommu_group_clean", gpu["group_clean"], "critical",
        "IOMMU grubu %s" % ("temiz" if gpu["group_clean"] else
                            "KİRLİ — başka aygıt(lar) var: %s" % ", ".join(gpu["group_extra_devices"])),
        "" if gpu["group_clean"] else
        "Grup üyeleri birlikte geçmeli VEYA ACS override (RİSKLİ) gerekir. "
        "GPU'yu başka bir PCIe slotuna taşımayı deneyin.")
    add("driver_status", True, "info",
        "Mevcut sürücü: %s" % (gpu["current_driver"] or "yok"))
    if gpu["bound_to_vfio"]:
        add("vfio_bound", True, "info", "GPU zaten vfio-pci'ye bağlı — hazır.")

    ready = all(c["ok"] for c in checks if c["severity"] == "critical")
    return {"pci": pci, "ready": ready, "checks": checks, "gpu": gpu}


def _vfio_modules_loaded() -> bool:
    try:
        r = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=5)
        return "vfio_pci" in r.stdout or "vfio-pci" in r.stdout
    except Exception:
        return False


# ── 4. Remediation planı (otomatik üret) ───────────────────────────────────────

def generate_plan(pci: str) -> dict:
    iommu = iommu_status()
    gpu = next((g for g in list_passthrough_gpus() if g["pci"] == pci), None)
    if not gpu:
        return {"ok": False, "error": "GPU %s bulunamadı" % pci}

    steps = []
    reboot = False

    # a) IOMMU kernel cmdline
    if not iommu["enabled"] or not iommu["kernel_cmdline_has_iommu"]:
        flag = "intel_iommu=on" if iommu["cpu_vendor"] == "intel" else "amd_iommu=on"
        steps.append({
            "id": "kernel_cmdline",
            "desc": "IOMMU'yu aç (GRUB_CMDLINE_LINUX'a ekle)",
            "file": "/etc/default/grub",
            "add": f"{flag} iommu=pt",
            "apply": "update-grub  # veya grub2-mkconfig -o /boot/grub2/grub.cfg",
            "reboot": True,
        })
        reboot = True

    # b) vfio-pci'yi GPU (+ses) id'lerine erken bağla
    ids = [gpu["ids"]]
    if gpu["audio_companion"]:
        av, ad = _pci_ids(gpu["audio_companion"])
        if av and ad:
            ids.append(f"{av}:{ad}")
    steps.append({
        "id": "modprobe_vfio",
        "desc": "vfio-pci'yi GPU (+ses) aygıt ID'lerine boot'ta bağla",
        "file": "/etc/modprobe.d/vfio-oxware.conf",
        "content": "options vfio-pci ids=%s\nsoftdep nvidia pre: vfio-pci\n"
                   "softdep nouveau pre: vfio-pci\nsoftdep amdgpu pre: vfio-pci"
                   % ",".join(ids),
        "apply": "update-initramfs -u   # veya dracut -f",
        "reboot": True,
    })
    reboot = True

    # c) vfio modüllerini yükle
    steps.append({
        "id": "modules_load",
        "desc": "vfio modüllerini boot'ta yükle",
        "file": "/etc/modules-load.d/vfio-oxware.conf",
        "content": "vfio\nvfio_iommu_type1\nvfio_pci",
    })

    # d) Grup kirliyse ACS override uyarısı
    warnings = []
    if not gpu["group_clean"]:
        warnings.append(
            "IOMMU grubu kirli (%s). Güvenli çözüm: GPU'yu CPU'ya doğrudan bağlı "
            "bir PCIe slotuna taşıyın. Son çare pcie_acs_override=downstream,multifunction "
            "GÜVENLİK RİSKİDİR (izolasyonu zayıflatır) — üretimde önerilmez."
            % gpu["iommu_group"])

    return {
        "ok": True, "pci": pci, "gpu": gpu["name"], "ids": ids,
        "steps": steps, "reboot_required": reboot, "warnings": warnings,
    }


# ── 5. vfio-pci'ye canlı bağla (reboot'suz, mümkünse) ──────────────────────────

def _assert_is_gpu(pci: str) -> dict | None:
    """SEC: yalnızca gerçekten GPU olan aygıtlara izin ver.

    Eskiden sadece /sys/bus/pci/devices/<pci> var mı diye bakılıyordu; bu,
    `0000:00:17.0` (SATA/NVMe denetleyici) veya yönetim NIC'i verilerek host'un
    kök diskini / panel erişimini kalıcı olarak koparmaya izin veriyordu.
    Ayrıca `../` içeren yollar PCI_DEVICES dizininden dışarı çıkabiliyordu.
    """
    if not re.fullmatch(r"(?:[0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", pci or ""):
        return {"ok": False, "error": "Geçersiz PCI adresi: %r" % pci}
    known = {g["pci"] for g in list_passthrough_gpus()}
    known |= {g["audio_companion"] for g in list_passthrough_gpus() if g["audio_companion"]}
    if pci not in known:
        return {"ok": False,
                "error": "%s bir GPU (veya GPU ses fonksiyonu) değil — reddedildi. "
                         "Passthrough'a uygun aygıtlar için /api/gpu/wizard/overview." % pci}
    return None


def bind_vfio(pci: str) -> dict:
    """GPU'yu mevcut sürücüden ayırıp vfio-pci'ye bağla. Root gerekir.
    Not: aktif kullanılan (host ekranı süren) GPU'da başarısız olabilir."""
    guard = _assert_is_gpu(pci)
    if guard:
        return guard
    dev = PCI_DEVICES / pci
    if not dev.exists():
        return {"ok": False, "error": "PCI aygıtı yok: %s" % pci}
    try:
        vid, did = _pci_ids(pci)
        # vfio-pci modülü + new_id
        subprocess.run(["modprobe", "vfio-pci"], timeout=10)
        cur = _current_driver(pci)
        if cur and cur != "vfio-pci":
            _write(dev / "driver" / "unbind", pci)
        _write(Path("/sys/bus/pci/drivers/vfio-pci/new_id"), f"{vid} {did}")
        if not _current_driver(pci):
            _write(Path("/sys/bus/pci/drivers/vfio-pci/bind"), pci)
        ok = _current_driver(pci) == "vfio-pci"
        return {"ok": ok, "pci": pci, "driver": _current_driver(pci),
                "note": "" if ok else "Canlı bind başarısız — generate_plan uygulayıp reboot edin."}
    except Exception as e:
        log.error("bind_vfio: %s", e)
        return {"ok": False, "error": str(e),
                "note": "Canlı bind başarısız — generate_plan uygulayıp reboot edin."}


def _write(path, value):
    with open(path, "w") as f:
        f.write(value)


# ── 6. VM'e <hostdev> PCI olarak ekle/çıkar ────────────────────────────────────

def _pci_addr_xml(pci: str) -> dict:
    # fullmatch: sonuna eklenmiş çöp (ör. "0000:65:00.0/../x") reddedilsin
    m = re.fullmatch(r"(?:([0-9a-fA-F]{4}):)?([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", pci or "")
    if not m:
        raise ValueError("geçersiz PCI adresi: %s" % pci)
    dom = m.group(1) or "0000"
    return {"domain": "0x" + dom, "bus": "0x" + m.group(2),
            "slot": "0x" + m.group(3), "function": "0x" + m.group(4)}


def _hostdev_xml(pci: str) -> str:
    a = _pci_addr_xml(pci)
    return (f"<hostdev mode='subsystem' type='pci' managed='yes'>"
            f"<source><address domain='{a['domain']}' bus='{a['bus']}' "
            f"slot='{a['slot']}' function='{a['function']}'/></source></hostdev>")


def _connect():
    if libvirt is None:
        raise RuntimeError("libvirt unavailable")
    import config
    return libvirt.open(config.LIBVIRT_URI)


def _lookup_domain(conn, vm_id: str):
    """VM'i önce UUID sonra isimle bul.

    Bug: yalnızca lookupByName kullanılıyordu; panel ise UUID gönderiyor
    (vm.id = dom.UUIDString()) → attach/detach HER ZAMAN
    'no domain with matching name' ile patlıyordu.
    """
    try:
        return conn.lookupByUUIDString(vm_id)
    except Exception:
        return conn.lookupByName(vm_id)


def attach_to_vm(vm_id: str, pci: str, with_audio: bool = True) -> dict:
    """GPU'yu (ve varsa ses fonksiyonunu) VM'e hostdev PCI olarak ekle."""
    guard = _assert_is_gpu(pci)
    if guard:
        return guard      # SEC: managed='yes' hostdev, VM açılışında aygıtı host'tan söker
    try:
        targets = [pci]
        if with_audio:
            gpu = next((g for g in list_passthrough_gpus() if g["pci"] == pci), None)
            if gpu and gpu["audio_companion"]:
                targets.append(gpu["audio_companion"])
        conn = _connect()
        try:
            dom = _lookup_domain(conn, vm_id)
            live = dom.isActive()
            flags = 0
            if live and libvirt:
                flags = libvirt.VIR_DOMAIN_AFFECT_CONFIG   # canlı GPU eki güvenli değil → config
            for t in targets:
                dom.attachDeviceFlags(_hostdev_xml(t),
                                      flags or (libvirt.VIR_DOMAIN_AFFECT_CONFIG if libvirt else 0))
            return {"ok": True, "vm_id": vm_id, "attached": targets,
                    "note": "VM (yeniden) başlatılınca aktif olur."}
        finally:
            conn.close()
    except Exception as e:
        log.error("attach_to_vm: %s", e)
        return {"ok": False, "error": str(e)}


def detach_from_vm(vm_id: str, pci: str) -> dict:
    try:
        conn = _connect()
        try:
            dom = _lookup_domain(conn, vm_id)
            dom.detachDeviceFlags(_hostdev_xml(pci),
                                  libvirt.VIR_DOMAIN_AFFECT_CONFIG if libvirt else 0)
            return {"ok": True, "vm_id": vm_id, "detached": pci}
        finally:
            conn.close()
    except Exception as e:
        log.error("detach_from_vm: %s", e)
        return {"ok": False, "error": str(e)}


def wizard_overview() -> dict:
    """UI wizard'ının açılışta çektiği özet."""
    return {
        "iommu": iommu_status(),
        "gpus": list_passthrough_gpus(),
    }


if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(wizard_overview(), indent=2, ensure_ascii=False))
