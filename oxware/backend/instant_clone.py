#!/usr/bin/env python3
# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy. MIT License.
"""
Instant Clone — memory-fork VM klonlama (VMware Instant Clone benzeri)
──────────────────────────────────────────────────────────────────────
Linked clone (linked_clone.py) sadece DİSK'i COW paylaşır — klon yine sıfırdan
boot eder. Instant clone RAM'i de forklar: klon, kaynağın ÇALIŞAN bellek
durumundan saniyeler içinde ayağa kalkar (boot yok).

Teknik (virsh + qemu-img, harici bağımlılık yok):
  1. Kaynak VM çalışıyor olmalı.
  2. `virsh save src mem.save` → kaynağın RAM'i dosyaya alınır (kaynak kısa süre
     duraklar — VMware vmfork gibi tam-canlı değil; dürüst uyarı).
  3. Her klon için:
       - tüm dosya-tabanlı diskler için COW overlay (backing = kaynak disk)
       - mem.save kopyası
       - save-image XML'i düzenle (name/uuid/mac/disk yolları)
       - `virsh save-image-define` + `virsh restore` → klon RAM'den ayağa kalkar
       - `virsh define` ile kalıcılaştır
  4. `virsh restore mem.save` → kaynak kaldığı yerden devam eder.

DURUM: experimental. Linux + KVM + libvirt + qemu-img gerektirir; gerçek
donanımda test edilmelidir. Diğer ortamlarda güvenli hata döner.
"""

import os
import re
import shutil
import uuid as _uuid
import random
import logging
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

log = logging.getLogger("instant_clone")

_STATE_DIR = os.environ.get("OXWARE_CLONE_MEM_DIR", "/var/lib/oxware/clone-mem")


def _virsh(args, timeout=60):
    return subprocess.run(["virsh"] + args, capture_output=True, text=True, timeout=timeout)


def _dumpxml(vm: str) -> str:
    r = _virsh(["dumpxml", vm])
    return r.stdout if r.returncode == 0 else ""


def _is_running(vm: str) -> bool:
    r = _virsh(["domstate", vm])
    return r.returncode == 0 and "running" in r.stdout.lower()


def _disk_paths_from_xml(xml: str) -> list:
    return re.findall(r"<source file='([^']+)'/>", xml)


def _new_mac() -> str:
    octs = [0x52, 0x54, 0x00] + [random.randint(0, 255) for _ in range(3)]
    return ":".join("%02x" % x for x in octs)


def _cow_overlay(base_disk: str, dest: str) -> None:
    r = subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", base_disk, dest],
        capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("qemu-img create başarısız: %s" % r.stderr.strip())


def _edit_clone_xml(src_xml: str, clone_name: str, new_uuid: str,
                    disk_map: dict) -> str:
    """Kaynak domain XML'ini klon için düzenle: name/uuid/mac/disk yolları."""
    root = ET.fromstring(src_xml)
    # name
    n = root.find("name")
    if n is None:
        n = ET.SubElement(root, "name")
    n.text = clone_name
    # uuid
    u = root.find("uuid")
    if u is None:
        u = ET.SubElement(root, "uuid")
    u.text = new_uuid
    # disk source paths
    for src in root.iter("source"):
        f = src.get("file")
        if f and f in disk_map:
            src.set("file", disk_map[f])
    # mac addresses → randomize
    for mac in root.iter("mac"):
        mac.set("address", _new_mac())
    return ET.tostring(root, encoding="unicode")


def instant_clone(src_vm: str, clone_prefix: str, count: int = 1,
                  disk_dir: str = "/var/lib/libvirt/images") -> dict:
    """Kaynak VM'den memory-fork ile `count` adet instant clone üret."""
    if shutil.which("virsh") is None or shutil.which("qemu-img") is None:
        return {"ok": False, "error": "virsh/qemu-img yok (Linux+KVM gerekir)"}
    if not clone_prefix or "/" in clone_prefix:
        return {"ok": False, "error": "geçersiz clone_prefix"}
    if not _is_running(src_vm):
        return {"ok": False, "error": "kaynak VM çalışmıyor — instant clone canlı bellek ister"}

    count = max(1, min(int(count), 64))
    os.makedirs(_STATE_DIR, exist_ok=True)
    os.makedirs(disk_dir, exist_ok=True)

    src_xml = _dumpxml(src_vm)
    src_disks = _disk_paths_from_xml(src_xml)
    if not src_disks:
        return {"ok": False, "error": "kaynak diskleri bulunamadı"}
    for d in src_disks:
        if not os.path.exists(d):
            return {"ok": False, "error": "kaynak disk yok: %s" % d}

    src_mem = os.path.join(_STATE_DIR, "src-%s.save" % _uuid.uuid4().hex[:8])
    created, clones = [], []
    try:
        # 1) Kaynağın RAM'ini dosyaya al (kaynak duraklar)
        r = _virsh(["save", src_vm, src_mem], timeout=300)
        if r.returncode != 0 or not os.path.exists(src_mem):
            return {"ok": False, "error": "virsh save başarısız: %s" % r.stderr.strip()}

        for i in range(count):
            clone_name = "%s-%d" % (clone_prefix, i + 1)
            new_uuid = str(_uuid.uuid4())
            disk_map = {}
            for idx, base in enumerate(src_disks):
                cd = os.path.join(disk_dir, "%s-d%d.qcow2" % (clone_name, idx))
                if os.path.exists(cd):
                    raise FileExistsError("klon diski var: %s" % cd)
                _cow_overlay(base, cd)
                created.append(cd)
                disk_map[base] = cd

            clone_mem = os.path.join(_STATE_DIR, "%s.save" % clone_name)
            shutil.copy2(src_mem, clone_mem)
            created.append(clone_mem)

            clone_xml = _edit_clone_xml(src_xml, clone_name, new_uuid, disk_map)
            tmp_xml = os.path.join(_STATE_DIR, "%s.xml" % clone_name)
            Path(tmp_xml).write_text(clone_xml)
            created.append(tmp_xml)

            # Save-image içindeki XML'i klon kimliğiyle değiştir
            rd = _virsh(["save-image-define", clone_mem, "--xml", tmp_xml])
            if rd.returncode != 0:
                raise RuntimeError("save-image-define başarısız: %s" % rd.stderr.strip())
            # RAM'den ayağa kaldır (saniyeler)
            rr = _virsh(["restore", clone_mem], timeout=120)
            if rr.returncode != 0:
                raise RuntimeError("virsh restore başarısız: %s" % rr.stderr.strip())
            # Kalıcılaştır (transient → persistent)
            _virsh(["define", tmp_xml])
            clones.append({"name": clone_name, "uuid": new_uuid,
                           "disks": list(disk_map.values())})

        return {"ok": True, "source": src_vm, "count": len(clones),
                "clones": clones,
                "note": "Kaynak kısa süre duraklatıldı; klonlar RAM durumundan ayağa kalktı."}
    except Exception as e:
        log.error("instant_clone: %s", e)
        # başarısızlıkta oluşturulanları temizle
        for f in created:
            try:
                if os.path.exists(f):
                    os.remove(f)
            except OSError:
                pass
        return {"ok": False, "error": str(e), "partial_clones": clones}
    finally:
        # 2) Kaynağı her hâlükârda geri yükle
        try:
            if os.path.exists(src_mem):
                _virsh(["restore", src_mem], timeout=300)
                os.remove(src_mem)
        except Exception as e:
            log.error("kaynak restore hatası: %s", e)


def status() -> dict:
    """Aktif memory-state dosyaları (temizlenmemiş)."""
    files = []
    try:
        if os.path.isdir(_STATE_DIR):
            files = [f for f in os.listdir(_STATE_DIR) if f.endswith(".save")]
    except OSError:
        pass
    return {"mem_state_dir": _STATE_DIR, "pending_mem_files": files,
            "available": shutil.which("virsh") is not None}


if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(status(), indent=2, ensure_ascii=False))
