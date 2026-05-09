"""
template_manager.py — VM şablon yönetimi (OXware Hypervisor)
"""

import subprocess
import json
import logging
import os
import threading
import uuid
import shutil
import time
import re
import tarfile
import xml.etree.ElementTree as ET

log = logging.getLogger("oxware.templates")

TEMPLATE_DIR = "/var/lib/oxware/templates"

_lock = threading.Lock()

# Önceden tanımlı şablonlar
PREDEFINED_TEMPLATES = [
    {
        "id": "ubuntu-2204",
        "name": "Ubuntu 22.04 LTS",
        "os_type": "linux",
        "description": "Ubuntu 22.04 LTS Server (cloud-init ready)",
        "tags": ["ubuntu", "linux", "official"],
    },
    {
        "id": "debian-12",
        "name": "Debian 12 Bookworm",
        "os_type": "linux",
        "description": "Debian 12 minimal server",
        "tags": ["debian", "linux", "official"],
    },
    {
        "id": "windows-2022",
        "name": "Windows Server 2022",
        "os_type": "windows",
        "description": "Windows Server 2022 Standard",
        "tags": ["windows", "official"],
    },
]

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


def _meta_path(template_id):
    """TEMPLATE_DIR/<id>/meta.json yolunu döner."""
    return os.path.join(TEMPLATE_DIR, str(template_id), "meta.json")


def _disk_path(template_id):
    """TEMPLATE_DIR/<id>/disk.qcow2 yolunu döner."""
    return os.path.join(TEMPLATE_DIR, str(template_id), "disk.qcow2")


def _load_meta(template_id):
    """meta.json'u yükler; hata durumunda None döner."""
    path = _meta_path(template_id)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log.error("meta.json okunamadı (%s): %s", template_id, exc)
        return None


def _save_meta(template_id, meta):
    """meta.json'u kaydeder."""
    path = _meta_path(template_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_templates():
    """
    Tüm template meta'larını listeler.
    PREDEFINED_TEMPLATES da dahil; disk yoksa "download_required": True işaretlenir.
    """
    templates = []

    # Kullanıcı tanımlı şablonlar
    try:
        os.makedirs(TEMPLATE_DIR, exist_ok=True)
        for tid in os.listdir(TEMPLATE_DIR):
            tdir = os.path.join(TEMPLATE_DIR, tid)
            if not os.path.isdir(tdir):
                continue
            meta = _load_meta(tid)
            if meta:
                disk = _disk_path(tid)
                meta["download_required"] = not os.path.exists(disk)
                templates.append(meta)
    except OSError as exc:
        log.error("Template dizini okunamadı: %s", exc)

    # Predefined şablonları ekle (kullanıcı tanımlı olanlarla çakışmıyorsa)
    existing_ids = {t["id"] for t in templates}
    for pt in PREDEFINED_TEMPLATES:
        if pt["id"] not in existing_ids:
            entry = dict(pt)
            disk = _disk_path(pt["id"])
            entry["download_required"] = not os.path.exists(disk)
            entry["predefined"] = True
            templates.append(entry)

    return templates


def get_template(template_id):
    """Belirli bir şablonun meta verisini döner."""
    try:
        # Önce kullanıcı tanımlı şablonlara bak
        meta = _load_meta(template_id)
        if meta:
            meta["download_required"] = not os.path.exists(_disk_path(template_id))
            return {"success": True, "template": meta}

        # Predefined'e bak
        for pt in PREDEFINED_TEMPLATES:
            if pt["id"] == template_id:
                entry = dict(pt)
                entry["download_required"] = not os.path.exists(_disk_path(template_id))
                entry["predefined"] = True
                return {"success": True, "template": entry}

        return {"success": False, "error": "Şablon bulunamadı"}
    except Exception as exc:
        log.exception("get_template hatası: %s", exc)
        return {"success": False, "error": str(exc)}


def create_from_vm(vm_id, name, description="", tags=None, os_type="linux"):
    """
    Çalışan/durdurulmuş VM'den şablon oluşturur.
    VM XML'ini alır, disk imajını kopyalar, meta.json yazar.
    """
    with _lock:
        try:
            template_id = str(uuid.uuid4())
            tdir = os.path.join(TEMPLATE_DIR, template_id)
            os.makedirs(tdir, exist_ok=True)

            # VM XML'ini al
            xml_result = _run("virsh", "dumpxml", str(vm_id))
            if xml_result is None or xml_result.returncode != 0:
                return {"success": False, "error": "VM XML alınamadı"}

            vm_xml = xml_result.stdout

            # XML parse: vCPU, memory, disk yolu
            vcpus = 1
            memory_mb = 512
            source_disk = None
            try:
                root = ET.fromstring(vm_xml)
                vcpu_elem = root.find("vcpu")
                if vcpu_elem is not None:
                    vcpus = int(vcpu_elem.text)
                mem_elem = root.find("memory")
                if mem_elem is not None:
                    unit = mem_elem.get("unit", "KiB")
                    val = int(mem_elem.text)
                    if unit == "KiB":
                        memory_mb = val // 1024
                    elif unit == "MiB":
                        memory_mb = val
                    elif unit == "GiB":
                        memory_mb = val * 1024
                # Disk yolu
                for disk in root.findall(".//disk[@type='file']"):
                    source = disk.find("source")
                    if source is not None:
                        source_disk = source.get("file")
                        break
            except ET.ParseError as exc:
                log.warning("VM XML parse hatası: %s", exc)

            # Disk imajını kopyala
            dest_disk = _disk_path(template_id)
            disk_size_gb = 0
            if source_disk and os.path.exists(source_disk):
                log.info("Disk kopyalanıyor: %s -> %s", source_disk, dest_disk)
                r = _run("qemu-img", "convert", "-f", "qcow2", "-O", "qcow2",
                         source_disk, dest_disk)
                if r and r.returncode == 0:
                    try:
                        disk_size_gb = os.path.getsize(dest_disk) / (1024 ** 3)
                    except OSError:
                        pass
                else:
                    # Fallback: direkt kopyala
                    try:
                        shutil.copy2(source_disk, dest_disk)
                        disk_size_gb = os.path.getsize(dest_disk) / (1024 ** 3)
                    except OSError as exc:
                        log.error("Disk kopyalanamadı: %s", exc)
            else:
                log.warning("Kaynak disk bulunamadı: %s", source_disk)

            # meta.json yaz
            meta = {
                "id": template_id,
                "name": name,
                "description": description,
                "tags": tags or [],
                "os_type": os_type,
                "created_at": int(time.time()),
                "disk_size_gb": round(disk_size_gb, 2),
                "vcpus": vcpus,
                "memory_mb": memory_mb,
                "source_vm_id": str(vm_id),
            }
            _save_meta(template_id, meta)

            log.info("Şablon oluşturuldu: %s (%s)", name, template_id)
            return {"success": True, "template_id": template_id, "meta": meta}
        except Exception as exc:
            log.exception("create_from_vm hatası: %s", exc)
            return {"success": False, "error": str(exc)}


def delete_template(template_id):
    """Şablon dizinini siler."""
    with _lock:
        try:
            tdir = os.path.join(TEMPLATE_DIR, str(template_id))
            if not os.path.exists(tdir):
                return {"success": False, "error": "Şablon dizini bulunamadı"}
            shutil.rmtree(tdir)
            log.info("Şablon silindi: %s", template_id)
            return {"success": True, "template_id": template_id}
        except OSError as exc:
            log.error("Şablon silinemedi: %s", exc)
            return {"success": False, "error": str(exc)}


def deploy(template_id, vm_name, vcpus=None, memory_mb=None, disk_path=None):
    """
    Şablondan yeni VM oluşturur.
    qemu-img ile disk klonlar, virsh define + start ile VM'i başlatır.
    Dönüş: {"vm_id": ..., "vm_name": ...}
    """
    with _lock:
        try:
            # Şablon meta'sını al
            result = get_template(template_id)
            if not result["success"]:
                return {"success": False, "error": "Şablon bulunamadı"}

            meta = result["template"]
            effective_vcpus = vcpus or meta.get("vcpus", 1)
            effective_memory = memory_mb or meta.get("memory_mb", 512)

            # Yeni disk yolu
            if disk_path is None:
                disk_path = f"/var/lib/libvirt/images/{vm_name}-{uuid.uuid4().hex[:8]}.qcow2"

            template_disk = _disk_path(template_id)
            if not os.path.exists(template_disk):
                return {"success": False, "error": f"Şablon diski bulunamadı: {template_disk}"}

            # qemu-img create (copy-on-write clone)
            r = _run("qemu-img", "create", "-f", "qcow2",
                     "-b", template_disk, "-F", "qcow2", disk_path)
            if r is None or r.returncode != 0:
                return {"success": False, "error": f"Disk klonlama hatası: {r.stderr.strip() if r else 'komut yok'}"}

            # Yeni VM için UUID
            new_uuid = str(uuid.uuid4())
            new_vm_id = new_uuid

            # Minimal libvirt XML
            vm_xml = f"""<domain type='kvm'>
  <name>{vm_name}</name>
  <uuid>{new_uuid}</uuid>
  <memory unit='MiB'>{effective_memory}</memory>
  <currentMemory unit='MiB'>{effective_memory}</currentMemory>
  <vcpu placement='static'>{effective_vcpus}</vcpu>
  <os>
    <type arch='x86_64' machine='pc-i440fx-6.2'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='host-model'/>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{disk_path}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <graphics type='vnc' port='-1' autoport='yes'/>
    <video>
      <model type='vga'/>
    </video>
    <console type='pty'/>
  </devices>
</domain>"""

            # VM XML dosyasına yaz ve virsh define
            xml_tmp = f"/tmp/oxware_vm_{vm_name}.xml"
            with open(xml_tmp, "w", encoding="utf-8") as f:
                f.write(vm_xml)

            r = _run("virsh", "define", xml_tmp)
            if r is None or r.returncode != 0:
                return {"success": False, "error": f"virsh define hatası: {r.stderr.strip() if r else 'komut yok'}"}

            # VM'i başlat
            r = _run("virsh", "start", vm_name)
            started = r is not None and r.returncode == 0
            if not started:
                log.warning("VM başlatılamadı: %s", r.stderr.strip() if r else "komut yok")

            log.info("VM deploy edildi: %s (uuid=%s)", vm_name, new_uuid)
            return {
                "success": True,
                "vm_id": new_uuid,
                "vm_name": vm_name,
                "disk_path": disk_path,
                "started": started,
            }
        except Exception as exc:
            log.exception("deploy hatası: %s", exc)
            return {"success": False, "error": str(exc)}


def get_disk_size(template_id):
    """Şablon disk boyutunu GB cinsinden döner."""
    try:
        disk = _disk_path(template_id)
        if not os.path.exists(disk):
            return {"success": False, "error": "Disk bulunamadı"}

        size_bytes = os.path.getsize(disk)
        size_gb = size_bytes / (1024 ** 3)

        # qemu-img info ile sanal boyutu da al
        r = _run("qemu-img", "info", "--output=json", disk)
        virtual_size_gb = None
        if r and r.returncode == 0:
            try:
                info = json.loads(r.stdout)
                virtual_size_gb = info.get("virtual-size", 0) / (1024 ** 3)
            except (json.JSONDecodeError, TypeError):
                pass

        return {
            "success": True,
            "actual_size_gb": round(size_gb, 2),
            "virtual_size_gb": round(virtual_size_gb, 2) if virtual_size_gb else None,
        }
    except Exception as exc:
        log.exception("get_disk_size hatası: %s", exc)
        return {"success": False, "error": str(exc)}


def update_template(template_id, name=None, description=None, tags=None):
    """Şablon meta verisini günceller."""
    with _lock:
        try:
            meta = _load_meta(template_id)
            if not meta:
                return {"success": False, "error": "Şablon bulunamadı"}

            if name is not None:
                meta["name"] = name
            if description is not None:
                meta["description"] = description
            if tags is not None:
                meta["tags"] = tags

            meta["updated_at"] = int(time.time())
            _save_meta(template_id, meta)

            log.info("Şablon güncellendi: %s", template_id)
            return {"success": True, "meta": meta}
        except Exception as exc:
            log.exception("update_template hatası: %s", exc)
            return {"success": False, "error": str(exc)}


def export_template(template_id, dest_path):
    """Şablonu tar.gz olarak dışa aktarır."""
    try:
        tdir = os.path.join(TEMPLATE_DIR, str(template_id))
        if not os.path.exists(tdir):
            return {"success": False, "error": "Şablon dizini bulunamadı"}

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        with tarfile.open(dest_path, "w:gz") as tar:
            tar.add(tdir, arcname=str(template_id))

        size_mb = os.path.getsize(dest_path) / (1024 ** 2)
        log.info("Şablon dışa aktarıldı: %s -> %s (%.1f MB)", template_id, dest_path, size_mb)
        return {
            "success": True,
            "template_id": template_id,
            "dest_path": dest_path,
            "size_mb": round(size_mb, 1),
        }
    except (OSError, tarfile.TarError) as exc:
        log.error("Export hatası: %s", exc)
        return {"success": False, "error": str(exc)}


def import_template(tar_path):
    """
    tar.gz şablonunu içe aktarır.
    meta.json varlığını doğrular ve kayıt ekler.
    """
    with _lock:
        try:
            if not os.path.exists(tar_path):
                return {"success": False, "error": "Dosya bulunamadı"}

            os.makedirs(TEMPLATE_DIR, exist_ok=True)

            with tarfile.open(tar_path, "r:gz") as tar:
                # Güvenlik: path traversal kontrolü
                members = tar.getmembers()
                for m in members:
                    if ".." in m.name or m.name.startswith("/"):
                        return {"success": False, "error": "Güvensiz tar içeriği"}

                tar.extractall(path=TEMPLATE_DIR)

            # meta.json bul ve doğrula
            meta = None
            template_id = None
            for m in members:
                if m.name.endswith("meta.json"):
                    # İlk dizin adı template_id
                    parts = m.name.split("/")
                    if parts:
                        template_id = parts[0]
                    meta_path = os.path.join(TEMPLATE_DIR, m.name)
                    try:
                        with open(meta_path, "r", encoding="utf-8") as f:
                            meta = json.load(f)
                    except (OSError, json.JSONDecodeError) as exc:
                        return {"success": False, "error": f"meta.json okunamadı: {exc}"}
                    break

            if not meta:
                return {"success": False, "error": "meta.json bulunamadı"}

            # ID tutarsızlığı varsa düzelt
            if template_id and meta.get("id") != template_id:
                meta["id"] = template_id
                _save_meta(template_id, meta)

            log.info("Şablon içe aktarıldı: %s (%s)", meta.get("name"), template_id)
            return {"success": True, "template_id": template_id, "meta": meta}
        except tarfile.TarError as exc:
            log.error("Tar açma hatası: %s", exc)
            return {"success": False, "error": str(exc)}
        except Exception as exc:
            log.exception("import_template hatası: %s", exc)
            return {"success": False, "error": str(exc)}
