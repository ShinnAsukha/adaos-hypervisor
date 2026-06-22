# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware VM → OVA/OVF export (portable VM, vendor-neutral).

Mirror of the existing OVA *import*: converts each VM disk to VMDK with
qemu-img, writes a minimal OVF descriptor, and tars everything into a single
.ova. Runs in a background thread (large disks are slow); progress tracked in
an in-process job registry. Guarded on qemu-img + virsh.

Output: /var/lib/oxware/exports/<name>-<ts>.ova
"""
from __future__ import annotations
import logging
import os
import re
import shutil
import subprocess
import tarfile
import threading
import time
import uuid

log = logging.getLogger("oxware.ova_export")
_EXPORT_DIR = "/var/lib/oxware/exports"
_NAME_RE = re.compile(r"^[a-zA-Z0-9._:-]{1,64}$")
_JOBS: dict = {}
_LOCK = threading.Lock()


def _bin(name):
    return shutil.which(name)


def available() -> bool:
    return bool(_bin("qemu-img") and _bin("virsh"))


def list_jobs() -> list:
    with _LOCK:
        return sorted(_JOBS.values(), key=lambda j: j.get("started", 0), reverse=True)


def get_job(job_id: str) -> dict | None:
    return _JOBS.get(job_id)


def _disk_sources(vm_name):
    r = subprocess.run([_bin("virsh"), "domblklist", vm_name, "--details"],
                       capture_output=True, text=True, timeout=20)
    out = []
    for line in r.stdout.splitlines():
        p = line.split()
        if len(p) >= 4 and p[1] == "disk" and p[0] in ("file", "block"):
            out.append(p[3])
    return out


def _ovf(name, vmdks, vcpus, mem_mb):
    refs = "".join(
        f'<File ovf:href="{os.path.basename(v)}" ovf:id="file{i}"/>'
        for i, v in enumerate(vmdks))
    disks = "".join(
        f'<Disk ovf:diskId="vmdisk{i}" ovf:fileRef="file{i}" '
        f'ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>'
        for i, _ in enumerate(vmdks))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData">
  <References>{refs}</References>
  <DiskSection><Info>Disks</Info>{disks}</DiskSection>
  <VirtualSystem ovf:id="{name}">
    <Info>OXware exported VM</Info>
    <Name>{name}</Name>
    <VirtualHardwareSection><Info>HW</Info>
      <Item><rasd:ResourceType>3</rasd:ResourceType><rasd:VirtualQuantity>{vcpus}</rasd:VirtualQuantity><rasd:ElementName>{vcpus} vCPU</rasd:ElementName></Item>
      <Item><rasd:ResourceType>4</rasd:ResourceType><rasd:VirtualQuantity>{mem_mb}</rasd:VirtualQuantity><rasd:ElementName>{mem_mb} MB RAM</rasd:ElementName></Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>"""


def _run_export(job_id, vm_id):
    job = _JOBS[job_id]
    try:
        import vm_manager as vm
        info = vm.get_vm(vm_id)
        name = info["name"]
        if not _NAME_RE.match(name):
            raise ValueError("geçersiz VM adı")
        sources = _disk_sources(name)
        if not sources:
            raise ValueError("disk bulunamadı")
        os.makedirs(_EXPORT_DIR, exist_ok=True)
        work = os.path.join(_EXPORT_DIR, f".{name}-{job_id}")
        os.makedirs(work, exist_ok=True)
        vmdks = []
        for i, src in enumerate(sources):
            job["state"] = f"disk {i+1}/{len(sources)} dönüştürülüyor"
            dst = os.path.join(work, f"{name}-disk{i}.vmdk")
            r = subprocess.run(
                [_bin("qemu-img"), "convert", "-O", "vmdk", "-o",
                 "subformat=streamOptimized", src, dst],
                capture_output=True, text=True, timeout=7200)
            if r.returncode != 0:
                raise RuntimeError("qemu-img: " + (r.stderr or "")[:200])
            vmdks.append(dst)
        ovf_path = os.path.join(work, f"{name}.ovf")
        with open(ovf_path, "w", encoding="utf-8") as f:
            f.write(_ovf(name, vmdks, info.get("vcpus", 1), info.get("memory_mb", 512)))
        job["state"] = "OVA paketleniyor"
        ova = os.path.join(_EXPORT_DIR, f"{name}-{int(time.time())}.ova")
        with tarfile.open(ova, "w") as tar:  # OVA = uncompressed tar, OVF first
            tar.add(ovf_path, arcname=os.path.basename(ovf_path))
            for v in vmdks:
                tar.add(v, arcname=os.path.basename(v))
        shutil.rmtree(work, ignore_errors=True)
        size_mb = round(os.path.getsize(ova) / (1024**2), 1)
        job.update({"state": "tamamlandı", "done": True, "ok": True,
                    "path": ova, "size_mb": size_mb})
        log.info("OVA export tamam: %s (%s MB)", ova, size_mb)
    except Exception as e:
        job.update({"state": "hata", "done": True, "ok": False,
                    "error": str(e)[:300]})
        log.warning("OVA export hata: %s", e)


def start_export(vm_id: str) -> dict:
    if not available():
        return {"ok": False, "error": "qemu-img/virsh yok"}
    job_id = "exp-" + uuid.uuid4().hex[:8]
    with _LOCK:
        _JOBS[job_id] = {"id": job_id, "vm_id": vm_id, "state": "başlatıldı",
                         "done": False, "ok": None, "started": time.time()}
    threading.Thread(target=_run_export, args=(job_id, vm_id), daemon=True).start()
    return {"ok": True, "job_id": job_id}
