# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware Golden-Image Marketplace (v2.8).

A thin presentation + cache-management layer on top of the cloud-image
support already built into ``vm_manager``. It does NOT duplicate the
download/convert logic: the single source of truth for which images
exist and where they are cached is ``vm_manager._CLOUD_IMAGE_URLS`` and
``vm_manager._CLOUD_CACHE_DIR``.

What this module adds:
  * a curated catalog with display metadata (name, icon, sane default
    vCPU/RAM/disk, cloud-init capability) for each supported os_variant;
  * cache status — is the golden image already downloaded on the host;
  * one-click *prefetch* — download the golden image into the same cache
    ``vm_manager`` reads from, so the first VM deploy is instant.

Actual VM creation still goes through the proven ``POST /api/vms`` path
with ``use_cloud_image: true`` + ``os_variant``; the panel just opens a
small deploy modal pre-filled from this catalog.
"""
from __future__ import annotations
import logging
import os
import shutil
import subprocess
import threading
import time

log = logging.getLogger("oxware.template_marketplace")
_LOCK = threading.Lock()
# In-process prefetch job registry: os_variant -> {state, started, error}.
_JOBS: dict[str, dict] = {}


def _vm_manager():
    """Import vm_manager lazily so this module loads even if libvirt deps
    are missing at import time on a dev host."""
    try:
        from oxware.backend import vm_manager as vm
        return vm
    except Exception:
        try:
            import vm_manager as vm  # flat import fallback (matches app.py)
            return vm
        except Exception:
            return None


# Display overlay. Keys MUST match vm_manager._CLOUD_IMAGE_URLS os_variants.
# Anything in the URL map without an entry here still appears (generic meta).
_META: dict[str, dict] = {
    "ubuntu24.04": {"name": "Ubuntu 24.04 LTS", "os_type": "linux",
                    "icon": "fa-brands fa-ubuntu", "color": "#e95420",
                    "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                    "desc": "Noble Numbat — cloud-init ready server image."},
    "ubuntu22.04": {"name": "Ubuntu 22.04 LTS", "os_type": "linux",
                    "icon": "fa-brands fa-ubuntu", "color": "#e95420",
                    "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                    "desc": "Jammy Jellyfish — cloud-init ready server image."},
    "ubuntu20.04": {"name": "Ubuntu 20.04 LTS", "os_type": "linux",
                    "icon": "fa-brands fa-ubuntu", "color": "#e95420",
                    "vcpus": 1, "memory_mb": 1024, "disk_gb": 15,
                    "desc": "Focal Fossa — long-term support server image."},
    "debian12": {"name": "Debian 12 Bookworm", "os_type": "linux",
                 "icon": "fa-brands fa-debian", "color": "#a80030",
                 "vcpus": 1, "memory_mb": 1024, "disk_gb": 15,
                 "desc": "Debian 12 generic cloud image — minimal + stable."},
    "debian11": {"name": "Debian 11 Bullseye", "os_type": "linux",
                 "icon": "fa-brands fa-debian", "color": "#a80030",
                 "vcpus": 1, "memory_mb": 1024, "disk_gb": 15,
                 "desc": "Debian 11 generic cloud image."},
    "rocky9": {"name": "Rocky Linux 9", "os_type": "linux",
               "icon": "fa-solid fa-mountain", "color": "#10b981",
               "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
               "desc": "RHEL-compatible enterprise base (GenericCloud)."},
    "alma9": {"name": "AlmaLinux 9", "os_type": "linux",
              "icon": "fa-solid fa-circle-dot", "color": "#0061a6",
              "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
              "desc": "RHEL-compatible enterprise base (GenericCloud)."},

    # ── v2.9 catalog expansion — every URL HEAD-verified upstream ────────────
    "ubuntu24.04-arm": {"name": "Ubuntu 24.04 LTS (ARM64)", "os_type": "linux",
                        "icon": "fa-brands fa-ubuntu", "color": "#e95420",
                        "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                        "desc": "Noble Numbat for aarch64 hosts."},
    "ubuntu22.04-arm": {"name": "Ubuntu 22.04 LTS (ARM64)", "os_type": "linux",
                        "icon": "fa-brands fa-ubuntu", "color": "#e95420",
                        "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                        "desc": "Jammy Jellyfish for aarch64 hosts."},
    "ubuntu-minimal24.04": {"name": "Ubuntu 24.04 Minimal", "os_type": "linux",
                            "icon": "fa-brands fa-ubuntu", "color": "#e95420",
                            "vcpus": 1, "memory_mb": 1024, "disk_gb": 10,
                            "desc": "Stripped-down Noble — smallest footprint."},
    "ubuntu-minimal22.04": {"name": "Ubuntu 22.04 Minimal", "os_type": "linux",
                            "icon": "fa-brands fa-ubuntu", "color": "#e95420",
                            "vcpus": 1, "memory_mb": 1024, "disk_gb": 10,
                            "desc": "Stripped-down Jammy — smallest footprint."},
    "debian13": {"name": "Debian 13 Trixie", "os_type": "linux",
                 "icon": "fa-brands fa-debian", "color": "#a80030",
                 "vcpus": 1, "memory_mb": 1024, "disk_gb": 15,
                 "desc": "Current Debian stable, generic cloud image."},
    "debian13-arm": {"name": "Debian 13 Trixie (ARM64)", "os_type": "linux",
                     "icon": "fa-brands fa-debian", "color": "#a80030",
                     "vcpus": 1, "memory_mb": 1024, "disk_gb": 15,
                     "desc": "Debian 13 for aarch64 hosts."},
    "debian12-arm": {"name": "Debian 12 Bookworm (ARM64)", "os_type": "linux",
                     "icon": "fa-brands fa-debian", "color": "#a80030",
                     "vcpus": 1, "memory_mb": 1024, "disk_gb": 15,
                     "desc": "Debian 12 for aarch64 hosts."},
    "debian12-nocloud": {"name": "Debian 12 (nocloud)", "os_type": "linux",
                         "icon": "fa-brands fa-debian", "color": "#a80030",
                         "vcpus": 1, "memory_mb": 1024, "disk_gb": 15,
                         "desc": "No cloud-init datasource — for bare provisioning."},
    "rocky10": {"name": "Rocky Linux 10", "os_type": "linux",
                "icon": "fa-solid fa-mountain", "color": "#10b981",
                "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                "desc": "Newest RHEL-compatible enterprise base."},
    "rocky9-arm": {"name": "Rocky Linux 9 (ARM64)", "os_type": "linux",
                   "icon": "fa-solid fa-mountain", "color": "#10b981",
                   "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                   "desc": "Rocky 9 for aarch64 hosts."},
    "rocky8": {"name": "Rocky Linux 8", "os_type": "linux",
               "icon": "fa-solid fa-mountain", "color": "#10b981",
               "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
               "desc": "Long-tail RHEL8-compatible workloads."},
    "alma10": {"name": "AlmaLinux 10", "os_type": "linux",
               "icon": "fa-solid fa-circle-dot", "color": "#0061a6",
               "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
               "desc": "Newest AlmaLinux GenericCloud."},
    "alma9-arm": {"name": "AlmaLinux 9 (ARM64)", "os_type": "linux",
                  "icon": "fa-solid fa-circle-dot", "color": "#0061a6",
                  "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                  "desc": "AlmaLinux 9 for aarch64 hosts."},
    "alma8": {"name": "AlmaLinux 8", "os_type": "linux",
              "icon": "fa-solid fa-circle-dot", "color": "#0061a6",
              "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
              "desc": "Long-tail RHEL8-compatible workloads."},
    "centos-stream10": {"name": "CentOS Stream 10", "os_type": "linux",
                        "icon": "fa-brands fa-centos", "color": "#a2278e",
                        "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                        "desc": "Upstream of the next RHEL minor."},
    "centos-stream9": {"name": "CentOS Stream 9", "os_type": "linux",
                       "icon": "fa-brands fa-centos", "color": "#a2278e",
                       "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                       "desc": "Rolling RHEL-compatible base."},
    "oracle9": {"name": "Oracle Linux 9", "os_type": "linux",
                "icon": "fa-solid fa-database", "color": "#c74634",
                "vcpus": 2, "memory_mb": 2048, "disk_gb": 25,
                "desc": "Oracle-supported RHEL-compatible base (UEK)."},
    "oracle8": {"name": "Oracle Linux 8", "os_type": "linux",
                "icon": "fa-solid fa-database", "color": "#c74634",
                "vcpus": 2, "memory_mb": 2048, "disk_gb": 25,
                "desc": "Oracle Linux 8 KVM image."},
    "fedora42": {"name": "Fedora 42", "os_type": "linux",
                 "icon": "fa-brands fa-fedora", "color": "#51a2da",
                 "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                 "desc": "Latest Fedora Cloud Base."},
    "fedora41": {"name": "Fedora 41", "os_type": "linux",
                 "icon": "fa-brands fa-fedora", "color": "#51a2da",
                 "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                 "desc": "Fedora Cloud Base, previous release."},
    "opensuse-tumbleweed": {"name": "openSUSE MicroOS", "os_type": "linux",
                            "icon": "fa-brands fa-suse", "color": "#73ba25",
                            "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                            "desc": "Rolling, transactional container host."},
    "alpine3.21": {"name": "Alpine Linux 3.21", "os_type": "linux",
                   "icon": "fa-solid fa-mountain-sun", "color": "#0d597f",
                   "vcpus": 1, "memory_mb": 512, "disk_gb": 5,
                   "desc": "Tiny musl/busybox base — cloud-init enabled."},
    "alpine3.20": {"name": "Alpine Linux 3.20", "os_type": "linux",
                   "icon": "fa-solid fa-mountain-sun", "color": "#0d597f",
                   "vcpus": 1, "memory_mb": 512, "disk_gb": 5,
                   "desc": "Previous Alpine stable."},
    "archlinux": {"name": "Arch Linux", "os_type": "linux",
                  "icon": "fa-solid fa-a", "color": "#1793d1",
                  "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                  "desc": "Rolling release, official cloud image."},
    "flatcar-stable": {"name": "Flatcar Container Linux", "os_type": "linux",
                       "icon": "fa-solid fa-cubes", "color": "#09bac8",
                       "vcpus": 2, "memory_mb": 2048, "disk_gb": 20,
                       "desc": "Immutable container host (stable channel)."},
}


def _cache_path(vm, os_variant: str) -> str:
    return os.path.join(vm._CLOUD_CACHE_DIR, f"{os_variant}-cloud.qcow2")


def _downloader() -> list | None:
    """Return an argv prefix for a present download tool, else None."""
    if shutil.which("wget"):
        return ["wget", "-q", "-O"]
    if shutil.which("curl"):
        return ["curl", "-fsSL", "-o"]
    return None


def catalog() -> list:
    """Golden images that can actually be deployed (os_variant present in
    vm_manager's URL map), with display metadata + cache status."""
    vm = _vm_manager()
    if not vm:
        return []
    urls = getattr(vm, "_CLOUD_IMAGE_URLS", {}) or {}
    out = []
    for os_variant, url in urls.items():
        meta = _META.get(os_variant, {
            "name": os_variant, "os_type": "linux",
            "icon": "fa-solid fa-server", "color": "#0091da",
            "vcpus": 1, "memory_mb": 1024, "disk_gb": 15,
            "desc": "Cloud-init capable image.",
        })
        cp = _cache_path(vm, os_variant)
        job = _JOBS.get(os_variant) or {}
        out.append({
            "os_variant": os_variant,
            "name": meta["name"],
            "os_type": meta["os_type"],
            "icon": meta["icon"],
            "color": meta["color"],
            "desc": meta["desc"],
            "vcpus": meta["vcpus"],
            "memory_mb": meta["memory_mb"],
            "disk_gb": meta["disk_gb"],
            "cloud_init": True,
            "source_url": url,
            "cached": os.path.exists(cp),
            "state": ("cached" if os.path.exists(cp)
                      else job.get("state", "available")),
            "error": job.get("error"),
        })
    out.sort(key=lambda e: e["name"])
    return out


def status() -> dict:
    """Cache + tooling readiness for the marketplace pane badge."""
    vm = _vm_manager()
    dl = _downloader()
    cached = [e["os_variant"] for e in catalog() if e["cached"]]
    return {
        "downloader": (dl[0] if dl else "(none)"),
        "qemu_img": shutil.which("qemu-img") or "(not found)",
        "ready": bool(dl) and bool(shutil.which("qemu-img")),
        "cache_dir": getattr(vm, "_CLOUD_CACHE_DIR", "(unknown)") if vm else "(unknown)",
        "cached": cached,
        "jobs": dict(_JOBS),
    }


def _do_prefetch(os_variant: str, url: str, cache_path: str, dl: list) -> None:
    tmp = cache_path + ".downloading"
    try:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        subprocess.run(dl + [tmp, url], check=True, timeout=3600)
        os.replace(tmp, cache_path)
        with _LOCK:
            _JOBS[os_variant] = {"state": "cached", "started": _JOBS.get(
                os_variant, {}).get("started", time.time()), "error": None}
        log.info("marketplace prefetch done: %s", os_variant)
    except Exception as e:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass
        with _LOCK:
            _JOBS[os_variant] = {"state": "error", "error": str(e)[:300],
                                 "started": time.time()}
        log.warning("marketplace prefetch failed: %s — %s", os_variant, e)


def prefetch(os_variant: str) -> dict:
    """Download the golden image into vm_manager's cache (background).
    Guarded on a download tool being present; otherwise returns a clear
    not-ready response (no crash on dev hosts)."""
    vm = _vm_manager()
    if not vm:
        return {"ok": False, "error": "vm_manager unavailable"}
    urls = getattr(vm, "_CLOUD_IMAGE_URLS", {}) or {}
    url = urls.get(os_variant)
    if not url:
        return {"ok": False, "error": f"unsupported os_variant: {os_variant}"}
    cp = _cache_path(vm, os_variant)
    if os.path.exists(cp):
        return {"ok": True, "os_variant": os_variant, "state": "cached"}
    # Dark Site Mode: önbellekte yoksa uzak indirmeyi reddet (cache'ten çalışır).
    try:
        import dark_site
        if dark_site.is_enabled():
            return dark_site.block_remote("Cloud image: %s" % os_variant)
    except Exception:
        pass
    dl = _downloader()
    if not dl:
        return {"ok": False, "error": "no download tool (wget/curl) on host"}
    with _LOCK:
        cur = _JOBS.get(os_variant)
        if cur and cur.get("state") == "downloading":
            return {"ok": True, "os_variant": os_variant, "state": "downloading"}
        _JOBS[os_variant] = {"state": "downloading", "started": time.time(),
                             "error": None}
    t = threading.Thread(target=_do_prefetch,
                         args=(os_variant, url, cp, dl), daemon=True)
    t.start()
    return {"ok": True, "os_variant": os_variant, "state": "downloading"}
