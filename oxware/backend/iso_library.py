#!/usr/bin/env python3
# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy. MIT License.
"""
ISO Library — küratörlü ISO kataloğu + checksum doğrulama + mirror
──────────────────────────────────────────────────────────────────
Mevcut ISO yönetimi (upload/list/delete, storage_manager + /api/storage/isos)
üstüne "resmi kaynaktan indir, SHA256 doğrula, mirror seç" katmanı ekler.

İndirilen ISO'lar `config.ISO_DIR`'e yazılır → mevcut ISO listesinde otomatik
görünür (ayrı depo yok). Cloud-init imajları BU MODÜLDE DEĞİL —
onlar template_marketplace.py (golden qcow2). Burası kurulum ISO'ları:
Linux dağıtımları + firewall/NAS appliance'ları + Windows Server eval.

Dark Site Mode açıkken uzak indirme reddedilir (yerel mirror kullanılır).
"""

from __future__ import annotations
import os
import time
import hashlib
import logging
import threading
import subprocess

log = logging.getLogger("oxware.iso_library")

_LOCK = threading.Lock()
_JOBS: dict = {}          # filename -> {state, pct, error, started, mirror}


# ── Küratörlü katalog ──────────────────────────────────────────────────────────
# checksum: ya sabit 'sha256' (pinlenmiş sürüm) ya da 'sha256_url' (yayıncının
# SHA256SUMS'u; online iken çekilir). Yanlış hash göndermemek için bilinmeyen
# sabit hash'ler boş bırakılır (yayıncı SHA256SUMS'una düşülür).
CATALOG = [
    {"id": "ubuntu-24.04-live-server", "name": "Ubuntu Server 24.04 LTS",
     "category": "linux", "os_type": "ubuntu", "arch": "amd64", "size_gb": 2.7,
     "filename": "ubuntu-24.04-live-server-amd64.iso",
     "mirrors": [
        "https://releases.ubuntu.com/24.04/ubuntu-24.04-live-server-amd64.iso",
        "https://mirror.ubuntu.com/releases/24.04/ubuntu-24.04-live-server-amd64.iso",
     ],
     "sha256": "", "sha256_url": "https://releases.ubuntu.com/24.04/SHA256SUMS"},

    {"id": "debian-12-netinst", "name": "Debian 12 (netinst)",
     "category": "linux", "os_type": "debian", "arch": "amd64", "size_gb": 0.65,
     "filename": "debian-12-netinst-amd64.iso",
     "mirrors": [
        "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.11.0-amd64-netinst.iso",
     ],
     "sha256": "", "sha256_url": "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA256SUMS"},

    {"id": "rocky-9-minimal", "name": "Rocky Linux 9 (minimal)",
     "category": "linux", "os_type": "rocky", "arch": "x86_64", "size_gb": 2.0,
     "filename": "Rocky-9-latest-x86_64-minimal.iso",
     "mirrors": [
        "https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9-latest-x86_64-minimal.iso",
     ],
     "sha256": "", "sha256_url": "https://download.rockylinux.org/pub/rocky/9/isos/x86_64/CHECKSUM"},

    {"id": "almalinux-9-minimal", "name": "AlmaLinux 9 (minimal)",
     "category": "linux", "os_type": "alma", "arch": "x86_64", "size_gb": 1.9,
     "filename": "AlmaLinux-9-latest-x86_64-minimal.iso",
     "mirrors": [
        "https://repo.almalinux.org/almalinux/9/isos/x86_64/AlmaLinux-9-latest-x86_64-minimal.iso",
     ],
     "sha256": "", "sha256_url": "https://repo.almalinux.org/almalinux/9/isos/x86_64/CHECKSUM"},

    {"id": "pfsense-ce", "name": "pfSense CE (firewall)",
     "category": "appliance", "os_type": "freebsd", "arch": "amd64", "size_gb": 0.8,
     "filename": "pfSense-CE-installer-amd64.iso",
     "mirrors": [
        "https://atxfiles.netgate.com/mirror/downloads/pfSense-CE-2.7.2-RELEASE-amd64.iso.gz",
     ],
     "sha256": "", "sha256_url": ""},

    {"id": "opnsense", "name": "OPNsense (firewall)",
     "category": "appliance", "os_type": "freebsd", "arch": "amd64", "size_gb": 0.5,
     "filename": "OPNsense-dvd-amd64.iso",
     "mirrors": [
        "https://mirror.dns-root.de/opnsense/releases/mirror/OPNsense-24.7-dvd-amd64.iso.bz2",
     ],
     "sha256": "", "sha256_url": ""},

    {"id": "truenas-scale", "name": "TrueNAS SCALE (storage)",
     "category": "appliance", "os_type": "linux", "arch": "amd64", "size_gb": 1.4,
     "filename": "TrueNAS-SCALE.iso",
     "mirrors": [
        "https://download.sys.truenas.net/TrueNAS-SCALE-Dragonfish/24.04.2/TrueNAS-SCALE-24.04.2.iso",
     ],
     "sha256": "", "sha256_url": ""},

    {"id": "windows-server-2022-eval", "name": "Windows Server 2022 (eval)",
     "category": "windows", "os_type": "windows", "arch": "amd64", "size_gb": 5.2,
     "filename": "Windows-Server-2022-eval.iso",
     "mirrors": [
        "https://software-download.microsoft.com/download/sg/20348.169.210806-2348.fe_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso",
     ],
     "sha256": "", "sha256_url": ""},
]


def _iso_dir() -> str:
    try:
        import config
        return config.ISO_DIR
    except Exception:
        return os.environ.get("OXWARE_ISO_DIR", "/var/lib/oxware/isos")


def _entry(iso_id: str) -> dict | None:
    return next((e for e in CATALOG if e["id"] == iso_id), None)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _downloader() -> list | None:
    from shutil import which
    if which("wget"):
        return ["wget", "-q", "-O"]
    if which("curl"):
        return ["curl", "-fsSL", "-o"]
    return None


# ── Katalog + durum ────────────────────────────────────────────────────────────

def catalog() -> list:
    d = _iso_dir()
    out = []
    for e in CATALOG:
        dest = os.path.join(d, e["filename"])
        present = os.path.exists(dest)
        job = _JOBS.get(e["filename"]) or {}
        out.append({
            **{k: e[k] for k in ("id", "name", "category", "os_type", "arch",
                                 "size_gb", "filename")},
            "mirrors": len(e["mirrors"]),
            "verifiable": bool(e.get("sha256") or e.get("sha256_url")),
            "present": present,
            "state": "present" if present else job.get("state", "available"),
            "progress": job.get("pct"),
            "error": job.get("error"),
        })
    return out


def mirrors(iso_id: str) -> list:
    e = _entry(iso_id)
    return list(e["mirrors"]) if e else []


def jobs() -> dict:
    with _LOCK:
        return dict(_JOBS)


# ── İndirme + doğrulama ─────────────────────────────────────────────────────────

def _fetch_published_sha256(sha_url: str, filename: str) -> str:
    """Yayıncının SHA256SUMS/CHECKSUM dosyasından ilgili filename hash'ini bul."""
    if not sha_url:
        return ""
    try:
        import urllib.request
        with urllib.request.urlopen(sha_url, timeout=20) as r:
            text = r.read().decode("utf-8", "replace")
        base = os.path.basename(filename).replace(".gz", "").replace(".bz2", "")
        for line in text.splitlines():
            parts = line.replace("*", " ").split()
            if len(parts) >= 2 and (base in line):
                cand = parts[0].strip()
                if len(cand) == 64:
                    return cand.lower()
    except Exception as e:
        log.warning("sha256 fetch fail: %s", e)
    return ""


def verify_local(filename: str, sha256: str = "") -> dict:
    """Yereldeki ISO'yu doğrula. sha256 verilmezse katalog/yayıncıdan çözer."""
    d = _iso_dir()
    path = os.path.join(d, filename)
    if not os.path.exists(path):
        return {"ok": False, "error": "ISO yok: %s" % filename}
    expected = sha256
    if not expected:
        e = next((x for x in CATALOG if x["filename"] == filename), None)
        if e:
            expected = e.get("sha256") or _fetch_published_sha256(e.get("sha256_url", ""), filename)
    actual = _sha256(path)
    if not expected:
        return {"ok": True, "verified": False, "sha256": actual,
                "note": "Beklenen hash bilinmiyor — hesaplanan döndürüldü."}
    match = actual.lower() == expected.lower()
    return {"ok": match, "verified": match, "sha256": actual,
            "expected": expected,
            "error": None if match else "SHA256 uyuşmuyor"}


def _stream_download(url: str, tmp: str, fn: str) -> None:
    """urllib ile stream indir + % ilerlemeyi _JOBS'a yaz (progress bar için)."""
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "OXware-ISO/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        done, last = 0, -1
        with open(tmp, "wb") as f:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                pct = int(done * 100 / total) if total else 0
                if pct != last:
                    last = pct
                    with _LOCK:
                        j = _JOBS.get(fn)
                        if j:
                            j["pct"] = pct
                            j["downloaded_mb"] = round(done / 1048576, 1)
    # Kesik indirmeyi tamamlanmış sayma: bağlantı yarıda koparsa boş read EOF
    # gibi görünüyor ve dosya "done" olarak ISO dizinine taşınıyordu.
    if total and done != total:
        raise RuntimeError("eksik indirme: %d/%d bayt" % (done, total))


def _do_download(e: dict, mirror_index: int) -> None:
    d = _iso_dir()
    os.makedirs(d, exist_ok=True)
    dest = os.path.join(d, e["filename"])
    urls = e["mirrors"]
    fn = e["filename"]
    tried = list(range(mirror_index, len(urls))) + list(range(0, mirror_index))
    for idx in tried:
        url = urls[idx]
        with _LOCK:
            _JOBS[fn] = {"state": "downloading", "pct": 0,
                         "started": time.time(), "mirror": idx, "error": None}
        try:
            tmp = dest + ".part"
            _stream_download(url, tmp, fn)
            if not os.path.exists(tmp):
                raise RuntimeError("indirme başarısız (mirror %d)" % idx)
            # verify
            with _LOCK:
                _JOBS[fn]["state"] = "verifying"
            expected = e.get("sha256") or _fetch_published_sha256(e.get("sha256_url", ""), fn)
            if expected:
                actual = _sha256(tmp)
                if actual.lower() != expected.lower():
                    os.remove(tmp)
                    raise RuntimeError("SHA256 uyuşmuyor (mirror %d)" % idx)
            os.replace(tmp, dest)
            try: os.chmod(dest, 0o640)
            except OSError: pass
            with _LOCK:
                _JOBS[fn] = {"state": "done", "pct": 100, "mirror": idx,
                             "verified": bool(expected), "error": None}
            log.info("ISO indirildi: %s (mirror %d, verified=%s)", fn, idx, bool(expected))
            return
        except Exception as ex:
            log.warning("ISO indirme mirror %d fail: %s", idx, ex)
            try:
                if os.path.exists(dest + ".part"): os.remove(dest + ".part")
            except OSError: pass
            with _LOCK:
                _JOBS[fn] = {"state": "error", "error": str(ex), "mirror": idx}
    # tüm mirror'lar başarısız
    with _LOCK:
        _JOBS[fn] = {"state": "error", "error": "tüm mirror'lar başarısız"}


def download(iso_id: str, mirror_index: int = 0) -> dict:
    e = _entry(iso_id)
    if not e:
        return {"ok": False, "error": "bilinmeyen ISO: %s" % iso_id}
    # Dark Site Mode: uzak indirme kapalı.
    try:
        import dark_site
        if dark_site.is_enabled():
            return dark_site.block_remote("ISO: %s" % e["name"])
    except Exception:
        pass
    dest = os.path.join(_iso_dir(), e["filename"])
    if os.path.exists(dest):
        return {"ok": True, "state": "present", "filename": e["filename"]}
    with _LOCK:
        cur = _JOBS.get(e["filename"])
        if cur and cur.get("state") in ("downloading", "verifying"):
            return {"ok": True, "state": cur["state"], "filename": e["filename"]}
    # SEC/DoS: mirror index sınırlanmalı. Sınırsızken _do_download içindeki
    # list(range(mirror_index, ...)) devasa bir liste ayırıp (ör. mirror=2e9)
    # servisi OOM-kill ettirebiliyordu; ayrıca aralık dışı indeks urls[idx]'te
    # try bloğunun DIŞINDA IndexError atıp job'ı sonsuza "downloading" bırakıyordu.
    try:
        mirror_index = int(mirror_index) % len(e["mirrors"])
    except (ValueError, TypeError, ZeroDivisionError):
        mirror_index = 0
    t = threading.Thread(target=_do_download, args=(e, mirror_index),
                         daemon=True)
    t.start()
    return {"ok": True, "state": "downloading", "filename": e["filename"],
            "mirrors": len(e["mirrors"])}


if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(catalog(), indent=2, ensure_ascii=False))
