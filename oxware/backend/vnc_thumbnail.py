"""
OXware VNC Thumbnail Manager
─────────────────────────────
Çalışan VM'lerden VNC üzerinden ekran görüntüsü alır (5 dk cache).
VM liste sayfasında canlı önizleme için.

API:
    get_thumbnail(vm_id) -> bytes | None
    refresh_all() -> int  (background)
    invalidate(vm_id)
"""

import os, time, threading, logging, hashlib, subprocess
from pathlib import Path

log = logging.getLogger("vnc_thumbnail")

_CACHE_DIR = Path("/var/lib/oxware/thumbnails")
_CACHE_TTL = 300                      # 5 dakika
_LOCK      = threading.Lock()
_IN_FLIGHT = set()                    # paralel duplicate önle


def _path_for(vm_id: str) -> Path:
    safe = hashlib.sha256(vm_id.encode()).hexdigest()[:16]
    return _CACHE_DIR / f"{safe}.png"


def _capture_via_virsh(vm_name: str, out_path: Path) -> bool:
    """virsh screenshot ile PNG yakala. VM çalışıyorsa."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp_ppm = out_path.with_suffix(".ppm")
        # virsh screenshot domain file --screen 0
        r = subprocess.run(
            ["virsh", "screenshot", vm_name, str(tmp_ppm), "--screen", "0"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode != 0 or not tmp_ppm.exists():
            log.debug("virsh screenshot başarısız (%s): %s", vm_name, r.stderr.strip())
            return False
        # PPM → PNG (küçült) — Pillow ile, ImageMagick `convert` sistem
        # paketine bağımlılık yok. virsh bazen PPM yerine başka format da
        # dökebilir; PIL formatı kendi tespit eder.
        try:
            from PIL import Image
        except Exception as e:
            log.warning("Pillow yok — thumbnail küçültülemez (pip install Pillow): %s", e)
            try:
                tmp_ppm.unlink()
            except Exception:
                pass
            return False
        try:
            with Image.open(tmp_ppm) as im:
                im = im.convert("RGB")
                im.thumbnail((320, 180))
                im.save(out_path, format="PNG", optimize=True)
        finally:
            try:
                tmp_ppm.unlink()
            except Exception:
                pass
        return out_path.exists()
    except FileNotFoundError as e:
        log.warning("virsh bulunamadı: %s", e)
        return False
    except Exception as e:
        log.warning("Thumbnail capture hatası %s: %s", vm_name, e)
        return False


def get_thumbnail(vm_id: str, vm_name: str = None) -> bytes:
    """Cache'ten dön, yoksa yakala. None = çekilemedi."""
    if not vm_id:
        return None
    p = _path_for(vm_id)
    if p.exists():
        age = time.time() - p.stat().st_mtime
        if age < _CACHE_TTL:
            try:
                return p.read_bytes()
            except Exception:
                pass

    # Anti-stampede: aynı VM için paralel istekleri engelle
    with _LOCK:
        if vm_id in _IN_FLIGHT:
            # Eski cache varsa onu dön
            if p.exists():
                try:
                    return p.read_bytes()
                except Exception:
                    pass
            return None
        _IN_FLIGHT.add(vm_id)

    try:
        if not vm_name:
            vm_name = vm_id
        ok = _capture_via_virsh(vm_name, p)
        if ok:
            return p.read_bytes()
    finally:
        with _LOCK:
            _IN_FLIGHT.discard(vm_id)
    return None


def invalidate(vm_id: str):
    """Cache'i sil — VM aksiyonu sonrası tetiklenir (start/reboot)."""
    try:
        p = _path_for(vm_id)
        if p.exists():
            p.unlink()
    except Exception:
        pass


def refresh_all(vm_list: list) -> int:
    """Tüm çalışan VM'leri arka planda yenile. vm_list = [{id, name, state}]"""
    count = 0
    for v in vm_list:
        if v.get("state") != "running":
            continue
        try:
            get_thumbnail(v["id"], v.get("name"))
            count += 1
        except Exception:
            pass
    return count


def stats() -> dict:
    """Cache istatistikleri."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        files = list(_CACHE_DIR.glob("*.png"))
        total_bytes = sum(f.stat().st_size for f in files)
        return {
            "cached":      len(files),
            "total_bytes": total_bytes,
            "total_mb":    round(total_bytes / (1024 * 1024), 2),
            "ttl_seconds": _CACHE_TTL,
            "cache_dir":   str(_CACHE_DIR),
        }
    except Exception as e:
        return {"error": str(e)}
