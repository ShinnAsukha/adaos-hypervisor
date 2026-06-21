# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware VM boot splash (firmware-level branding).

Shows an OXware-branded logo during the VM's BIOS POST — before ANY guest OS
boots — so every VM (Linux/Windows/whatever) displays OXware at power-on, the
way VMware shows its logo. Implemented at the SeaBIOS layer via fw_cfg
(`bootsplash.jpg` + `etc/boot-menu-wait`), injected as additive
qemu:commandline so it does NOT touch the libvirt boot order.

Safe-by-default: DISABLED until the operator turns it on (so it can be
verified on one VM first). Only injects when enabled AND the JPEG exists.
SeaBIOS needs a BASELINE JPEG at a VESA resolution (1024x768).

State: /var/lib/oxware/boot_splash.json   Image: /var/lib/oxware/boot-splash.jpg
"""
from __future__ import annotations
import json
import logging
import os
from pathlib import Path

log = logging.getLogger("oxware.boot_splash")
_CFG = Path("/var/lib/oxware/boot_splash.json")
_IMG = Path("/var/lib/oxware/boot-splash.jpg")
_LOGO = "/var/lib/oxware/sadeceikon.png"  # optional brand icon overlay
_QEMU_NS = "http://libvirt.org/schemas/domain/qemu/1.0"


def get_config() -> dict:
    cfg = {"enabled": False, "splash_time_ms": 5000}
    if _CFG.exists():
        try:
            cfg.update(json.loads(_CFG.read_text(encoding="utf-8")))
        except Exception:
            pass
    cfg["image_ready"] = _IMG.exists()
    cfg["pillow"] = _have_pillow()
    return cfg


def set_config(enabled: bool = None, splash_time_ms: int = None) -> dict:
    cur = get_config()
    if enabled is not None:
        cur["enabled"] = bool(enabled)
    if splash_time_ms is not None:
        cur["splash_time_ms"] = max(1000, min(int(splash_time_ms), 20000))
    # Generate the image when enabling, if not present.
    if cur["enabled"] and not _IMG.exists():
        ensure_image()
    out = {"enabled": cur["enabled"], "splash_time_ms": cur["splash_time_ms"]}
    try:
        _CFG.parent.mkdir(parents=True, exist_ok=True)
        _CFG.write_text(json.dumps(out, indent=2), encoding="utf-8")
    except Exception as e:
        return {"ok": False, "error": str(e)[:160]}
    return {"ok": True, **get_config()}


def _have_pillow() -> bool:
    try:
        import PIL  # noqa
        return True
    except Exception:
        return False


def ensure_image() -> dict:
    """Render the OXware splash as a baseline 1024x768 JPEG. Pillow required."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception:
        return {"ok": False, "error": "Pillow yok — splash görseli üretilemedi"}
    W, H = 1024, 768
    img = Image.new("RGB", (W, H), (5, 8, 16))  # OXware --bg-0
    d = ImageDraw.Draw(img)

    def _big(text, target_w, color):
        """Render text with the default bitmap font, then scale up — avoids a
        hard TTF dependency."""
        try:
            f = ImageFont.load_default()
        except Exception:
            f = None
        tmp = Image.new("RGB", (max(1, len(text) * 6), 11), (5, 8, 16))
        ImageDraw.Draw(tmp).text((0, 0), text, fill=color, font=f)
        bbox = tmp.getbbox() or (0, 0, tmp.width, tmp.height)
        tmp = tmp.crop(bbox)
        scale = max(1, int(target_w / max(1, tmp.width)))
        return tmp.resize((tmp.width * scale, tmp.height * scale), Image.NEAREST)

    # optional logo
    y_logo = 210
    try:
        if os.path.exists(_LOGO):
            logo = Image.open(_LOGO).convert("RGBA")
            logo.thumbnail((150, 150))
            img.paste(logo, ((W - logo.width) // 2, 150), logo)
            y_logo = 150 + logo.height + 20
    except Exception:
        pass

    title = _big("OXware", 560, (255, 255, 255))
    img.paste(title, ((W - title.width) // 2, y_logo))
    sub = _big("OXware Hypervisor", 380, (0, 145, 218))
    img.paste(sub, ((W - sub.width) // 2, y_logo + title.height + 24))

    # bottom firmware-style lines
    foot = _big("Starting OXware...", 300, (180, 194, 214))
    img.paste(foot, ((W - foot.width) // 2, 590))
    hint = _big("Press F2 SETUP   F12 Boot Menu   ESC Boot", 520, (107, 118, 137))
    img.paste(hint, ((W - hint.width) // 2, 650))

    try:
        _IMG.parent.mkdir(parents=True, exist_ok=True)
        img.save(str(_IMG), "JPEG", quality=88, progressive=False)  # baseline
    except Exception as e:
        return {"ok": False, "error": str(e)[:160]}
    log.info("boot splash görseli üretildi: %s", _IMG)
    return {"ok": True, "path": str(_IMG)}


def _active() -> bool:
    cfg = get_config()
    return bool(cfg.get("enabled")) and _IMG.exists()


def domain_inject() -> tuple[str, str]:
    """Return (namespace_attr, commandline_block) for the libvirt domain XML.
    Empty strings when disabled or image missing (→ no change to the VM)."""
    if not _active():
        return "", ""
    wait = int(get_config().get("splash_time_ms", 5000))
    ns = f" xmlns:qemu='{_QEMU_NS}'"
    block = (
        "\n  <qemu:commandline>\n"
        "    <qemu:arg value='-fw_cfg'/>\n"
        f"    <qemu:arg value='name=bootsplash.jpg,file={_IMG}'/>\n"
        "    <qemu:arg value='-fw_cfg'/>\n"
        f"    <qemu:arg value='name=etc/boot-menu-wait,string={wait}'/>\n"
        "  </qemu:commandline>")
    return ns, block


def os_bootmenu_xml() -> str:
    """libvirt <os> snippet — enabling the boot menu makes SeaBIOS reliably
    display the splash for the wait window. Empty when splash inactive."""
    if not _active():
        return ""
    wait = int(get_config().get("splash_time_ms", 5000))
    return f"\n    <bootmenu enable='yes' timeout='{wait}'/>"


def image_bytes() -> bytes | None:
    """Raw JPEG for the panel preview, or None."""
    try:
        return _IMG.read_bytes() if _IMG.exists() else None
    except Exception:
        return None
