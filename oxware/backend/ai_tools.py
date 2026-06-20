# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware AI tool layer — lets the chat assistant actually DO things.

Instead of printing shell commands, the assistant calls these tools and the
server executes them through the same internal functions the REST API uses
(vm_manager, system_monitor, template_marketplace). Provider-neutral specs
are converted to Anthropic / OpenAI tool formats by ai_agent.

Safety: inputs are validated/clamped; the only destructive tool (delete_vm)
requires an explicit confirm=true and is otherwise refused.
"""
from __future__ import annotations
import logging
import re

log = logging.getLogger("oxware.ai_tools")

_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")
_ISO_ROOTS = ("/var/lib/oxware/isos", "/var/lib/libvirt/images", "/tmp",
              "/var/lib/oxware/images")


def _vm():
    try:
        import vm_manager as m
        return m
    except Exception:
        try:
            from oxware.backend import vm_manager as m
            return m
        except Exception:
            return None


def _mod(name):
    try:
        return __import__(name)
    except Exception:
        try:
            return __import__(f"oxware.backend.{name}", fromlist=["*"])
        except Exception:
            return None


def _clamp(v, lo, hi, default):
    try:
        v = int(v)
    except Exception:
        return default
    return max(lo, min(hi, v))


# ── Tool specs (provider-neutral) ────────────────────────────────────────────
SPECS = [
    {"name": "list_vms",
     "description": "Tüm sanal makineleri listele (ad, durum, vCPU, RAM, IP).",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "system_status",
     "description": "Host CPU/RAM/VM özetini döndür.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "list_golden_images",
     "description": "Hazır cloud-init golden image kataloğunu listele (os_variant, önbellek durumu).",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "create_vm",
     "description": ("Yeni VM oluştur ve başlat. source='cloud' ise os_variant "
                     "ile hazır cloud image kullanır (ISO kurulumu gerekmez, "
                     "anında boot). source='iso' ise iso_path gerekir."),
     "parameters": {"type": "object", "properties": {
         "name": {"type": "string", "description": "VM adı (a-z0-9._-)"},
         "memory_mb": {"type": "integer", "description": "RAM (MB)"},
         "vcpus": {"type": "integer"},
         "disk_gb": {"type": "integer"},
         "source": {"type": "string", "enum": ["cloud", "iso"]},
         "os_variant": {"type": "string", "description": "cloud için: ubuntu22.04, ubuntu24.04, debian12, rocky9, alma9 vb."},
         "iso_path": {"type": "string", "description": "iso için tam yol"},
         "username": {"type": "string", "description": "cloud-init kullanıcı (opsiyonel)"},
         "password": {"type": "string", "description": "cloud-init parola (opsiyonel)"},
     }, "required": ["name", "memory_mb", "vcpus", "disk_gb", "source"]}},
    {"name": "start_vm", "description": "VM başlat.",
     "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "stop_vm", "description": "VM durdur (kapat).",
     "parameters": {"type": "object", "properties": {
         "name": {"type": "string"}, "force": {"type": "boolean"}}, "required": ["name"]}},
    {"name": "reboot_vm", "description": "VM yeniden başlat.",
     "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "delete_vm",
     "description": "VM SİL (geri alınamaz). confirm=true zorunlu.",
     "parameters": {"type": "object", "properties": {
         "name": {"type": "string"}, "confirm": {"type": "boolean"}}, "required": ["name", "confirm"]}},
]


# ── Handlers ─────────────────────────────────────────────────────────────────
def _t_list_vms(_):
    vm = _vm()
    if not vm:
        return {"error": "vm_manager yok"}
    out = []
    for v in vm.list_vms():
        ip = ""
        for n in (v.get("networks") or []):
            if n.get("ip"):
                ip = n["ip"]; break
        out.append({"name": v["name"], "state": v["state"],
                    "vcpus": v["vcpus"], "memory_mb": v["memory_mb"], "ip": ip})
    return {"count": len(out), "vms": out}


def _t_system_status(_):
    sm = _mod("system_monitor")
    if not sm:
        return {"error": "system_monitor yok"}
    s = sm.get_system_stats()
    vms = sm.get_vm_summary()
    return {
        "cpu_percent": round(s["cpu"]["percent"], 1),
        "memory_percent": round(s["memory"]["percent"], 1),
        "memory_used_mb": s["memory"]["used_mb"],
        "memory_total_mb": s["memory"]["total_mb"],
        "vms_running": vms["running"], "vms_total": vms["total"],
    }


def _t_list_golden_images(_):
    mkt = _mod("template_marketplace")
    if not mkt:
        return {"error": "template_marketplace yok"}
    return {"images": [{"os_variant": e["os_variant"], "name": e["name"],
                        "cached": e["cached"]} for e in mkt.catalog()]}


def _t_create_vm(a):
    vm = _vm()
    if not vm:
        return {"error": "vm_manager yok"}
    name = (a.get("name") or "").strip()
    if not _NAME_RE.match(name):
        return {"error": "geçersiz VM adı (a-z0-9._-, 1-64)"}
    memory_mb = _clamp(a.get("memory_mb"), 256, 262144, 2048)
    vcpus = _clamp(a.get("vcpus"), 1, 128, 2)
    disk_gb = _clamp(a.get("disk_gb"), 1, 4096, 20)
    source = a.get("source")
    kwargs = dict(name=name, memory_mb=memory_mb, vcpus=vcpus, disk_gb=disk_gb,
                  network="default", os_variant=a.get("os_variant") or "generic")
    if source == "cloud":
        osv = a.get("os_variant") or ""
        urls = getattr(vm, "_CLOUD_IMAGE_URLS", {}) or {}
        if osv not in urls:
            return {"error": f"desteklenmeyen os_variant: {osv}. "
                             f"Seçenekler: {', '.join(urls.keys())}"}
        kwargs["use_cloud_image"] = True
        kwargs["boot_order"] = "hd"
        ci = {}
        if a.get("username"):
            ci["user"] = a["username"]
        if a.get("password"):
            ci["password"] = a["password"]
        if ci:
            ci["hostname"] = name
            kwargs["cloud_init"] = ci
    elif source == "iso":
        iso = a.get("iso_path") or ""
        if not any(iso.startswith(r) for r in _ISO_ROOTS):
            return {"error": "iso_path izinli dizinlerde olmalı: " + ", ".join(_ISO_ROOTS)}
        kwargs["iso_path"] = iso
        kwargs["boot_order"] = "cdrom,hd"
    else:
        return {"error": "source 'cloud' veya 'iso' olmalı"}
    try:
        r = vm.create_vm(**kwargs)
    except Exception as e:
        return {"error": f"oluşturma hatası: {str(e)[:200]}"}
    return {"ok": True, "created": r.get("name"), "id": r.get("id"),
            "vnc_port": r.get("vnc_port"),
            "note": "VM oluşturuldu ve başlatıldı." if source == "cloud"
                    else "VM oluşturuldu; ISO'dan kuruluma başladı."}


def _vm_action(a, fn_name):
    vm = _vm()
    if not vm:
        return {"error": "vm_manager yok"}
    name = (a.get("name") or "").strip()
    if not name:
        return {"error": "name zorunlu"}
    try:
        fn = getattr(vm, fn_name)
        if fn_name == "stop_vm":
            fn(name, force=bool(a.get("force")))
        else:
            fn(name)
        return {"ok": True, "action": fn_name, "vm": name}
    except Exception as e:
        return {"error": str(e)[:200]}


def _t_delete_vm(a):
    if not a.get("confirm"):
        return {"error": "Silme için confirm=true gerekli. Kullanıcıdan onay iste."}
    vm = _vm()
    if not vm:
        return {"error": "vm_manager yok"}
    name = (a.get("name") or "").strip()
    if not name:
        return {"error": "name zorunlu"}
    try:
        vm.delete_vm(name)
        return {"ok": True, "deleted": name}
    except Exception as e:
        return {"error": str(e)[:200]}


_HANDLERS = {
    "list_vms": _t_list_vms,
    "system_status": _t_system_status,
    "list_golden_images": _t_list_golden_images,
    "create_vm": _t_create_vm,
    "start_vm": lambda a: _vm_action(a, "start_vm"),
    "stop_vm": lambda a: _vm_action(a, "stop_vm"),
    "reboot_vm": lambda a: _vm_action(a, "reboot_vm"),
    "delete_vm": _t_delete_vm,
}


def execute(name: str, args: dict) -> dict:
    """Run a tool by name. Always returns a JSON-serializable dict."""
    fn = _HANDLERS.get(name)
    if not fn:
        return {"error": f"bilinmeyen araç: {name}"}
    try:
        log.info("ai_tool exec: %s args=%s", name, {k: args.get(k) for k in args if k != "password"})
        return fn(args or {})
    except Exception as e:
        return {"error": str(e)[:200]}
