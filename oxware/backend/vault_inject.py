# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware Vault → VM secret injection.

Reads a secret from HashiCorp Vault (via vault_integration) and writes it
INTO a running VM through the QEMU guest agent — no SSH, no network exposure
of the secret. Useful for delivering DB passwords / API keys to a VM at first
boot or on demand.

Format: 'env' (KEY=VALUE lines) or 'json'. Target path + file mode are
validated. Guarded on the guest agent being responsive.
"""
from __future__ import annotations
import base64
import json
import logging
import re

log = logging.getLogger("oxware.vault_inject")
_PATH_RE = re.compile(r"^/[\w./-]{1,255}$")


def _mod(name):
    try:
        return __import__(name)
    except Exception:
        try:
            return __import__(f"oxware.backend.{name}", fromlist=["*"])
        except Exception:
            return None


def _render(secret: dict, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(secret, ensure_ascii=False, indent=2)
    # env format
    lines = []
    for k, v in secret.items():
        key = re.sub(r"[^A-Za-z0-9_]", "_", str(k)).upper()
        val = str(v).replace("\n", "\\n")
        lines.append(f"{key}={val}")
    return "\n".join(lines) + "\n"


def inject_to_vm(vm_id: str, vault_path: str, target_file: str,
                 fmt: str = "env", mode: str = "0600") -> dict:
    if fmt not in ("env", "json"):
        return {"ok": False, "error": "format 'env' veya 'json' olmalı"}
    if not _PATH_RE.match(target_file or ""):
        return {"ok": False, "error": "hedef yol mutlak ve güvenli olmalı (/...)"}
    if not re.match(r"^0?[0-7]{3}$", mode or ""):
        return {"ok": False, "error": "mode 0600 gibi octal olmalı"}

    vault = _mod("vault_integration")
    if not vault:
        return {"ok": False, "error": "vault_integration yok"}
    vm = _mod("vm_manager")
    if not vm:
        return {"ok": False, "error": "vm_manager yok"}

    # Read secret from Vault.
    try:
        sec = vault.read_secret(vault_path)
    except Exception as e:
        return {"ok": False, "error": f"Vault okuma hatası: {str(e)[:160]}"}
    data = sec.get("data") if isinstance(sec, dict) else None
    if not isinstance(data, dict) or not data:
        return {"ok": False, "error": "Vault yolunda veri yok"}

    content = _render(data, fmt)

    # Resolve VM + ensure agent up.
    try:
        info = vm.get_vm(vm_id)
        vm_name = info["name"]
    except Exception as e:
        return {"ok": False, "error": f"VM bulunamadı: {str(e)[:120]}"}
    if vm.get_guest_agent_status(vm_id) != "running":
        return {"ok": False, "error": "Guest agent yanıt vermiyor (VM çalışıyor mu?)"}

    # Write via guest-file-open / write / close.
    handle = vm._qemu_agent_cmd(vm_name, "guest-file-open",
                               {"path": target_file, "mode": "w"})
    if not isinstance(handle, int):
        return {"ok": False, "error": "guest-file-open başarısız (agent yazma izni?)"}
    try:
        b64 = base64.b64encode(content.encode("utf-8")).decode()
        wr = vm._qemu_agent_cmd(vm_name, "guest-file-write",
                               {"handle": handle, "buf-b64": b64})
        ok_write = isinstance(wr, dict) and "count" in wr
    finally:
        vm._qemu_agent_cmd(vm_name, "guest-file-close", {"handle": handle})
    if not ok_write:
        return {"ok": False, "error": "guest-file-write başarısız"}

    # Best-effort chmod via guest-exec.
    try:
        vm._qemu_agent_cmd(vm_name, "guest-exec",
                          {"path": "/bin/chmod", "arg": [mode.lstrip("0") or "600", target_file]})
    except Exception:
        pass

    log.info("vault secret injected: %s → %s:%s (%d bytes, %s)",
             vault_path, vm_name, target_file, len(content), fmt)
    return {"ok": True, "vm": vm_name, "target": target_file,
            "format": fmt, "bytes": len(content), "keys": list(data.keys())}
