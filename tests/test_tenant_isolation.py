"""Regression tests for provisioning tenant isolation and the credential/console
role gates.

Before these fixes a billing-panel API key could act on *any* VM UUID (delete,
reinstall, read the stored root password, mint a console token), and any
authenticated user — including a default-role `viewer` — could read every
guest's credentials or open a VNC console over Socket.IO.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest


def _imp(name):
    try:
        return importlib.import_module(name)
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"{name} not importable: {exc}")


@pytest.fixture
def owners(tmp_path, monkeypatch):
    monkeypatch.setenv("OXWARE_PROVISION_OWNERS", str(tmp_path / "owners.json"))
    monkeypatch.delenv("OXWARE_PROVISION_ENFORCE_OWNER", raising=False)
    po = _imp("provision_owner")
    return po


# ── Ownership model ─────────────────────────────────────────────────────────
def test_reseller_cannot_touch_another_tenants_vm(owners):
    owners.record("vm-b", "reseller_B")
    assert owners.check("vm-b", "reseller_B", ["provisioning"]) is True
    assert owners.check("vm-b", "reseller_A", ["provisioning"]) is False


def test_all_permission_is_the_operator_escape_hatch(owners):
    owners.record("vm-b", "reseller_B")
    assert owners.check("vm-b", "control_panel", ["all"]) is True


def test_legacy_unowned_vm_still_works_after_upgrade(owners):
    """Existing customers' VMs predate the owner store; enforcing on them would
    break every live WHMCS/WiseCP integration on upgrade."""
    assert owners.owner_of("vm-legacy") is None
    assert owners.check("vm-legacy", "anyone", ["provisioning"]) is True


def test_enforce_owner_flag_locks_down_unowned_vms(owners, monkeypatch):
    monkeypatch.setenv("OXWARE_PROVISION_ENFORCE_OWNER", "1")
    assert owners.check("vm-legacy", "anyone", ["provisioning"]) is False


def test_forget_removes_the_record(owners):
    owners.record("vm-x", "reseller_B")
    owners.forget("vm-x")
    assert owners.owner_of("vm-x") is None


# ── The wiring in app.py (source-level, no libvirt needed) ──────────────────
def _app_source() -> str:
    here = Path(__file__).resolve().parent.parent
    return (here / "oxware" / "backend" / "app.py").read_text(encoding="utf-8",
                                                              errors="replace")


def test_every_vm_scoped_provision_route_passes_vm_id_to_the_guard():
    """Each /api/provision/<vm_id>/... handler must call
    _require_provision_key(vm_id) so ownership is enforced."""
    src = _app_source()
    blocks = re.split(r'(?=@app\.route\("/api/provision/)', src)
    checked = 0
    for b in blocks:
        m = re.match(r'@app\.route\("(/api/provision/[^"]*)"', b)
        if not m or "<vm_id>" not in m.group(1):
            continue
        body = b            # the lookahead split already yields exactly one route
        if "_require_provision_key" not in body:
            # console-info is guarded by a one-time VNC token instead
            assert "vnc_token" in body, f"{m.group(1)} has no guard at all"
            continue
        assert "_require_provision_key(vm_id)" in body, (
            f"{m.group(1)} calls the guard without vm_id -> no ownership check")
        checked += 1
    assert checked >= 12, f"expected the full provisioning surface, saw {checked}"


def test_provision_key_check_is_fail_closed_on_empty_permissions():
    src = _app_source()
    body = src.split("def _require_provision_key", 1)[1][:1600]
    # strip comments so the explanatory note about the old bug isn't matched
    code = "\n".join(l.split("#", 1)[0] for l in body.splitlines())
    assert "if perms and " not in code, (
        "empty permission list must not skip the provisioning gate")
    assert 'if "provisioning" not in perms' in code


def test_credential_vault_routes_are_role_gated():
    """/api/vms/<id>/credentials returns cleartext guest passwords."""
    src = _app_source()
    for fn in ("def api_vault_list", "def api_vault_store",
               "def api_vault_get", "def api_vault_delete"):
        head = src.rsplit(fn, 1)[0][-320:]
        assert "@require_role" in head, f"{fn} is missing a role gate"


def test_socketio_vnc_proxy_enforces_role():
    src = _app_source()
    body = src.split("def ws_vnc_connect", 1)[1][:2600]
    assert "_resolve_user_role" in body, "SocketIO VNC proxy does not resolve a role"
    assert "operator" in body, "SocketIO VNC proxy does not gate on operator+"
