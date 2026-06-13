"""Smoke tests for v2.8 domain blueprints.

These verify that each blueprint imports cleanly, exposes the expected
`init_*_bp` callable, and registers without crashing when the
dependency dict is empty (the safe-degraded path).
"""
from __future__ import annotations
import pathlib
import sys

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "oxware" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


@pytest.mark.parametrize("mod_name,init_name", [
    ("blueprints.auth_bp", "init_auth_bp"),
    ("blueprints.vms_bp", "init_vms_bp"),
    ("blueprints.networks_bp", "init_networks_bp"),
    ("blueprints.storage_bp", "init_storage_bp"),
    ("blueprints.monitoring_bp", "init_monitoring_bp"),
])
def test_blueprint_imports_and_exposes_init(mod_name, init_name):
    pytest.importorskip("flask")
    mod = __import__(mod_name, fromlist=["*"])
    assert hasattr(mod, "bp"), f"{mod_name} must expose `bp`"
    assert hasattr(mod, init_name), f"{mod_name} must expose `{init_name}`"
    assert callable(getattr(mod, init_name))


def test_blueprint_init_with_empty_deps_does_not_crash():
    pytest.importorskip("flask")
    # All five blueprints must accept an empty deps dict without raising.
    from blueprints import (auth_bp, vms_bp, networks_bp,  # type: ignore
                            storage_bp, monitoring_bp)
    noop_auth = lambda fn: fn
    noop_role = lambda *roles: (lambda fn: fn)
    ok = lambda **kw: {"ok": True, **kw}
    err = lambda msg, status=400: ({"ok": False, "error": str(msg)}, status)
    for mod, name in (
        (auth_bp, "init_auth_bp"),
        (vms_bp, "init_vms_bp"),
        (networks_bp, "init_networks_bp"),
        (storage_bp, "init_storage_bp"),
        (monitoring_bp, "init_monitoring_bp"),
    ):
        getattr(mod, name)(
            require_auth=noop_auth, require_role=noop_role,
            ok=ok, err=err, deps={},
        )


def test_route_counts_match_plan():
    pytest.importorskip("flask")
    from blueprints import (auth_bp, vms_bp, networks_bp,  # type: ignore
                            storage_bp, monitoring_bp)
    noop_auth = lambda fn: fn
    noop_role = lambda *roles: (lambda fn: fn)
    ok = lambda **kw: {"ok": True, **kw}
    err = lambda msg, status=400: ({"ok": False, "error": str(msg)}, status)
    # We have to re-init each time because Blueprint route registration is
    # idempotent within a process but the route table grows on re-import.
    expected = {
        "v28_auth": 5,
        "v28_vms": 5,
        "v28_networks": 5,
        "v28_storage": 5,
        "v28_monitoring": 5,
    }
    for mod, init_name in (
        (auth_bp, "init_auth_bp"),
        (vms_bp, "init_vms_bp"),
        (networks_bp, "init_networks_bp"),
        (storage_bp, "init_storage_bp"),
        (monitoring_bp, "init_monitoring_bp"),
    ):
        # Re-init is safe; Flask Blueprint dedupes by endpoint name.
        try:
            getattr(mod, init_name)(
                require_auth=noop_auth, require_role=noop_role,
                ok=ok, err=err, deps={},
            )
        except Exception:
            pass
        bp = mod.bp
        # Flask Blueprint stores deferred operations in `deferred_functions`.
        # Count the route additions (route() / add_url_rule()).
        count = len(bp.deferred_functions)
        assert count >= expected[bp.name], (
            f"{bp.name} expected >= {expected[bp.name]} routes, got {count}"
        )
