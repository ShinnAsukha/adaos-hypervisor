"""Shared pytest fixtures for OXware test suite.

The fixtures here avoid any dependency on a real libvirt daemon, a real
KVM-capable host, or persistent state under /var/lib/oxware. Tests should
be runnable on a developer laptop with only Python and the dev requirements
installed.
"""

from __future__ import annotations

import os
import sys
import types
import tempfile
import pathlib

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
# Backend lives at <repo>/oxware/backend (not <repo>/backend).
BACKEND_DIR = REPO_ROOT / "oxware" / "backend"
if not BACKEND_DIR.is_dir():
    BACKEND_DIR = REPO_ROOT / "backend"  # legacy fallback
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def tmp_state_dir(monkeypatch):
    """Provide a clean temporary directory in place of /var/lib/oxware."""
    with tempfile.TemporaryDirectory(prefix="oxware-test-") as d:
        monkeypatch.setenv("OXWARE_STATE_DIR", d)
        monkeypatch.setenv("OXWARE_AUDIT_LOG", os.path.join(d, "audit.log"))
        yield d


@pytest.fixture
def mock_libvirt(monkeypatch):
    """Install a stub libvirt module so backend imports succeed without KVM."""
    stub = types.ModuleType("libvirt")

    class _Conn:
        def listAllDomains(self, *_a, **_kw):
            return []

        def listAllNetworks(self, *_a, **_kw):
            return []

        def listAllStoragePools(self, *_a, **_kw):
            return []

        def close(self):
            return 0

    def _open(_uri=None):
        return _Conn()

    stub.open = _open
    stub.openReadOnly = _open
    stub.libvirtError = type("libvirtError", (Exception,), {})
    # Domain state + flag constants the backend reads at import time. Values
    # mirror libvirt's real enum where it matters (NOSTATE=0 … PMSUSPENDED=7);
    # flag bitmasks are given distinct nonzero values — exact values are not
    # asserted, presence is what lets the modules import under the stub.
    _consts = {
        "VIR_DOMAIN_NOSTATE": 0,
        "VIR_DOMAIN_RUNNING": 1,
        "VIR_DOMAIN_BLOCKED": 2,
        "VIR_DOMAIN_PAUSED": 3,
        "VIR_DOMAIN_SHUTDOWN": 4,
        "VIR_DOMAIN_SHUTOFF": 5,
        "VIR_DOMAIN_CRASHED": 6,
        "VIR_DOMAIN_PMSUSPENDED": 7,
        "VIR_DOMAIN_XML_INACTIVE": 2,
        "VIR_DOMAIN_AFFECT_CONFIG": 2,
        "VIR_DOMAIN_AFFECT_LIVE": 1,
        "VIR_DOMAIN_MEM_CONFIG": 2,
        "VIR_DOMAIN_MEM_LIVE": 1,
        "VIR_DOMAIN_VCPU_CONFIG": 2,
        "VIR_DOMAIN_VCPU_LIVE": 1,
        "VIR_DOMAIN_UNDEFINE_MANAGED_SAVE": 1,
        "VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA": 2,
        "VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE": 1,
        "VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE": 0,
        "VIR_MIGRATE_LIVE": 1,
        "VIR_MIGRATE_PEER2PEER": 2,
        "VIR_MIGRATE_TUNNELLED": 4,
    }
    for _k, _v in _consts.items():
        setattr(stub, _k, _v)
    monkeypatch.setitem(sys.modules, "libvirt", stub)
    return stub


@pytest.fixture
def app(mock_libvirt, tmp_state_dir, monkeypatch):
    """Return a Flask test client without starting SocketIO."""
    monkeypatch.setenv("OXWARE_TEST_MODE", "1")
    monkeypatch.setenv("OXWARE_DISABLE_SOCKETIO", "1")

    try:
        import backend.main as main_module  # type: ignore
    except Exception:
        try:
            import main as main_module  # type: ignore
        except Exception as exc:
            pytest.skip(f"backend not importable in this environment: {exc}")

    flask_app = getattr(main_module, "app", None)
    if flask_app is None:
        pytest.skip("backend exposes no `app` attribute")

    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    with flask_app.test_client() as client:
        yield client
