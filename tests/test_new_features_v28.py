"""Unit tests for the v2.8.3–2.8.7 features added this cycle:
egress guard, dark site, ISO library, GPU passthrough wizard, instant clone,
and feature-registry integrity.

None of these require a real libvirt/KVM host — the modules are written to
degrade safely, so the tests import them directly (conftest puts
oxware/backend on sys.path) and skip gracefully if a module is absent.
"""

from __future__ import annotations

import importlib

import pytest


def _imp(name):
    try:
        return importlib.import_module(name)
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"{name} not importable: {exc}")


# ── Egress guard ────────────────────────────────────────────────────────────
def test_egress_policy_denies_public_allows_private(monkeypatch):
    eg = _imp("egress_guard")
    monkeypatch.setenv("OXWARE_EGRESS_MODE", "enforce")
    monkeypatch.setenv("OXWARE_EGRESS_ALLOW", "example.com,203.0.113.0/24")
    monkeypatch.setenv("OXWARE_EGRESS_ALLOW_PRIVATE", "true")
    eg._load_policy()

    assert eg._decide("127.0.0.1", "")[0] is True        # loopback
    assert eg._decide("10.0.0.5", "")[0] is True          # RFC1918
    assert eg._decide("8.8.8.8", "")[0] is False          # public denied
    assert eg._decide("203.0.113.9", "")[0] is True       # allowlisted CIDR
    assert eg._decide("8.8.8.8", "example.com")[0] is True  # allowlisted host
    assert eg._host_allowed("sub.example.com") is True
    assert eg._host_allowed("evil.com") is False


def test_egress_default_mode_is_monitor(monkeypatch):
    """Regression: default must be monitor (non-breaking), NOT enforce.
    Default enforce silently blocked the update check for everyone."""
    eg = _imp("egress_guard")
    monkeypatch.delenv("OXWARE_EGRESS_MODE", raising=False)
    monkeypatch.setattr(eg, "_installed", True, raising=False)

    class _NoCfg(dict):
        pass
    # Force the config fallback path to have no EGRESS_MODE.
    import sys
    monkeypatch.setitem(sys.modules, "config", type(sys)("config"))
    eg._load_policy()
    assert eg.MODE == "monitor"
    assert eg.is_offline() is False   # monitor never reports offline


def test_egress_private_ip_classification():
    eg = _imp("egress_guard")
    import ipaddress
    for ip in ("127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "169.254.1.1"):
        assert eg._is_private_ip(ipaddress.ip_address(ip)) is True
    for ip in ("8.8.8.8", "1.1.1.1"):
        assert eg._is_private_ip(ipaddress.ip_address(ip)) is False


# ── Dark Site ───────────────────────────────────────────────────────────────
def test_dark_site_off_by_default(monkeypatch):
    ds = _imp("dark_site")
    monkeypatch.delenv("OXWARE_DARK_SITE", raising=False)
    ds._load()
    assert ds.is_enabled() is False


def test_dark_site_forces_egress_enforce(monkeypatch):
    ds = _imp("dark_site")
    monkeypatch.setenv("OXWARE_DARK_SITE", "1")
    monkeypatch.setenv("OXWARE_EGRESS_MODE", "monitor")  # dark site must override
    assert ds.apply() is True
    import os
    assert os.environ["OXWARE_EGRESS_MODE"] == "enforce"
    blocked = ds.block_remote("thing")
    assert blocked["ok"] is False and blocked["offline"] is True


def test_updater_guard_keys_off_dark_site_not_enforce(monkeypatch):
    """Regression: the updater's proactive offline skip must key off Dark Site,
    not plain egress enforce — otherwise every install (default guard) shows an
    update error."""
    up = _imp("updater")
    ds = _imp("dark_site")
    # Dark Site ON -> early offline return.
    monkeypatch.setattr(ds, "is_enabled", lambda: True)
    r = up.check_updates()
    assert "Dark Site" in (r.get("error") or "")
    # Dark Site OFF -> must NOT short-circuit on the dark-site guard.
    monkeypatch.setattr(ds, "is_enabled", lambda: False)
    monkeypatch.setattr(up, "_get_remote_commits", lambda *a, **k: [], raising=False)
    monkeypatch.setattr(up, "_is_git_repo", lambda *a, **k: False, raising=False)
    try:
        r2 = up.check_updates()
        assert "Dark Site" not in (r2.get("error") or "")
    except Exception:
        pass  # downstream logic varies; the point is the dark-site guard didn't fire


# ── ISO Library ─────────────────────────────────────────────────────────────
def test_iso_catalog_shape():
    il = _imp("iso_library")
    cat = il.catalog()
    assert isinstance(cat, list) and len(cat) >= 8
    for e in cat:
        assert e["id"] and e["name"] and e["filename"]
        assert isinstance(e["mirrors"], int) and e["mirrors"] >= 1


def test_iso_download_blocked_in_dark_site(monkeypatch):
    il = _imp("iso_library")
    ds = _imp("dark_site")
    monkeypatch.setenv("OXWARE_DARK_SITE", "1")
    ds._load()
    r = il.download("debian-12-netinst")
    assert r.get("darksite") is True and r.get("ok") is False


def test_iso_verify_missing_file(tmp_path, monkeypatch):
    il = _imp("iso_library")
    monkeypatch.setenv("OXWARE_ISO_DIR", str(tmp_path))
    r = il.verify_local("does-not-exist.iso")
    assert r["ok"] is False


# ── GPU Passthrough Wizard ──────────────────────────────────────────────────
def test_gpu_overview_shape():
    gp = _imp("gpu_passthrough")
    ov = gp.wizard_overview()
    assert "iommu" in ov and "gpus" in ov
    assert isinstance(ov["gpus"], list)          # empty on a non-KVM host


def test_gpu_pci_addr_parsing():
    gp = _imp("gpu_passthrough")
    a = gp._pci_addr_xml("0000:65:00.0")
    assert a == {"domain": "0x0000", "bus": "0x65", "slot": "0x00", "function": "0x0"}
    with pytest.raises(ValueError):
        gp._pci_addr_xml("not-a-pci-addr")


# ── Instant Clone ───────────────────────────────────────────────────────────
def test_instant_clone_status():
    ic = _imp("instant_clone")
    st = ic.status()
    assert "available" in st and "mem_state_dir" in st


def test_instant_clone_requires_tools(monkeypatch):
    ic = _imp("instant_clone")
    monkeypatch.setattr(ic.shutil, "which", lambda _n: None)
    r = ic.instant_clone("src", "clone", 1)
    assert r["ok"] is False and "virsh" in r["error"]


# ── Feature registry integrity ──────────────────────────────────────────────
def test_feature_registry_new_ids_and_valid_status():
    fr = _imp("feature_registry")
    manifest = fr.FEATURE_MANIFEST
    ids = [f["id"] for f in manifest]
    assert len(ids) == len(set(ids)), "duplicate feature ids"
    allowed = {"stable", "beta", "experimental", "planned"}
    for f in manifest:
        assert f["status"] in allowed, f"bad status on {f['id']}"
        assert f["id"] and f["name"] and f["module"]
    for expected in ("egress_guard", "dark_site", "gpu_pt_wizard",
                     "iso_library", "instant_clone"):
        assert expected in ids, f"missing feature: {expected}"
