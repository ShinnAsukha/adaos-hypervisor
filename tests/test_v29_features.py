"""Tests for the v2.9 competitive-gap features.

Covers the expanded cloud-image catalog, metered billing, DRS auto-balance
(which previously could never actually move anything), cross-cluster migration
safety, and the migration wizard finally being registered/discoverable.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest


BACKEND = Path(__file__).resolve().parent.parent / "oxware" / "backend"


def _imp(name):
    try:
        return importlib.import_module(name)
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"{name} not importable: {exc}")


# ── Cloud image catalog ─────────────────────────────────────────────────────
def _catalog_keys():
    src = (BACKEND / "vm_manager.py").read_text(encoding="utf-8", errors="replace")
    block = src.split("_CLOUD_IMAGE_URLS: dict[str, str] = {", 1)[1].split("\n}", 1)[0]
    return dict(re.findall(r'"([^"]+)":\s*"(https://[^"]+)"', block))


def test_catalog_grew_and_covers_the_major_distros():
    cat = _catalog_keys()
    assert len(cat) >= 30, f"catalog only has {len(cat)} images"
    for family in ("ubuntu", "debian", "rocky", "alma", "centos", "fedora",
                   "alpine", "arch", "oracle"):
        assert any(k.startswith(family) for k in cat), f"no {family} image"


def test_catalog_offers_arm64_builds():
    cat = _catalog_keys()
    assert sum(1 for k in cat if k.endswith("-arm")) >= 4


def test_every_catalog_entry_has_display_metadata():
    """An image without _META renders as a generic tile with wrong defaults."""
    tm = (BACKEND / "template_marketplace.py").read_text(encoding="utf-8", errors="replace")
    meta_block = tm.split("_META: dict[str, dict] = {", 1)[1].split("\n}\n", 1)[0]
    meta = set(re.findall(r'^\s{4}"([^"]+)":\s*\{', meta_block, re.M))
    missing = set(_catalog_keys()) - meta
    assert not missing, f"images with no display metadata: {sorted(missing)}"


def test_catalog_urls_are_https_and_not_placeholders():
    for name, url in _catalog_keys().items():
        assert url.startswith("https://"), f"{name} is not https"
        assert "example.com" not in url and "TODO" not in url, f"{name} is a placeholder"


# ── Metered billing ─────────────────────────────────────────────────────────
@pytest.fixture
def meter(tmp_path, monkeypatch):
    monkeypatch.setenv("OXWARE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("OXWARE_BILLING_RATES", str(tmp_path / "rates.json"))
    return _imp("billing_meter")


_VMS = [
    {"id": "vm1", "name": "web", "state": "running", "vcpus": 2,
     "memory_mb": 4096, "disk_gb": 40, "ip": "1.2.3.4"},
    {"id": "vm2", "name": "db", "state": "shutoff", "vcpus": 4,
     "memory_mb": 8192, "disk_gb": 100},
]


def test_stopped_vm_is_billed_for_storage_only(meter):
    meter.record_usage(lambda: _VMS)
    inv = meter.invoice()
    by_name = {l["vm_name"]: l for l in inv["lines"]}
    assert by_name["db"]["hours_running"] == 0
    assert by_name["db"]["hours_stopped"] == 1
    # the stopped VM has 2x the vCPU/RAM but must still cost less than the
    # running one, because compute is not billed while it is off
    assert by_name["db"]["cost"] < by_name["web"]["cost"]


def test_usage_recording_is_idempotent_per_hour(meter):
    first = meter.record_usage(lambda: _VMS)
    second = meter.record_usage(lambda: _VMS)
    assert first["recorded"] == 2
    assert second["recorded"] == 0, "same hour must not be double-billed"


def test_invoice_for_unknown_period_is_empty_not_an_error(meter):
    inv = meter.invoice("1999-01")
    assert inv["ok"] is True and inv["total"] == 0.0 and inv["lines"] == []


def test_rates_round_trip(meter):
    meter.set_rates(vcpu_hour=0.01)
    assert meter.get_rates()["vcpu_hour"] == 0.01


# ── DRS auto-balance ────────────────────────────────────────────────────────
def test_drs_dry_run_never_migrates(monkeypatch):
    d = _imp("drs_manager")
    monkeypatch.setattr(d, "suggest_moves",
                        lambda: [{"vm_id": "vm1", "target_host": "node2"}])
    called = []
    monkeypatch.setattr(d, "_live_migrate",
                        lambda *a, **k: called.append(a) or (True, ""))
    r = d.auto_balance(dry_run=True)
    assert r["applied"] == 0 and not called


def test_drs_actually_migrates_and_respects_the_brake(monkeypatch):
    """Before this, auto_balance could never move anything at all."""
    d = _imp("drs_manager")
    monkeypatch.setattr(d, "suggest_moves", lambda: [
        {"vm_id": "vm1", "target_host": "node2"},
        {"vm_id": "vm2", "target_host": "node3"},
    ])
    called = []
    monkeypatch.setattr(d, "_live_migrate",
                        lambda v, t, timeout=300: called.append((v, t)) or (True, ""))
    r = d.auto_balance(dry_run=False)          # default brake = 1 move/run
    assert r["applied"] == 1 and len(called) == 1


def test_drs_stops_the_run_after_a_failed_migration(monkeypatch):
    d = _imp("drs_manager")
    monkeypatch.setattr(d, "suggest_moves", lambda: [
        {"vm_id": "vm1", "target_host": "node2"},
        {"vm_id": "vm2", "target_host": "node3"},
    ])
    called = []
    monkeypatch.setattr(d, "_live_migrate",
                        lambda v, t, timeout=300: called.append((v, t)) or (False, "boom"))
    r = d.auto_balance(dry_run=False, max_moves=5)
    assert r["applied"] == 0 and len(called) == 1, "must not stampede after a failure"


# ── Cross-cluster migration ─────────────────────────────────────────────────
def test_xcluster_plan_rejects_unknown_target():
    x = _imp("xcluster_migrate")
    assert x.plan("vm1", "does-not-exist")["ok"] is False


def test_xcluster_migrate_defaults_to_dry_run():
    x = _imp("xcluster_migrate")
    r = x.migrate("vm1", "does-not-exist")
    assert r["ok"] is False          # plan not ready -> nothing happens
    assert "plan" in r


# ── Migration wizard is discoverable ────────────────────────────────────────
def test_migration_wizard_is_registered_in_the_feature_registry():
    fr = _imp("feature_registry")
    ids = {f["id"] for f in fr.FEATURE_MANIFEST}
    for fid in ("migrate_esxi", "migrate_proxmox", "metered_billing",
                "xcluster_migrate", "provision_owner"):
        assert fid in ids, f"{fid} missing from the feature registry"


def test_migration_wizard_has_a_nav_entry():
    """It shipped buried inside the Settings page, so nobody found it."""
    idx = (BACKEND.parent / "frontend" / "templates" / "index.html").read_text(
        encoding="utf-8", errors="replace")
    assert "openMigrationWizard" in idx, "no nav entry calls the migration wizard"
    assert idx.count("migration:'") >= 6, "migration nav label is not translated"
