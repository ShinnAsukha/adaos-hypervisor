"""Tests for the v2.8.2 kernel-level pack (I/O perf, eBPF, host kernel ops, LKMs).

These run cross-platform. On a dev box without libvirt/bpftrace/sysfs the
modules must degrade gracefully (available=False + reason) and never crash —
that honest-degradation contract is exactly what's locked in here.
"""

from __future__ import annotations

import json

import pytest


# ── io_perf_manager: graceful without libvirt ────────────────────────────────

def test_io_perf_get_config_graceful(mock_libvirt):
    import io_perf_manager  # type: ignore
    res = io_perf_manager.get_io_config("nonexistent-vm")
    assert isinstance(res, dict)
    assert "ok" in res  # never raises


def test_io_perf_recommend_shape(mock_libvirt):
    import io_perf_manager  # type: ignore
    res = io_perf_manager.recommend("nonexistent-vm")
    assert isinstance(res, dict) and "ok" in res


def test_io_perf_set_disk_rejects_bad_aio():
    import io_perf_manager  # type: ignore
    res = io_perf_manager.set_disk_perf("vm", "vda", aio="bogus")
    assert res["ok"] is False
    assert "aio" in res["error"]


# ── ebpf_observability: honest status, no fake metrics ───────────────────────

def test_ebpf_status_reports_availability():
    import ebpf_observability  # type: ignore
    s = ebpf_observability.status()
    assert s["ok"] is True
    assert isinstance(s["available"], bool)
    # When the toolchain is absent, a reason must be given (no fake "enabled").
    if not s["available"]:
        assert s["reason"]


def test_ebpf_syscalls_gated_without_tools():
    import ebpf_observability  # type: ignore
    res = ebpf_observability.vm_syscalls("some-vm", seconds=1)
    assert isinstance(res, dict) and "ok" in res


# ── kernel_ops: sysfs-backed, graceful off-Linux ─────────────────────────────

def test_kernel_ops_status_calls_safe():
    import kernel_ops  # type: ignore
    for fn in (kernel_ops.zram_status, kernel_ops.zswap_status,
               kernel_ops.cpu_power_status, kernel_ops.livepatch_status):
        r = fn()
        assert r["ok"] is True
        assert "available" in r


def test_kernel_ops_governor_validates():
    import kernel_ops  # type: ignore
    # Off-Linux this returns root-required or no-cpufreq, but must not crash.
    r = kernel_ops.cpu_set_governor("performance")
    assert isinstance(r, dict) and "ok" in r


# ── kernel_modules: LKM inventory ────────────────────────────────────────────

def test_kernel_modules_status_lists_both():
    import kernel_modules  # type: ignore
    st = kernel_modules.status()
    assert st["ok"] is True
    names = {m["name"] for m in st["modules"]}
    assert names == {"oxware_audit", "oxware_guard"}


def test_kernel_modules_rejects_unknown():
    import kernel_modules  # type: ignore
    assert kernel_modules.build("evil")["ok"] is False
    assert kernel_modules.load("evil")["ok"] is False


# ── wiring: new routes present in the OpenAPI surface ─────────────────────────

def test_kernel_pack_routes_registered(app):
    resp = app.get("/api/openapi")
    assert resp.status_code == 200
    paths = json.loads(resp.data)["paths"]
    for expected in ("/api/io-perf/{vm_id}", "/api/ebpf/status",
                     "/api/kernel/zram", "/api/kernel/modules"):
        assert expected in paths, f"route missing from OpenAPI: {expected}"
