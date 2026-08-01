"""Regression tests for archive extraction safety (tar-slip / zip-slip).

OXware runs as root on the hypervisor, so an unvalidated ``extractall`` on an
archive fetched over the network is arbitrary-file-write-as-root. These tests
lock in that every extraction path goes through ``security_utils.safe_tar_extract``
and that the helper actually rejects the three classic escapes.
"""

from __future__ import annotations

import io
import importlib
import os
import tarfile

import pytest


def _imp(name):
    try:
        return importlib.import_module(name)
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"{name} not importable: {exc}")


def _tar_with_member(path, name, payload=b"PWNED"):
    with tarfile.open(path, "w") as tf:
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    return str(path)


# ── The helper itself ───────────────────────────────────────────────────────
@pytest.mark.parametrize("evil_name", ["../../etc/oxware_pwned", "/etc/oxware_abs"])
def test_safe_tar_extract_blocks_path_escape(tmp_path, evil_name):
    su = _imp("security_utils")
    archive = _tar_with_member(tmp_path / "evil.tar", evil_name)
    dest = tmp_path / "dest"
    with pytest.raises(su.SecurityValidationError):
        su.safe_tar_extract(archive, str(dest))


def test_safe_tar_extract_blocks_symlink_escape(tmp_path):
    su = _imp("security_utils")
    archive = tmp_path / "sym.tar"
    with tarfile.open(archive, "w") as tf:
        li = tarfile.TarInfo("escape")
        li.type = tarfile.SYMTYPE
        li.linkname = "../../../../tmp"
        tf.addfile(li)
    with pytest.raises(su.SecurityValidationError):
        su.safe_tar_extract(str(archive), str(tmp_path / "dest"))


def test_safe_tar_extract_allows_benign_archive(tmp_path):
    """The guard must not break normal extraction."""
    su = _imp("security_utils")
    archive = _tar_with_member(tmp_path / "ok.tar", "pkg/file.txt", b"hello")
    dest = tmp_path / "dest"
    su.safe_tar_extract(archive, str(dest))
    assert (dest / "pkg" / "file.txt").read_bytes() == b"hello"


# ── Call sites must use it ──────────────────────────────────────────────────
def test_marketplace_and_templates_use_safe_extractor():
    """Both modules must expose the shared safe extractor, not raw extractall."""
    for mod_name in ("app_marketplace", "template_manager"):
        mod = _imp(mod_name)
        fn = getattr(mod, "_safe_tar_extract", None)
        assert fn is not None, f"{mod_name} does not import the safe extractor"
        assert fn.__name__ == "safe_tar_extract"


def test_no_raw_extractall_in_call_sites():
    """Guard against a future edit reintroducing a bare extractall.

    security_utils itself is exempt — it *is* the validated implementation.
    """
    import pathlib

    backend = pathlib.Path(_imp("app_marketplace").__file__).parent
    offenders = []
    for name in ("app_marketplace.py", "template_manager.py"):
        src = (backend / name).read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(src.splitlines(), 1):
            stripped = line.strip()
            if "extractall(" in stripped and not stripped.startswith("#"):
                offenders.append(f"{name}:{i}: {stripped[:70]}")
    assert not offenders, "raw extractall found: " + "; ".join(offenders)
