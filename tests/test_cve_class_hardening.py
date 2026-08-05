"""Hardening against the vulnerability *classes* behind the 2026 vCenter CVEs.

Prompted by CVE-2026-59309 (auth bypass in the vCenter directory service) and
CVE-2026-59310 (directory traversal in the vCenter syslog server). These tests
do not concern VMware code — they assert OXware is not vulnerable to the same
two classes.
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


# ── Class 1: directory-service authentication bypass ────────────────────────
@pytest.mark.parametrize("pwd", ["", "   ", "\t", None])
def test_ldap_rejects_empty_password_before_binding(monkeypatch, pwd):
    """An empty/whitespace password in a SIMPLE bind is an *unauthenticated
    bind* (RFC 4513); most LDAP servers answer success and treat it as
    anonymous. Accepting that would authenticate anyone who knows a username.
    """
    ldap = _imp("ldap_manager")
    monkeypatch.setattr(ldap, "LDAP_AVAILABLE", True, raising=False)
    called = []
    monkeypatch.setattr(ldap, "_full_config",
                        lambda: called.append("config") or
                        {"enabled": True, "server": "ldap.example.com"},
                        raising=False)
    r = ldap.authenticate("valid.user", pwd)
    assert r["authenticated"] is False
    # must fail closed *before* touching the server at all
    assert not called, "empty password reached the LDAP connection path"


def test_ldap_rejects_blank_username(monkeypatch):
    ldap = _imp("ldap_manager")
    monkeypatch.setattr(ldap, "LDAP_AVAILABLE", True, raising=False)
    for user in ("", "   ", None):
        assert ldap.authenticate(user, "realpassword")["authenticated"] is False


def test_ldap_authenticate_verifies_the_bind_took_effect():
    """Defense in depth: some servers return bound=False / an anonymous
    identity instead of raising on a failed bind."""
    src = (BACKEND / "ldap_manager.py").read_text(encoding="utf-8", errors="replace")
    body = src.split("def authenticate(", 1)[1]
    assert "bound" in body, "bind result is never checked"
    assert "who_am_i" in body, "no anonymous-identity check after bind"


# ── Class 2: traversal in the log/syslog surface ───────────────────────────
def test_syslog_module_takes_no_caller_supplied_path():
    """get_* helpers must read a fixed allowlist of files, never a path from
    the request."""
    src = (BACKEND / "syslog_manager.py").read_text(encoding="utf-8", errors="replace")
    for fn in re.findall(r"def (get_\w+)\(([^)]*)\)", src):
        name, args = fn
        for suspicious in ("path", "file", "filename", "dir"):
            assert suspicious not in args.lower(), (
                f"syslog_manager.{name} accepts a caller-supplied {suspicious}")


def test_syslog_commands_are_argv_lists_not_shell_strings():
    src = (BACKEND / "syslog_manager.py").read_text(encoding="utf-8", errors="replace")
    assert "shell=True" not in src
    assert "os.system" not in src


def test_vault_secret_path_cannot_escape_the_kv_mount():
    """The secret path is interpolated into the remote Vault API URL; `..`
    would reach Vault endpoints outside the configured KV mount using the
    stored root-capable token."""
    v = _imp("vault_integration")
    for bad in ("../../sys/policies/acl/root", "a/../../b", "..", "/../x"):
        with pytest.raises(ValueError):
            v._safe_secret_path(bad)
    assert v._safe_secret_path("app/db/creds") == "app/db/creds"
    assert v._safe_secret_path("/leading/slash") == "leading/slash"


def test_all_vault_helpers_use_the_path_guard():
    src = (BACKEND / "vault_integration.py").read_text(encoding="utf-8", errors="replace")
    for fn in ("read_secret", "write_secret", "delete_secret", "list_secrets"):
        body = src.split(f"def {fn}(", 1)[1].split("\ndef ", 1)[0]
        assert "_safe_secret_path" in body, f"{fn} interpolates the raw path"
