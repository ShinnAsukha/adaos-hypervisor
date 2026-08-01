"""Regression tests for the Socket.IO and SSO authentication fixes.

Before these, an unauthenticated Socket.IO client could stream host stats and
every VM's identity, an OAuth2 user could impersonate the primary admin by
controlling an email local-part, and a forged SAML assertion was accepted
whenever python3-saml happened to be installed.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest


APP_PY = Path(__file__).resolve().parent.parent / "oxware" / "backend" / "app.py"


def _imp(name):
    try:
        return importlib.import_module(name)
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"{name} not importable: {exc}")


def _handler_body(name: str, span: int = 2000) -> str:
    src = APP_PY.read_text(encoding="utf-8", errors="replace")
    assert f"def {name}(" in src, f"handler {name} not found"
    return src.split(f"def {name}(", 1)[1][:span]


# ── Socket.IO subscribe handlers ────────────────────────────────────────────
@pytest.mark.parametrize("handler", [
    "on_subscribe_vm_events",
    "on_subscribe_vm_metrics",
    "on_subscribe_stats",
])
def test_socketio_subscribe_handlers_require_identity(handler):
    body = _handler_body(handler)
    assert "_ws_identity" in body, f"{handler} does not authenticate the caller"
    assert "Kimlik doğrulama gerekli" in body, f"{handler} does not reject anonymous callers"


def test_vm_events_no_longer_swallows_auth_failure():
    """The old code wrapped auth in try/except: pass and carried on with
    vm_ids='*', so a failed check still leaked every VM."""
    body = _handler_body("on_subscribe_vm_events")
    # the auth result must gate an early return, not be discarded
    idx = body.index("_ws_identity")
    assert "return" in body[idx:idx + 400], "auth result does not gate an early return"


def test_ws_identity_rejects_missing_and_revoked_tokens():
    src = APP_PY.read_text(encoding="utf-8", errors="replace")
    body = src.split("def _ws_identity(", 1)[1][:1400]
    assert "is_revoked" in body, "_ws_identity accepts revoked sessions"
    assert "return None, None" in body, "_ws_identity does not fail closed"


# ── OAuth2 username collision ───────────────────────────────────────────────
def _derive(email, provider, primary_admin, existing_users):
    """Mirror of the collision logic in api_oauth2_callback."""
    import re as _re_sso
    username = email.split("@")[0]
    collides = bool(primary_admin) and username.lower() == primary_admin.lower()
    if not collides:
        existing = existing_users.get(username)
        if existing and not existing.get("oauth2"):
            collides = True
    if collides:
        safe = _re_sso.sub(r"[^a-zA-Z0-9_.-]", "", str(provider))[:24] or "sso"
        username = f"{safe}_{username}"
    return username


def test_oauth2_cannot_impersonate_primary_admin():
    users = {"operator1": {"oauth2": False}, "ali": {"oauth2": True}}
    assert _derive("admin@attacker.tld", "google", "admin", users) != "admin"
    # nor take over an existing local (non-SSO) account
    assert _derive("operator1@attacker.tld", "google", "admin", users) != "operator1"


def test_oauth2_leaves_normal_users_alone():
    """Existing SSO users and fresh accounts must keep their plain username."""
    users = {"operator1": {"oauth2": False}, "ali": {"oauth2": True}}
    assert _derive("ali@sirket.com", "google", "admin", users) == "ali"
    assert _derive("yeni@sirket.com", "google", "admin", users) == "yeni"


def test_oauth2_collision_logic_is_wired_into_the_callback():
    src = APP_PY.read_text(encoding="utf-8", errors="replace")
    body = src.split("def api_oauth2_callback(", 1)[1][:2500]
    assert "_collides" in body, "callback does not check for username collisions"
    assert "get_username" in body, "callback does not compare against the primary admin"


# ── SAML fail-closed ────────────────────────────────────────────────────────
def test_saml_acs_is_fail_closed_without_real_verification(monkeypatch):
    sso = _imp("sso_manager")
    monkeypatch.delenv("OXWARE_ALLOW_UNVERIFIED_SSO", raising=False)
    # Even with the library "available", an unverified assertion must be refused.
    monkeypatch.setattr(sso, "_SAML_VERIFY_AVAILABLE", True, raising=False)
    r = sso.saml_process_acs("PHNhbWw+", "")
    assert r["ok"] is False
    assert r.get("verified") is False
