"""Authorization coverage: every state-changing endpoint must carry a role gate.

New secondary users default to ``viewer`` (user_manager), so an endpoint that
only has ``@require_auth`` is reachable by every account in the panel. This test
enumerates the real route table from app.py and fails if a write endpoint is
missing ``@require_role`` unless it is on an explicit, justified allowlist.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


APP_PY = Path(__file__).resolve().parent.parent / "oxware" / "backend" / "app.py"

# Endpoints that legitimately run without a role gate, each with the reason.
ROLE_EXEMPT = {
    # The caller acts on their own account only.
    "/api/auth/2fa/setup":            "user's own 2FA",
    "/api/auth/2fa/enable":           "user's own 2FA",
    "/api/auth/2fa/disable":          "user's own 2FA",
    "/api/auth/change-password":      "user's own password",
    "/api/recovery-codes/generate":   "user's own recovery codes",
    "/api/recovery-codes/revoke":     "user's own recovery codes",
    "/api/settings/language":         "per-user UI preference",
    "/api/rbac/check":                "permission query helper, no state change",
    # Ownership is enforced inside the handler / manager.
    "/api/apikeys/<key_id>":          "ownership checked in handler",
    "/api/apikeys/<key_id>/revoke":   "revoke_key(key_id, username) scopes it",
    "/api/self-service/vms":          "self_service enforces per-user quota",
    "/api/self-service/vms/<vm_id>/<action>": "self_service._user_owns_vm",
    "/api/self-service/console/<vm_id>":      "self_service._user_owns_vm",
}


def _routes():
    src = APP_PY.read_text(encoding="utf-8", errors="replace").splitlines()
    out, i = [], 0
    while i < len(src):
        m = re.match(r'@app\.route\("([^"]+)"(.*)', src[i].strip())
        if not m:
            i += 1
            continue
        decos, j = [], i + 1
        while j < len(src) and src[j].lstrip().startswith("@"):
            decos.append(src[j].strip())
            j += 1
        methods = re.findall(r'"(GET|POST|PUT|DELETE|PATCH)"', m.group(2)) or ["GET"]
        out.append({
            "path": m.group(1), "methods": methods, "line": i + 1,
            "auth": any("require_auth" in d for d in decos),
            "role": any("require_role" in d for d in decos),
        })
        i = j
    return out


def test_route_table_is_parseable():
    routes = _routes()
    assert len(routes) > 500, f"only parsed {len(routes)} routes — parser drifted"


def test_no_write_endpoint_is_reachable_by_a_bare_viewer():
    offenders = []
    for r in _routes():
        if not (set(r["methods"]) - {"GET"}):
            continue                      # read-only
        if not r["auth"] or r["role"]:
            continue                      # unauthenticated (login/API-key) or gated
        if r["path"] in ROLE_EXEMPT:
            continue
        offenders.append(f"{r['path']} ({','.join(r['methods'])}) at app.py:{r['line']}")
    assert not offenders, (
        "write endpoints with @require_auth but no @require_role — a default-role "
        "viewer can call these:\n  " + "\n  ".join(offenders))


def test_host_level_endpoints_are_admin_only():
    """Firewall/VPN/TLS/nginx/LDAP/sessions change host or auth state; operator
    is not enough."""
    admin_prefixes = ("/api/firewall/", "/api/vpn/", "/api/ssl/", "/api/nginx/",
                      "/api/ldap/", "/api/sessions/", "/api/webhooks",
                      "/api/security/lockouts", "/api/security/audit/fix")
    src = APP_PY.read_text(encoding="utf-8", errors="replace").splitlines()
    checked = 0
    for r in _routes():
        if not (set(r["methods"]) - {"GET"}):
            continue
        if not any(r["path"].startswith(p) for p in admin_prefixes):
            continue
        if not r["auth"]:
            continue
        block = "\n".join(src[r["line"]:r["line"] + 4])
        assert "require_role" in block, f"{r['path']} has no role gate"
        assert "operator" not in block, (
            f"{r['path']} allows operator; host-level changes must be admin-only")
        checked += 1
    assert checked >= 15, f"expected the host-level surface, saw {checked}"


def test_billing_provisioning_api_keeps_working():
    """The X-API-Key provisioning surface must NOT gain @require_role — those
    callers are billing panels with no JWT, so a role gate would 401 every
    WHMCS/WiseCP/HostBill/Blesta integration."""
    src = APP_PY.read_text(encoding="utf-8", errors="replace").splitlines()
    checked = 0
    for r in _routes():
        # Billing routes authenticate with X-API-Key inside the handler, so they
        # carry no @require_auth. (/api/provision and /api/provision/bulk are
        # JWT-authenticated panel routes and are correctly admin-gated.)
        if not r["path"].startswith("/api/provision/") or r["auth"]:
            continue
        block = "\n".join(src[r["line"]:r["line"] + 4])
        assert "require_role" not in block, (
            f"{r['path']} gained a role gate — this breaks billing integrations")
        body = "\n".join(src[r["line"]:r["line"] + 12])
        # console-info is guarded by the one-time VNC token, which is bound to
        # the vm_id, instead of the API key.
        assert ("_require_provision_key" in body) or ("vnc_token" in body), (
            f"{r['path']} has neither a JWT gate nor an API-key/one-time-token guard")
        checked += 1
    assert checked >= 12, f"expected the billing provisioning surface, saw {checked}"
