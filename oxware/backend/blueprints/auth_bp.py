"""auth_bp — v2 authentication + session endpoints.

Mounted at /api/v2/auth. Delegates to the existing `auth` module +
audit log so the legacy /api/auth/* routes in app.py keep working
unchanged. This file is intentionally small — full extraction of the
auth subsystem is tracked in MODULARIZATION_PLAN.md.

New endpoints exposed here:
    GET  /api/v2/auth/me             — current user info
    GET  /api/v2/auth/sessions       — active sessions for current user
    POST /api/v2/auth/csrf/rotate    — rotate CSRF cookie pair
    GET  /api/v2/auth/permissions    — flat list of role permissions
    POST /api/v2/auth/touch          — bump session last-seen
"""
from __future__ import annotations
import time
from flask import Blueprint, request

bp = Blueprint("v28_auth", __name__)

_require_auth = lambda fn: fn
_require_role = lambda *roles: (lambda fn: fn)
_ok = None
_err = None
_deps: dict = {}


def init_auth_bp(require_auth, require_role, ok, err, deps=None):
    """Wire late-bound dependencies. Call before register_blueprint."""
    global _require_auth, _require_role, _ok, _err, _deps
    _require_auth = require_auth
    _require_role = require_role
    _ok = ok
    _err = err
    _deps = deps or {}
    _register_routes()


def _safe_get(name):
    return _deps.get(name)


def _register_routes():
    @bp.route("/api/v2/auth/me", methods=["GET"])
    @_require_auth
    def api_v2_me():
        # Pull JWT claims via the auth module helper if available; fall back
        # to whatever the legacy /api/me endpoint shape gave us.
        get_current = _safe_get("get_current_user")
        if not callable(get_current):
            return _err("user resolver unavailable", 503)
        try:
            user = get_current()
        except Exception as e:
            return _err(str(e), 401)
        if not user:
            return _err("not authenticated", 401)
        return _ok(user={
            "username": user.get("username") or user.get("sub"),
            "role": user.get("role"),
            "email": user.get("email"),
            "full_name": user.get("full_name"),
            "two_factor": bool(user.get("two_factor")),
            "issued_at": user.get("iat"),
            "expires_at": user.get("exp"),
        })

    @bp.route("/api/v2/auth/sessions", methods=["GET"])
    @_require_auth
    def api_v2_sessions():
        sess_mgr = _safe_get("session_manager") or _safe_get("auth")
        list_fn = getattr(sess_mgr, "list_sessions", None) if sess_mgr else None
        if not callable(list_fn):
            return _ok(sessions=[], note="session_manager not wired")
        try:
            current = (_safe_get("get_current_user") or (lambda: {}))() or {}
            sessions = list_fn(current.get("username") or current.get("sub"))
            return _ok(sessions=sessions)
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/auth/csrf/rotate", methods=["POST"])
    @_require_auth
    def api_v2_csrf_rotate():
        rotate = _safe_get("rotate_csrf")
        if not callable(rotate):
            return _err("csrf rotator not wired", 503)
        try:
            new_token = rotate()
            return _ok(csrf_token=new_token, rotated_at=time.time())
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/auth/permissions", methods=["GET"])
    @_require_auth
    def api_v2_permissions():
        rbac = _safe_get("rbac") or _safe_get("auth")
        list_perms = getattr(rbac, "list_role_permissions", None) if rbac else None
        if not callable(list_perms):
            # Minimal fallback derived from the role string only.
            current = (_safe_get("get_current_user") or (lambda: {}))() or {}
            role = current.get("role", "viewer")
            return _ok(role=role, permissions=_minimal_perms_for(role))
        try:
            return _ok(permissions=list_perms())
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/auth/touch", methods=["POST"])
    @_require_auth
    def api_v2_touch():
        sess_mgr = _safe_get("session_manager") or _safe_get("auth")
        touch_fn = getattr(sess_mgr, "touch_session", None) if sess_mgr else None
        if not callable(touch_fn):
            return _ok(touched=False, ts=time.time())
        try:
            current = (_safe_get("get_current_user") or (lambda: {}))() or {}
            touch_fn(current.get("session_id") or current.get("jti"))
            return _ok(touched=True, ts=time.time())
        except Exception as e:
            return _err(str(e), 400)


# Conservative defaults for the fallback path — real perms come from the
# auth module's RBAC table when wired.
_BASE_PERMS = {
    "administrator": ["*"],
    "operator": [
        "vm.read", "vm.start", "vm.stop", "vm.reboot",
        "network.read", "storage.read", "monitoring.read",
        "snapshot.read", "snapshot.create",
    ],
    "viewer": [
        "vm.read", "network.read", "storage.read", "monitoring.read",
    ],
    "vm-user": ["vm.read.assigned", "vm.start.assigned", "vm.stop.assigned"],
}


def _minimal_perms_for(role: str) -> list:
    return list(_BASE_PERMS.get(role, _BASE_PERMS["viewer"]))
