"""storage_bp — v2 storage pool + volume + ISO endpoints.

Mounted at /api/v2/storage.

Endpoints:
    GET /api/v2/storage/pools                       — pool list with usage
    GET /api/v2/storage/pools/<name>                — pool detail
    GET /api/v2/storage/pools/<name>/volumes        — volumes under pool
    GET /api/v2/storage/pools/<name>/free-space     — fast free-byte query
    GET /api/v2/storage/isos                        — ISO library
"""
from __future__ import annotations
from flask import Blueprint

bp = Blueprint("v28_storage", __name__)

_require_auth = lambda fn: fn
_require_role = lambda *roles: (lambda fn: fn)
_ok = None
_err = None
_deps: dict = {}


def init_storage_bp(require_auth, require_role, ok, err, deps=None):
    global _require_auth, _require_role, _ok, _err, _deps
    _require_auth = require_auth
    _require_role = require_role
    _ok = ok
    _err = err
    _deps = deps or {}
    _register_routes()


def _safe_get(name):
    return _deps.get(name)


def _light_pool(p):
    if not isinstance(p, dict):
        return {}
    cap = p.get("capacity_bytes") or 0
    used = p.get("used_bytes") or 0
    free = max(cap - used, 0)
    pct = (used / cap * 100) if cap > 0 else 0
    return {
        "name": p.get("name"),
        "type": p.get("type"),
        "path": p.get("path") or p.get("target_path"),
        "active": bool(p.get("active", True)),
        "autostart": bool(p.get("autostart", False)),
        "capacity_bytes": cap,
        "used_bytes": used,
        "free_bytes": free,
        "used_percent": round(pct, 2),
    }


def _light_vol(v):
    if not isinstance(v, dict):
        return {}
    return {
        "name": v.get("name"),
        "path": v.get("path"),
        "capacity_bytes": v.get("capacity_bytes") or v.get("size"),
        "allocation_bytes": v.get("allocation_bytes") or v.get("allocation"),
        "format": v.get("format"),
    }


def _register_routes():
    @bp.route("/api/v2/storage/pools", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_storage_pools():
        sm = _safe_get("storage_manager")
        list_fn = getattr(sm, "list_pools", None) if sm else None
        if not callable(list_fn):
            return _err("storage_manager unavailable", 503)
        try:
            raw = list_fn() or []
            pools = [_light_pool(p) for p in raw]
            return _ok(pools=pools, count=len(pools))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/storage/pools/<name>", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_storage_pool_detail(name):
        sm = _safe_get("storage_manager")
        get_fn = getattr(sm, "get_pool", None) if sm else None
        if not callable(get_fn):
            return _err("storage_manager unavailable", 503)
        try:
            p = get_fn(name)
            if not p:
                return _err("pool not found", 404)
            return _ok(pool=_light_pool(p))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/storage/pools/<name>/volumes", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_storage_volumes(name):
        sm = _safe_get("storage_manager")
        list_fn = getattr(sm, "list_volumes", None) if sm else None
        if not callable(list_fn):
            return _err("storage_manager unavailable", 503)
        try:
            raw = list_fn(name) or []
            vols = [_light_vol(v) for v in raw]
            return _ok(pool=name, volumes=vols, count=len(vols))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/storage/pools/<name>/free-space", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_storage_free(name):
        sm = _safe_get("storage_manager")
        get_fn = getattr(sm, "get_pool", None) if sm else None
        if not callable(get_fn):
            return _err("storage_manager unavailable", 503)
        try:
            p = get_fn(name)
            if not p:
                return _err("pool not found", 404)
            cap = p.get("capacity_bytes") or 0
            used = p.get("used_bytes") or 0
            free = max(cap - used, 0)
            return _ok(pool=name, free_bytes=free,
                       free_gb=round(free / (1024 ** 3), 2))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/storage/isos", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_isos():
        iso_mgr = _safe_get("iso_manager") or _safe_get("storage_manager")
        list_fn = (getattr(iso_mgr, "list_isos", None)
                   if iso_mgr else None)
        if not callable(list_fn):
            return _err("iso_manager unavailable", 503)
        try:
            isos = list_fn() or []
            light = [{"name": i.get("name"), "size_bytes": i.get("size"),
                      "path": i.get("path"), "os_hint": i.get("os")}
                     for i in isos if isinstance(i, dict)]
            return _ok(isos=light, count=len(light))
        except Exception as e:
            return _err(str(e), 400)
