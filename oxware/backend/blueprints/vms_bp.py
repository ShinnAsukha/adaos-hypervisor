"""vms_bp — v2 read-only VM endpoints.

Mounted at /api/v2/vms. Mirrors the legacy /api/vms* shape but returns a
trimmed payload tailored to panel dashboards (no XML, no internal IDs).

Endpoints:
    GET /api/v2/vms                      — list with light fields
    GET /api/v2/vms/<id>                 — detail with quick stats
    GET /api/v2/vms/<id>/state           — power state + uptime
    GET /api/v2/vms/<id>/snapshots/count — snapshot count (fast)
    GET /api/v2/vms/by-tag/<tag>         — filter helper used by panel
"""
from __future__ import annotations
from flask import Blueprint

bp = Blueprint("v28_vms", __name__)

_require_auth = lambda fn: fn
_require_role = lambda *roles: (lambda fn: fn)
_ok = None
_err = None
_deps: dict = {}


def init_vms_bp(require_auth, require_role, ok, err, deps=None):
    global _require_auth, _require_role, _ok, _err, _deps
    _require_auth = require_auth
    _require_role = require_role
    _ok = ok
    _err = err
    _deps = deps or {}
    _register_routes()


def _safe_get(name):
    return _deps.get(name)


def _list_light(vm):
    if not isinstance(vm, dict):
        return {}
    return {
        "id": vm.get("id") or vm.get("uuid") or vm.get("name"),
        "name": vm.get("name"),
        "state": vm.get("state") or vm.get("status"),
        "vcpus": vm.get("vcpus") or vm.get("cpu_count"),
        "memory_mb": vm.get("memory_mb") or vm.get("memory"),
        "ip": vm.get("ip") or vm.get("ipv4"),
        "os_hint": vm.get("os") or vm.get("os_hint"),
        "tags": vm.get("tags") or [],
    }


def _register_routes():
    @bp.route("/api/v2/vms", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer", "vm-user")
    def api_v2_vms_list():
        vm_mgr = _safe_get("vm_manager")
        list_fn = getattr(vm_mgr, "list_vms", None) if vm_mgr else None
        if not callable(list_fn):
            return _err("vm_manager unavailable", 503)
        try:
            raw = list_fn() or []
            vms = [_list_light(v) for v in raw]
            return _ok(vms=vms, count=len(vms))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/vms/<vm_id>", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer", "vm-user")
    def api_v2_vm_detail(vm_id):
        vm_mgr = _safe_get("vm_manager")
        get_fn = getattr(vm_mgr, "get_vm", None) if vm_mgr else None
        if not callable(get_fn):
            return _err("vm_manager unavailable", 503)
        try:
            vm = get_fn(vm_id)
            if not vm:
                return _err("vm not found", 404)
            light = _list_light(vm)
            light["disks"] = [{"path": d.get("path"), "size_gb": d.get("size_gb"),
                               "bus": d.get("bus")} for d in (vm.get("disks") or [])]
            light["interfaces"] = [{"mac": i.get("mac"), "network": i.get("network"),
                                    "model": i.get("model")} for i in (vm.get("interfaces") or [])]
            return _ok(vm=light)
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/vms/<vm_id>/state", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer", "vm-user")
    def api_v2_vm_state(vm_id):
        vm_mgr = _safe_get("vm_manager")
        get_fn = getattr(vm_mgr, "get_vm_state", None) if vm_mgr else None
        if not callable(get_fn):
            return _err("vm_manager unavailable", 503)
        try:
            state = get_fn(vm_id)
            return _ok(vm_id=vm_id, **(state if isinstance(state, dict) else {"state": state}))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/vms/<vm_id>/snapshots/count", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer", "vm-user")
    def api_v2_vm_snapshot_count(vm_id):
        snap_mgr = _safe_get("snapshot_manager") or _safe_get("vm_manager")
        list_fn = (getattr(snap_mgr, "list_snapshots", None)
                   if snap_mgr else None)
        if not callable(list_fn):
            return _err("snapshot_manager unavailable", 503)
        try:
            snaps = list_fn(vm_id) or []
            return _ok(vm_id=vm_id, count=len(snaps))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/vms/by-tag/<tag>", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer", "vm-user")
    def api_v2_vms_by_tag(tag):
        vm_mgr = _safe_get("vm_manager")
        list_fn = getattr(vm_mgr, "list_vms", None) if vm_mgr else None
        if not callable(list_fn):
            return _err("vm_manager unavailable", 503)
        try:
            raw = list_fn() or []
            tagged = [_list_light(v) for v in raw
                      if tag in (v.get("tags") or [])]
            return _ok(tag=tag, vms=tagged, count=len(tagged))
        except Exception as e:
            return _err(str(e), 400)
