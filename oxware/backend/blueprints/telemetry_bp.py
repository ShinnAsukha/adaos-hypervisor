"""telemetry_bp — opt-in anonymous usage telemetry endpoints.

Mounted at /api/v2/telemetry. Lets the operator inspect, enable, disable,
and trigger an immediate ping. Default state is DISABLED and no data
leaves the host until enable() is called.

Endpoints:
    GET  /api/v2/telemetry/status      — current state + preview payload
    GET  /api/v2/telemetry/preview     — exact JSON we would send right now
    POST /api/v2/telemetry/enable      — turn it on (mints installation_id)
    POST /api/v2/telemetry/disable     — turn it off (wipes installation_id)
    POST /api/v2/telemetry/send-now    — fire one ping (debug/test)
    GET  /api/v2/telemetry/history     — local audit copy of past sends
"""
from __future__ import annotations
import json
from flask import Blueprint, request

bp = Blueprint("v28_telemetry", __name__)

_require_auth = lambda fn: fn
_require_role = lambda *roles: (lambda fn: fn)
_ok = None
_err = None
_deps_factory = lambda: {}
_tele = None


def init_telemetry_bp(require_auth, require_role, ok, err,
                     telemetry_module, deps_factory):
    """Wire deps. `deps_factory` is a callable that returns the live counts
    dict (oxware_version / vm_count / node_count / enabled_features)."""
    global _require_auth, _require_role, _ok, _err, _tele, _deps_factory
    _require_auth = require_auth
    _require_role = require_role
    _ok = ok
    _err = err
    _tele = telemetry_module
    _deps_factory = deps_factory or (lambda: {})
    _register_routes()


def _register_routes():
    @bp.route("/api/v2/telemetry/status", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_v2_tele_status():
        if not _tele:
            return _err("telemetry module unavailable", 503)
        return _ok(**_tele.status())

    @bp.route("/api/v2/telemetry/preview", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_v2_tele_preview():
        if not _tele:
            return _err("telemetry module unavailable", 503)
        try:
            payload = _tele.build_payload(_deps_factory() or {})
            return _ok(preview=payload)
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/telemetry/enable", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_v2_tele_enable():
        if not _tele:
            return _err("telemetry module unavailable", 503)
        d = request.get_json(silent=True) or {}
        endpoint = d.get("endpoint")
        try:
            new = _tele.enable(endpoint=endpoint)
            return _ok(**new)
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/telemetry/disable", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_v2_tele_disable():
        if not _tele:
            return _err("telemetry module unavailable", 503)
        try:
            return _ok(**_tele.disable())
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/telemetry/send-now", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_v2_tele_send():
        if not _tele:
            return _err("telemetry module unavailable", 503)
        try:
            return _ok(**_tele.send_once(_deps_factory() or {}))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/telemetry/history", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_v2_tele_history():
        try:
            from pathlib import Path
            p = Path("/var/lib/oxware/telemetry_history.jsonl")
            if not p.exists():
                return _ok(history=[])
            entries = []
            for line in p.read_text(encoding="utf-8").splitlines()[-100:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
            return _ok(history=entries, count=len(entries))
        except Exception as e:
            return _err(str(e), 400)
