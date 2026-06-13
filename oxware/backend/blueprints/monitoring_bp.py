"""monitoring_bp — v2 monitoring + metrics endpoints.

Mounted at /api/v2/monitoring. Trims the verbose legacy payloads down
to what the dashboard widgets actually consume, so panel rendering
doesn't spend time parsing fields it discards.

Endpoints:
    GET /api/v2/monitoring/host                      — host vitals snapshot
    GET /api/v2/monitoring/top                       — top 5 VMs by CPU/RAM
    GET /api/v2/monitoring/alerts/recent             — last 50 alerts
    GET /api/v2/monitoring/anomalies/recent          — last 50 anomalies
    GET /api/v2/monitoring/system-health             — composite health score
"""
from __future__ import annotations
import time
from flask import Blueprint

bp = Blueprint("v28_monitoring", __name__)

_require_auth = lambda fn: fn
_require_role = lambda *roles: (lambda fn: fn)
_ok = None
_err = None
_deps: dict = {}


def init_monitoring_bp(require_auth, require_role, ok, err, deps=None):
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
    @bp.route("/api/v2/monitoring/host", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_host_vitals():
        mon = _safe_get("system_monitor")
        host_fn = getattr(mon, "get_host_info", None) if mon else None
        if not callable(host_fn):
            return _err("system_monitor unavailable", 503)
        try:
            host = host_fn() or {}
            light = {
                "hostname": host.get("hostname"),
                "uptime_sec": host.get("uptime") or host.get("uptime_sec"),
                "cpu_percent": host.get("cpu_percent"),
                "memory_percent": host.get("memory_percent"),
                "load_average": host.get("load_average"),
                "kernel": host.get("kernel"),
                "ts": time.time(),
            }
            return _ok(host=light)
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/monitoring/top", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_top_vms():
        mon = _safe_get("system_monitor")
        vm_mgr = _safe_get("vm_manager")
        perf_fn = getattr(mon, "get_vm_perf", None) if mon else None
        list_fn = getattr(vm_mgr, "list_vms", None) if vm_mgr else None
        if not callable(perf_fn) or not callable(list_fn):
            return _err("monitor or vm_manager unavailable", 503)
        try:
            vms = list_fn() or []
            samples = []
            for vm in vms:
                vid = vm.get("id") or vm.get("name")
                if not vid:
                    continue
                try:
                    perf = perf_fn(vid) or {}
                except Exception:
                    perf = {}
                samples.append({
                    "vm_id": vid,
                    "name": vm.get("name"),
                    "cpu_percent": perf.get("cpu_percent", 0),
                    "memory_percent": perf.get("memory_percent", 0),
                })
            by_cpu = sorted(samples, key=lambda s: s["cpu_percent"], reverse=True)[:5]
            by_mem = sorted(samples, key=lambda s: s["memory_percent"], reverse=True)[:5]
            return _ok(top_cpu=by_cpu, top_memory=by_mem, sampled=len(samples))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/monitoring/alerts/recent", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_alerts_recent():
        ar = _safe_get("alert_rules")
        recent_fn = getattr(ar, "recent", None) if ar else None
        if not callable(recent_fn):
            return _ok(alerts=[], note="alert_rules.recent unavailable")
        try:
            alerts = recent_fn(50) or []
            return _ok(alerts=alerts, count=len(alerts))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/monitoring/anomalies/recent", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_anomalies_recent():
        ad = _safe_get("anomaly_detector")
        recent_fn = getattr(ad, "recent_anomalies", None) if ad else None
        if not callable(recent_fn):
            return _ok(anomalies=[], note="anomaly_detector.recent_anomalies unavailable")
        try:
            anomalies = recent_fn(50) or []
            return _ok(anomalies=anomalies, count=len(anomalies))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/monitoring/system-health", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_system_health():
        mon = _safe_get("system_monitor")
        host_fn = getattr(mon, "get_host_info", None) if mon else None
        score = 100
        issues = []
        try:
            host = host_fn() if callable(host_fn) else {}
            cpu = host.get("cpu_percent") or 0
            mem = host.get("memory_percent") or 0
            if cpu > 90:
                score -= 30
                issues.append({"signal": "host_cpu", "value": cpu, "weight": 30})
            elif cpu > 75:
                score -= 10
                issues.append({"signal": "host_cpu", "value": cpu, "weight": 10})
            if mem > 90:
                score -= 30
                issues.append({"signal": "host_memory", "value": mem, "weight": 30})
            elif mem > 75:
                score -= 10
                issues.append({"signal": "host_memory", "value": mem, "weight": 10})
        except Exception:
            score -= 5
            issues.append({"signal": "host_info_read_failed", "weight": 5})
        # Recent anomalies bump the issue count further.
        ad = _safe_get("anomaly_detector")
        recent_fn = getattr(ad, "recent_anomalies", None) if ad else None
        if callable(recent_fn):
            try:
                n = len(recent_fn(20) or [])
                if n > 0:
                    bumps = min(n * 4, 20)
                    score -= bumps
                    issues.append({"signal": "recent_anomalies",
                                   "value": n, "weight": bumps})
            except Exception:
                pass
        score = max(score, 0)
        verdict = ("excellent" if score >= 90
                   else "good" if score >= 75
                   else "degraded" if score >= 50
                   else "critical")
        return _ok(score=score, verdict=verdict, issues=issues, ts=time.time())
