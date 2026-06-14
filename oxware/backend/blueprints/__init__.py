"""OXware backend blueprints package (v2.8 modularization).

The historic `app.py` ships ~270 routes in a single 30k-line file. v2.8
introduces a `blueprints/` package that hosts domain-scoped Flask
blueprints — auth, vms, networks, storage, monitoring — each exposing
new `/api/v2/{domain}/*` endpoints.

Legacy `/api/*` routes in `app.py` are kept for backward compatibility.
New work lands in blueprints; old routes will be retired in a future
release once all clients migrate.

Wiring contract (mirrors bp_v270 / bp_v272):
    from .blueprints import auth_bp, init_auth_bp
    init_auth_bp(require_auth=..., require_role=..., ok=..., err=...,
                 deps={"audit_log": audit_log, "auth": auth, ...})
    app.register_blueprint(auth_bp.bp)
"""
from . import auth_bp, vms_bp, networks_bp, storage_bp, monitoring_bp, telemetry_bp

__all__ = [
    "auth_bp",
    "vms_bp",
    "networks_bp",
    "storage_bp",
    "monitoring_bp",
    "telemetry_bp",
]
