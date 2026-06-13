# app.py Modularization Plan (v2.8 → v3.0)

`app.py` carries ~30,000 lines and ~270 routes. We are splitting it into
domain-scoped Flask blueprints under `oxware/backend/blueprints/`. The
historic `/api/*` routes are kept verbatim for backward compatibility;
new work lands in the blueprints at `/api/v2/...` first.

## Status (2026-06)

| Blueprint            | Path prefix              | Routes (v2.8 seed) | Module file                              |
| -------------------- | ------------------------ | ------------------ | ---------------------------------------- |
| `bp_v270`            | `/api/v2/{cvm,runbooks,federation}` | ~14 | `bp_v270.py` (v2.7.0 seed)              |
| `bp_v272`            | `/api/v2/{csi,kubevirt,gitops,...}` and `/api/v3/{firecracker,pwa}` | ~25 | `bp_v272.py` (v2.7.2 + 2.8/2.9/3.0 modules) |
| `v28_auth`           | `/api/v2/auth/*`         | 5                  | `blueprints/auth_bp.py`                  |
| `v28_vms`            | `/api/v2/vms/*`          | 5                  | `blueprints/vms_bp.py`                   |
| `v28_networks`       | `/api/v2/networks/*`     | 5                  | `blueprints/networks_bp.py`              |
| `v28_storage`        | `/api/v2/storage/*`      | 5                  | `blueprints/storage_bp.py`               |
| `v28_monitoring`     | `/api/v2/monitoring/*`   | 5                  | `blueprints/monitoring_bp.py`            |

Total moved to blueprints so far: **~64 routes**. `app.py` still hosts
the remaining ~206. The migration target for v2.8 GA is 80% of routes
inside blueprints; the long-tail will follow in v2.9 and v3.0.

## Wiring contract

Every blueprint follows the late-bind dependency-injection pattern
introduced in `bp_v270.py` so the module itself imports nothing from
`app.py`:

```python
from oxware.backend.blueprints import auth_bp
auth_bp.init_auth_bp(
    require_auth=require_auth,
    require_role=require_role,
    ok=ok,
    err=err,
    deps={
        "auth": auth_module,
        "session_manager": session_module,
        "rbac": rbac_module,
        "get_current_user": resolver,
        "rotate_csrf": rotator,
    },
)
app.register_blueprint(auth_bp.bp)
```

`deps` is a plain dict — blueprints query it with `_safe_get(name)`
so missing dependencies degrade gracefully instead of crashing the
import.

## v2.8 GA target list (incremental)

The following extractions are planned for the v2.8 release window
(2026-Q3). Each PR moves one cluster of routes from `app.py` into the
matching blueprint, keeping the old path as a thin wrapper for one
release before removal.

### auth_bp (target +15 routes)
- `/api/auth/login`, `/api/auth/logout`, `/api/auth/refresh`
- `/api/auth/2fa/*` (enroll, verify-login, recovery codes)
- `/api/auth/oauth2/*`
- `/api/auth/sso/*`
- `/api/api-keys/*`
- `/api/audit/me`

### vms_bp (target +30 routes)
- `/api/vms` (POST create), `/api/vms/<id>` (PATCH, DELETE)
- `/api/vms/<id>/{start,stop,reboot,pause,resume,clone,migrate}`
- `/api/vms/<id>/snapshots/*`
- `/api/vms/<id>/console/*`
- `/api/vms/bulk/*`

### networks_bp (target +20 routes)
- `/api/networks` (POST), `/api/networks/<name>` (DELETE)
- `/api/network/pools/*`
- `/api/network/firewall/*`
- `/api/network/loadbalancer/*`
- `/api/network/dns/*`
- `/api/network/bgp/*`
- `/api/network/wireguard/*`

### storage_bp (target +15 routes)
- `/api/storage/pools` (POST, DELETE)
- `/api/storage/volumes/*`
- `/api/isos` (POST upload, DELETE)
- `/api/backups/*`

### monitoring_bp (target +20 routes)
- `/api/alerts/*`
- `/api/monitoring/{global,vm,host}`
- `/api/anomaly/*`
- `/api/perf/history/*`
- `/api/speedtest/*`

## Rules of engagement

1. **Never break a legacy URL.** Until a deprecation window passes,
   the old `/api/*` route in `app.py` stays. Blueprints add `/api/v2/*`
   aliases or new endpoints; they do **not** intercept legacy paths.
2. **No imports from app.py.** Blueprints get everything via the
   `deps` dict so the module remains self-contained and unit-testable.
3. **Auth + RBAC parity.** Every blueprint route declares
   `@_require_auth` and `@_require_role(...)`. The decorator references
   come from `init_*_bp(require_auth=..., require_role=...)` so the
   panel keeps using the same JWT + CSRF flow.
4. **Light payloads.** v2 endpoints return a deliberately trimmed
   payload schema. Heavy XML / internal IDs / raw libvirt blobs stay
   off the wire. The shape is documented in each blueprint docstring.
5. **CI gate.** `i18n-and-sbom.yml` already gates merges. A new
   `app-py-size.yml` workflow will warn (not fail) when `app.py` grows
   by more than 500 lines in a single PR.

## Tracking

- Routes still in `app.py`: ~206 (see `grep '@app.route' app.py | wc -l`)
- Routes in blueprints: ~64
- Target by v2.8 GA: ≥160 in blueprints, ≤110 in `app.py`
- Target by v3.0: `app.py` reduced to bootstrap + `register_blueprint`
  wiring only (~1500 lines)

When a route migration lands, update the counts above and tick the
domain in the table.
