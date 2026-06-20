"""OXware v2.7.2 + v2.8 + v2.9 + v3.0 Flask Blueprint.

Wires the new feature modules to REST routes under /api/v2/ and /api/v3/.
Like bp_v270, dependencies (auth decorators, response helpers) are
injected via init_bp_v272() so this module does not import app.py.
"""
from __future__ import annotations
from flask import Blueprint, request

bp_v272 = Blueprint("v272", __name__)

_require_auth = lambda fn: fn
_require_role = lambda *roles: (lambda fn: fn)
_ok = None
_err = None


def init_bp_v272(require_auth, require_role, ok, err):
    global _require_auth, _require_role, _ok, _err
    _require_auth = require_auth
    _require_role = require_role
    _ok = ok
    _err = err
    _register_routes()


def _safe_import(name):
    try:
        mod = __import__(f"oxware.backend.{name}", fromlist=["*"])
        return mod
    except Exception:
        try:
            return __import__(name)
        except Exception:
            return None


def _register_routes():
    # ── CSI driver ───────────────────────────────────────────────────────
    csi = _safe_import("csi_driver")

    @bp_v272.route("/api/v2/csi/info", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_csi_info():
        if not csi:
            return _err("module unavailable", 503)
        return _ok(**csi.driver_info())

    @bp_v272.route("/api/v2/csi/volumes", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_csi_volumes():
        if not csi:
            return _err("module unavailable", 503)
        if request.method == "GET":
            return _ok(volumes=csi.list_volumes())
        d = request.get_json(silent=True) or {}
        r = csi.provision(d.get("pool", ""), int(d.get("size_gb", 1)),
                          d.get("k8s_namespace", "default"),
                          d.get("pvc_name", "pvc"),
                          d.get("fs_type", "ext4"))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/csi/volumes/<vol_id>", methods=["DELETE"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_csi_delete(vol_id):
        if not csi:
            return _err("module unavailable", 503)
        r = csi.delete(vol_id)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 404))

    # ── KubeVirt bridge ──────────────────────────────────────────────────
    kv = _safe_import("kubevirt_bridge")

    @bp_v272.route("/api/v2/kubevirt/clusters", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_kv_clusters():
        if not kv:
            return _err("module unavailable", 503)
        if request.method == "GET":
            safe = []
            for link in kv.list_links():
                copy = dict(link)
                copy["kubeconfig_b64"] = "***"
                safe.append(copy)
            return _ok(clusters=safe)
        d = request.get_json(silent=True) or {}
        r = kv.register_cluster(d.get("name", ""), d.get("kubeconfig_b64", ""),
                                d.get("watch_namespace", ""))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/kubevirt/clusters/<name>", methods=["DELETE"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_kv_unregister(name):
        if not kv:
            return _err("module unavailable", 503)
        r = kv.unregister(name)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 404))

    # ── GitOps ───────────────────────────────────────────────────────────
    go = _safe_import("gitops_manager")

    @bp_v272.route("/api/v2/gitops/repos", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_go_repos():
        if not go:
            return _err("module unavailable", 503)
        if request.method == "GET":
            return _ok(repos=go.list_repos())
        d = request.get_json(silent=True) or {}
        r = go.add_repo(d.get("name", ""), d.get("url", ""),
                        d.get("branch", "main"), d.get("auth_token", ""),
                        bool(d.get("auto_apply", False)),
                        int(d.get("sync_interval_sec", 300)))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/gitops/repos/<name>", methods=["DELETE"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_go_remove(name):
        if not go:
            return _err("module unavailable", 503)
        r = go.remove_repo(name)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 404))

    @bp_v272.route("/api/v2/gitops/repos/<name>/sync", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_go_sync(name):
        if not go:
            return _err("module unavailable", 503)
        r = go.sync_now(name)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 404))

    # ── Firecracker microVMs ─────────────────────────────────────────────
    fc = _safe_import("firecracker_runtime")

    @bp_v272.route("/api/v3/firecracker/vms", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_fc_vms():
        if not fc:
            return _err("module unavailable", 503)
        if request.method == "GET":
            return _ok(vms=fc.list_microvms())
        d = request.get_json(silent=True) or {}
        r = fc.launch(d.get("name", ""), d.get("kernel_path", ""),
                      d.get("rootfs_path", ""),
                      int(d.get("vcpus", 1)),
                      int(d.get("memory_mb", 128)))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v3/firecracker/vms/<vm_id>/stop", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_fc_stop(vm_id):
        if not fc:
            return _err("module unavailable", 503)
        r = fc.stop(vm_id)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 404))

    # ── OAuth2 presets ───────────────────────────────────────────────────
    op = _safe_import("oauth2_presets")

    @bp_v272.route("/api/v2/auth/oauth2/presets", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_op_presets():
        if not op:
            return _err("module unavailable", 503)
        return _ok(presets=op.list_presets())

    @bp_v272.route("/api/v2/auth/oauth2/presets/<preset_id>/render", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_op_render(preset_id):
        if not op:
            return _err("module unavailable", 503)
        d = request.get_json(silent=True) or {}
        try:
            url = op.render_discovery_url(preset_id, d.get("params", {}))
            return _ok(discovery_url=url)
        except ValueError as e:
            return _err(str(e), 400)

    # ── Audit log retention ──────────────────────────────────────────────
    ar = _safe_import("audit_retention")

    @bp_v272.route("/api/v2/audit/retention", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_ar_policy():
        if not ar:
            return _err("module unavailable", 503)
        if request.method == "GET":
            return _ok(policy=ar.get_policy())
        d = request.get_json(silent=True) or {}
        return _ok(policy=ar.set_policy(d))

    @bp_v272.route("/api/v2/audit/retention/rotate", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_ar_rotate():
        if not ar:
            return _err("module unavailable", 503)
        return _ok(**ar.run_rotation_pass())

    # ── SBOM ─────────────────────────────────────────────────────────────
    sb = _safe_import("sbom_generator")

    @bp_v272.route("/api/v2/sbom", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_sb_latest():
        if not sb:
            return _err("module unavailable", 503)
        return _ok(**sb.latest())

    @bp_v272.route("/api/v2/sbom/generate", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_sb_gen():
        if not sb:
            return _err("module unavailable", 503)
        return _ok(**sb.generate())

    # ── PWA offline ──────────────────────────────────────────────────────
    pwa = _safe_import("pwa_offline")

    @bp_v272.route("/api/v3/pwa/manifest", methods=["GET"])
    def api_pwa_manifest():
        if not pwa:
            return _err("module unavailable", 503)
        return _ok(**pwa.sw_manifest())

    @bp_v272.route("/api/v3/pwa/status", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_pwa_status():
        if not pwa:
            return _err("module unavailable", 503)
        if request.method == "GET":
            return _ok(**pwa.status())
        d = request.get_json(silent=True) or {}
        if "enabled" in d:
            return _ok(**pwa.set_enabled(bool(d["enabled"])))
        return _ok(**pwa.bump_cache_version())

    # ── SSH known-hosts ──────────────────────────────────────────────────
    kh = _safe_import("ssh_known_hosts")

    @bp_v272.route("/api/v2/security/known-hosts/pending", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_kh_pending():
        if not kh:
            return _err("module unavailable", 503)
        return _ok(pending=kh.pending_prompts())

    @bp_v272.route("/api/v2/security/known-hosts/<prompt_id>/approve",
                   methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_kh_approve(prompt_id):
        if not kh:
            return _err("module unavailable", 503)
        r = kh.approve(prompt_id)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 404))

    @bp_v272.route("/api/v2/security/known-hosts/<prompt_id>/reject",
                   methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_kh_reject(prompt_id):
        if not kh:
            return _err("module unavailable", 503)
        r = kh.reject(prompt_id)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 404))

    # ── Golden-image marketplace ─────────────────────────────────────────
    mkt = _safe_import("template_marketplace")

    @bp_v272.route("/api/v2/templates/marketplace", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_mkt_catalog():
        if not mkt:
            return _err("module unavailable", 503)
        return _ok(catalog=mkt.catalog())

    @bp_v272.route("/api/v2/templates/marketplace/status", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_mkt_status():
        if not mkt:
            return _err("module unavailable", 503)
        return _ok(**mkt.status())

    @bp_v272.route("/api/v2/templates/marketplace/<os_variant>/prefetch",
                   methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_mkt_prefetch(os_variant):
        if not mkt:
            return _err("module unavailable", 503)
        r = mkt.prefetch(os_variant)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    # ── AI chat (multi-conversation, server-light) ───────────────────────
    aic = _safe_import("ai_chat")

    @bp_v272.route("/api/v2/ai/chats", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_ai_chats():
        if not aic:
            return _err("module unavailable", 503)
        if request.method == "GET":
            return _ok(chats=aic.list_chats())
        d = request.get_json(silent=True) or {}
        return _ok(chat=aic.create_chat(d.get("title", ""),
                                        d.get("agent_id", "")))

    @bp_v272.route("/api/v2/ai/chats/<chat_id>", methods=["GET", "PUT", "DELETE"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_ai_chat(chat_id):
        if not aic:
            return _err("module unavailable", 503)
        if request.method == "GET":
            c = aic.get_chat(chat_id)
            return (_ok(chat=c) if c else _err("not found", 404))
        if request.method == "DELETE":
            r = aic.delete_chat(chat_id)
            return (_ok(**r) if r.get("ok") else _err(r.get("error"), 404))
        d = request.get_json(silent=True) or {}
        r = aic.update_chat(chat_id, d.get("title"), d.get("agent_id"))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 404))

    @bp_v272.route("/api/v2/ai/chats/<chat_id>/send", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_ai_chat_send(chat_id):
        if not aic:
            return _err("module unavailable", 503)
        d = request.get_json(silent=True) or {}
        r = aic.send_message(chat_id, d.get("text", ""),
                             d.get("images") or [], d.get("agent_id"))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    # ── Brand integrity / provenance ─────────────────────────────────────
    brand = _safe_import("brand_integrity")

    @bp_v272.route("/api/v2/brand/integrity", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_brand_integrity():
        if not brand:
            return _err("module unavailable", 503)
        return _ok(**brand.verify())
