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


def _caller_ctx() -> dict:
    """Resolve {username, role, is_primary} of the authenticated caller so the
    AI tool layer can gate sensitive tools. is_primary == main administrator
    (cred_mgr.get_username())."""
    ctx = {"username": "", "role": "", "is_primary": False}
    try:
        from flask_jwt_extended import get_jwt_identity
        ctx["username"] = (get_jwt_identity() or "")
    except Exception:
        return ctx
    cred = _safe_import("credentials") or _safe_import("cred_manager")
    primary = ""
    try:
        if cred and hasattr(cred, "get_username"):
            primary = cred.get_username() or ""
    except Exception:
        pass
    if primary and ctx["username"].lower() == primary.lower():
        ctx["is_primary"] = True
        ctx["role"] = "administrator"
        return ctx
    um = _safe_import("user_manager")
    try:
        if um and hasattr(um, "get_user_role"):
            ctx["role"] = um.get_user_role(ctx["username"]) or ""
    except Exception:
        pass
    return ctx


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
                             d.get("images") or [], d.get("agent_id"),
                             ctx=_caller_ctx())
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    # ── VM boot health-check ─────────────────────────────────────────────
    vmh = _safe_import("vm_health")

    @bp_v272.route("/api/v2/vms/<vm_id>/health", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_vm_health(vm_id):
        if not vmh:
            return _err("module unavailable", 503)
        r = vmh.check(vm_id)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 404))

    @bp_v272.route("/api/v2/vms/<vm_id>/health/policy", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_vm_health_policy(vm_id):
        if not vmh:
            return _err("module unavailable", 503)
        # policy is keyed by VM name; resolve via vm_manager
        try:
            import vm_manager as _vmm
        except Exception:
            from oxware.backend import vm_manager as _vmm  # type: ignore
        try:
            name = _vmm.get_vm(vm_id)["name"]
        except Exception as e:
            return _err(f"VM bulunamadı: {str(e)[:120]}", 404)
        if request.method == "GET":
            return _ok(policy=vmh.get_policy(name))
        d = request.get_json(silent=True) or {}
        return _ok(**vmh.set_policy(name, d.get("services"), d.get("ports")))

    # ── Per-VM disk QoS (storage I/O throttling) ─────────────────────────
    sqos = _safe_import("storage_qos")

    @bp_v272.route("/api/v2/vms/<vm_name>/disk-qos", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_disk_qos_list(vm_name):
        if not sqos:
            return _err("module unavailable", 503)
        r = sqos.list_disks(vm_name)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/vms/<vm_name>/disk-qos/<dev>",
                   methods=["GET", "PUT"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_disk_qos(vm_name, dev):
        if not sqos:
            return _err("module unavailable", 503)
        if request.method == "GET":
            r = sqos.get_qos(vm_name, dev)
        else:
            d = request.get_json(silent=True) or {}
            r = sqos.set_qos(vm_name, dev, d.get("limits") or d)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    # ── AI Ops Insights (event summary + health analysis) ────────────────
    aii = _safe_import("ai_insights")

    @bp_v272.route("/api/v2/ai/insights/events", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_ai_insight_events():
        if not aii:
            return _err("module unavailable", 503)
        d = request.get_json(silent=True) or {}
        r = aii.summarize_events(int(d.get("hours", 12)), d.get("agent_id", ""))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/ai/insights/health", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_ai_insight_health():
        if not aii:
            return _err("module unavailable", 503)
        d = request.get_json(silent=True) or {}
        r = aii.analyze_health(d.get("agent_id", ""))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    # ── Carbon / energy footprint (ESG) ──────────────────────────────────
    carbon = _safe_import("carbon_report")

    @bp_v272.route("/api/v2/sustainability/carbon", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_carbon_report():
        if not carbon:
            return _err("module unavailable", 503)
        try:
            days = int(request.args.get("days", 30))
        except ValueError:
            days = 30
        return _ok(**carbon.report(days))

    # ── Snapshot / backing-chain analysis ────────────────────────────────
    snc = _safe_import("snapshot_chain")

    @bp_v272.route("/api/v2/vms/<vm_id>/snapshot-chain", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_snapshot_chain(vm_id):
        if not snc:
            return _err("module unavailable", 503)
        r = snc.analyze(vm_id)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 404))

    # ── Vault → VM secret injection ──────────────────────────────────────
    vij = _safe_import("vault_inject")

    @bp_v272.route("/api/v2/vms/<vm_id>/vault-inject", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_vault_inject(vm_id):
        if not vij:
            return _err("module unavailable", 503)
        d = request.get_json(silent=True) or {}
        r = vij.inject_to_vm(vm_id, d.get("vault_path", ""),
                             d.get("target_file", ""),
                             d.get("format", "env"), d.get("mode", "0600"))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    # ── Federation mTLS identity ─────────────────────────────────────────
    mtls = _safe_import("mtls_identity")

    @bp_v272.route("/api/v2/federation/mtls/ca", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_mtls_ca():
        if not mtls:
            return _err("module unavailable", 503)
        if request.method == "POST":
            r = mtls.ensure_ca()
            return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))
        return _ok(fingerprint=mtls.ca_fingerprint(), nodes=mtls.list_nodes(),
                   available=mtls.available())

    @bp_v272.route("/api/v2/federation/mtls/nodes/<node>", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_mtls_issue(node):
        if not mtls:
            return _err("module unavailable", 503)
        r = mtls.issue_node_cert(node)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    # ── SDN overlay (VXLAN) ──────────────────────────────────────────────
    sdn = _safe_import("sdn_overlay")

    @bp_v272.route("/api/v2/sdn/overlays", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_sdn_overlays():
        if not sdn:
            return _err("module unavailable", 503)
        if request.method == "GET":
            return _ok(overlays=sdn.list_overlays(), available=sdn.available())
        d = request.get_json(silent=True) or {}
        r = sdn.create_overlay(d.get("name", ""), d.get("vni", 0),
                               d.get("dev", ""), int(d.get("mtu", 1450)))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/sdn/overlays/<name>", methods=["DELETE"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_sdn_delete(name):
        if not sdn:
            return _err("module unavailable", 503)
        r = sdn.delete_overlay(name)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    # ── Built-in L4 load balancer ────────────────────────────────────────
    lb = _safe_import("load_balancer")

    @bp_v272.route("/api/v2/lb/pools", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_lb_pools():
        if not lb:
            return _err("module unavailable", 503)
        if request.method == "GET":
            return _ok(pools=lb.list_pools(), available=lb.available())
        d = request.get_json(silent=True) or {}
        r = lb.upsert_pool(d.get("name", ""), d.get("port", 0),
                           d.get("backends") or [], d.get("algo", "roundrobin"))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/lb/pools/<name>", methods=["DELETE"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_lb_delete(name):
        if not lb:
            return _err("module unavailable", 503)
        return _ok(**lb.delete_pool(name))

    # ── VM boot splash (firmware branding) ───────────────────────────────
    bsplash = _safe_import("boot_splash")

    @bp_v272.route("/api/v2/boot-splash", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_boot_splash():
        if not bsplash:
            return _err("module unavailable", 503)
        if request.method == "GET":
            return _ok(**bsplash.get_config())
        d = request.get_json(silent=True) or {}
        r = bsplash.set_config(d.get("enabled"), d.get("splash_time_ms"))
        return (_ok(**r) if r.get("ok", True) else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/boot-splash/generate", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_boot_splash_gen():
        if not bsplash:
            return _err("module unavailable", 503)
        r = bsplash.ensure_image()
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/boot-splash/image", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_boot_splash_image():
        from flask import Response
        if not bsplash:
            return _err("module unavailable", 503)
        data = bsplash.image_bytes()
        if not data:
            return _err("görsel yok", 404)
        return Response(data, mimetype="image/jpeg",
                        headers={"Cache-Control": "no-store"})

    # ── OVA export ───────────────────────────────────────────────────────
    ovae = _safe_import("ova_export")

    @bp_v272.route("/api/v2/vms/<vm_id>/export-ova", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_ova_export(vm_id):
        if not ovae:
            return _err("module unavailable", 503)
        r = ovae.start_export(vm_id)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/ova-exports", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_ova_jobs():
        if not ovae:
            return _err("module unavailable", 503)
        return _ok(jobs=ovae.list_jobs(), available=ovae.available())

    # ── vApp (VM group boot orchestration) ───────────────────────────────
    vapp = _safe_import("vapp_manager")

    @bp_v272.route("/api/v2/vapps", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_vapps():
        if not vapp:
            return _err("module unavailable", 503)
        if request.method == "GET":
            return _ok(vapps=vapp.list_vapps())
        d = request.get_json(silent=True) or {}
        r = vapp.upsert_vapp(d.get("name", ""), d.get("members") or [], d.get("id"))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/vapps/<vapp_id>", methods=["DELETE"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_vapp_delete(vapp_id):
        if not vapp:
            return _err("module unavailable", 503)
        return _ok(**vapp.delete_vapp(vapp_id))

    @bp_v272.route("/api/v2/vapps/<vapp_id>/<action>", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_vapp_power(vapp_id, action):
        if not vapp:
            return _err("module unavailable", 503)
        r = vapp.power_vapp(vapp_id, action)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    # ── Scheduled reports ────────────────────────────────────────────────
    rep = _safe_import("report_scheduler")

    @bp_v272.route("/api/v2/reports/generate/<kind>", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_report_gen(kind):
        if not rep:
            return _err("module unavailable", 503)
        r = rep.generate(kind)
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/reports/send/<kind>", methods=["POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_report_send(kind):
        if not rep:
            return _err("module unavailable", 503)
        d = request.get_json(silent=True) or {}
        r = rep.send_now(kind, d.get("channel", "all"))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/reports/schedules", methods=["GET", "POST"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_report_schedules():
        if not rep:
            return _err("module unavailable", 503)
        if request.method == "GET":
            return _ok(schedules=rep.list_schedules())
        d = request.get_json(silent=True) or {}
        r = rep.add_schedule(d.get("kind", ""), int(d.get("interval_days", 7)),
                             d.get("channel", "all"))
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/reports/schedules/<sid>", methods=["DELETE"])
    @_require_auth
    @_require_role("admin", "administrator")
    def api_report_sched_del(sid):
        if not rep:
            return _err("module unavailable", 503)
        return _ok(**rep.delete_schedule(sid))

    # ── Network mode detection + VM IP audit ─────────────────────────────
    netd = _safe_import("network_detect")

    @bp_v272.route("/api/v2/network/detect", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_net_detect():
        if not netd:
            return _err("module unavailable", 503)
        r = netd.analyze_networks()
        return (_ok(**r) if r.get("ok") else _err(r.get("error"), 400))

    @bp_v272.route("/api/v2/network/ip-audit", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_net_ip_audit():
        if not netd:
            return _err("module unavailable", 503)
        r = netd.vm_ip_audit()
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
