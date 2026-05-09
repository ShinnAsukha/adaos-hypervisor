#!/usr/bin/env python3
"""
OXware Hypervisor Management API v2.0
Ubuntu/KVM tabanlı — VMware ESXi / Proxmox alternatifi
"""

import os
import sys
import ssl
import time
import json
import logging
import subprocess
import threading
from datetime import timedelta

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_socketio import SocketIO, emit
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, verify_jwt_in_request
)
from flask_cors import CORS

import config
import credentials as cred_mgr
import user_manager
import vm_manager
import network_manager
import storage_manager
import system_monitor
import ip_pool as ip_pool_mgr
import auto_provisioner
import ai_agent
import event_logger as ev
import notifications
import topology
import security
import updater

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(config.LOG_DIR, "oxware.log")),
    ],
)
log = logging.getLogger("oxware")

# ── Yeni Modül İmportları ─────────────────────────────────────────────────────
def _safe_import(name):
    try:
        import importlib
        return importlib.import_module(name)
    except Exception as e:
        log.warning("Modül yüklenemedi: %s — %s", name, e)
        return None

perf_history    = _safe_import("perf_history")
audit_log       = _safe_import("audit_log")
totp_mgr        = _safe_import("totp_manager")
api_key_mgr     = _safe_import("api_key_manager")
backup_sched    = _safe_import("backup_scheduler")
firewall_mgr    = _safe_import("firewall_manager")
wireguard_mgr   = _safe_import("wireguard_manager")
dns_mgr         = _safe_import("dns_manager")
vlan_mgr        = _safe_import("vlan_manager")
resource_quota  = _safe_import("resource_quota")
template_mgr    = _safe_import("template_manager")
smart_mon       = _safe_import("smart_monitor")
ssl_mgr         = _safe_import("ssl_manager")
nginx_mgr       = _safe_import("nginx_manager")
haproxy_mgr     = _safe_import("haproxy_manager")
webhook_mgr     = _safe_import("webhook_manager")
uptime_tracker  = _safe_import("uptime_tracker")
ldap_mgr        = _safe_import("ldap_manager")
ai_planner      = _safe_import("ai_planner")
anomaly_det     = _safe_import("anomaly_detector")
auto_scaler     = _safe_import("auto_scaler")
sdn_mgr         = _safe_import("sdn_manager")
ids_mgr         = _safe_import("ids_manager")
minio_mgr       = _safe_import("minio_manager")

# ── Flask ─────────────────────────────────────────────────────────────────────
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend", "templates")
STATIC_DIR   = os.path.join(os.path.dirname(__file__), "..", "frontend", "static")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR, static_url_path="/static")
app.config["JWT_SECRET_KEY"]           = config.SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)
app.config["JWT_TOKEN_LOCATION"]       = ["headers", "cookies"]
app.config["MAX_CONTENT_LENGTH"]       = 64 * 1024 * 1024 * 1024

CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
jwt  = JWTManager(app)
sock = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet", logger=False)

# Güvenlik katmanını kaydet
security.register_security(app)

# Başlangıçta şifre sıfırlaması uygula
cred_mgr.apply_reset_if_exists()

# AI agentları başlat
ai_agent.start_all_agents()

# ── Helpers ───────────────────────────────────────────────────────────────────
def ok(data=None, **kwargs):
    payload = kwargs if data is None else (data if isinstance(data, dict) else {"result": data})
    return jsonify({"status": "ok", **payload})

def err(msg, code=400):
    return jsonify({"status": "error", "error": str(msg)}), code

def require_auth(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except Exception:
            return err("Kimlik doğrulama gerekli", 401)
        return fn(*args, **kwargs)
    return wrapper

# ── HTML Sayfaları ────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if not cred_mgr.is_setup_done():
        return render_template("setup.html")
    resp = app.make_response(render_template("index.html"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.route("/docs")
def docs_page():
    return render_template("docs.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/setup")
def setup_page():
    return render_template("setup.html")

@app.route("/console/<vm_id>")
def console_page(vm_id):
    return render_template("console.html", vm_id=vm_id)

# ── İlk Kurulum ───────────────────────────────────────────────────────────────
@app.route("/api/setup/status")
def api_setup_status():
    return ok(done=cred_mgr.is_setup_done())

@app.route("/api/setup/init", methods=["POST"])
def api_setup_init():
    if cred_mgr.is_setup_done():
        return err("Kurulum zaten tamamlandı", 409)
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or len(password) < 8:
        return err("Kullanıcı adı ve en az 8 karakterli şifre gerekli")
    try:
        cred_mgr.first_setup(username, password)
        ev.info(f"İlk kurulum tamamlandı. Kullanıcı: {username}", category="auth")
        token = create_access_token(identity=username)
        return ok(token=token, username=username, message="Kurulum tamamlandı")
    except Exception as e:
        return err(e)

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return err("Kullanıcı adı ve şifre zorunludur")
    if not cred_mgr.verify_credentials(username, password):
        ev.warn(f"Başarısız giriş: {username} / {request.remote_addr}", category="auth")
        return err("Geçersiz kimlik bilgileri", 401)
    token = create_access_token(identity=username)
    ev.info(f"Giriş başarılı: {username}", category="auth")
    return ok(token=token, username=username)

@app.route("/api/auth/2fa/status", methods=["GET"])
@require_auth
def api_2fa_status():
    username = get_jwt_identity()
    if not totp_mgr: return ok({"enabled": False, "available": False})
    return ok(totp_mgr.get_status(username))

@app.route("/api/auth/2fa/setup", methods=["POST"])
@require_auth
def api_2fa_setup():
    username = get_jwt_identity()
    if not totp_mgr: return err("2FA modülü yüklenemedi")
    return ok(totp_mgr.setup_totp(username))

@app.route("/api/auth/2fa/enable", methods=["POST"])
@require_auth
def api_2fa_enable():
    username = get_jwt_identity()
    code = request.json.get("code", "")
    if not totp_mgr: return err("2FA modülü yüklenemedi")
    ok_ = totp_mgr.enable_totp(username, code)
    return ok({"success": ok_}) if ok_ else err("Geçersiz kod")

@app.route("/api/auth/2fa/disable", methods=["DELETE"])
@require_auth
def api_2fa_disable():
    username = get_jwt_identity()
    if not totp_mgr: return err("2FA modülü yüklenemedi")
    totp_mgr.disable_totp(username)
    return ok({"disabled": True})

@app.route("/api/auth/me")
@require_auth
def api_me():
    username = get_jwt_identity()
    info = cred_mgr.get_credential_info()
    return ok(username=username, **info)

@app.route("/api/auth/change-password", methods=["POST"])
@require_auth
def api_change_password():
    data = request.get_json() or {}
    old_pass = data.get("old_password", "")
    new_pass = data.get("new_password", "")
    if len(new_pass) < 8:
        return err("Yeni şifre en az 8 karakter olmalıdır")
    if not cred_mgr.change_password(old_pass, new_pass):
        return err("Mevcut şifre yanlış", 401)
    ev.info("Şifre değiştirildi", category="auth")
    return ok(message="Şifre değiştirildi")

# ── VM API ────────────────────────────────────────────────────────────────────
@app.route("/api/vms")
@require_auth
def api_list_vms():
    try:
        vms = vm_manager.list_vms()
        return ok(vms=vms, count=len(vms))
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>")
@require_auth
def api_get_vm(vm_id):
    try:
        return ok(vm=vm_manager.get_vm(vm_id))
    except Exception as e:
        return err(e, 404)

@app.route("/api/vms", methods=["POST"])
@require_auth
def api_create_vm():
    data = request.get_json() or {}
    try:
        name       = security.validate_vm_name(data.get("name", ""))
        memory_mb  = security.validate_memory_mb(data.get("memory_mb", 512))
        vcpus      = security.validate_vcpus(data.get("vcpus", 1))
        disk_gb    = security.validate_disk_gb(data.get("disk_gb", 10))
        network    = security.sanitize_str(data.get("network", "default"), 64)
        disk_format= data.get("disk_format", "qcow2")
        if disk_format not in ("qcow2", "raw"):
            disk_format = "qcow2"
        os_variant = security.sanitize_str(data.get("os_variant", "generic"), 64)
        boot_order = data.get("boot_order", "cdrom,hd")
        if boot_order not in ("cdrom,hd", "hd,cdrom", "hd", "cdrom"):
            boot_order = "cdrom,hd"
        iso_path   = data.get("iso_path")
        if iso_path:
            iso_path = security.validate_path_safe(
                iso_path, [config.ISO_DIR, "/var/lib/oxware/isos"]
            )
    except (ValueError, TypeError) as e:
        return err(str(e))
    try:
        result = vm_manager.create_vm(
            name=name, memory_mb=memory_mb, vcpus=vcpus, disk_gb=disk_gb,
            iso_path=iso_path, network=network, disk_format=disk_format,
            os_variant=os_variant, boot_order=boot_order,
        )
        ev.vm_event(f"VM oluşturuldu: {name}", result["id"], level="INFO")
        if webhook_mgr: webhook_mgr.trigger("vm.created", {"vm_id": result.get("id"), "vm_name": name})
        if resource_quota: resource_quota.check_quota(get_jwt_identity(), vcpus, memory_mb)
        return ok(**result), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>", methods=["DELETE"])
@require_auth
def api_delete_vm(vm_id):
    delete_disk = request.args.get("delete_disk", "true").lower() == "true"
    try:
        vm = vm_manager.get_vm(vm_id)
        result = vm_manager.delete_vm(vm_id, delete_disk=delete_disk)
        ip_pool_mgr.release_ip(vm_id)
        ev.vm_event(f"VM silindi: {vm.get('name')}", vm_id, level="WARNING")
        return ok(**result)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/start", methods=["POST"])
@require_auth
def api_start_vm(vm_id):
    try:
        r = vm_manager.start_vm(vm_id)
        ev.vm_event("VM başlatıldı", vm_id)
        if webhook_mgr: webhook_mgr.trigger("vm.started", {"vm_id": vm_id})
        if uptime_tracker: uptime_tracker.record_start(vm_id, "")
        return ok(**r)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/stop", methods=["POST"])
@require_auth
def api_stop_vm(vm_id):
    force = request.args.get("force", "false").lower() == "true"
    try:
        r = vm_manager.stop_vm(vm_id, force=force)
        ev.vm_event("VM durduruldu", vm_id, level="WARNING")
        if webhook_mgr: webhook_mgr.trigger("vm.stopped", {"vm_id": vm_id})
        if uptime_tracker: uptime_tracker.record_stop(vm_id)
        return ok(**r)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/reboot", methods=["POST"])
@require_auth
def api_reboot_vm(vm_id):
    force = request.args.get("force", "false").lower() == "true"
    try:
        return ok(**vm_manager.reboot_vm(vm_id, force=force))
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/pause", methods=["POST"])
@require_auth
def api_pause_vm(vm_id):
    try:
        return ok(**vm_manager.pause_vm(vm_id))
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/resume", methods=["POST"])
@require_auth
def api_resume_vm(vm_id):
    try:
        return ok(**vm_manager.resume_vm(vm_id))
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/stats")
@require_auth
def api_vm_stats(vm_id):
    try:
        return ok(stats=vm_manager.get_vm_stats(vm_id))
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/clone", methods=["POST"])
@require_auth
def api_clone_vm(vm_id):
    data = request.get_json() or {}
    new_name = data.get("name")
    if not new_name:
        return err("Yeni VM adı zorunludur")
    try:
        return ok(**vm_manager.clone_vm(vm_id, new_name)), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/autostart", methods=["PUT"])
@require_auth
def api_vm_autostart(vm_id):
    data = request.get_json() or {}
    return ok(**vm_manager.set_autostart(vm_id, bool(data.get("enabled", False))))

@app.route("/api/vms/<vm_id>/console")
@require_auth
def api_vm_console(vm_id):
    try:
        vm = vm_manager.get_vm(vm_id)
        host = request.host.split(":")[0]
        return ok(
            vnc_port=vm.get("vnc_port", -1),
            websocket_port=config.WS_PORT,
            host=host,
        )
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/console/start", methods=["POST"])
@require_auth
def api_start_console(vm_id):
    try:
        vm = vm_manager.get_vm(vm_id)
        vnc_port = vm.get("vnc_port", -1)
        if vnc_port < 0:
            return err("VNC portu bulunamadı")
        ws_port = config.WS_PORT
        def _start():
            subprocess.Popen(
                ["websockify", "--web", config.NOVNC_DIR, str(ws_port), f"localhost:{vnc_port}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        threading.Thread(target=_start, daemon=True).start()
        return ok(vnc_port=vnc_port, ws_port=ws_port)
    except Exception as e:
        return err(e, 500)

# ── Snapshot ──────────────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/snapshots")
@require_auth
def api_list_snapshots(vm_id):
    try:
        return ok(snapshots=vm_manager.list_snapshots(vm_id))
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/snapshots", methods=["POST"])
@require_auth
def api_take_snapshot(vm_id):
    data = request.get_json() or {}
    name = data.get("name", f"snap-{int(time.time())}")
    try:
        return ok(**vm_manager.take_snapshot(vm_id, name, data.get("description", ""))), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/snapshots/<snap_name>/revert", methods=["POST"])
@require_auth
def api_revert_snapshot(vm_id, snap_name):
    try:
        return ok(**vm_manager.revert_snapshot(vm_id, snap_name))
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/snapshots/<snap_name>", methods=["DELETE"])
@require_auth
def api_delete_snapshot(vm_id, snap_name):
    try:
        return ok(**vm_manager.delete_snapshot(vm_id, snap_name))
    except Exception as e:
        return err(e, 500)

# ── Network ───────────────────────────────────────────────────────────────────
@app.route("/api/networks")
@require_auth
def api_list_networks():
    try:
        return ok(networks=network_manager.list_networks())
    except Exception as e:
        return err(e, 500)

@app.route("/api/networks", methods=["POST"])
@require_auth
def api_create_network():
    data = request.get_json() or {}
    if "name" not in data:
        return err("name zorunludur")
    try:
        return ok(**network_manager.create_network(**data)), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/networks/<net_uuid>", methods=["DELETE"])
@require_auth
def api_delete_network(net_uuid):
    try:
        return ok(**network_manager.delete_network(net_uuid))
    except Exception as e:
        return err(e, 500)

@app.route("/api/networks/<net_uuid>/start", methods=["POST"])
@require_auth
def api_start_network(net_uuid):
    try:
        return ok(**network_manager.start_network(net_uuid))
    except Exception as e:
        return err(e, 500)

@app.route("/api/networks/<net_uuid>/stop", methods=["POST"])
@require_auth
def api_stop_network(net_uuid):
    try:
        return ok(**network_manager.stop_network(net_uuid))
    except Exception as e:
        return err(e, 500)

@app.route("/api/networks/host-interfaces")
@require_auth
def api_host_interfaces():
    return ok(interfaces=network_manager.get_host_interfaces())

# ── Storage ───────────────────────────────────────────────────────────────────
@app.route("/api/storage/pools")
@require_auth
def api_list_pools():
    try:
        return ok(pools=storage_manager.list_pools())
    except Exception as e:
        return err(e, 500)

@app.route("/api/storage/pools", methods=["POST"])
@require_auth
def api_create_pool():
    data = request.get_json() or {}
    if "name" not in data or "path" not in data:
        return err("name ve path zorunludur")
    try:
        return ok(**storage_manager.create_pool(data["name"], data["path"], data.get("type","dir"))), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/storage/pools/<pool_uuid>", methods=["DELETE"])
@require_auth
def api_delete_pool(pool_uuid):
    delete_files = request.args.get("delete_files", "false").lower() == "true"
    try:
        return ok(**storage_manager.delete_pool(pool_uuid, delete_files=delete_files))
    except Exception as e:
        return err(e, 500)

@app.route("/api/storage/pools/<pool_uuid>/volumes")
@require_auth
def api_list_volumes(pool_uuid):
    try:
        return ok(volumes=storage_manager.list_volumes(pool_uuid))
    except Exception as e:
        return err(e, 500)

@app.route("/api/storage/pools/<pool_uuid>/volumes", methods=["POST"])
@require_auth
def api_create_volume(pool_uuid):
    data = request.get_json() or {}
    if "name" not in data or "size_gb" not in data:
        return err("name ve size_gb zorunludur")
    try:
        return ok(**storage_manager.create_volume(pool_uuid, data["name"], int(data["size_gb"]), data.get("format","qcow2"))), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/storage/pools/<pool_uuid>/volumes/<vol_name>", methods=["DELETE"])
@require_auth
def api_delete_volume(pool_uuid, vol_name):
    try:
        return ok(**storage_manager.delete_volume(pool_uuid, vol_name))
    except Exception as e:
        return err(e, 500)

@app.route("/api/storage/isos")
@require_auth
def api_list_isos():
    return ok(isos=storage_manager.list_isos())

@app.route("/api/storage/isos", methods=["POST"])
@require_auth
def api_upload_iso():
    if "file" not in request.files:
        return err("Dosya gönderilmedi")
    f = request.files["file"]
    try:
        safe_name = security.validate_filename(f.filename or "")
        if not safe_name.lower().endswith(".iso"):
            return err("Sadece .iso dosyaları kabul edilir")
    except ValueError as e:
        return err(str(e))
    dest = os.path.join(config.ISO_DIR, safe_name)
    os.makedirs(config.ISO_DIR, exist_ok=True)
    f.save(dest)
    os.chmod(dest, 0o640)
    ev.info(f"ISO yüklendi: {safe_name}", category="storage")
    return ok(name=safe_name, path=dest, size=os.path.getsize(dest)), 201

@app.route("/api/storage/isos/<name>", methods=["DELETE"])
@require_auth
def api_delete_iso(name):
    try:
        return ok(**storage_manager.delete_iso(name))
    except FileNotFoundError as e:
        return err(e, 404)

@app.route("/api/storage/disks")
@require_auth
def api_disk_usage():
    return ok(disks=storage_manager.get_disk_usage())

@app.route("/api/storage/block-devices")
@require_auth
def api_block_devices():
    return ok(devices=storage_manager.get_block_devices())

# ── IP Havuzu ─────────────────────────────────────────────────────────────────
@app.route("/api/ippool")
@require_auth
def api_list_ip_pools():
    return ok(pools=ip_pool_mgr.list_pools())

@app.route("/api/ippool", methods=["POST"])
@require_auth
def api_create_ip_pool():
    data = request.get_json() or {}
    required = ["name", "network", "gateway"]
    missing = [f for f in required if f not in data]
    if missing:
        return err(f"Zorunlu alanlar eksik: {', '.join(missing)}")
    try:
        pool = ip_pool_mgr.create_pool(**data)
        ev.info(f"IP havuzu oluşturuldu: {data['name']}", category="network")
        return ok(pool=pool), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/ippool/<name>", methods=["DELETE"])
@require_auth
def api_delete_ip_pool(name):
    try:
        ip_pool_mgr.delete_pool(name)
        return ok(status="deleted")
    except Exception as e:
        return err(e, 500)

@app.route("/api/ippool/<name>/assignments")
@require_auth
def api_ip_assignments(name):
    return ok(assignments=ip_pool_mgr.list_assignments(name))

@app.route("/api/ippool/<name>/stats")
@require_auth
def api_ip_pool_stats(name):
    try:
        return ok(**ip_pool_mgr.get_pool_stats(name))
    except Exception as e:
        return err(e, 404)

@app.route("/api/ippool/allocate", methods=["POST"])
@require_auth
def api_allocate_ip():
    data = request.get_json() or {}
    required = ["pool_name", "vm_id", "vm_name"]
    missing = [f for f in required if f not in data]
    if missing:
        return err(f"Zorunlu alanlar: {', '.join(missing)}")
    try:
        info = ip_pool_mgr.allocate_ip(data["pool_name"], data["vm_id"], data["vm_name"], data.get("mac"))
        return ok(**info)
    except Exception as e:
        return err(e, 500)

@app.route("/api/ippool/release/<vm_id>", methods=["POST"])
@require_auth
def api_release_ip(vm_id):
    released = ip_pool_mgr.release_ip(vm_id)
    return ok(released=released)

# ── Otomatik Kurulum ──────────────────────────────────────────────────────────
@app.route("/api/provision", methods=["POST"])
@require_auth
def api_provision():
    data = request.get_json() or {}
    if "name" not in data:
        return err("VM adı zorunludur")
    try:
        result = auto_provisioner.provision_vm(**data)
        return ok(**result), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/provision/bulk", methods=["POST"])
@require_auth
def api_bulk_provision():
    data = request.get_json() or {}
    specs = data.get("specs", [])
    if not specs:
        return err("specs listesi zorunludur")
    results = auto_provisioner.bulk_provision(specs)
    return ok(results=results)

@app.route("/api/provision/list")
@require_auth
def api_provision_list():
    limit = int(request.args.get("limit", 50))
    return ok(provisions=auto_provisioner.list_provisions(limit=limit))

@app.route("/api/provision/<provision_id>")
@require_auth
def api_get_provision(provision_id):
    p = auto_provisioner.get_provision(provision_id)
    if not p:
        return err("Kurulum kaydı bulunamadı", 404)
    return ok(provision=p)

# ── AI Agentlar ───────────────────────────────────────────────────────────────
@app.route("/api/ai/agents")
@require_auth
def api_list_agents():
    return ok(agents=ai_agent.list_agents())

@app.route("/api/ai/agents", methods=["POST"])
@require_auth
def api_add_agent():
    data = request.get_json() or {}
    required = ["agent_id", "name", "provider", "api_key"]
    missing = [f for f in required if f not in data]
    if missing:
        return err(f"Zorunlu alanlar: {', '.join(missing)}")
    try:
        result = ai_agent.add_agent(**data)
        ev.info(f"AI Agent eklendi: {data['name']}", category="ai")
        return ok(agent=result), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/ai/agents/<agent_id>", methods=["DELETE"])
@require_auth
def api_delete_agent(agent_id):
    try:
        ai_agent.delete_agent(agent_id)
        return ok(status="deleted")
    except Exception as e:
        return err(e, 500)

@app.route("/api/ai/agents/<agent_id>", methods=["PUT"])
@require_auth
def api_update_agent(agent_id):
    data = request.get_json() or {}
    try:
        return ok(agent=ai_agent.update_agent(agent_id, data))
    except Exception as e:
        return err(e, 500)

@app.route("/api/ai/agents/<agent_id>/query", methods=["POST"])
@require_auth
def api_query_agent(agent_id):
    data = request.get_json() or {}
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return err("prompt zorunludur")
    try:
        response = ai_agent.query_agent(agent_id, prompt, data.get("system_prompt", ""))
        return ok(response=response)
    except Exception as e:
        return err(e, 500)

@app.route("/api/ai/agents/<agent_id>/query-vm", methods=["POST"])
@require_auth
def api_query_agent_vm(agent_id):
    data = request.get_json() or {}
    vm_id    = data.get("vm_id")
    question = data.get("question", "").strip()
    if not vm_id or not question:
        return err("vm_id ve question zorunludur")
    try:
        return ok(response=ai_agent.ask_agent_about_vm(agent_id, vm_id, question))
    except Exception as e:
        return err(e, 500)

@app.route("/api/ai/agents/<agent_id>/logs")
@require_auth
def api_agent_logs(agent_id):
    limit = int(request.args.get("limit", 20))
    return ok(logs=ai_agent.get_agent_logs(agent_id, limit=limit))

@app.route("/api/ai/providers")
@require_auth
def api_ai_providers():
    return ok(providers=[
        {"id": "openrouter", "name": "OpenRouter",    "url": "https://openrouter.ai",       "notes": "100+ model, tek API"},
        {"id": "anthropic",  "name": "Anthropic Claude","url": "https://anthropic.com",      "notes": "Claude Haiku/Sonnet/Opus"},
        {"id": "openai",     "name": "OpenAI",         "url": "https://openai.com",          "notes": "GPT-4o, GPT-4o-mini"},
        {"id": "ollama",     "name": "Ollama (Local)",  "url": "http://localhost:11434",      "notes": "Yerel LLM, internet gerekmez"},
        {"id": "custom",     "name": "Özel / Diğer",   "url": "",                            "notes": "OpenAI uyumlu herhangi bir API"},
    ])

# ── Bildirimler ───────────────────────────────────────────────────────────────
@app.route("/api/notifications/config")
@require_auth
def api_notif_config():
    return ok(**notifications.get_notif_config())

@app.route("/api/notifications/config", methods=["POST"])
@require_auth
def api_save_notif_config():
    data = request.get_json() or {}
    notifications.save_notif_config(**data)
    ev.info("Bildirim yapılandırması güncellendi", category="system")
    return ok(message="Kaydedildi")

@app.route("/api/notifications/test", methods=["POST"])
@require_auth
def api_test_notification():
    channel = (request.json or {}).get("channel")  # "telegram", "discord", None=hepsi
    result = notifications.test_notification(channel=channel)
    return ok(**result)

# ── Güncelleme Sistemi ────────────────────────────────────────────────────────
@app.route("/api/update/config")
@require_auth
def api_update_config_get():
    return ok(**updater.get_config())

@app.route("/api/update/config", methods=["POST"])
@require_auth
def api_update_config_save():
    data = request.get_json() or {}
    repo_url = data.get("repo_url", "").strip()
    branch   = data.get("branch", "main").strip() or "main"
    auto_check = bool(data.get("auto_check", False))
    if not repo_url:
        return err_resp("repo_url boş olamaz", 400)
    updater.save_config(repo_url, branch, auto_check)
    ev.info("Güncelleme yapılandırması kaydedildi", category="system")
    return ok(message="Kaydedildi")

@app.route("/api/update/check")
@require_auth
def api_update_check():
    result = updater.check_updates()
    return ok(**result)

@app.route("/api/update/apply", methods=["POST"])
@require_auth
def api_update_apply():
    result = updater.apply_update()
    if result.get("success"):
        ev.info(f"Güncelleme uygulandı: {result.get('old_sha')} → {result.get('new_sha')}", category="system")
    else:
        ev.error(f"Güncelleme başarısız: {result.get('error')}", category="system")
    return ok(**result)

@app.route("/api/update/history")
@require_auth
def api_update_history():
    return ok(history=updater.get_update_history())

# ── Olay Defteri ──────────────────────────────────────────────────────────────
@app.route("/api/events")
@require_auth
def api_events():
    limit    = int(request.args.get("limit", 100))
    level    = request.args.get("level")
    category = request.args.get("category")
    vm_id    = request.args.get("vm_id")
    since    = request.args.get("since")
    offset   = int(request.args.get("offset", 0))

    since_ts = float(since) if since else None
    events = ev.get_events(limit=limit, level=level, category=category,
                            vm_id=vm_id, since=since_ts, offset=offset)
    return ok(events=events, count=len(events))

@app.route("/api/events/stats")
@require_auth
def api_event_stats():
    return ok(stats=ev.get_event_stats())

# ── Sistem ────────────────────────────────────────────────────────────────────
@app.route("/api/system/info")
@require_auth
def api_system_info():
    return ok(
        host=system_monitor.get_host_info(),
        libvirt=system_monitor.get_libvirt_version(),
        oxware_version="2.0.0",
    )

@app.route("/api/system/stats")
@require_auth
def api_system_stats():
    return ok(stats=system_monitor.get_system_stats())

@app.route("/api/system/processes")
@require_auth
def api_processes():
    return ok(processes=system_monitor.get_process_list(int(request.args.get("limit", 20))))

@app.route("/api/system/vmsummary")
@require_auth
def api_vm_summary():
    return ok(**system_monitor.get_vm_summary())

# ── Kullanıcı Yönetimi ───────────────────────────────────────────────────────
@app.route("/api/users")
@require_auth
def api_list_users():
    try:
        users = user_manager.list_users()
        # Ana admin kullanıcısını da ekle
        admin_username = cred_mgr.get_username()
        admin_entry = {"username": admin_username, "role": "administrator", "created": None, "is_primary": True}
        # Çakışma yoksa ekle
        names = {u["username"] for u in users}
        if admin_username not in names:
            users.insert(0, admin_entry)
        return ok(users=users)
    except Exception as e:
        return err(e, 500)

@app.route("/api/users", methods=["POST"])
@require_auth
def api_create_user():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "viewer")
    if not username or not password:
        return err("Kullanıcı adı ve şifre zorunludur")
    try:
        result = user_manager.add_user(username, password, role)
        ev.info(f"Kullanıcı oluşturuldu: {username} ({role})", category="auth")
        return ok(user=result), 201
    except (ValueError, Exception) as e:
        return err(str(e))

@app.route("/api/users/<username>", methods=["DELETE"])
@require_auth
def api_delete_user(username):
    primary_admin = cred_mgr.get_username()
    if username == primary_admin:
        return err("Ana yönetici silinemez", 403)
    try:
        user_manager.delete_user(username)
        ev.info(f"Kullanıcı silindi: {username}", category="auth")
        return ok(status="deleted")
    except KeyError as e:
        return err(str(e), 404)
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/users/<username>/role", methods=["PUT"])
@require_auth
def api_update_user_role(username):
    data = request.get_json() or {}
    role = data.get("role", "")
    try:
        user_manager.update_user_role(username, role)
        ev.info(f"Kullanıcı rolü güncellendi: {username} → {role}", category="auth")
        return ok(status="updated")
    except (ValueError, KeyError) as e:
        return err(str(e))

# ── Shell Konsol ──────────────────────────────────────────────────────────────
@app.route("/api/system/execute", methods=["POST"])
@require_auth
def api_execute_command():
    """Tek komut çalıştır (non-interactive)."""
    data = request.get_json() or {}
    command = data.get("command", "").strip()
    if not command:
        return err("command boş olamaz")
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=30,
            env={**os.environ, "TERM": "xterm-256color"},
        )
        ev.info(f"Shell komutu: {command[:80]}", category="system")
        return ok(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return err("Komut zaman aşımına uğradı (30s)")
    except Exception as e:
        return err(str(e), 500)

# ── Topoloji ─────────────────────────────────────────────────────────────────
@app.route("/api/topology")
@require_auth
def api_topology():
    try:
        data = topology.get_topology()
        return ok(topology=data)
    except Exception as e:
        log.error("Topoloji hatası: %s", e)
        return err(e, 500)

# ── Snapshot (detaylı) ────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/snapshots")
@require_auth
def api_list_snapshots_v2(vm_id):
    try:
        vm_id = security.validate_uuid(vm_id, "vm_id")
        return ok(snapshots=vm_manager.list_snapshots(vm_id))
    except (ValueError, Exception) as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/snapshots", methods=["POST"])
@require_auth
def api_take_snapshot_v2(vm_id):
    try:
        vm_id = security.validate_uuid(vm_id, "vm_id")
    except ValueError as e:
        return err(str(e))
    data = request.get_json() or {}
    raw_name = data.get("name", f"snap-{int(time.time())}")
    try:
        snap_name = security.validate_vm_name(raw_name)
    except ValueError:
        snap_name = f"snap-{int(time.time())}"
    desc = security.sanitize_str(data.get("description", ""), 256)
    try:
        result = vm_manager.take_snapshot(vm_id, snap_name, desc)
        ev.vm_event(f"Snapshot alındı: {snap_name}", vm_id, level="INFO")
        return ok(**result), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/snapshots/<snap_name>/revert", methods=["POST"])
@require_auth
def api_revert_snapshot_v2(vm_id, snap_name):
    try:
        vm_id     = security.validate_uuid(vm_id, "vm_id")
        snap_name = security.validate_vm_name(snap_name)
    except ValueError as e:
        return err(str(e))
    try:
        result = vm_manager.revert_snapshot(vm_id, snap_name)
        ev.vm_event(f"Snapshot geri alındı: {snap_name}", vm_id, level="WARNING")
        notifications.send_alert(
            f"Snapshot geri alındı: {snap_name}",
            level="WARNING", category="vm", vm_id=vm_id,
        )
        return ok(**result)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/snapshots/<snap_name>", methods=["DELETE"])
@require_auth
def api_delete_snapshot_v2(vm_id, snap_name):
    try:
        vm_id     = security.validate_uuid(vm_id, "vm_id")
        snap_name = security.validate_vm_name(snap_name)
    except ValueError as e:
        return err(str(e))
    try:
        result = vm_manager.delete_snapshot(vm_id, snap_name)
        ev.vm_event(f"Snapshot silindi: {snap_name}", vm_id, level="INFO")
        return ok(**result)
    except Exception as e:
        return err(e, 500)

# ── WebSocket ─────────────────────────────────────────────────────────────────
@sock.on("subscribe_stats")
def on_subscribe_stats(data):
    def push():
        while True:
            try:
                stats = system_monitor.get_system_stats()
                vm_sum = system_monitor.get_vm_summary()
                emit("stats_update", {"stats": stats, "vms": vm_sum})
            except Exception:
                pass
            time.sleep(3)
    threading.Thread(target=push, daemon=True).start()

# ── PTY Shell WebSocket ────────────────────────────────────────────────────────
_shell_sessions = {}

@sock.on("shell_open")
def ws_shell_open(data=None):
    # WebSocket event'inde HTTP header yok — token data payload'dan alınır
    try:
        from flask_jwt_extended import decode_token
        token = (data or {}).get("token", "")
        if not token:
            emit("shell_output", {"data": "\r\n[Hata: token gönderilmedi]\r\n"})
            return
        decoded = decode_token(token)
        log.info("Shell açıldı: %s", decoded.get("sub", "?"))
    except Exception as e:
        log.error("Shell token hatası: %s", e)
        emit("shell_output", {"data": f"\r\n[Yetkilendirme hatası: {e}]\r\n"})
        return

    from flask_socketio import join_room
    import pty, fcntl, struct, termios
    session_id = request.sid

    try:
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(
            ["/bin/bash", "--norc", "--noprofile"],
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            close_fds=True, preexec_fn=os.setsid,
            env={**os.environ, "TERM": "xterm-256color", "PS1": r"\u@oxware:\w\$ "},
        )
        os.close(slave_fd)
        _shell_sessions[session_id] = {"proc": proc, "master_fd": master_fd}

        import eventlet
        import fcntl as _fcntl2

        # Non-blocking yaparak eventlet ile uyumlu hale getir
        fl = _fcntl2.fcntl(master_fd, _fcntl2.F_GETFL)
        _fcntl2.fcntl(master_fd, _fcntl2.F_SETFL, fl | os.O_NONBLOCK)

        def _read_loop():
            while True:
                try:
                    out = os.read(master_fd, 4096)
                    if out:
                        sock.emit("shell_output",
                                  {"data": out.decode("utf-8", errors="replace")},
                                  to=session_id, namespace="/")
                    else:
                        break
                except BlockingIOError:
                    eventlet.sleep(0.05)
                    continue
                except OSError:
                    break
                except Exception as _ex:
                    log.error("_read_loop hatası: %s", _ex)
                    break
            sock.emit("shell_output", {"data": "\r\n[Oturum kapatıldı]\r\n"},
                      to=session_id, namespace="/")

        eventlet.spawn(_read_loop)
        emit("shell_output", {"data": "\r\nOXware Host Shell — güvenli terminal\r\n"})

    except Exception as e:
        emit("shell_output", {"data": f"\r\n[Shell açılamadı: {e}]\r\n"})


@sock.on("shell_input")
def ws_shell_input(data):
    session_id = request.sid
    sess = _shell_sessions.get(session_id)
    if not sess:
        log.warning("shell_input: oturum bulunamadı %s", session_id)
        return
    try:
        inp = data.get("data", "")
        if isinstance(inp, str):
            inp = inp.encode("utf-8")
        os.write(sess["master_fd"], inp)
    except Exception as e:
        log.error("shell_input yazma hatası: %s", e)


@sock.on("shell_resize")
def ws_shell_resize(data):
    import fcntl, struct, termios
    session_id = request.sid
    sess = _shell_sessions.get(session_id)
    if sess:
        try:
            rows = int(data.get("rows", 24))
            cols = int(data.get("cols", 80))
            ws = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(sess["master_fd"], termios.TIOCSWINSZ, ws)
        except Exception:
            pass


@sock.on("disconnect")
def ws_disconnect():
    session_id = request.sid
    sess = _shell_sessions.pop(session_id, None)
    if sess:
        try:
            sess["proc"].terminate()
        except Exception:
            pass
        try:
            os.close(sess["master_fd"])
        except Exception:
            pass

# ── API Key Yönetimi ──────────────────────────────────────────────────────────
@app.route("/api/apikeys", methods=["GET"])
@require_auth
def api_list_keys():
    username = get_jwt_identity()
    if not api_key_mgr: return ok({"keys": []})
    return ok({"keys": api_key_mgr.list_keys(username)})

@app.route("/api/apikeys", methods=["POST"])
@require_auth
def api_create_key():
    username = get_jwt_identity()
    data = request.json or {}
    if not api_key_mgr: return err("API key modülü yüklenemedi")
    result = api_key_mgr.create_key(username, data.get("name","key"), data.get("permissions"), data.get("expires_days"))
    return ok(result)

@app.route("/api/apikeys/<key_id>", methods=["DELETE"])
@require_auth
def api_delete_key(key_id):
    username = get_jwt_identity()
    if not api_key_mgr: return err("API key modülü yüklenemedi")
    return ok({"deleted": api_key_mgr.delete_key(key_id)})

@app.route("/api/apikeys/<key_id>/revoke", methods=["POST"])
@require_auth
def api_revoke_key(key_id):
    username = get_jwt_identity()
    if not api_key_mgr: return err("API key modülü yüklenemedi")
    return ok({"revoked": api_key_mgr.revoke_key(key_id, username)})

# ── Audit Log ─────────────────────────────────────────────────────────────────
@app.route("/api/audit", methods=["GET"])
@require_auth
def api_audit_logs():
    if not audit_log: return ok({"logs": []})
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))
    username = request.args.get("username")
    action = request.args.get("action")
    logs = audit_log.get_logs(username=username, action=action, limit=limit, offset=offset)
    return ok({"logs": logs})

@app.route("/api/audit/stats", methods=["GET"])
@require_auth
def api_audit_stats():
    if not audit_log: return ok({})
    return ok(audit_log.get_stats())

@app.route("/api/audit/export", methods=["GET"])
@require_auth
def api_audit_export():
    if not audit_log: return err("Audit log modülü yüklenemedi")
    csv_data = audit_log.export_csv()
    from flask import Response
    return Response(csv_data, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=audit_log.csv"})

# ── Performance History ───────────────────────────────────────────────────────
@app.route("/api/metrics/system", methods=["GET"])
@require_auth
def api_metrics_system():
    if not perf_history: return ok({"data": []})
    period = request.args.get("period", "1h")
    return ok({"data": perf_history.get_system_history(period)})

@app.route("/api/metrics/vm/<vm_id>", methods=["GET"])
@require_auth
def api_metrics_vm(vm_id):
    if not perf_history: return ok({"data": []})
    period = request.args.get("period", "1h")
    return ok({"data": perf_history.get_vm_history(vm_id, period)})

# ── Backup Scheduler ──────────────────────────────────────────────────────────
@app.route("/api/backup/schedules", methods=["GET"])
@require_auth
def api_backup_list():
    if not backup_sched: return ok({"schedules": []})
    return ok({"schedules": backup_sched.list_schedules()})

@app.route("/api/backup/schedules", methods=["POST"])
@require_auth
def api_backup_create():
    if not backup_sched: return err("Backup modülü yüklenemedi")
    d = request.json or {}
    s = backup_sched.create_schedule(d["vm_id"], d.get("vm_name",""), d["cron_expr"],
                                      d.get("retention_count", 7), d.get("description",""),
                                      d.get("remote_type"), d.get("remote_config"))
    return ok({"schedule": s})

@app.route("/api/backup/schedules/<sid>", methods=["DELETE"])
@require_auth
def api_backup_delete(sid):
    if not backup_sched: return err("Backup modülü yüklenemedi")
    return ok({"deleted": backup_sched.delete_schedule(sid)})

@app.route("/api/backup/schedules/<sid>/run", methods=["POST"])
@require_auth
def api_backup_trigger(sid):
    if not backup_sched: return err("Backup modülü yüklenemedi")
    return ok(backup_sched.trigger_now(sid))

@app.route("/api/backup/history", methods=["GET"])
@require_auth
def api_backup_history():
    if not backup_sched: return ok({"history": []})
    vm_id = request.args.get("vm_id")
    return ok({"history": backup_sched.get_history(vm_id)})

# ── Firewall ──────────────────────────────────────────────────────────────────
@app.route("/api/firewall/status", methods=["GET"])
@require_auth
def api_fw_status():
    if not firewall_mgr: return ok({"available": False})
    return ok(firewall_mgr.get_status())

@app.route("/api/firewall/rules", methods=["GET"])
@require_auth
def api_fw_rules():
    if not firewall_mgr: return ok({"rules": []})
    return ok({"rules": firewall_mgr.list_rules()})

@app.route("/api/firewall/rules", methods=["POST"])
@require_auth
def api_fw_add_rule():
    if not firewall_mgr: return err("Firewall modülü yüklenemedi")
    d = request.json or {}
    return ok(firewall_mgr.add_rule(d.get("table","inet filter"), d.get("chain","input"),
              d.get("protocol"), d.get("src_ip"), d.get("dst_ip"), d.get("dst_port"),
              d.get("action","accept"), d.get("comment","")))

@app.route("/api/firewall/rules/<handle>", methods=["DELETE"])
@require_auth
def api_fw_del_rule(handle):
    if not firewall_mgr: return err("Firewall modülü yüklenemedi")
    d = request.json or {}
    return ok(firewall_mgr.delete_rule(d.get("table","inet filter"), d.get("chain","input"), handle))

@app.route("/api/firewall/save", methods=["POST"])
@require_auth
def api_fw_save():
    if not firewall_mgr: return err("Firewall modülü yüklenemedi")
    return ok(firewall_mgr.save_ruleset())

# ── WireGuard VPN ─────────────────────────────────────────────────────────────
@app.route("/api/vpn/status", methods=["GET"])
@require_auth
def api_vpn_status():
    if not wireguard_mgr: return ok({"available": False})
    return ok(wireguard_mgr.get_status())

@app.route("/api/vpn/init", methods=["POST"])
@require_auth
def api_vpn_init():
    if not wireguard_mgr: return err("WireGuard modülü yüklenemedi")
    d = request.json or {}
    return ok(wireguard_mgr.init_server(d.get("interface","wg0"), d.get("address","10.8.0.1/24"), d.get("listen_port",51820)))

@app.route("/api/vpn/peers", methods=["GET"])
@require_auth
def api_vpn_peers():
    if not wireguard_mgr: return ok({"peers": []})
    return ok({"peers": wireguard_mgr.list_peers()})

@app.route("/api/vpn/peers", methods=["POST"])
@require_auth
def api_vpn_add_peer():
    if not wireguard_mgr: return err("WireGuard modülü yüklenemedi")
    d = request.json or {}
    return ok(wireguard_mgr.add_peer(d["peer_name"], d.get("allowed_ips"), d.get("endpoint")))

@app.route("/api/vpn/peers/<peer_name>", methods=["DELETE"])
@require_auth
def api_vpn_del_peer(peer_name):
    if not wireguard_mgr: return err("WireGuard modülü yüklenemedi")
    return ok(wireguard_mgr.remove_peer(peer_name))

@app.route("/api/vpn/peers/<peer_name>/config", methods=["GET"])
@require_auth
def api_vpn_peer_config(peer_name):
    if not wireguard_mgr: return err("WireGuard modülü yüklenemedi")
    cfg = wireguard_mgr.get_peer_config(peer_name)
    from flask import Response
    return Response(cfg, mimetype="text/plain",
                    headers={"Content-Disposition": f"attachment;filename={peer_name}.conf"})

@app.route("/api/vpn/start", methods=["POST"])
@require_auth
def api_vpn_start():
    if not wireguard_mgr: return err("WireGuard modülü yüklenemedi")
    return ok(wireguard_mgr.start())

@app.route("/api/vpn/stop", methods=["POST"])
@require_auth
def api_vpn_stop():
    if not wireguard_mgr: return err("WireGuard modülü yüklenemedi")
    return ok(wireguard_mgr.stop())

# ── DNS ───────────────────────────────────────────────────────────────────────
@app.route("/api/dns/status", methods=["GET"])
@require_auth
def api_dns_status():
    if not dns_mgr: return ok({"available": False})
    return ok(dns_mgr.get_status())

@app.route("/api/dns/hosts", methods=["GET"])
@require_auth
def api_dns_hosts():
    if not dns_mgr: return ok({"hosts": []})
    return ok({"hosts": dns_mgr.list_hosts()})

@app.route("/api/dns/hosts", methods=["POST"])
@require_auth
def api_dns_add_host():
    if not dns_mgr: return err("DNS modülü yüklenemedi")
    d = request.json or {}
    return ok(dns_mgr.add_host(d["ip"], d["hostname"], d.get("comment","")))

@app.route("/api/dns/hosts/<hostname>", methods=["DELETE"])
@require_auth
def api_dns_del_host(hostname):
    if not dns_mgr: return err("DNS modülü yüklenemedi")
    return ok(dns_mgr.delete_host(hostname))

@app.route("/api/dns/leases", methods=["GET"])
@require_auth
def api_dns_leases():
    if not dns_mgr: return ok({"leases": []})
    return ok({"leases": dns_mgr.list_leases()})

@app.route("/api/dns/config", methods=["GET", "PUT"])
@require_auth
def api_dns_config():
    if not dns_mgr: return ok({})
    if request.method == "GET":
        return ok(dns_mgr.get_config())
    d = request.json or {}
    return ok(dns_mgr.update_config(**d))

# ── VLAN ──────────────────────────────────────────────────────────────────────
@app.route("/api/vlan", methods=["GET"])
@require_auth
def api_vlan_list():
    if not vlan_mgr: return ok({"vlans": []})
    return ok({"vlans": vlan_mgr.list_vlans()})

@app.route("/api/vlan", methods=["POST"])
@require_auth
def api_vlan_create():
    if not vlan_mgr: return err("VLAN modülü yüklenemedi")
    d = request.json or {}
    return ok(vlan_mgr.create_vlan(d["parent_iface"], d["vlan_id"], d["name"],
                                    d.get("ip_address"), d.get("gateway")))

@app.route("/api/vlan/<int:vlan_id>", methods=["DELETE"])
@require_auth
def api_vlan_delete(vlan_id):
    if not vlan_mgr: return err("VLAN modülü yüklenemedi")
    return ok(vlan_mgr.delete_vlan(vlan_id))

# ── Resource Quotas ───────────────────────────────────────────────────────────
@app.route("/api/quotas", methods=["GET"])
@require_auth
def api_quota_list():
    if not resource_quota: return ok({"quotas": []})
    return ok({"quotas": resource_quota.list_quotas()})

@app.route("/api/quotas/<vm_id>", methods=["GET", "PUT", "DELETE"])
@require_auth
def api_quota_vm(vm_id):
    if not resource_quota: return ok({})
    if request.method == "GET":
        return ok(resource_quota.get_quota(vm_id))
    elif request.method == "PUT":
        d = request.json or {}
        return ok(resource_quota.set_quota(vm_id, **d))
    else:
        return ok(resource_quota.delete_quota(vm_id))

@app.route("/api/quotas/global", methods=["GET", "PUT"])
@require_auth
def api_quota_global():
    if not resource_quota: return ok({})
    if request.method == "GET":
        return ok(resource_quota.get_global_quota())
    return ok(resource_quota.set_global_quota(**(request.json or {})))

# ── Templates ─────────────────────────────────────────────────────────────────
@app.route("/api/templates", methods=["GET"])
@require_auth
def api_templates_list():
    if not template_mgr: return ok({"templates": []})
    return ok({"templates": template_mgr.list_templates()})

@app.route("/api/templates", methods=["POST"])
@require_auth
def api_template_create():
    if not template_mgr: return err("Template modülü yüklenemedi")
    d = request.json or {}
    return ok(template_mgr.create_from_vm(d["vm_id"], d["name"], d.get("description",""), d.get("tags")))

@app.route("/api/templates/<tid>", methods=["GET", "DELETE"])
@require_auth
def api_template(tid):
    if not template_mgr: return ok({})
    if request.method == "DELETE":
        return ok(template_mgr.delete_template(tid))
    return ok(template_mgr.get_template(tid))

@app.route("/api/templates/<tid>/deploy", methods=["POST"])
@require_auth
def api_template_deploy(tid):
    if not template_mgr: return err("Template modülü yüklenemedi")
    d = request.json or {}
    return ok(template_mgr.deploy(tid, d["vm_name"], d.get("vcpus"), d.get("memory_mb")))

# ── SMART Disk ────────────────────────────────────────────────────────────────
@app.route("/api/smart/summary", methods=["GET"])
@require_auth
def api_smart_summary():
    if not smart_mon: return ok({"available": False})
    return ok(smart_mon.get_summary())

@app.route("/api/smart/devices", methods=["GET"])
@require_auth
def api_smart_devices():
    if not smart_mon: return ok({"devices": []})
    return ok({"devices": smart_mon.get_all_devices_health()})

@app.route("/api/smart/devices/<path:device>/data", methods=["GET"])
@require_auth
def api_smart_device(device):
    if not smart_mon: return ok({})
    return ok(smart_mon.get_smart_data("/" + device))

# ── SSL ───────────────────────────────────────────────────────────────────────
@app.route("/api/ssl/status", methods=["GET"])
@require_auth
def api_ssl_status():
    if not ssl_mgr: return ok({})
    return ok(ssl_mgr.get_status())

@app.route("/api/ssl/letsencrypt", methods=["POST"])
@require_auth
def api_ssl_letsencrypt():
    if not ssl_mgr: return err("SSL modülü yüklenemedi")
    d = request.json or {}
    return ok(ssl_mgr.request_letsencrypt(d["domain"], d["email"]))

@app.route("/api/ssl/renew", methods=["POST"])
@require_auth
def api_ssl_renew():
    if not ssl_mgr: return err("SSL modülü yüklenemedi")
    return ok(ssl_mgr.renew_cert())

@app.route("/api/ssl/upload", methods=["POST"])
@require_auth
def api_ssl_upload():
    if not ssl_mgr: return err("SSL modülü yüklenemedi")
    d = request.json or {}
    return ok(ssl_mgr.upload_custom_cert(d["cert_pem"], d["key_pem"]))

# ── Nginx Reverse Proxy ───────────────────────────────────────────────────────
@app.route("/api/nginx/status", methods=["GET"])
@require_auth
def api_nginx_status():
    if not nginx_mgr: return ok({"available": False})
    return ok(nginx_mgr.get_status())

@app.route("/api/nginx/sites", methods=["GET"])
@require_auth
def api_nginx_sites():
    if not nginx_mgr: return ok({"sites": []})
    return ok({"sites": nginx_mgr.list_sites()})

@app.route("/api/nginx/sites", methods=["POST"])
@require_auth
def api_nginx_create_site():
    if not nginx_mgr: return err("Nginx modülü yüklenemedi")
    d = request.json or {}
    return ok(nginx_mgr.create_site(d["name"], d["server_name"], d["upstream_host"],
              d["upstream_port"], d.get("ssl", False), d.get("ssl_cert"), d.get("ssl_key"),
              d.get("websocket", False)))

@app.route("/api/nginx/sites/<name>/enable", methods=["POST"])
@require_auth
def api_nginx_enable(name):
    if not nginx_mgr: return err("Nginx modülü yüklenemedi")
    return ok(nginx_mgr.enable_site(name))

@app.route("/api/nginx/sites/<name>/disable", methods=["POST"])
@require_auth
def api_nginx_disable(name):
    if not nginx_mgr: return err("Nginx modülü yüklenemedi")
    return ok(nginx_mgr.disable_site(name))

@app.route("/api/nginx/sites/<name>", methods=["DELETE"])
@require_auth
def api_nginx_delete_site(name):
    if not nginx_mgr: return err("Nginx modülü yüklenemedi")
    return ok(nginx_mgr.delete_site(name))

@app.route("/api/nginx/reload", methods=["POST"])
@require_auth
def api_nginx_reload():
    if not nginx_mgr: return err("Nginx modülü yüklenemedi")
    return ok(nginx_mgr.reload())

# ── HAProxy Load Balancer ─────────────────────────────────────────────────────
@app.route("/api/haproxy/status", methods=["GET"])
@require_auth
def api_haproxy_status():
    if not haproxy_mgr: return ok({"available": False})
    return ok(haproxy_mgr.get_status())

@app.route("/api/haproxy/stats", methods=["GET"])
@require_auth
def api_haproxy_stats():
    if not haproxy_mgr: return ok({"stats": []})
    return ok({"stats": haproxy_mgr.get_stats()})

@app.route("/api/haproxy/frontends", methods=["GET", "POST"])
@require_auth
def api_haproxy_frontends():
    if not haproxy_mgr: return ok({"frontends": []})
    if request.method == "GET":
        return ok({"frontends": haproxy_mgr.list_frontends()})
    d = request.json or {}
    return ok(haproxy_mgr.create_frontend(d["name"], d["bind_port"], d["default_backend"],
              d.get("bind_ssl", False), d.get("ssl_cert")))

@app.route("/api/haproxy/backends", methods=["GET", "POST"])
@require_auth
def api_haproxy_backends():
    if not haproxy_mgr: return ok({"backends": []})
    if request.method == "GET":
        return ok({"backends": haproxy_mgr.list_backends()})
    d = request.json or {}
    return ok(haproxy_mgr.create_backend(d["name"], d.get("algorithm","roundrobin")))

@app.route("/api/haproxy/backends/<bname>/servers", methods=["POST"])
@require_auth
def api_haproxy_add_server(bname):
    if not haproxy_mgr: return err("HAProxy modülü yüklenemedi")
    d = request.json or {}
    return ok(haproxy_mgr.add_server(bname, d["server_name"], d["host"], d["port"], d.get("weight",1)))

@app.route("/api/haproxy/backends/<bname>/servers/<sname>", methods=["DELETE"])
@require_auth
def api_haproxy_del_server(bname, sname):
    if not haproxy_mgr: return err("HAProxy modülü yüklenemedi")
    return ok(haproxy_mgr.remove_server(bname, sname))

@app.route("/api/haproxy/reload", methods=["POST"])
@require_auth
def api_haproxy_reload():
    if not haproxy_mgr: return err("HAProxy modülü yüklenemedi")
    return ok(haproxy_mgr.reload())

# ── Webhook ───────────────────────────────────────────────────────────────────
@app.route("/api/webhooks", methods=["GET"])
@require_auth
def api_webhooks_list():
    if not webhook_mgr: return ok({"webhooks": []})
    return ok({"webhooks": webhook_mgr.list_webhooks()})

@app.route("/api/webhooks", methods=["POST"])
@require_auth
def api_webhook_create():
    if not webhook_mgr: return err("Webhook modülü yüklenemedi")
    d = request.json or {}
    return ok(webhook_mgr.register(d["name"], d["url"], d.get("events",[]), d.get("secret","")))

@app.route("/api/webhooks/<wid>", methods=["PUT", "DELETE"])
@require_auth
def api_webhook(wid):
    if not webhook_mgr: return err("Webhook modülü yüklenemedi")
    if request.method == "DELETE":
        return ok(webhook_mgr.delete_webhook(wid))
    return ok(webhook_mgr.update_webhook(wid, **(request.json or {})))

@app.route("/api/webhooks/<wid>/test", methods=["POST"])
@require_auth
def api_webhook_test(wid):
    if not webhook_mgr: return err("Webhook modülü yüklenemedi")
    return ok(webhook_mgr.test_webhook(wid))

@app.route("/api/webhooks/<wid>/deliveries", methods=["GET"])
@require_auth
def api_webhook_deliveries(wid):
    if not webhook_mgr: return ok({"deliveries": []})
    return ok({"deliveries": webhook_mgr.get_deliveries(wid)})

# ── AI Planner ────────────────────────────────────────────────────────────────
@app.route("/api/ai/recommendations", methods=["GET"])
@require_auth
def api_ai_recs():
    if not ai_planner: return ok({"recommendations": []})
    return ok(ai_planner.get_recommendations())

@app.route("/api/ai/analyze", methods=["POST"])
@require_auth
def api_ai_analyze():
    if not ai_planner: return err("AI modülü yüklenemedi")
    return ok(ai_planner.analyze_resources())

@app.route("/api/ai/predict/capacity", methods=["GET"])
@require_auth
def api_ai_predict():
    if not ai_planner: return ok({})
    days = int(request.args.get("days", 30))
    return ok(ai_planner.predict_capacity(days))

@app.route("/api/ai/suggest/vm/<vm_id>", methods=["POST"])
@require_auth
def api_ai_suggest_vm(vm_id):
    if not ai_planner: return ok({})
    return ok(ai_planner.suggest_vm_sizing(vm_id))

@app.route("/api/ai/nl", methods=["POST"])
@require_auth
def api_ai_nl():
    if not ai_planner: return err("AI modülü yüklenemedi")
    username = get_jwt_identity()
    cmd = (request.json or {}).get("command", "")
    return ok(ai_planner.process_natural_language(cmd, username))

# ── Anomaly Detector ──────────────────────────────────────────────────────────
@app.route("/api/anomalies", methods=["GET"])
@require_auth
def api_anomalies():
    if not anomaly_det: return ok({"anomalies": []})
    vm_id = request.args.get("vm_id")
    limit = int(request.args.get("limit", 50))
    return ok({"anomalies": anomaly_det.get_anomalies(limit, vm_id)})

@app.route("/api/anomalies/summary", methods=["GET"])
@require_auth
def api_anomaly_summary():
    if not anomaly_det: return ok({})
    return ok(anomaly_det.get_summary())

@app.route("/api/anomalies/config", methods=["GET", "PUT"])
@require_auth
def api_anomaly_config():
    if not anomaly_det: return ok({})
    if request.method == "GET":
        return ok(anomaly_det.get_config())
    return ok(anomaly_det.update_config(**(request.json or {})))

# ── Auto Scaler ───────────────────────────────────────────────────────────────
@app.route("/api/autoscaler/policies", methods=["GET"])
@require_auth
def api_scaler_list():
    if not auto_scaler: return ok({"policies": []})
    return ok({"policies": auto_scaler.list_policies()})

@app.route("/api/autoscaler/policies", methods=["POST"])
@require_auth
def api_scaler_create():
    if not auto_scaler: return err("Auto-scaler modülü yüklenemedi")
    d = request.json or {}
    return ok(auto_scaler.create_policy(d["vm_id"], d.get("vm_name",""), **{k:v for k,v in d.items() if k not in ["vm_id","vm_name"]}))

@app.route("/api/autoscaler/policies/<pid>", methods=["PUT", "DELETE"])
@require_auth
def api_scaler_policy(pid):
    if not auto_scaler: return err("Auto-scaler modülü yüklenemedi")
    if request.method == "DELETE":
        return ok(auto_scaler.delete_policy(pid))
    return ok(auto_scaler.update_policy(pid, **(request.json or {})))

@app.route("/api/autoscaler/events", methods=["GET"])
@require_auth
def api_scaler_events():
    if not auto_scaler: return ok({"events": []})
    return ok({"events": auto_scaler.get_scaling_events(request.args.get("vm_id"))})

# ── SDN ───────────────────────────────────────────────────────────────────────
@app.route("/api/sdn/status", methods=["GET"])
@require_auth
def api_sdn_status():
    if not sdn_mgr: return ok({"available": False})
    return ok(sdn_mgr.get_status())

@app.route("/api/sdn/networks", methods=["GET", "POST"])
@require_auth
def api_sdn_networks():
    if not sdn_mgr: return ok({"networks": []})
    if request.method == "GET":
        return ok({"networks": sdn_mgr.list_sdn_networks()})
    d = request.json or {}
    return ok(sdn_mgr.create_sdn_network(d["name"], d["subnet"], d["gateway"], d.get("vlan_id")))

@app.route("/api/sdn/networks/<nid>", methods=["DELETE"])
@require_auth
def api_sdn_delete(nid):
    if not sdn_mgr: return err("SDN modülü yüklenemedi")
    return ok(sdn_mgr.delete_sdn_network(nid))

@app.route("/api/sdn/bridges", methods=["GET", "POST"])
@require_auth
def api_sdn_bridges():
    if not sdn_mgr: return ok({"bridges": []})
    if request.method == "GET":
        return ok({"bridges": sdn_mgr.list_bridges()})
    d = request.json or {}
    return ok(sdn_mgr.create_bridge(d["name"], d.get("fail_mode","standalone")))

# ── IDS/IPS ───────────────────────────────────────────────────────────────────
@app.route("/api/ids/status", methods=["GET"])
@require_auth
def api_ids_status():
    if not ids_mgr: return ok({"available": False})
    return ok(ids_mgr.get_status())

@app.route("/api/ids/alerts", methods=["GET"])
@require_auth
def api_ids_alerts():
    if not ids_mgr: return ok({"alerts": []})
    limit = int(request.args.get("limit", 100))
    hours = int(request.args.get("hours", 24))
    return ok({"alerts": ids_mgr.get_alerts(limit, since_hours=hours)})

@app.route("/api/ids/summary", methods=["GET"])
@require_auth
def api_ids_summary():
    if not ids_mgr: return ok({})
    return ok(ids_mgr.get_alert_summary())

@app.route("/api/ids/start", methods=["POST"])
@require_auth
def api_ids_start():
    if not ids_mgr: return err("IDS modülü yüklenemedi")
    return ok(ids_mgr.start())

@app.route("/api/ids/stop", methods=["POST"])
@require_auth
def api_ids_stop():
    if not ids_mgr: return err("IDS modülü yüklenemedi")
    return ok(ids_mgr.stop())

@app.route("/api/ids/rules", methods=["GET", "POST"])
@require_auth
def api_ids_rules():
    if not ids_mgr: return ok({"rules": []})
    if request.method == "GET":
        return ok({"rules": ids_mgr.list_custom_rules()})
    return ok(ids_mgr.add_custom_rule((request.json or {}).get("rule","")))

# ── MinIO / S3 ────────────────────────────────────────────────────────────────
@app.route("/api/s3/config", methods=["GET", "POST"])
@require_auth
def api_s3_config():
    if not minio_mgr: return ok({"available": False})
    if request.method == "GET":
        return ok(minio_mgr.get_config())
    d = request.json or {}
    return ok(minio_mgr.save_config(d["endpoint"], d["access_key"], d["secret_key"], d["bucket"], d.get("region","us-east-1")))

@app.route("/api/s3/test", methods=["POST"])
@require_auth
def api_s3_test():
    if not minio_mgr: return err("MinIO modülü yüklenemedi")
    return ok(minio_mgr.test_connection())

@app.route("/api/s3/objects", methods=["GET"])
@require_auth
def api_s3_objects():
    if not minio_mgr: return ok({"objects": []})
    return ok({"objects": minio_mgr.list_objects(prefix=request.args.get("prefix",""))})

@app.route("/api/s3/stats", methods=["GET"])
@require_auth
def api_s3_stats():
    if not minio_mgr: return ok({})
    return ok(minio_mgr.get_storage_stats())

# ── Uptime Tracker ────────────────────────────────────────────────────────────
@app.route("/api/uptime", methods=["GET"])
@require_auth
def api_uptime_all():
    if not uptime_tracker: return ok({"uptimes": []})
    return ok({"uptimes": uptime_tracker.get_all_uptimes()})

@app.route("/api/uptime/<vm_id>", methods=["GET"])
@require_auth
def api_uptime_vm(vm_id):
    if not uptime_tracker: return ok({})
    return ok(uptime_tracker.get_uptime(vm_id))

# ── LDAP ──────────────────────────────────────────────────────────────────────
@app.route("/api/ldap/config", methods=["GET", "POST"])
@require_auth
def api_ldap_config():
    if not ldap_mgr: return ok({"available": False, "enabled": False})
    if request.method == "GET":
        return ok(ldap_mgr.get_config())
    d = request.json or {}
    return ok(ldap_mgr.save_config(**d))

@app.route("/api/ldap/test", methods=["POST"])
@require_auth
def api_ldap_test():
    if not ldap_mgr: return err("LDAP modülü yüklenemedi")
    return ok(ldap_mgr.test_connection())

@app.route("/api/ldap/sync", methods=["POST"])
@require_auth
def api_ldap_sync():
    if not ldap_mgr: return err("LDAP modülü yüklenemedi")
    return ok(ldap_mgr.sync_users())

# ── Notifications / Alerts ────────────────────────────────────────────────────
@app.route("/api/notifications/email-config", methods=["GET", "POST"])
@require_auth
def api_email_config():
    if request.method == "GET":
        return ok(notifications.get_email_config() if hasattr(notifications, "get_email_config") else {})
    d = request.json or {}
    if hasattr(notifications, "save_email_config"):
        return ok(notifications.save_email_config(**d))
    return err("Email config fonksiyonu bulunamadı")

@app.route("/api/notifications/test-email", methods=["POST"])
@require_auth
def api_test_email():
    to = (request.json or {}).get("to","")
    if hasattr(notifications, "test_email"):
        return ok(notifications.test_email(to))
    return err("Email test fonksiyonu bulunamadı")

@app.route("/api/notifications/test-channel", methods=["POST"])
@require_auth
def api_test_notification_channel():
    channel = (request.json or {}).get("channel", "telegram")
    if hasattr(notifications, "send_alert"):
        notifications.send_alert("OXware test bildirimi", channels=[channel])
        return ok({"sent": True})
    return err("Bildirim modülü hazır değil")

# ── ISO Upload (streaming / chunked) ────────────────────────────────────────────
@app.route("/api/storage/iso/upload", methods=["POST"])
@require_auth
def upload_iso():
    """ISO dosyası yükle — progress bar için chunked upload."""
    import shutil, tempfile, re as _re

    if "file" not in request.files:
        return jsonify({"error": "Dosya bulunamadı"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Dosya adı boş"}), 400

    # Güvenlik: sadece .iso
    fname = f.filename
    if not fname.lower().endswith(".iso"):
        return jsonify({"error": "Yalnızca .iso dosyaları kabul edilir"}), 400

    # Güvenli dosya adı
    safe_name = _re.sub(r"[^a-zA-Z0-9_\-\. ]", "_", fname)
    safe_name = safe_name.replace(" ", "_")

    iso_dir = config.ISO_DIR
    os.makedirs(iso_dir, exist_ok=True)
    dest = os.path.join(iso_dir, safe_name)

    tmp_path = None
    try:
        # Temp dosyaya yaz, sonra taşı (atomik)
        with tempfile.NamedTemporaryFile(dir=iso_dir, delete=False, suffix=".tmp") as tmp:
            chunk_size = 65536  # 64KB chunks
            while True:
                chunk = f.stream.read(chunk_size)
                if not chunk:
                    break
                tmp.write(chunk)
            tmp_path = tmp.name

        shutil.move(tmp_path, dest)
        size = os.path.getsize(dest)

        log.info("ISO yüklendi: %s (%d bytes)", safe_name, size)
        if audit_log:
            audit_log.log("system", "iso_upload", fname, "success")
        else:
            log.info("Audit: iso_upload %s success", fname)

        return jsonify({
            "success": True,
            "filename": safe_name,
            "size": size,
            "path": dest,
        })
    except Exception as e:
        log.error("ISO upload hatası: %s", e)
        # Temp dosyayı temizle
        try:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass
        return jsonify({"error": str(e)}), 500


# ── Lisans ──────────────────────────────────────────────────────────────────────

def _license_mgr():
    return _safe_import("license_manager")

@app.route("/api/license/status", methods=["GET"])
@require_auth
def license_status():
    m = _license_mgr()
    if m:
        return jsonify(m.get_license_status())
    return jsonify({"active": False})

@app.route("/api/license/validate", methods=["POST"])
@require_auth
def license_validate():
    try:
        m = _license_mgr()
        if not m:
            return jsonify({"valid": False, "error": "Lisans modülü yüklenemedi"})
        code = (request.json or {}).get("code", "").strip()
        if not code:
            return jsonify({"valid": False, "error": "Kod boş"}), 400
        # Gerçek client IP'yi al (proxy arkasındaysa X-Forwarded-For)
        client_ip = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                     or request.remote_addr or "unknown")
        result = m.validate_license(code, ip=client_ip)
        try:
            username = get_jwt_identity() or "unknown"
            if audit_log:
                audit_log.log(username, "license_validate", code[:14],
                              "success" if result.get("valid") else "fail")
        except Exception:
            pass
        return jsonify(result)
    except Exception as e:
        log.error("license_validate hata: %s", e, exc_info=True)
        return jsonify({"valid": False, "error": "Doğrulama sırasında hata oluştu"})

@app.route("/api/license/activations", methods=["GET"])
@require_auth
def license_activations():
    """Tüm aktivasyon kayıtlarını listele (yönetici)."""
    try:
        m = _license_mgr()
        if not m:
            return jsonify({"activations": []})
        return jsonify({"activations": m.get_activations()})
    except Exception as e:
        log.error("license_activations hata: %s", e, exc_info=True)
        return jsonify({"activations": [], "error": str(e)})

@app.route("/api/license/deactivate", methods=["POST"])
@require_auth
def license_deactivate():
    try:
        m = _license_mgr()
        if not m:
            return jsonify({"success": False, "error": "Lisans modülü yüklenemedi"})
        result = m.deactivate_license()
        try:
            username = get_jwt_identity() or "unknown"
            if audit_log:
                audit_log.log(username, "license_deactivate", "", "success")
        except Exception:
            pass
        return jsonify(result)
    except Exception as e:
        log.error("license_deactivate hata: %s", e, exc_info=True)
        return jsonify({"success": False, "error": str(e)})


# ── Dil Tercihi ─────────────────────────────────────────────────────────────────

@app.route("/api/settings/language", methods=["GET", "POST"])
@require_auth
def language_setting():
    lang_file = "/var/lib/oxware/language.json"
    if request.method == "GET":
        try:
            if os.path.exists(lang_file):
                with open(lang_file) as f:
                    return jsonify(json.load(f))
        except Exception:
            pass
        return jsonify({"language": "en"})

    lang = (request.json or {}).get("language", "en")
    supported = ["en", "tr", "es", "de", "zh"]
    if lang not in supported:
        return jsonify({"error": "Desteklenmeyen dil"}), 400
    os.makedirs("/var/lib/oxware", exist_ok=True)
    with open(lang_file, "w") as f:
        json.dump({"language": lang}, f)
    return jsonify({"success": True, "language": lang})


# ── Background Servisleri Başlat ───────────────────────────────────────────────
def _start_background_services():
    services = [
        (perf_history,   "start_collector",         {"interval": 60}),
        (audit_log,      "init_db",                 {}),
        (backup_sched,   "start_scheduler",         {}),
        (smart_mon,      "start_monitoring",        {"interval": 3600}),
        (ssl_mgr,        "start_monitor",           {"interval": 86400}),
        (uptime_tracker, "start_tracker",           {"interval": 60}),
        (anomaly_det,    "start_detector",          {"interval": 300}),
        (auto_scaler,    "start_auto_scaler",       {"interval": 60}),
        (ai_planner,     "start_periodic_analysis", {"interval_hours": 24}),
    ]
    for mod, fn, kwargs in services:
        if mod and hasattr(mod, fn):
            try:
                getattr(mod, fn)(**kwargs)
                log.info("✓ %s.%s başlatıldı", mod.__name__, fn)
            except Exception as e:
                log.warning("✗ %s.%s başlatılamadı: %s", mod.__name__, fn, e)

_start_background_services()

# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Kaynak bulunamadı"}), 404
    return render_template("index.html")

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Sunucu hatası"}), 500

# ── Live Migration ────────────────────────────────────────────────────────────
@app.route("/api/vms/migrate", methods=["POST"])
@require_auth
def api_vm_migrate():
    data = request.get_json() or {}
    vm_id = data.get("vm_id", "")
    target = data.get("target_host", "")
    protocol = data.get("protocol", "qemu+ssh")
    if not vm_id or not target:
        return err("vm_id ve target_host zorunludur")
    try:
        import subprocess
        uri = f"{protocol}://{target}/system"
        cmd = ["virsh", "-c", uri, "migrate", "--live", "--persistent", vm_id,
               f"qemu+ssh://{target}/system"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return err(result.stderr or "Geçiş başarısız", 500)
        ev.info(f"Canlı geçiş: {vm_id} → {target}", category="vm")
        return ok(status="ok", message=f"{vm_id} → {target} geçişi başlatıldı")
    except subprocess.TimeoutExpired:
        return err("Geçiş zaman aşımına uğradı (120s)", 504)
    except Exception as e:
        return err(e, 500)

# ── Backup Schedule ───────────────────────────────────────────────────────────
BACKUP_SCHEDULE_FILE = os.path.join(config.DATA_DIR if hasattr(config,'DATA_DIR') else '/var/lib/oxware', 'backup_schedule.json')

@app.route("/api/backup/schedule", methods=["GET"])
@require_auth
def api_backup_schedule_get():
    try:
        if os.path.exists(BACKUP_SCHEDULE_FILE):
            with open(BACKUP_SCHEDULE_FILE) as f:
                return ok(schedule=json.load(f))
        return ok(schedule=[])
    except Exception as e:
        return err(e, 500)

@app.route("/api/backup/schedule", methods=["POST"])
@require_auth
def api_backup_schedule_set():
    data = request.get_json() or {}
    try:
        schedules = []
        if os.path.exists(BACKUP_SCHEDULE_FILE):
            with open(BACKUP_SCHEDULE_FILE) as f:
                schedules = json.load(f)
        # Add or update
        vm_id = data.get("vm_id", "all")
        schedules = [s for s in schedules if s.get("vm_id") != vm_id]
        schedules.append(data)
        os.makedirs(os.path.dirname(BACKUP_SCHEDULE_FILE), exist_ok=True)
        with open(BACKUP_SCHEDULE_FILE, 'w') as f:
            json.dump(schedules, f, indent=2)
        ev.info(f"Yedekleme planı güncellendi: {vm_id}", category="backup")
        return ok(status="ok")
    except Exception as e:
        return err(e, 500)

# ── HA Status ─────────────────────────────────────────────────────────────────
@app.route("/api/ha/status", methods=["GET"])
@require_auth
def api_ha_status():
    """Basit HA durumu — libvirt multi-host veya tek node kontrolü."""
    try:
        import subprocess
        # Check if there are any remote libvirt connections configured
        nodes = []
        # Try to get local node info
        hostname_r = subprocess.run(['hostname', '-s'], capture_output=True, text=True)
        local_ip_r = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        local_name = hostname_r.stdout.strip() or 'local'
        local_ip = local_ip_r.stdout.strip().split()[0] if local_ip_r.stdout.strip() else '127.0.0.1'
        nodes.append({"name": local_name, "ip": local_ip, "role": "primary", "online": True})
        # Check for HA config file
        ha_cfg = '/etc/oxware/ha_nodes.json'
        if os.path.exists(ha_cfg):
            with open(ha_cfg) as f:
                extra_nodes = json.load(f)
            for n in extra_nodes:
                # Ping check
                ping = subprocess.run(['ping', '-c', '1', '-W', '2', n.get('ip','')],
                                      capture_output=True, timeout=5)
                n['online'] = ping.returncode == 0
                nodes.append(n)
        return ok(nodes=nodes, ha_enabled=len(nodes) > 1)
    except Exception as e:
        return ok(nodes=[], ha_enabled=False, error=str(e))

# ── VM Clone ──────────────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/clone", methods=["POST"])
@require_auth
def api_vm_clone(vm_id):
    data = request.get_json() or {}
    new_name = data.get("name", "")
    if not new_name:
        return err("name zorunludur")
    try:
        import subprocess
        result = subprocess.run(
            ["virt-clone", "--original", vm_id, "--name", new_name, "--auto-clone"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            return err(result.stderr or "Klonlama başarısız", 500)
        ev.info(f"VM klonlandı: {vm_id} → {new_name}", category="vm")
        return ok(status="ok", name=new_name)
    except subprocess.TimeoutExpired:
        return err("Klonlama zaman aşımına uğradı", 504)
    except Exception as e:
        return err(e, 500)

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("OXware Hypervisor v2.0 başlatılıyor")
    log.info("Dinleniyor: %s:%s (SSL: %s)", config.HOST, config.PORT, config.SSL_ENABLED)

    use_ssl = (
        config.SSL_ENABLED
        and os.path.exists(config.SSL_CERT)
        and os.path.exists(config.SSL_KEY)
    )

    if use_ssl:
        log.info("SSL aktif: %s / %s", config.SSL_CERT, config.SSL_KEY)
        sock.run(
            app,
            host=config.HOST,
            port=config.PORT,
            debug=False,
            use_reloader=False,
            certfile=config.SSL_CERT,
            keyfile=config.SSL_KEY,
        )
    else:
        log.warning("SSL devre dışı — HTTP olarak başlatılıyor")
        sock.run(app, host=config.HOST, port=config.PORT, debug=False, use_reloader=False)
