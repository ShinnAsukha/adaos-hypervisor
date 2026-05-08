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
    return render_template("index.html")

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
    result = notifications.test_notification()
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

# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Kaynak bulunamadı"}), 404
    return render_template("index.html")

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Sunucu hatası"}), 500

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
