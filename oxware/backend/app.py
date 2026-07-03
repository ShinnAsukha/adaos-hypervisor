#!/usr/bin/env python3
# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). This copyright notice and the
# LICENSE text must be retained in copies and forks per the MIT terms.
"""
OXware Hypervisor Management API v2.7.0
Ubuntu/KVM tabanlı — VMware ESXi / Proxmox alternatifi
"""

import os
import sys
import ssl
import time
import json
import hmac
import logging
import mimetypes
import subprocess
import threading
import ipaddress
from datetime import timedelta
from html import escape as html_escape

# Ensure .js files are served with correct MIME type even on minimal systems
# (without this, X-Content-Type-Options: nosniff causes browsers to reject
# ES module dynamic imports when the system mime.types file is missing/incomplete)
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("application/javascript", ".mjs")
mimetypes.add_type("text/css",               ".css")
mimetypes.add_type("image/svg+xml",          ".svg")
mimetypes.add_type("application/wasm",       ".wasm")

sys.path.insert(0, os.path.dirname(__file__))

# ── Dark Site + Egress guard — HER ŞEYDEN önce (offline + dışa-çıkış kilidi) ───
# Dark Site açıksa egress'i enforce'a zorlar; bu yüzden egress_guard'tan ÖNCE
# uygulanır. Guard, eventlet/flask import edilmeden önce socket'i sarmalamalı ki
# eventlet yeşil socket'leri de korumalı primitifler üzerine binsin.
import dark_site
dark_site.apply()
import egress_guard
egress_guard.install()

from flask import Flask, request, jsonify, send_from_directory, render_template, make_response, send_file
from flask_socketio import SocketIO, emit
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, verify_jwt_in_request,
    set_access_cookies, unset_jwt_cookies,
)
from flask_cors import CORS

import config
import credentials as cred_mgr
import user_manager
import vm_manager

# ── Rolling perf-sample cache (avoids 600 ms blocking sleep in /perf endpoint) ─
_perf_cache: dict = {}           # vm_id → {"ts": float, "stats": dict}
_perf_cache_lock = threading.Lock()
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
    level=getattr(logging, (config.LOG_LEVEL or "INFO"), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(config.LOG_DIR, "oxware.log")),
    ],
)
log = logging.getLogger("oxware")


def _bg_notify(message: str, level: str = "DEBUG", category: str = "vm",
               vm_id: str = None, details: dict = None):
    """Arka planda bildirim gönder — response'u bloklamaz."""
    def _send():
        try:
            notifications.send_alert(
                message=message, level=level, category=category,
                vm_id=vm_id, details=details or {}
            )
        except Exception as _ne:
            log.debug("Bildirim gönderilemedi: %s", _ne)
    threading.Thread(target=_send, daemon=True, name="notif-bg").start()


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
bgp_mgr         = _safe_import("bgp_manager")
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
auto_snap       = _safe_import("auto_snapshot")
sec_hard        = _safe_import("security_hardening")
vm_sched        = _safe_import("vm_scheduler")
sess_mgr        = _safe_import("session_manager")
hook_mgr        = _safe_import("hook_manager")
pool_mgr        = _safe_import("resource_pool_manager")
hotplug_mgr     = _safe_import("hotplug_manager")
stor_mig        = _safe_import("storage_migration")
net_qos         = _safe_import("network_qos")
ssh_watchdog    = _safe_import("ssh_watchdog")

# ── v2.5.3 Enterprise modules ────────────────────────────────────────────────
vnc_thumb       = _safe_import("vnc_thumbnail")
snapshot_clean  = _safe_import("snapshot_cleanup")
affinity_mgr    = _safe_import("affinity_manager")
backup_enc      = _safe_import("backup_encryption")
linked_clone    = _safe_import("linked_clone")
siem_exp        = _safe_import("siem_exporter")
session_rec     = _safe_import("session_recorder")
maint_mode      = _safe_import("maintenance_mode")
evc_mgr         = _safe_import("evc_manager")
nioc_mgr        = _safe_import("nioc_manager")
predictive_fail = _safe_import("predictive_failure")
right_sizing    = _safe_import("right_sizing")
alert_corr      = _safe_import("alert_correlation")
site_recovery   = _safe_import("site_recovery")
drs_mgr         = _safe_import("drs_manager")
lifecycle_mgr   = _safe_import("lifecycle_manager")
compute_tune    = _safe_import("compute_tuning")
storage_adv     = _safe_import("storage_advanced")
network_adv     = _safe_import("network_advanced")
automation_eng  = _safe_import("automation_engine")
# ── v2.8.2 Kernel-level pack ───────────────────────────────────────────────────
io_perf         = _safe_import("io_perf_manager")
ebpf_obs        = _safe_import("ebpf_observability")
kernel_ops      = _safe_import("kernel_ops")
kernel_mods     = _safe_import("kernel_modules")

# ── v2.5.4 Enterprise modules ────────────────────────────────────────────────
secboot_mgr     = _safe_import("secureboot_manager")
vault_int_mgr   = _safe_import("vault_integration")
audit_chain_mgr = _safe_import("audit_chain")
hugepages_mgr   = _safe_import("hugepages_manager")
sriov_mgr       = _safe_import("sriov_manager")
vgpu_mgr        = _safe_import("vgpu_manager")
gpu_pt          = _safe_import("gpu_passthrough")
cdp_mgr         = _safe_import("cdp_manager")
boot_order_mgr  = _safe_import("boot_order_manager")
geo_dns_mgr     = _safe_import("geo_dns_manager")
# vtpm_manager is also re-imported below for legacy endpoints

# ── v2.5.5 Security & Compliance modules ─────────────────────────────────────
confidential_vm  = _safe_import("confidential_vm")
disk_encryption  = _safe_import("disk_encryption")
compliance_scan  = _safe_import("compliance_scanner")
dlp_engine       = _safe_import("dlp_engine")
forensics        = _safe_import("forensics_engine")
mfa_policy       = _safe_import("mfa_enforcement")
sso_manager      = _safe_import("sso_manager")

# ── v2.5.6 Multi-tenancy modules ─────────────────────────────────────────────
tenant_mgr       = _safe_import("tenant_manager")
self_service     = _safe_import("self_service_portal")
chargeback       = _safe_import("chargeback_engine")
svc_catalog      = _safe_import("service_catalog")
tenant_rl        = _safe_import("tenant_rate_limit")

# ── v2.5.7 Backup Advanced modules ───────────────────────────────────────────
app_consistent   = _safe_import("app_consistent_snapshot")
backup_321       = _safe_import("backup_321")
backup_verify    = _safe_import("backup_verify")
cross_replication = _safe_import("cross_replication")

# ── v2.5.8 Observability modules ─────────────────────────────────────────────
otel_tracing     = _safe_import("otel_tracing")
grafana_embed    = _safe_import("grafana_embed")
topology_viz     = _safe_import("topology_viz")
ml_forecaster    = _safe_import("ml_forecaster")
drift_capacity   = _safe_import("drift_capacity")

# ── v2.5.9 Network Advanced 2 modules ────────────────────────────────────────
microseg         = _safe_import("microsegmentation")
bfd_mgr          = _safe_import("bfd_manager")
service_chain    = _safe_import("service_chain")
service_mesh     = _safe_import("service_mesh")

# ── v2.5.10 Cloud/K8s modules ────────────────────────────────────────────────
pulumi_provider  = _safe_import("pulumi_provider")
k8s_csi          = _safe_import("k8s_csi")
k8s_operator     = _safe_import("k8s_operator")
kubevirt_int     = _safe_import("kubevirt_integration")
gitops_sync      = _safe_import("gitops_sync")

# ── v2.5.11 Modern Workloads modules ─────────────────────────────────────────
firecracker_mgr  = _safe_import("firecracker_mgr")
kata_runtime     = _safe_import("kata_runtime")
wasm_runtime     = _safe_import("wasm_runtime")
edge_mode        = _safe_import("edge_mode")

# ── v2.7.0 IaC + Clients modules ────────────────────────────────────────────
workflow_engine  = _safe_import("workflow_engine")
opa_policy       = _safe_import("opa_policy")
cloudevents_mod  = _safe_import("cloudevents")
electron_client  = _safe_import("electron_client")
cloud_export     = _safe_import("cloud_export")

# ── v2.7.0 modules ───────────────────────────────────────────────────────────
fault_tolerance_mgr  = _safe_import("fault_tolerance")
storage_drs_mgr      = _safe_import("storage_drs")
console_recorder_mgr = _safe_import("console_recorder")
recovery_codes_mgr   = _safe_import("recovery_codes")
plugin_sdk_mgr       = _safe_import("plugin_sdk")
vm_hot_extend_mgr    = _safe_import("vm_hot_extend")
bulk_vm_ops_mgr      = _safe_import("bulk_vm_ops")
net_mode_mgr         = _safe_import("network_mode_manager")
green_mode_mgr       = _safe_import("green_mode")

# ── v2.7.0 modules ───────────────────────────────────────────────────────────
multi_region_mgr     = _safe_import("multi_region")
marketplace_mgr      = _safe_import("app_marketplace")
cloud_burst_mgr      = _safe_import("cloud_burst")
bare_metal_mgr       = _safe_import("bare_metal")
oauth2_sso_mgr       = _safe_import("oauth2_sso")

# ── v2.7.0 modules ───────────────────────────────────────────────────────────
runbook_exec     = _safe_import("runbook_executor")
federation_mgr   = _safe_import("cluster_federation")
bp_v270_mod      = _safe_import("bp_v270")  # v2.7 blueprint (modularization start)
bp_v272_mod      = _safe_import("bp_v272")  # v2.7.2 + v2.8 + v2.9 + v3.0 blueprint

# Central feature registry
feature_reg      = _safe_import("feature_registry")

# ── Flask ─────────────────────────────────────────────────────────────────────
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend", "templates")
STATIC_DIR   = os.path.join(os.path.dirname(__file__), "..", "frontend", "static")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR, static_url_path="/static")
app.config["JWT_SECRET_KEY"]           = config.SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)   # OXW-SEC-002: 12h → 1h (shorter blast radius)
app.config["JWT_TOKEN_LOCATION"]       = ["headers", "cookies"]
app.config["MAX_CONTENT_LENGTH"]       = 64 * 1024 * 1024 * 1024
# CVE-2023-25577 / Werkzeug multipart resource exhaustion mitigation
app.config["MAX_FORM_MEMORY_SIZE"]     = 16 * 1024 * 1024   # 16 MB form fields max
app.config["MAX_FORM_PARTS"]           = 256                 # max multipart parts
# Security: restrict JWT to HS256 only — blocks alg:none / RSA confusion attacks.
# Allowlist'in tek kanonik kaynağı auth.JWT_ALGORITHMS (drift'i önler).
try:
    import auth as _auth_mod
    _JWT_ALGS = list(_auth_mod.JWT_ALGORITHMS)
except Exception:
    _JWT_ALGS = ["HS256"]
app.config["JWT_ALGORITHM"]            = _JWT_ALGS[0]
app.config["JWT_DECODE_ALGORITHMS"]    = _JWT_ALGS
# OXW-2026-001 fix: JWT cookie security attributes (SameSite=Strict blocks CSRF)
app.config["JWT_COOKIE_SECURE"]        = True
app.config["JWT_COOKIE_SAMESITE"]      = "Strict"
app.config["JWT_COOKIE_CSRF_PROTECT"]  = True
# SEC-014 — HttpOnly cookie session: cookie names + double-submit CSRF cookie.
# Access cookie is HttpOnly (JS cannot read it). CSRF cookie is readable so the
# frontend can echo it into X-CSRF-TOKEN. flask-jwt-extended verifies both.
app.config["JWT_ACCESS_COOKIE_NAME"]      = "oxware_access"
app.config["JWT_ACCESS_CSRF_COOKIE_NAME"] = "oxware_csrf"
app.config["JWT_ACCESS_CSRF_HEADER_NAME"] = "X-CSRF-TOKEN"
app.config["JWT_ACCESS_COOKIE_PATH"]      = "/"
app.config["JWT_CSRF_IN_COOKIES"]         = True
app.config["JWT_COOKIE_DOMAIN"]           = None  # default = request host

# OXW-2026-002 fix: CORS origins operatör config'inden gelir, wildcard yok
# /etc/oxware/oxware.conf → [server] → cors_origins = https://panel.example.com
if config.CORS_ORIGINS:
    CORS(app, resources={r"/api/*": {"origins": config.CORS_ORIGINS}}, supports_credentials=True)
# else: CORS yok — frontend same-origin'den serve edilir
jwt     = JWTManager(app)
# OXW-2026-002 fix: SocketIO CORS da config'den gelsin
_sock_origins = config.CORS_ORIGINS if config.CORS_ORIGINS else []
# Test/CI'da eventlet kurulu olmayabilir; async_mode="eventlet" import'u
# "Invalid async_mode specified" ile patlatır. OXWARE_DISABLE_SOCKETIO=1 ise
# threading moduna düş (gerçek WS proxy çalışmaz ama import temiz olur).
_sock_async = "threading" if os.environ.get("OXWARE_DISABLE_SOCKETIO") == "1" else "eventlet"
sock    = SocketIO(app, cors_allowed_origins=_sock_origins, async_mode=_sock_async, logger=False)

# ── VNC WebSocket proxy — manual RFC 6455 + eventlet trampoline ───────────────
# @_evws.WebSocketWSGI fails in eventlet 0.35.x (returns 400, handler not called).
# Manual handshake: write 101 directly to raw socket, then trampoline for reads.
import socket as _raw_sk, struct as _struct, hashlib as _hashlib, base64 as _b64
import time as _time_mod
from urllib.parse import unquote as _unquote
import eventlet as _ev_vnc
import eventlet.green.select as _egreen_select   # cooperative select — hub yields properly
import eventlet.green.socket as _egreen_socket   # cooperative socket — tcp.recv() yields hub, not OS-blocks

def _ws_build_frame(data: bytes) -> bytes:
    """RFC 6455 binary frame (opcode 0x82, server→client, unmasked)."""
    n = len(data)
    if n < 126:
        hdr = bytes([0x82, n])
    elif n < 65536:
        hdr = bytes([0x82, 126]) + _struct.pack(">H", n)
    else:
        hdr = bytes([0x82, 127]) + _struct.pack(">Q", n)
    return hdr + data

_WS_RECV_TIMEOUT = 120  # seconds total wait for a complete read

def _ws_recvall(sock, n):
    """Recv exactly n bytes from the browser SSL/GreenSSLSocket.

    GreenSSLSocket problem: OpenSSL decrypts a TLS record into its internal
    buffer.  The underlying fd is then NOT readable (TCP buffer empty), so
    trampoline(fd, read=True) blocks forever even though recv() would succeed
    immediately.  Fix: check ssl.pending() first (already-decoded bytes in SSL
    buffer); only call select() if the buffer is empty.  select() is
    eventlet-patched so it yields cooperatively to the hub.
    """
    buf      = b""
    deadline = _time_mod.time() + _WS_RECV_TIMEOUT
    fd       = None
    try:
        fd = sock.fileno()
    except Exception:
        pass

    while len(buf) < n:
        remaining = deadline - _time_mod.time()
        if remaining <= 0:
            log.warning("VNC WS: recv TIMEOUT %ds (need=%d have=%d sock=%s)",
                        _WS_RECV_TIMEOUT, n, len(buf), type(sock).__name__)
            return None

        # ── Step 1: check SSL-layer buffer ────────────────────────────────
        pending = 0
        try:
            pending = sock.pending()
        except Exception:
            pass

        # ── Step 2: if no buffered SSL data, wait for the fd via select ───
        if pending == 0 and fd is not None:
            try:
                # _egreen_select = eventlet.green.select → cooperative, yields to hub
                # (plain select.select would block the OS thread and starve other greenlets)
                r, _, _ = _egreen_select.select([fd], [], [], min(remaining, 5.0))
                if not r:
                    # select timed out in 5-s slice; loop and recheck deadline
                    continue
            except Exception as _se:
                log.warning("VNC WS: select error (need=%d have=%d): %s", n, len(buf), _se)
                return None

        # ── Step 3: recv — SSL buffer has data OR fd is readable ──────────
        try:
            chunk = sock.recv(n - len(buf))
        except Exception as _e:
            log.warning("VNC WS: recv exception (need=%d have=%d): %s (%s)",
                        n, len(buf), _e, type(_e).__name__)
            return None

        if not chunk:
            log.warning("VNC WS: recv EOF (got %d of %d bytes)", len(buf), n)
            return None
        log.debug("VNC WS: recvall got %d bytes (total %d/%d)",
                  len(chunk), len(buf) + len(chunk), n)
        buf += chunk
    return buf

def _ws_recv_frame(sock):
    """Read one RFC 6455 frame. Returns (opcode, payload) or (None, None)."""
    hdr = _ws_recvall(sock, 2)
    if not hdr:
        return None, None
    opcode = hdr[0] & 0x0F
    masked = bool(hdr[1] & 0x80)
    length = hdr[1] & 0x7F
    if length == 126:
        b = _ws_recvall(sock, 2)
        if not b: return None, None
        length = _struct.unpack(">H", b)[0]
    elif length == 127:
        b = _ws_recvall(sock, 8)
        if not b: return None, None
        length = _struct.unpack(">Q", b)[0]
    # OXW-2026-016 fix: 16 MiB çerçeve sınırı — bellek bombası DoS önleme
    _WS_MAX_FRAME = 16 * 1024 * 1024
    if length > _WS_MAX_FRAME:
        log.warning("VNC WS: çerçeve çok büyük (%d > %d) — bağlantı kapatılıyor", length, _WS_MAX_FRAME)
        return None, None
    mask_key = _ws_recvall(sock, 4) if masked else b""
    if mask_key is None: return None, None
    payload  = _ws_recvall(sock, length) if length else b""
    if payload is None: return None, None
    if masked:
        payload = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))
    return opcode, payload

_socketio_wsgi = app.wsgi_app

def _vnc_ws_middleware(environ, start_response):
    path = environ.get("PATH_INFO", "")
    if not path.startswith("/ws/vnc/"):
        return _socketio_wsgi(environ, start_response)

    qs    = environ.get("QUERY_STRING", "")
    parts = path.strip("/").split("/")           # ['ws','vnc','<vm_id>']
    vm_id = parts[2] if len(parts) > 2 else ""
    ws_key = environ.get("HTTP_SEC_WEBSOCKET_KEY", "")
    log.info("VNC WS: request vm=%s upgrade=%s key=%s proto=%r",
             vm_id, environ.get("HTTP_UPGRADE", "NONE"), ws_key[:8] or "MISSING",
             environ.get("HTTP_SEC_WEBSOCKET_PROTOCOL", ""))

    token     = ""
    vnc_token = ""
    for p in qs.split("&"):
        if p.startswith("token="):
            token = _unquote(p[6:])
        elif p.startswith("vnc_token="):
            vnc_token = _unquote(p[10:])

    # OXW-2026-008 fix: one-time token path (preferred) → falls back to JWT for compatibility
    _vnc_caller = ""
    _vnc_role   = "viewer"

    if vnc_token:
        # One-time token — atomik tüket
        with _vnc_token_lock:
            _ott = _vnc_one_time_tokens.get(vnc_token)
            if _ott and not _ott.get("used") and _time_mod.time() < _ott.get("expires", 0):
                if _ott["vm_id"] == vm_id:
                    _ott["used"] = True
                    _vnc_caller  = _ott["username"]
                    _vnc_role    = _ott["role"]
                else:
                    log.warning("VNC WS: vnc_token vm mismatch req=%s tok=%s", vm_id, _ott["vm_id"])
            else:
                log.warning("VNC WS: geçersiz/süresi dolmuş vnc_token vm=%s", vm_id)
        if not _vnc_caller:
            start_response("401 Unauthorized", [("Content-Type", "text/plain")])
            return [b"VNC token invalid or expired"]
    elif token:
        # Legacy JWT path — geriye uyumluluk (yeni istemciler vnc_token kullanmalı)
        try:
            with app.app_context():
                from flask_jwt_extended import decode_token
                _decoded = decode_token(token)
                _vnc_caller = _decoded.get("sub", "")
        except Exception as _e:
            log.warning("VNC WS: auth failed vm=%s: %s", vm_id, _e)
            start_response("401 Unauthorized", [("Content-Type", "text/plain")])
            return [b"Unauthorized"]
        try:
            with app.app_context():
                _prim = cred_mgr.get_username() if hasattr(cred_mgr, "get_username") else ""
                if _vnc_caller == _prim:
                    _vnc_role = "admin"
                elif hasattr(cred_mgr, "get_role"):
                    _vnc_role = cred_mgr.get_role(_vnc_caller) or "viewer"
                else:
                    _vnc_role = user_manager.get_user_role(_vnc_caller) if user_manager else "viewer"
        except Exception:
            _vnc_role = "viewer"
    else:
        start_response("401 Unauthorized", [("Content-Type", "text/plain")])
        return [b"Unauthorized"]

    # OMERATI-2026-001: enforce role
    if _vnc_role not in ("admin", "administrator", "operator"):
        log.warning("VNC WS blocked: vm=%s user=%s role=%s", vm_id, _vnc_caller, _vnc_role)
        start_response("403 Forbidden", [("Content-Type", "text/plain")])
        return [b"Forbidden: VNC access requires operator or admin role"]

    # ── VNC port from libvirt XML ──
    try:
        import libvirt as _lv_vnc
        import xml.etree.ElementTree as _ET_vnc
        _conn = _lv_vnc.open(config.LIBVIRT_URI)
        _dom  = _conn.lookupByUUIDString(vm_id)
        _xml  = _dom.XMLDesc()
        _conn.close()
        _root   = _ET_vnc.fromstring(_xml)
        _vnc_el = _root.find(".//graphics[@type='vnc']")
        vnc_port = int(_vnc_el.get("port", -1)) if _vnc_el is not None else -1
        if vnc_port < 5900:
            log.warning("VNC WS: no VNC port vm=%s port=%d", vm_id, vnc_port)
            start_response("503 Service Unavailable", [("Content-Type", "text/plain")])
            return [b"VNC not available"]
    except Exception as _e:
        log.warning("VNC WS: libvirt failed vm=%s: %s", vm_id, _e)
        start_response("503 Service Unavailable", [("Content-Type", "text/plain")])
        return [b"VM not found"]

    # ── TCP connect to QEMU VNC ──
    # Use eventlet.green.socket — cooperative recv/send, yields to hub instead of
    # blocking the OS thread.  Plain socket.create_connection() without monkey_patch
    # would block the entire eventlet hub whenever VNC has no data (idle screen).
    try:
        tcp = _egreen_socket.create_connection(("127.0.0.1", vnc_port), timeout=5)
        tcp.settimeout(None)   # cooperative blocking — hub yields on recv
    except Exception as _e:
        log.warning("VNC WS: TCP failed vm=%s port=%d: %s", vm_id, vnc_port, _e)
        start_response("503 Service Unavailable", [("Content-Type", "text/plain")])
        return [b"VNC connect failed"]

    # ── RFC 6455 handshake — write directly to raw SSL socket ──
    if not ws_key:
        log.error("VNC WS: missing Sec-WebSocket-Key vm=%s", vm_id)
        try: tcp.close()
        except Exception: pass
        start_response("400 Bad Request", [("Content-Type", "text/plain")])
        return [b"Missing WebSocket key"]

    accept = _b64.b64encode(
        _hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    # Echo Sec-WebSocket-Protocol: binary — noVNC requires this to enable
    # arraybuffer binary mode; without it ws.protocol == '' and binary frames break
    ws_proto = environ.get("HTTP_SEC_WEBSOCKET_PROTOCOL", "")
    proto_line = f"Sec-WebSocket-Protocol: binary\r\n" if "binary" in ws_proto else ""
    handshake = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        f"{proto_line}"
        "\r\n"
    ).encode()

    # Get raw socket via eventlet API
    _ei = environ.get("eventlet.input")
    raw_sock = None
    if _ei is not None and hasattr(_ei, "get_socket"):
        try:
            raw_sock = _ei.get_socket()
        except Exception as _e:
            log.warning("VNC WS: get_socket() failed: %s", _e)
    if raw_sock is None:
        _wi = environ.get("wsgi.input")
        for _chain in [("raw", "_sock"), ("_sock",), ("raw",)]:
            try:
                _o = _wi
                for _a in _chain: _o = getattr(_o, _a)
                if hasattr(_o, "sendall"):
                    raw_sock = _o
                    break
            except AttributeError:
                continue
    if raw_sock is None:
        log.error("VNC WS: cannot get raw socket vm=%s environ_keys=%s",
                  vm_id, [k for k in environ if not k.startswith("wsgi.")])
        try: tcp.close()
        except Exception: pass
        start_response("500 Internal Server Error", [("Content-Type", "text/plain")])
        return [b"Internal error"]

    log.info("VNC WS: socket=%s vm=%s", type(raw_sock).__name__, vm_id)

    try:
        raw_sock.sendall(handshake)
    except Exception as _e:
        log.warning("VNC WS: handshake send failed vm=%s: %s", vm_id, _e)
        try: tcp.close()
        except Exception: pass
        return []

    log.info("VNC WS proxy: vm=%s port=%d sock_fd=%d", vm_id, vnc_port, raw_sock.fileno())

    # ── VNC → WebSocket (greenlet) ──
    def _vnc_to_ws():
        pkt = 0
        try:
            while True:
                data = tcp.recv(65536)
                if not data:
                    log.info("VNC WS: VNC closed connection vm=%s after %d pkts", vm_id, pkt)
                    break
                pkt += 1
                if pkt <= 5:
                    log.info("VNC WS: vnc→ws pkt#%d len=%d first=%r vm=%s",
                             pkt, len(data), data[:16], vm_id)
                raw_sock.sendall(_ws_build_frame(data))
        except Exception as _e:
            log.warning("VNC WS: vnc→ws err vm=%s: %s", vm_id, _e)
        finally:
            try: tcp.close()
            except Exception: pass
            try: raw_sock.sendall(bytes([0x88, 0x00]))
            except Exception: pass

    _ev_vnc.spawn(_vnc_to_ws)

    # ── WebSocket → VNC (this greenlet, trampoline-based recv) ──
    first = True
    try:
        while True:
            opcode, payload = _ws_recv_frame(raw_sock)
            if opcode is None:
                break
            if first:
                log.info("VNC WS: first frame op=0x%02x len=%d vm=%s",
                         opcode, len(payload) if payload else 0, vm_id)
                first = False
            if opcode == 0x8:
                break
            if opcode in (0x1, 0x2) and payload:
                tcp.sendall(payload)
    except BaseException as _e:
        log.warning("VNC WS: ws→vnc err vm=%s: %s (%s)", vm_id, _e, type(_e).__name__)
    finally:
        try: tcp.close()
        except Exception: pass
        # Shut down SSL layer cleanly so eventlet WSGI finish() doesn't get SSLEOFError
        try: raw_sock.shutdown(_raw_sk.SHUT_RDWR)
        except Exception: pass
        try: raw_sock.close()
        except Exception: pass

    return []

app.wsgi_app = _vnc_ws_middleware

# ── CSRF Token store (stateless double-submit pattern) ────────────────────────
_csrf_exempt_paths = {"/api/auth/login", "/api/auth/2fa/verify-login",
                      "/api/setup", "/metrics"}

@app.before_request
def _check_csrf():
    """State-changing istekler için CSRF token doğrula (double-submit cookie pattern)."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    path = request.path
    if path in _csrf_exempt_paths or path.startswith("/static") or path.startswith("/api/setup"):
        return
    # API istekleri için X-CSRF-Token header kontrolü
    # Token, /api/auth/csrf endpoint'inden alınır ve localStorage'da saklanır
    csrf_header = request.headers.get("X-CSRF-Token", "")
    csrf_cookie = request.cookies.get("csrf_token", "")
    # OXW-2026-001 fix: Authorization: Bearer header ile gelen API çağrıları
    # cookie taşımaz, CSRF'e karşı korumalıdır — yalnızca cookie tabanlı JWT'de zorunlu
    if request.headers.get("Authorization", "").startswith("Bearer "):
        return  # Header-based JWT: CSRF riski yok
    if not csrf_header or not csrf_cookie:
        return jsonify({"status": "error", "error": "CSRF token gerekli"}), 403
    if not hmac.compare_digest(csrf_header, csrf_cookie):
        return jsonify({"status": "error", "error": "CSRF token geçersiz"}), 403

@app.route("/api/auth/csrf", methods=["GET"])
def api_csrf_token():
    """CSRF token üret ve cookie olarak set et."""
    import secrets
    token = secrets.token_hex(32)
    resp = make_response(jsonify({"csrf_token": token}))
    resp.set_cookie("csrf_token", token,
                    secure=True, httponly=False, samesite="Strict",
                    max_age=3600)
    return resp

# Güvenlik katmanını kaydet
security.register_security(app)

# Başlangıçta şifre sıfırlaması uygula
cred_mgr.apply_reset_if_exists()

# Test/CI modunda arka plan thread'lerini başlatma (import temiz + hızlı kalsın)
_TEST_MODE = os.environ.get("OXWARE_TEST_MODE") == "1"

# AI agentları başlat
if not _TEST_MODE:
    ai_agent.start_all_agents()

# Zamanlanmış rapor gönderici (haftalık) — opsiyonel, hata olursa atla
if not _TEST_MODE:
    try:
        _rep_sched = _safe_import("report_scheduler")
        if _rep_sched:
            _rep_sched.start_background()
    except Exception as _rs_e:
        log.debug("report scheduler başlatılamadı: %s", _rs_e)

# ChatOps (Telegram iki-yön) — yalnızca panelden etkinleştirilmişse başlar
if not _TEST_MODE:
    try:
        _cops = _safe_import("chatops")
        if _cops:
            _cops.start_background()
    except Exception as _co_e:
        log.debug("chatops başlatılamadı: %s", _co_e)

# Marka bütünlüğü / provenance kontrolü — varsayılan "warn" (engellemez,
# sadece loglar + panelde uyarı). OXWARE_BRAND_MODE=strict ile fork+rebrand
# tespitinde başlatma engellenir, =off ile tamamen kapatılır.
try:
    import brand_integrity as _brand
    _brand_verdict = _brand.enforce()
    if _brand_verdict.get("block"):
        log.critical("OXware başlatma engellendi (brand integrity strict). "
                     "Yetkisiz fork/rebrand tespit edildi. "
                     "OXWARE_BRAND_MODE=warn ile devam edebilirsiniz.")
        import sys as _sys
        _sys.exit(3)
except SystemExit:
    raise
except Exception as _be:
    log.debug("brand integrity kontrolü atlandı: %s", _be)

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
        # Token valid — session kayıtlı değilse otomatik kaydet (restart sonrası)
        if sess_mgr:
            try:
                from flask_jwt_extended import get_jwt, get_jwt_identity
                claims = get_jwt()
                jti = claims.get("jti", "")
                # rapor #16 fix: revoke edilmiş token → 401
                if jti and sess_mgr.is_revoked(jti):
                    return err("Oturum iptal edildi. Yeniden giriş yapın.", 401)
                if jti and not sess_mgr.is_revoked(jti):
                    # is_revoked False döndürüyor + session yoksa da False → kaydet
                    if jti not in sess_mgr._sessions:
                        sess_mgr.register_session(
                            jti=jti,
                            username=get_jwt_identity() or "unknown",
                            ip=request.headers.get("X-Forwarded-For", request.remote_addr or ""),
                            user_agent=request.headers.get("User-Agent", "")[:120],
                        )
                    else:
                        sess_mgr.touch_session(jti)
            except Exception:
                pass
        return fn(*args, **kwargs)
    return wrapper


def require_role(*allowed_roles):
    """
    Decorator: JWT valid olmalı VE kullanıcının rolü allowed_roles içinde olmalı.
    Kullanım: @require_role("admin") veya @require_role("admin", "operator")
    CVE-2023-43320 / CVE-2024-38813 — API token privilege escalation mitigation.
    """
    from functools import wraps
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
                username = get_jwt_identity()
            except Exception:
                return err("Kimlik doğrulama gerekli", 401)
            try:
                # Primary admin check (credentials.py sadece tek admin tutar)
                _primary_admin = cred_mgr.get_username() if hasattr(cred_mgr, "get_username") else ""
                if username.lower() == _primary_admin.lower():
                    role = "admin"
                elif hasattr(cred_mgr, "get_role"):
                    role = cred_mgr.get_role(username) or "viewer"
                else:
                    # user_manager secondary user — gerçek rolünü al
                    role = user_manager.get_user_role(username)
            except Exception:
                role = "viewer"
            if role not in allowed_roles:
                log.warning("require_role: %s rolü %s için yetersiz (gerekli: %s)",
                            role, username, allowed_roles)
                return err("Bu işlem için yetki gerekli", 403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ── SEC-014b — modularization seed: register the v2.7 blueprint.
# New v2.7 endpoints live in bp_v270.py under /api/v2/... and inherit the same
# auth + role decorators. Old /api/... routes in this file remain for
# back-compat; once the panel migrates, they can be retired.
if bp_v270_mod is not None:
    try:
        bp_v270_mod.init_bp_v270(
            confidential_vm, runbook_exec, federation_mgr,
            require_auth=require_auth, require_role=require_role,
            ok=ok, err=err,
        )
        app.register_blueprint(bp_v270_mod.bp_v270)
        log.info("v2.7 blueprint registered (/api/v2/...)")
    except Exception as _bpe:
        log.warning("bp_v270 register failed: %s", _bpe)

# v2.7.2 + v2.8 + v2.9 + v3.0 blueprint: CSI, KubeVirt, GitOps,
# Firecracker, OAuth2 presets, audit retention, SBOM, PWA, SSH known-hosts.
if bp_v272_mod is not None:
    try:
        bp_v272_mod.init_bp_v272(
            require_auth=require_auth, require_role=require_role,
            ok=ok, err=err,
        )
        app.register_blueprint(bp_v272_mod.bp_v272)
        log.info("v2.7.2/2.8/2.9/3.0 blueprint registered "
                 "(/api/v2/csi, /api/v2/kubevirt, /api/v2/gitops, "
                 "/api/v3/firecracker, /api/v3/pwa, ...)")
    except Exception as _bpe2:
        log.warning("bp_v272 register failed: %s", _bpe2)

# ── v2.8 modularization: domain blueprints under /api/v2/{auth,vms,...}
# Legacy /api/* routes in this file are unchanged. New work lands here.
try:
    from oxware.backend import blueprints as _v28
except Exception:
    try:
        import blueprints as _v28  # type: ignore
    except Exception:
        _v28 = None

if _v28 is not None:
    _v28_deps = {
        "vm_manager": _safe_import("vm_manager"),
        "network_manager": _safe_import("network_manager"),
        "storage_manager": _safe_import("storage_manager"),
        "iso_manager": _safe_import("iso_manager"),
        "ipam": _safe_import("ipam_manager") or _safe_import("ip_pool"),
        "system_monitor": _safe_import("system_monitor"),
        "alert_rules": _safe_import("alert_rules"),
        "anomaly_detector": _safe_import("anomaly_detector"),
        "snapshot_manager": _safe_import("snapshot_manager"),
        "auth": _safe_import("auth"),
        "session_manager": _safe_import("session_manager") or _safe_import("auth"),
        "rbac": _safe_import("rbac") or _safe_import("auth"),
        "audit_log": _safe_import("audit_log"),
        "get_current_user": (
            lambda: (_safe_import("auth").get_current_user()
                     if _safe_import("auth")
                     and hasattr(_safe_import("auth"), "get_current_user")
                     else None)
        ),
        "rotate_csrf": (
            lambda: (_safe_import("auth").rotate_csrf()
                     if _safe_import("auth")
                     and hasattr(_safe_import("auth"), "rotate_csrf")
                     else None)
        ),
    }
    for _bp_mod, _init_name, _bp_name in (
        (_v28.auth_bp, "init_auth_bp", "v28_auth"),
        (_v28.vms_bp, "init_vms_bp", "v28_vms"),
        (_v28.networks_bp, "init_networks_bp", "v28_networks"),
        (_v28.storage_bp, "init_storage_bp", "v28_storage"),
        (_v28.monitoring_bp, "init_monitoring_bp", "v28_monitoring"),
    ):
        try:
            getattr(_bp_mod, _init_name)(
                require_auth=require_auth, require_role=require_role,
                ok=ok, err=err, deps=_v28_deps,
            )
            app.register_blueprint(_bp_mod.bp)
            log.info("v2.8 blueprint registered: %s", _bp_name)
        except Exception as _bpe3:
            log.warning("v2.8 blueprint %s failed: %s", _bp_name, _bpe3)

    # ── Anonymous opt-in telemetry (default OFF) ──────────────────────────
    try:
        _telemetry = _safe_import("telemetry_collector")
    except Exception:
        _telemetry = None

    def _telemetry_deps_factory():
        """Cheap snapshot used by the background ping and the panel preview.
        Counts only — no names, no paths, no identifiers."""
        try:
            _vm = _safe_import("vm_manager")
            _fed = _safe_import("cluster_federation")
            _flags = _safe_import("feature_registry")
            return {
                "oxware_version": "2.8.1",
                "vm_count": len((_vm.list_vms() if _vm else []) or []),
                "node_count": len((_fed.list_members() if _fed else []) or []),
                "enabled_features": [
                    f["id"] for f in (_flags.list_enabled() if _flags else [])
                ] if _flags and hasattr(_flags, "list_enabled") else [],
            }
        except Exception:
            return {"oxware_version": "2.8.1"}

    if _telemetry is not None:
        try:
            _v28.telemetry_bp.init_telemetry_bp(
                require_auth=require_auth, require_role=require_role,
                ok=ok, err=err,
                telemetry_module=_telemetry,
                deps_factory=_telemetry_deps_factory,
            )
            app.register_blueprint(_v28.telemetry_bp.bp)
            if os.environ.get("OXWARE_TEST_MODE") != "1":
                _telemetry.start_background_sender(_telemetry_deps_factory)
            log.info("v2.8 telemetry blueprint registered (opt-in, default OFF)")
        except Exception as _bpe4:
            log.warning("telemetry blueprint failed: %s", _bpe4)


def _vmuser_check(vm_id):
    """
    vm-user rolü için: JWT'den kullanıcıyı al, sadece atanmış VM'e erişime izin ver.
    Başka rol içinse None döner (check skip).
    Returns: None (pass) or Flask error response (block).
    """
    try:
        verify_jwt_in_request()
        username = get_jwt_identity()
        _primary = cred_mgr.get_username() if hasattr(cred_mgr, "get_username") else ""
        if username.lower() == _primary.lower():
            return None  # admin — pass
        role = (cred_mgr.get_role(username) if hasattr(cred_mgr, "get_role")
                else user_manager.get_user_role(username)) or "viewer"
        if role != "vm-user":
            return None  # not vm-user — existing require_role handles it
        allowed = set(user_manager.get_user_vms(username))
        if vm_id not in allowed:
            log.warning("vm-user %s tried to access unassigned vm %s", username, vm_id)
            return err("Bu VM size atanmamış", 403)
    except Exception:
        pass
    return None


# noVNC session token store — CVE-2022-35508 mitigation
# Short-lived tokens prevent unauthenticated direct WebSocket access
import secrets as _secrets
_novnc_sessions: dict = {}   # {token: {"vm_id": str, "ws_port": int, "ip": str, "expires": float}}
_NOVNC_TOKEN_TTL = 300       # 5 minutes

# OXW-2026-008 fix: VNC WebSocket one-time token store
# JWT sorgu dizesinde taşınmaz — tek kullanımlık kısa ömürlü token
_vnc_one_time_tokens: dict = {}  # {token: {"vm_id": str, "username": str, "role": str, "expires": float, "used": bool}}
_vnc_token_lock = threading.Lock()
_VNC_TOKEN_TTL  = 60  # 60 saniye — yalnızca bağlantı kurulumunda kullanılır

def _vnc_token_cleanup_worker():
    while True:
        try:
            _time_mod.sleep(120)
            now = _time_mod.time()
            with _vnc_token_lock:
                expired = [t for t, v in _vnc_one_time_tokens.items()
                           if v.get("expires", 0) < now or v.get("used", False)]
                for t in expired:
                    _vnc_one_time_tokens.pop(t, None)
        except Exception:
            pass

threading.Thread(target=_vnc_token_cleanup_worker, daemon=True, name="vnc-token-cleanup").start()


def _novnc_clean():
    """Expire old noVNC tokens."""
    now = time.time()
    expired = [t for t, v in _novnc_sessions.items() if v["expires"] < now]
    for t in expired:
        del _novnc_sessions[t]


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
@app.route("/docs/")
def docs_page():
    # Panel artık kendi docs.html'ini servis etmiyor — merkezi dokümana yönlendir.
    # Tek kaynak: https://oxware.top/docs (bakım kolaylığı + dosya yoğunluğu azalır)
    from flask import redirect as _redirect
    return _redirect("https://oxware.top/docs/", code=302)

# ── ISO Download ──────────────────────────────────────────────────────────────
_ISO_SEARCH_PATHS = [
    "/opt/oxware/OXware-Hypervisor-2.7.0-amd64.iso",
    "/root/OXware-Hypervisor-2.7.0-amd64.iso",
    "/tmp/OXware-Hypervisor-2.7.0-amd64.iso",
    "/opt/oxware/OXware-Hypervisor-2.7.0-amd64.iso",
    "/root/OXware-Hypervisor-2.7.0-amd64.iso",
    "/tmp/OXware-Hypervisor-2.7.0-amd64.iso",
]

@app.route("/download/iso")
@require_auth
def download_iso():
    import glob as _glob
    # Dynamic search — any OXware ISO
    candidates = _iso_find()
    if not candidates:
        return jsonify({"error": "ISO bulunamadı. Önce build/build-iso.sh çalıştırın."}), 404
    iso_path = candidates[0]
    return send_file(iso_path, as_attachment=True,
                     download_name=os.path.basename(iso_path),
                     mimetype="application/x-iso9660-image")

@app.route("/api/iso/info")
@require_auth
def api_iso_info():
    candidates = _iso_find()
    if not candidates:
        return ok(available=False, message="ISO bulunamadı")
    iso_path = candidates[0]
    size = os.path.getsize(iso_path)
    mtime = os.path.getmtime(iso_path)
    return ok(available=True, path=iso_path,
              name=os.path.basename(iso_path),
              size=size,
              size_human=f"{size / (1024**3):.2f} GB",
              built_at=mtime)

def _iso_find():
    import glob as _glob
    found = []
    for p in _ISO_SEARCH_PATHS:
        if os.path.isfile(p):
            found.append(p)
    # Glob common build output dirs + OXware ISO library + repo root
    _repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    for pattern in [
        "/opt/oxware/*.iso",
        "/root/*.iso",
        "/tmp/oxware*/*.iso",
        "/var/lib/oxware/isos/*.iso",
        os.path.join(_repo_root, "*.iso"),
        os.path.join(_repo_root, "OXware-Hypervisor-*.iso"),
    ]:
        found.extend(_glob.glob(pattern))
    # Deduplicate, sort by mtime newest first
    seen = set()
    result = []
    for p in found:
        if p not in seen and os.path.isfile(p):
            seen.add(p)
            result.append(p)
    result.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return result

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/setup")
def setup_page():
    return render_template("setup.html")

@app.route("/console/<vm_id>")
def console_page(vm_id):
    # OXW-2026-SEC-006: vm_id sanitize (defense-in-depth; tojson zaten escape eder)
    import re as _re_vid
    if not _re_vid.match(r"^[a-zA-Z0-9_.\-]{1,128}$", vm_id or ""):
        return "Invalid VM identifier", 400
    return render_template("console.html", vm_id=vm_id)

# OXW-2026-008 fix: VNC bağlantısı için tek kullanımlık kısa ömürlü token üret.
# JWT sorgu dizesi yerine bu token /ws/vnc/<vm_id>?vnc_token=<token> ile kullanılır.
@app.route("/api/vms/<vm_id>/vnc-token", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vnc_token(vm_id):
    username = get_jwt_identity()
    token = _secrets.token_urlsafe(32)
    try:
        _prim  = cred_mgr.get_username() if hasattr(cred_mgr, "get_username") else ""
        _role  = "administrator" if username.lower() == _prim.lower() else (
            user_manager.get_user_role(username) or "viewer")
    except Exception:
        _role = "viewer"
    with _vnc_token_lock:
        _vnc_one_time_tokens[token] = {
            "vm_id":    vm_id,
            "username": username,
            "role":     _role,
            "expires":  _time_mod.time() + _VNC_TOKEN_TTL,
            "used":     False,
        }
    return ok(token=token, ttl=_VNC_TOKEN_TTL)

@app.route("/vnc_console/<vm_id>")
def vnc_console_page(vm_id):
    """Dedicated VNC console page — SocketIO TCP proxy, no websockify needed."""
    # OXW-2026-SEC-006: vm_id sanitize
    import re as _re_vid
    if not _re_vid.match(r"^[a-zA-Z0-9_.\-]{1,128}$", vm_id or ""):
        return "Invalid VM identifier", 400
    embed = request.args.get("embed", "0") == "1"
    resp = make_response(render_template("vnc_console.html", vm_id=vm_id, embed=embed))
    # Allow embedding from same origin (needed for in-page modal iframe)
    resp.headers.pop("X-Frame-Options", None)
    resp.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
    return resp

@app.route("/novnc/")
@app.route("/novnc/<path:filename>")
def serve_novnc(filename="vnc.html"):
    """noVNC statik dosyalarını Flask üzerinden serve et (same-origin, X-Frame-Options yok)."""
    novnc_dir = config.NOVNC_DIR
    if not os.path.isdir(novnc_dir):
        # Fallback: yaygın kurulum yerleri
        for d in ["/usr/share/novnc", "/opt/novnc", "/usr/share/novnc/app",
                  "/usr/share/novnc/utils", "/opt/novnc/utils"]:
            if os.path.isdir(d):
                novnc_dir = d
                break
        else:
            return "noVNC bulunamadı. Lütfen sunucuya novnc kurun.", 404

    # Path traversal guard + early 404
    _real_dir = os.path.realpath(novnc_dir)
    _real_abs = os.path.realpath(os.path.join(novnc_dir, filename))
    if not _real_abs.startswith(_real_dir + os.sep) and _real_abs != _real_dir:
        return "Forbidden", 403
    if not os.path.isfile(_real_abs):
        return f"noVNC dosyası bulunamadı: {filename}", 404

    # Explicit MIME types — critical for ES module dynamic imports under nosniff
    _ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    _mime = {
        "js":   "application/javascript; charset=utf-8",
        "mjs":  "application/javascript; charset=utf-8",
        "css":  "text/css; charset=utf-8",
        "html": "text/html; charset=utf-8",
        "svg":  "image/svg+xml",
        "png":  "image/png",
        "ico":  "image/x-icon",
        "wasm": "application/wasm",
        "woff": "font/woff",
        "woff2":"font/woff2",
        "map":  "application/json",
    }.get(_ext)

    resp = send_from_directory(novnc_dir, filename, mimetype=_mime)
    # iframe içinde gösterim için X-Frame-Options kaldır
    resp.headers.pop("X-Frame-Options", None)
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    # Cache noVNC static assets (they don't change between requests)
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp

# ── İlk Kurulum ───────────────────────────────────────────────────────────────
@app.route("/api/setup/status")
def api_setup_status():
    return ok(done=cred_mgr.is_setup_done())

def _attach_session_cookies(resp, token: str):
    """SEC-014: emit JWT in HttpOnly + Secure + SameSite=Strict cookie alongside
    the JSON body. Existing Bearer-token clients keep working; new clients can
    move to credentials:'include' and stop touching localStorage entirely.
    flask-jwt-extended will also drop a non-HttpOnly CSRF cookie that the
    frontend must echo back as the X-CSRF-TOKEN header on writes."""
    try:
        set_access_cookies(resp, token)
    except Exception as _e:
        log.debug("set_access_cookies failed: %s", _e)
    return resp


def _is_local_request() -> bool:
    """Allow setup only from loopback or trusted unix socket / X-Real-IP local.
    Blocks remote first-admin takeover on a freshly booted, publicly-bound node.
    Override with OXWARE_SETUP_ALLOW_REMOTE=1 (development only — logged on use)."""
    if os.environ.get("OXWARE_SETUP_ALLOW_REMOTE") == "1":
        log.warning("Setup remote-allow override active (OXWARE_SETUP_ALLOW_REMOTE=1) — INSECURE")
        return True
    addr = (request.remote_addr or "").strip()
    return addr in ("127.0.0.1", "::1", "localhost", "")


@app.route("/api/setup/init", methods=["POST"])
def api_setup_init():
    if cred_mgr.is_setup_done():
        return err("Kurulum zaten tamamlandı", 409)
    if not _is_local_request():
        log.warning("Setup attempted from non-local address: %s", request.remote_addr)
        return err("Setup endpoint sadece localhost'tan erişilebilir. "
                   "Sunucuda 'curl -X POST http://127.0.0.1:8006/api/setup/init ...' kullanın.", 403)
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or len(password) < 8:
        return err("Kullanıcı adı ve en az 8 karakterli şifre gerekli")
    try:
        cred_mgr.first_setup(username, password)
        ev.info(f"İlk kurulum tamamlandı. Kullanıcı: {username}", category="auth")
        token = create_access_token(identity=username)
        return _attach_session_cookies(ok(token=token, username=username, message="Kurulum tamamlandı"), token)
    except Exception as e:
        return err(e)

# ── 2FA pending store (in-memory, 5 dk TTL) ───────────────────────────────────
# OXW-2026-020 fix: threading.Lock ile TOCTOU penceresi kapatıldı.
# Atomik pop ile temp_token tekrar kullanımı engellendi.
# Arka plan cleanup thread'i bellek sızıntısını önler.
import threading as _threading
_2fa_lock    = _threading.Lock()
_2fa_pending: dict = {}  # temp_token → {username, expires, ip, ua}

def _2fa_cleanup_worker():
    """Süresi dolmuş 2FA pending token'larını temizle (bellek sızıntısı önleme)."""
    while True:
        try:
            _time_mod.sleep(60)
            now = _time_mod.time()
            with _2fa_lock:
                expired = [t for t, v in _2fa_pending.items() if v.get("expires", 0) < now]
                for t in expired:
                    _2fa_pending.pop(t, None)
        except Exception:
            pass

_t_2fa_cleanup = _threading.Thread(target=_2fa_cleanup_worker, daemon=True, name="2fa-cleanup")
_t_2fa_cleanup.start()

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    # IP bazlı rate limit — brute-force koruması (20 deneme/60 sn/IP)
    _client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    if not _ip_check_login(_client_ip):
        ev.warn(f"Login IP rate limit aşıldı: {_client_ip}", category="auth")
        return err("Çok fazla istek. Lütfen bekleyin.", 429)
    # rapor #15 fix: case-insensitive bypass önleme — kullanıcı adı her zaman lowercase
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    if not username or not password:
        return err("Kullanıcı adı ve şifre zorunludur")
    # Account lockout kontrolü
    if sec_hard:
        locked, secs = sec_hard.is_account_locked(username)
        if locked:
            ev.warn(f"Kilitli hesaba giriş denemesi: {username} / {request.remote_addr}", category="auth")
            return err(f"Hesap kilitli. {secs} saniye bekleyin.", 429)
    # ── OXW-2026-012 fix: Constant-time login — kullanıcı var/yok timing oracle kapatıldı ──
    # Kullanıcı yoksa bile dummy PBKDF2 çalıştırarak yanıt süresini sabit tut.
    import hashlib as _hlib
    _DUMMY_HASH = "pbkdf2_sha256$260000$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    def _dummy_pbkdf2():
        _hlib.pbkdf2_hmac("sha256", password.encode("utf-8", errors="ignore"),
                          b"\x00" * 32, 260_000)
    # ── Kimlik doğrulama: önce primary admin (credentials.py), sonra user_manager ──
    _auth_ok = cred_mgr.verify_credentials(username, password)
    _is_primary_admin = _auth_ok  # cred_mgr = primary (tek) admin hesabı
    if not _auth_ok:
        # Secondary users (user_manager / users.json)
        try:
            _auth_ok = user_manager.verify_user(username, password)
        except Exception:
            _auth_ok = False
    if not _auth_ok:
        # Kullanıcı bulunamadıysa dummy hash çalıştır — timing sabit
        _dummy_pbkdf2()
    # ── LDAP fallback ─────────────────────────────────────────────────────────
    _ldap_role = None
    if not _auth_ok and ldap_mgr:
        try:
            _ldap_result = ldap_mgr.authenticate(username, password)
            if _ldap_result and _ldap_result.get("authenticated"):
                _auth_ok   = True
                _ldap_role = _ldap_result.get("role", "viewer")
                # Auto-provision LDAP user into local user store so sessions work
                try:
                    if not user_manager.get_user(username):
                        user_manager.create_user(
                            username=username,
                            password=None,  # no local password — LDAP only
                            role=_ldap_role,
                            display_name=_ldap_result.get("display_name", username),
                            ldap=True,
                        )
                    else:
                        user_manager.update_user(username, role=_ldap_role)
                except Exception:
                    pass
                ev.info(f"LDAP girişi başarılı: {username} / rol={_ldap_role}", category="auth")
        except Exception as _le:
            log.warning("LDAP authenticate error: %s", _le)
    if not _auth_ok:
        if sec_hard:
            sec_hard.record_failed_login(username)
        ev.warn(f"Başarısız giriş: {username} / {request.remote_addr}", category="auth")
        _bg_notify(f"Başarısız giriş denemesi: {username}", level="WARNING", category="auth",
                   details={"user": username,
                            "ip": request.headers.get("X-Forwarded-For", request.remote_addr or "")})
        return err("Geçersiz kimlik bilgileri", 401)
    if sec_hard:
        sec_hard.record_successful_login(username)
    # ── 2FA kontrolü ──────────────────────────────────────────────────────────
    if totp_mgr and totp_mgr.is_enabled(username):
        import uuid as _uuid
        temp_token = str(_uuid.uuid4())
        with _2fa_lock:
            _2fa_pending[temp_token] = {
                "username": username,
                "expires":  time.time() + 300,
                "ip":       request.headers.get("X-Forwarded-For", request.remote_addr or ""),
                "ua":       request.headers.get("User-Agent", "")[:120],
            }
        ev.info(f"2FA bekleniyor: {username} / {request.remote_addr}", category="auth")
        return jsonify({"requires_2fa": True, "temp_token": temp_token}), 200
    # ── 2FA yok: direkt JWT ver ───────────────────────────────────────────────
    token = create_access_token(identity=username)
    # Telemetry: login IP kaydet (arka planda, hata görmezden gelinir)
    try:
        import sys as _sys, os as _os
        _tele_path = _os.path.join(_os.path.dirname(__file__), "..", "..", "telemetry", "collector.py")
        if _os.path.exists(_tele_path) and "telemetry_collector" not in _sys.modules:
            import importlib.util as _ilu
            _spec = _ilu.spec_from_file_location("telemetry_collector", _tele_path)
            _tele = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_tele)
            _sys.modules["telemetry_collector"] = _tele
        _tc = _sys.modules.get("telemetry_collector")
        if _tc:
            _login_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
            _tc.collect_login(_login_ip, username)
    except Exception:
        pass
    # Session kayıt
    if sess_mgr:
        try:
            from flask_jwt_extended import decode_token
            decoded = decode_token(token)
            jti = decoded.get("jti", token[:16])
            sess_mgr.register_session(
                jti=jti, username=username,
                ip=request.headers.get("X-Forwarded-For", request.remote_addr or ""),
                user_agent=request.headers.get("User-Agent", "")[:120],
            )
        except Exception:
            pass
    # Resolve role for frontend
    try:
        _primary = cred_mgr.get_username()
        _role = "administrator" if username.lower() == _primary.lower() else (
            _ldap_role or user_manager.get_user_role(username)
        )
    except Exception:
        _role = "administrator"
    ev.info(f"Giriş başarılı: {username} ({_role})", category="auth")
    _bg_notify(f"Giriş başarılı: {username}", level="INFO", category="auth",
               details={"user": username, "role": _role,
                        "ip": request.headers.get("X-Forwarded-For", request.remote_addr or "")})
    return _attach_session_cookies(ok(token=token, username=username, role=_role), token)

@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    """SEC-014 — server-side logout. Clears the JWT + CSRF cookies (no payload
    needed). The frontend should also wipe sessionStorage/localStorage on its
    side; this endpoint is the only way to invalidate the HttpOnly cookie."""
    try:
        # Revoke the session record so other replicas see the logout.
        if sess_mgr:
            tok_hdr = request.headers.get("Authorization", "")
            if tok_hdr.startswith("Bearer "):
                try:
                    from flask_jwt_extended import decode_token
                    decoded = decode_token(tok_hdr.split(" ", 1)[1])
                    sess_mgr.revoke_session(decoded.get("jti", ""))
                except Exception:
                    pass
    except Exception:
        pass
    resp = ok(message="logged_out")
    try:
        unset_jwt_cookies(resp)
    except Exception as _ue:
        log.debug("unset_jwt_cookies failed: %s", _ue)
    return resp


@app.route("/api/auth/2fa/verify-login", methods=["POST"])
def api_2fa_verify_login():
    """2FA doğrulama — temp_token + 6 haneli TOTP kodu → gerçek JWT."""
    _client_ip2 = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    if not _ip_check_login(_client_ip2):
        return err("Çok fazla istek. Lütfen bekleyin.", 429)
    data = request.get_json() or {}
    temp_token = data.get("temp_token", "").strip()
    code = data.get("code", "").strip()
    if not temp_token or not code:
        return err("temp_token ve code zorunludur", 400)
    # OXW-2026-020 fix: atomik pop — temp_token tek kullanımlık, TOCTOU penceresi yok
    with _2fa_lock:
        pending = _2fa_pending.pop(temp_token, None)
    if not pending:
        return err("Geçersiz veya süresi dolmuş token", 401)
    if time.time() > pending["expires"]:
        return err("2FA süresi doldu. Tekrar giriş yapın.", 401)
    username = pending["username"]
    # TOTP doğrula
    # OXW-2026-SEC-005: brute-force oracle önleme — login ile aynı genel mesaj.
    # Geçersiz kod / geçersiz kullanıcı ayrımı yapılmaz.
    if not totp_mgr or not totp_mgr.verify_totp(username, code):
        ev.warn(f"Başarısız 2FA: {username} / {request.remote_addr}", category="auth")
        if sec_hard:
            try: sec_hard.record_failed_login(username)
            except Exception: pass
        return err("Geçersiz kimlik bilgileri", 401)
    # temp_token zaten atomik pop ile tüketildi (OXW-2026-020)
    # Gerçek JWT ver
    token = create_access_token(identity=username)
    if sess_mgr:
        try:
            from flask_jwt_extended import decode_token
            decoded = decode_token(token)
            jti = decoded.get("jti", token[:16])
            sess_mgr.register_session(
                jti=jti, username=username,
                ip=pending.get("ip", request.remote_addr or ""),
                user_agent=pending.get("ua", "")[:120],
            )
        except Exception:
            pass
    try:
        _2fa_role = "administrator" if username.lower() == cred_mgr.get_username().lower() \
            else user_manager.get_user_role(username)
    except Exception:
        _2fa_role = "administrator"
    ev.info(f"2FA giriş başarılı: {username} ({_2fa_role}) / {request.remote_addr}", category="auth")
    return _attach_session_cookies(ok(token=token, username=username, role=_2fa_role), token)

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

# OXW-2026-005 fix: /api/auth/2fa/debug üretim ortamından kaldırıldı.
# Anlık TOTP kodunu döndürmek 2FA'yı anlamsız kılar (same-channel ifşa).
# Saat senkronizasyonu için yalnızca server_timestamp döndüren endpoint yeterli.
@app.route("/api/auth/2fa/debug")
@require_auth
def api_2fa_debug():
    """2FA debug endpoint — DEVRE DIŞI (OXW-2026-005)."""
    return err("Bu endpoint üretim ortamında devre dışıdır.", 410)

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
    # Resolve role for RBAC frontend use
    try:
        _primary_admin = cred_mgr.get_username() if hasattr(cred_mgr, "get_username") else ""
        if username.lower() == _primary_admin.lower():
            _role = "administrator"
        else:
            _role = user_manager.get_user_role(username)
    except Exception:
        _role = "viewer"
    _user = user_manager.get_user(username) if hasattr(user_manager, "get_user") else None
    _display = (_user or {}).get("display_name", username) if _user else username
    return ok(username=username, role=_role, display_name=_display, **info)

@app.route("/api/auth/change-password", methods=["POST"])
@require_auth
def api_change_password():
    """
    Sadece kurulum sırasında oluşturulan birincil yönetici
    kendi şifresini değiştirebilir.
    Alt kullanıcılar ve diğer roller bu endpoint'i kullanamaz.
    """
    from flask_jwt_extended import get_jwt_identity
    caller = get_jwt_identity()
    try:
        primary_admin = cred_mgr.get_username()
    except Exception:
        return err("Birincil yönetici bilgisi okunamadı", 500)

    if caller != primary_admin:
        return err("Sadece sistem kurucusu kendi şifresini değiştirebilir", 403)

    data = request.get_json() or {}
    old_pass = data.get("old_password", "")
    new_pass = data.get("new_password", "")
    if len(new_pass) < 8:
        return err("Yeni şifre en az 8 karakter olmalıdır")
    if not cred_mgr.change_password(old_pass, new_pass):
        return err("Mevcut şifre yanlış", 401)
    ev.info("Birincil yönetici şifresi değiştirildi", category="auth")
    return ok(message="Şifre değiştirildi")

# ── VM API ────────────────────────────────────────────────────────────────────
@app.route("/api/vms")
@require_auth
def api_list_vms():
    try:
        from flask_jwt_extended import get_jwt_identity
        username = get_jwt_identity()
        role = user_manager.get_user_role(username)
        # Primary admin check
        try:
            _pa = cred_mgr.get_username()
            if username == _pa:
                role = "administrator"
        except Exception:
            pass
        vms = vm_manager.list_vms()
        if role == "vm-user":
            allowed = set(user_manager.get_user_vms(username))
            vms = [v for v in vms if v.get("id") in allowed or v.get("name") in allowed]
        return ok(vms=vms, count=len(vms))
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>")
@require_auth
def api_get_vm(vm_id):
    try:
        from flask_jwt_extended import get_jwt_identity
        username = get_jwt_identity()
        role = user_manager.get_user_role(username)
        try:
            if username.lower() == cred_mgr.get_username().lower():
                role = "administrator"
        except Exception:
            pass
        vm = vm_manager.get_vm(vm_id)
        if role == "vm-user":
            allowed = set(user_manager.get_user_vms(username))
            if vm_id not in allowed and (vm or {}).get("name") not in allowed:
                return err("Bu VM'e erişim izniniz yok", 403)
        # Attach assignees list for admin/operator
        if role in ("administrator", "admin", "operator"):
            vm["assignees"] = user_manager.get_vm_users(vm_id)
        # Attach pool IP (public/assigned IP from ip_pool) — separate from DHCP lease
        try:
            assignment = ip_pool_mgr.get_vm_assignment(vm_id)
            if assignment and assignment.get("pool") not in ("__internal__", "", None):
                vm["pool_ip"]   = assignment.get("ip", "")
                vm["pool_name"] = assignment.get("pool", "")
                # Detect NAT mode: pool IP not in any libvirt NAT subnet
                _pub_ip = vm["pool_ip"]
                _nat_mode = False
                _internal_ip_val = ""
                try:
                    import ipaddress as _ipa
                    _lv_nets_chk = network_manager.list_networks()
                    for _ln in _lv_nets_chk:
                        if _ln.get("ip") and _ln.get("forward_mode") in ("nat", "", None):
                            try:
                                _subnet = _ipa.IPv4Network(
                                    f"{_ln['ip']}/{_ln.get('netmask','255.255.255.0')}",
                                    strict=False
                                )
                                if _ipa.IPv4Address(_pub_ip) not in _subnet:
                                    _nat_mode = True
                            except Exception:
                                pass
                except Exception:
                    pass
                vm["nat_mode"] = _nat_mode
                # Detect if pool IP is the host's own IP (VPS single-IP problem)
                _host_ip_conflict = False
                try:
                    _host_ips_set = set(_get_host_ips())
                    _host_ip_conflict = _pub_ip in _host_ips_set
                except Exception:
                    pass
                vm["host_ip_conflict"] = _host_ip_conflict
                # Internal IP (from __internal__ pool, libvirt DHCP lease, or derived from MAC)
                if _nat_mode or _host_ip_conflict:
                    try:
                        _vm_mac = vm.get("mac", "") or (vm.get("networks", [{}])[0].get("mac", "") if vm.get("networks") else "")
                        # Check __internal__ first
                        _int_assigns = ip_pool_mgr.list_assignments("__internal__")
                        _int_entry = next((a for a in _int_assigns if a.get("mac") == _vm_mac), None)
                        if _int_entry:
                            _internal_ip_val = _int_entry["ip"]
                        else:
                            # Try libvirt DHCP leases
                            _vm_nets = vm.get("networks", [])
                            for _n in _vm_nets:
                                if _n.get("ip") and _n["ip"] != _pub_ip:
                                    _internal_ip_val = _n["ip"]
                                    break
                    except Exception:
                        pass
                vm["internal_ip"] = _internal_ip_val
            else:
                vm["pool_ip"]     = ""
                vm["pool_name"]   = ""
                vm["nat_mode"]    = False
                vm["internal_ip"] = ""
        except Exception:
            vm["pool_ip"]     = ""
            vm["pool_name"]   = ""
            vm["nat_mode"]    = False
            vm["internal_ip"] = ""

        # is_nat_vm: VM NAT ağında mı? — cached, her request'te list_networks() çağırmaz
        try:
            _vm_networks = vm.get("networks", [])
            _vm_net_name = (_vm_networks[0].get("network") if _vm_networks else None) or vm.get("network", "default")
            # default/virbr0 = NAT — libvirt default network her zaman NAT
            # Sadece açıkça "bridge"/"passthrough" olanlar NAT değil
            _is_nat_vm = _vm_net_name in ("default", "") or not _vm_net_name
            # NAT iç IP — VM'in DHCP'den aldığı gerçek IP
            _nat_vm_ip = vm.get("internal_ip", "")
            if not _nat_vm_ip:
                for _n in _vm_networks:
                    if _n.get("ip"):
                        _nat_vm_ip = _n["ip"]
                        break
            vm["is_nat_vm"] = _is_nat_vm
            if _nat_vm_ip:
                vm["internal_ip"] = _nat_vm_ip
        except Exception:
            vm["is_nat_vm"] = False

        # Guest agent quick status (non-blocking, 2s timeout)
        try:
            vm["guest_agent"] = vm_manager.get_guest_agent_status(vm_id)
        except Exception:
            vm["guest_agent"] = "unavailable"
        return ok(vm=vm)
    except Exception as e:
        return err(e, 404)


@app.route("/api/vms/<vm_id>/guest-agent")
@require_auth
def api_vm_guest_agent(vm_id):
    """QEMU guest agent üzerinden detaylı VM içi bilgi."""
    try:
        info = vm_manager.get_guest_agent_info(vm_id)
        return ok(guest_agent=info)
    except Exception as e:
        return ok(guest_agent={"status": "unavailable", "error": str(e)})


@app.route("/api/vms", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
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
                iso_path, [config.ISO_DIR, "/var/lib/oxware/isos",
                           "/tmp", "/var/lib/libvirt/images"]
            )
        app_install = security.sanitize_str(data.get("app_install", ""), 64)
        if app_install and app_install not in _VALID_APPS:
            app_install = ""
        disk_bus = security.sanitize_str(data.get("disk_bus", "sata"), 16)
        if disk_bus not in ("sata", "virtio", "ide"):
            disk_bus = "sata"
        vm_type = data.get("vm_type", "vps")
        if vm_type not in ("vps", "vds"):
            vm_type = "vps"
        # VDS: host-passthrough CPU; VPS: host-model
        cpu_mode = "host-passthrough" if vm_type == "vds" else "host-model"
    except (ValueError, TypeError) as e:
        return err(str(e))
    try:
        # Build cloud-init config
        ci_obj = data.get("cloud_init") or {}
        ci_user     = security.sanitize_str(ci_obj.get("user", ""), 64)
        ci_password = ci_obj.get("password", "")[:128]
        ci_ssh_key  = ci_obj.get("ssh_key", "")[:4096]
        ci_hostname = security.sanitize_str(ci_obj.get("hostname", ""), 64)
        ci_userdata = ci_obj.get("user_data", "") or data.get("ci_userdata", "")
        if app_install:
            app_script = _get_app_install_script(app_install)
            if app_script:
                ci_userdata = (ci_userdata + "\n" + app_script).strip() if ci_userdata else app_script

        # Statik IP (bridge/passthrough ağ için — cloud-init network-config'e yazılır)
        static_ip  = security.sanitize_str(data.get("static_ip", ""), 48)
        vm_gateway = security.sanitize_str(data.get("gateway", ""), 48)
        vm_netmask = security.sanitize_str(data.get("netmask", "255.255.255.0"), 48)
        vm_dns     = data.get("dns", ["8.8.8.8", "1.1.1.1"])
        if isinstance(vm_dns, str):
            vm_dns = [d.strip() for d in vm_dns.split(",") if d.strip()]
        # Validate static_ip + gateway
        try:
            if static_ip:
                ipaddress.IPv4Address(static_ip)
            if vm_gateway:
                ipaddress.IPv4Address(vm_gateway)
        except ValueError:
            static_ip = ""
            vm_gateway = ""

        # ── Early IPAM allocation for bridge pools (before cloud-init ISO build) ──
        # Bridge ağlarda IP cloud-init'e gömülmesi gerekiyor. IPAM'dan erken al,
        # cloud-init static_ip'ye yaz. Sonraki auto_ip bloğu DHCP/NAT işlemlerini atlar.
        _early_alloc     = None
        _early_pool_name = security.sanitize_str(data.get("ip_pool", ""), 64)
        _early_auto_ip   = data.get("auto_ip", False)
        if _early_auto_ip and _early_pool_name and not static_ip:
            try:
                _early_pool_net_name = None
                try:
                    _ep = ip_pool_mgr._load()["pools"].get(_early_pool_name, {})
                    _early_pool_net_name = _ep.get("libvirt_network", "")
                except Exception:
                    pass
                # Only do early allocation for bridge/passthrough pools
                if _early_pool_net_name:
                    _lv_nets_e = network_manager.list_networks()
                    _pl_net_e  = next((n for n in _lv_nets_e
                                       if n["name"] == _early_pool_net_name), None)
                    if _pl_net_e and _pl_net_e.get("forward_mode") in (
                            "bridge", "passthrough", "private", "vepa"):
                        # Allocate now — use a temporary vm_id (will be updated after create)
                        _early_alloc = ip_pool_mgr.allocate_ip(
                            _early_pool_name, f"__pre__{name}", name, ""
                        )
                        static_ip  = _early_alloc["ip"]
                        vm_gateway = vm_gateway or _early_alloc.get("gateway", "")
                        vm_netmask = vm_netmask or _early_alloc.get("netmask", "255.255.255.0")
                        vm_dns     = vm_dns     or _early_alloc.get("dns", ["8.8.8.8"])
                        log.info("Bridge IPAM erken tahsis: %s → %s", name, static_ip)
            except Exception as _ea_e:
                log.warning("Bridge IPAM erken tahsis başarısız: %s", _ea_e)

        cloud_init = None
        if any([ci_user, ci_password, ci_ssh_key, ci_hostname, ci_userdata, static_ip]):
            cloud_init = {
                "user":      ci_user or None,
                "password":  ci_password or None,
                "ssh_key":   ci_ssh_key or None,
                "hostname":  ci_hostname or name,
                "user_data": ci_userdata or None,
                "static_ip": static_ip or None,
                "gateway":   vm_gateway or None,
                "netmask":   vm_netmask or None,
                "dns":       vm_dns,
            }

        use_cloud_image = bool(data.get("use_cloud_image", False))
        template_id = security.sanitize_str(data.get("template_id", "") or "", 64) or None
        clone_type  = data.get("clone_type", "linked") or "linked"
        if clone_type not in ("linked", "full"):
            clone_type = "linked"

        create_kwargs = dict(
            name=name, memory_mb=memory_mb, vcpus=vcpus, disk_gb=disk_gb,
            iso_path=iso_path, network=network, disk_format=disk_format,
            os_variant=os_variant, boot_order=boot_order, disk_bus=disk_bus,
            cpu_mode=cpu_mode, cloud_init=cloud_init,
            use_cloud_image=use_cloud_image,
            template_id=template_id, clone_type=clone_type,
        )

        try:
            result = vm_manager.create_vm(**create_kwargs)
        except Exception as _create_exc:
            # VM oluşturma başarısız — erken IPAM tahsisini temizle
            if _early_alloc:
                try:
                    ip_pool_mgr.release_ip(f"__pre__{name}")
                    log.info("IPAM erken tahsis temizlendi (VM oluşturma başarısız): %s", name)
                except Exception as _ipam_rl_e:
                    log.warning("IPAM erken tahsis temizleme hatası: %s", _ipam_rl_e)
            raise _create_exc

        vm_id  = result["id"]
        vm_mac = result.get("mac", "")

        # ── IPAM: erken tahsis temizle — MAC alınamadıysa (edge case) ────────
        if _early_alloc and not vm_mac:
            try:
                ip_pool_mgr.release_ip(f"__pre__{name}")
                # MAC olmadan vm_id ile kayıt et — cloud-init IP zaten gömüldü
                if vm_id:
                    ip_pool_mgr.manual_assign(
                        ip=static_ip, mac="", vm_name=name,
                        pool_name=_early_pool_name, vm_id=vm_id
                    )
                log.info("IPAM erken tahsis vm_id ile güncellendi (MAC yok): %s → %s", name, static_ip)
            except Exception as _ipam_no_mac_e:
                log.warning("IPAM erken tahsis temizleme (MAC yok): %s", _ipam_no_mac_e)

        # ── Auto IP assignment via libvirt DHCP static entry ──────────────
        auto_ip   = data.get("auto_ip", False)
        pool_name = security.sanitize_str(data.get("ip_pool", ""), 64)
        if auto_ip and pool_name and vm_mac:
            try:
                if _early_alloc:
                    # Bridge pool: already allocated early — update vm_id + mac in IPAM
                    alloc = _early_alloc
                    alloc["ip"] = static_ip
                    ip_pool_mgr.release_ip(f"__pre__{name}")   # remove temp entry
                    ip_pool_mgr.manual_assign(
                        ip=static_ip, mac=vm_mac, vm_name=name,
                        pool_name=pool_name, vm_id=vm_id
                    )
                    assigned_ip = static_ip
                    dhcp_net    = alloc.get("libvirt_network") or network
                else:
                    alloc        = ip_pool_mgr.allocate_ip(pool_name, vm_id, name, vm_mac)
                    assigned_ip  = alloc["ip"]
                    dhcp_net     = alloc.get("libvirt_network") or network

                # Bridge ağ mı kontrol et (oxbridge / passthrough) — bridge'de NAT yapma
                _is_bridge_net = False
                try:
                    _lv_nets_chk = network_manager.list_networks()
                    _pool_net    = next((n for n in _lv_nets_chk if n["name"] == dhcp_net), None)
                    if _pool_net and _pool_net.get("forward_mode") in (
                            "bridge", "passthrough", "private", "vepa"):
                        _is_bridge_net = True
                except Exception:
                    pass

                _nat_needed  = False
                _internal_ip = assigned_ip

                if _is_bridge_net:
                    # Bridge ağ: DHCP reservation yok, cloud-init ile IP enjekte et
                    log.info("Bridge ağ tespit edildi (%s) — NAT atlanıyor, cloud-init ile IP: %s",
                             dhcp_net, assigned_ip)
                    ev.vm_event(
                        f"IP atandı: {assigned_ip} ({pool_name}) [bridge/cloud-init]",
                        vm_id, level="INFO"
                    )
                else:
                    # NAT ağ: public IP libvirt subnet dışındaysa NAT gerekli
                    try:
                        _lv_nets  = network_manager.list_networks()
                        _virbr    = next((n for n in _lv_nets if n["name"] == "default"), None)
                        if _virbr:
                            _virbr_net = ipaddress.IPv4Network(
                                f"{_virbr['ip']}/{_virbr.get('netmask','255.255.255.0')}",
                                strict=False
                            )
                            if ipaddress.IPv4Address(assigned_ip) not in _virbr_net:
                                _nat_needed  = True
                                _internal_ip = _mac_to_internal_ip(vm_mac)
                                dhcp_net     = "default"
                    except Exception:
                        pass

                    vm_manager.add_dhcp_host(dhcp_net, vm_mac, _internal_ip, name)

                    if _nat_needed:
                        _setup_nat(assigned_ip, _internal_ip)
                        ip_pool_mgr.manual_assign(ip=_internal_ip, mac=vm_mac, vm_name=name,
                                                  pool_name="__internal__", vm_id=vm_id)
                        threading.Thread(
                            target=_post_install_nat_sync,
                            args=(vm_id, name, vm_mac, assigned_ip),
                            daemon=True,
                            name=f"post-install-nat-{name}"
                        ).start()
                        log.info("Auto IP + NAT kuruldu: %s → %s (internal: %s)",
                                 name, assigned_ip, _internal_ip)
                    else:
                        ev.vm_event(f"IP atandı: {assigned_ip} ({pool_name})", vm_id, level="INFO")

                result["assigned_ip"]  = assigned_ip
                result["internal_ip"]  = _internal_ip if _nat_needed else None
                result["nat_mode"]     = _nat_needed
                result["bridge_mode"]  = _is_bridge_net
                result["gateway"]      = alloc["gateway"]
                result["dns"]          = alloc["dns"]
                result["netmask"]      = alloc["netmask"]
            except Exception as _ip_e:
                log.warning("Auto IP atama başarısız vm=%s: %s", vm_id, _ip_e)
                result["auto_ip_error"] = str(_ip_e)

        ev.vm_event(f"VM oluşturuldu: {name}", vm_id, level="INFO")
        _bg_notify(f"VM oluşturuldu: {name}", level="DEBUG", category="vm",
                   vm_id=vm_id, details={"vm": name, "action": "create",
                                         "vcpus": str(vcpus), "memory_mb": str(memory_mb),
                                         "disk_gb": str(disk_gb)})
        if static_ip:
            ev.vm_event(f"Statik IP atandı: {static_ip} (cloud-init)", vm_id, level="INFO")
            # Persist static IP by MAC so it shows in VM list (bridge VMs)
            if vm_mac:
                try:
                    vm_manager.save_vm_static_ip(vm_mac, static_ip)
                except Exception as _sie:
                    log.warning("Static IP kayıt hatası: %s", _sie)
        if app_install:
            ev.vm_event(f"App kurulum planlandı: {app_install}", vm_id, level="INFO")
        if webhook_mgr: webhook_mgr.trigger("vm.created", {"vm_id": vm_id, "vm_name": name})
        if plugin_sdk_mgr:
            try: plugin_sdk_mgr.emit_event("vm.created", {"vm_id": vm_id, "vm_name": name, "vcpus": vcpus, "memory_mb": memory_mb, "disk_gb": disk_gb})
            except Exception as _pse: log.warning("plugin emit vm.created: %s", _pse)
        if resource_quota: resource_quota.check_quota(get_jwt_identity(), vcpus, memory_mb)
        resp = dict(result)
        if static_ip:
            resp["static_ip"] = static_ip
            resp["gateway"]   = vm_gateway
        if app_install:
            resp["app_install"] = app_install
            resp["app_script"]  = _get_app_install_script(app_install)
        return ok(**resp), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_delete_vm(vm_id):
    delete_disk = request.args.get("delete_disk", "true").lower() == "true"
    try:
        vm = vm_manager.get_vm(vm_id)
        _vm_name_del = vm.get("name", vm_id) if vm else vm_id
        if hook_mgr:
            try: hook_mgr.run_hooks("pre-delete", vm_id, _vm_name_del)
            except Exception as _he: log.warning("pre-delete hook hatası vm=%s: %s", vm_id, _he)
        # Tek seferinde fetch — race condition önle
        assignment     = ip_pool_mgr.get_vm_assignment(vm_id)
        mac            = assignment.get("mac", "") if assignment else ""
        public_ip      = assignment.get("ip", "")  if assignment else ""

        # __internal__ pool'dan gerçek internal IP bul
        internal_ip = None
        try:
            internal_assignments = ip_pool_mgr.list_assignments("__internal__")
            internal_ip = next(
                (a["ip"] for a in internal_assignments if a.get("mac") == mac),
                None
            )
        except Exception:
            pass
        internal_ip = internal_ip or (_mac_to_internal_ip(mac) if mac else "")

        # DHCP static entry sil (internal_ip ile eklenmişti)
        if mac and internal_ip:
            try:
                vm_manager.remove_dhcp_host("default", mac, internal_ip)
            except Exception as _dhcp_e:
                log.warning("DHCP host silinemedi vm=%s: %s", vm_id, _dhcp_e)

        # NAT kurallarını temizle
        if public_ip and internal_ip and public_ip != internal_ip:
            try:
                _remove_nat(public_ip, internal_ip)
            except Exception as _nat_e:
                log.warning("NAT temizleme başarısız vm=%s: %s", vm_id, _nat_e)

        result = vm_manager.delete_vm(vm_id, delete_disk=delete_disk)

        # Tüm IPAM kayıtlarını temizle (vm_id ve mac ile)
        ip_pool_mgr.release_ip(vm_id)
        if mac:
            ip_pool_mgr.release_ip(mac)  # __internal__ entries stored with mac as vm_id
        ev.vm_event(f"VM silindi: {vm.get('name')}", vm_id, level="WARNING")
        if plugin_sdk_mgr:
            try: plugin_sdk_mgr.emit_event("vm.deleted", {"vm_id": vm_id, "vm_name": _vm_name_del})
            except Exception as _pse: log.warning("plugin emit vm.deleted: %s", _pse)
        _bg_notify(f"VM silindi: {_vm_name_del}", level="INFO", category="vm",
                   vm_id=vm_id, details={"vm": _vm_name_del, "action": "delete",
                                         "delete_disk": str(delete_disk)})
        if uptime_tracker:
            try:
                uptime_tracker.delete_uptime(vm_id)
            except Exception:
                pass
        if hook_mgr:
            try: hook_mgr.run_hooks("post-delete", vm_id, _vm_name_del)
            except Exception as _he: log.warning("post-delete hook hatası vm=%s: %s", vm_id, _he)
        return ok(**result)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/start", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator", "vm-user")
def api_start_vm(vm_id):
    _chk = _vmuser_check(vm_id)
    if _chk: return _chk
    try:
        _vm_name_start = ""
        try:
            _vm_start_info = vm_manager.get_vm(vm_id)
            _vm_name_start = _vm_start_info.get("name", vm_id) if _vm_start_info else vm_id
        except Exception:
            _vm_name_start = vm_id
        if hook_mgr:
            try: hook_mgr.run_hooks("pre-start", vm_id, _vm_name_start)
            except Exception as _he: log.warning("pre-start hook hatası vm=%s: %s", vm_id, _he)
        r = vm_manager.start_vm(vm_id)
        ev.vm_event("VM başlatıldı", vm_id)
        _bg_notify(f"VM başlatıldı: {_vm_name_start}", level="DEBUG", category="vm",
                   vm_id=vm_id, details={"vm": _vm_name_start, "action": "start"})
        if webhook_mgr: webhook_mgr.trigger("vm.started", {"vm_id": vm_id})
        if plugin_sdk_mgr:
            try: plugin_sdk_mgr.emit_event("vm.started", {"vm_id": vm_id, "vm_name": _vm_name_start})
            except Exception as _pse: log.warning("plugin emit vm.started: %s", _pse)
        if uptime_tracker: uptime_tracker.record_start(vm_id, "")
        if hook_mgr:
            try: hook_mgr.run_hooks("post-start", vm_id, _vm_name_start)
            except Exception as _he: log.warning("post-start hook hatası vm=%s: %s", vm_id, _he)

        # VM'in public IP ataması varsa NAT kurallarını arka planda senkronize et
        try:
            _si   = _vm_start_info if "_vm_start_info" in dir() else vm_manager.get_vm(vm_id)
            _nets = (_si.get("networks", []) or []) if _si else []
            _mac  = (_si.get("mac", "") or (_nets[0].get("mac", "") if _nets else "")) if _si else ""
            if _mac:
                _pub = next(
                    (a for a in ip_pool_mgr.list_assignments()
                     if a.get("mac") == _mac and a.get("pool") not in ("__internal__", "")),
                    None
                )
                if _pub:
                    threading.Thread(
                        target=_post_install_nat_sync,
                        args=(vm_id, _vm_name_start, _mac, _pub["ip"]),
                        daemon=True,
                        name=f"nat-autostart-{vm_id[:8]}"
                    ).start()
                    log.info("NAT auto-sync tetiklendi: %s → %s", _mac, _pub["ip"])
        except Exception as _nse:
            log.warning("NAT auto-sync başlatılamadı vm=%s: %s", vm_id, _nse)

        return ok(**r)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/stop", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator", "vm-user")
def api_stop_vm(vm_id):
    _chk = _vmuser_check(vm_id)
    if _chk: return _chk
    force = request.args.get("force", "false").lower() == "true"
    try:
        _vm_name_stop = ""
        try:
            _vm_stop_info = vm_manager.get_vm(vm_id)
            _vm_name_stop = _vm_stop_info.get("name", vm_id) if _vm_stop_info else vm_id
        except Exception:
            _vm_name_stop = vm_id
        if hook_mgr:
            try: hook_mgr.run_hooks("pre-stop", vm_id, _vm_name_stop)
            except Exception as _he: log.warning("pre-stop hook hatası vm=%s: %s", vm_id, _he)
        r = vm_manager.stop_vm(vm_id, force=force)
        ev.vm_event("VM durduruldu", vm_id, level="WARNING")
        _bg_notify(f"VM durduruldu: {_vm_name_stop}", level="DEBUG", category="vm",
                   vm_id=vm_id, details={"vm": _vm_name_stop, "action": "stop", "force": str(force)})
        if webhook_mgr: webhook_mgr.trigger("vm.stopped", {"vm_id": vm_id})
        if plugin_sdk_mgr:
            try: plugin_sdk_mgr.emit_event("vm.stopped", {"vm_id": vm_id, "vm_name": _vm_name_stop})
            except Exception as _pse: log.warning("plugin emit vm.stopped: %s", _pse)
        if uptime_tracker: uptime_tracker.record_stop(vm_id)
        if hook_mgr:
            try: hook_mgr.run_hooks("post-stop", vm_id, _vm_name_stop)
            except Exception as _he: log.warning("post-stop hook hatası vm=%s: %s", vm_id, _he)
        return ok(**r)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/reboot", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator", "vm-user")
def api_reboot_vm(vm_id):
    _chk = _vmuser_check(vm_id)
    if _chk: return _chk
    force = request.args.get("force", "false").lower() == "true"
    try:
        _vm_name_rb = vm_id
        try:
            _rb_info = vm_manager.get_vm(vm_id)
            _vm_name_rb = _rb_info.get("name", vm_id) if _rb_info else vm_id
        except Exception:
            pass
        r = vm_manager.reboot_vm(vm_id, force=force)
        _bg_notify(f"VM yeniden başlatıldı: {_vm_name_rb}", level="DEBUG", category="vm",
                   vm_id=vm_id, details={"vm": _vm_name_rb, "action": "reboot", "force": str(force)})
        return ok(**r)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/pause", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator", "vm-user")
def api_pause_vm(vm_id):
    _chk = _vmuser_check(vm_id)
    if _chk: return _chk
    try:
        _vm_name_ps = vm_id
        try:
            _ps_info = vm_manager.get_vm(vm_id)
            _vm_name_ps = _ps_info.get("name", vm_id) if _ps_info else vm_id
        except Exception:
            pass
        r = vm_manager.pause_vm(vm_id)
        _bg_notify(f"VM duraklatıldı: {_vm_name_ps}", level="DEBUG", category="vm",
                   vm_id=vm_id, details={"vm": _vm_name_ps, "action": "pause"})
        return ok(**r)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/resume", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator", "vm-user")
def api_resume_vm(vm_id):
    _chk = _vmuser_check(vm_id)
    if _chk: return _chk
    try:
        _vm_name_rs = vm_id
        try:
            _rs_info = vm_manager.get_vm(vm_id)
            _vm_name_rs = _rs_info.get("name", vm_id) if _rs_info else vm_id
        except Exception:
            pass
        r = vm_manager.resume_vm(vm_id)
        _bg_notify(f"VM devam ettirildi: {_vm_name_rs}", level="DEBUG", category="vm",
                   vm_id=vm_id, details={"vm": _vm_name_rs, "action": "resume"})
        return ok(**r)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/stats")
@require_auth
def api_vm_stats(vm_id):
    try:
        return ok(stats=vm_manager.get_vm_stats(vm_id))
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/perf")
@require_auth
def api_vm_perf(vm_id):
    """
    Live performance metrics via rolling sample cache — no blocking sleep.
    First call returns RAM instantly (CPU/IO = 0); subsequent calls diff
    against the previous sample using the real elapsed time.
    """
    try:
        s2 = vm_manager.get_vm_stats(vm_id)
        if s2.get("state") == "stopped":
            with _perf_cache_lock:
                _perf_cache.pop(vm_id, None)
            return ok(state="stopped", cpu_percent=0, ram_percent=0,
                      ram_used_mb=0, ram_total_mb=0,
                      disk_read_mbs=0, disk_write_mbs=0,
                      net_rx_mbs=0, net_tx_mbs=0)

        t2 = time.monotonic()
        with _perf_cache_lock:
            prev = _perf_cache.get(vm_id)
            _perf_cache[vm_id] = {"ts": t2, "stats": s2}

        mem_kb  = s2.get("memory_kb", 0)
        max_kb  = s2.get("max_memory_kb", 0) or mem_kb or 1
        ram_pct = min(100.0, (mem_kb / max_kb) * 100) if max_kb else 0

        # No previous sample or sample too stale → return RAM, zeroes for deltas
        if not prev or (t2 - prev["ts"]) > 15.0:
            return ok(state=s2.get("state", "running"),
                      cpu_percent=0.0,
                      ram_percent=round(ram_pct, 2),
                      ram_used_mb=round(mem_kb / 1024, 1),
                      ram_total_mb=round(max_kb / 1024, 1),
                      disk_read_mbs=0.0, disk_write_mbs=0.0,
                      net_rx_mbs=0.0, net_tx_mbs=0.0)

        s1      = prev["stats"]
        elapsed = max(t2 - prev["ts"], 0.1)

        vcpus     = max(s2.get("vcpus", 1), 1)
        cpu_delta = s2.get("cpu_time_ns", 0) - s1.get("cpu_time_ns", 0)
        cpu_pct   = min(100.0, max(0.0,
                        (cpu_delta / (elapsed * 1e9 * vcpus)) * 100))

        d1s   = s1.get("disk_stats", {})
        d2s   = s2.get("disk_stats", {})
        drb   = sum((d2s.get(k, {}).get("read_bytes",  0) - d1s.get(k, {}).get("read_bytes",  0)) for k in d2s)
        dwb   = sum((d2s.get(k, {}).get("write_bytes", 0) - d1s.get(k, {}).get("write_bytes", 0)) for k in d2s)
        disk_r = max(0.0, drb / elapsed / 1_048_576)
        disk_w = max(0.0, dwb / elapsed / 1_048_576)

        n1s   = s1.get("net_stats", {})
        n2s   = s2.get("net_stats", {})
        rxb   = sum((n2s.get(k, {}).get("rx_bytes", 0) - n1s.get(k, {}).get("rx_bytes", 0)) for k in n2s)
        txb   = sum((n2s.get(k, {}).get("tx_bytes", 0) - n1s.get(k, {}).get("tx_bytes", 0)) for k in n2s)
        net_rx = max(0.0, rxb / elapsed / 1_048_576)
        net_tx = max(0.0, txb / elapsed / 1_048_576)

        return ok(
            state          = s2.get("state", "running"),
            cpu_percent    = round(cpu_pct, 2),
            ram_percent    = round(ram_pct, 2),
            ram_used_mb    = round(mem_kb / 1024, 1),
            ram_total_mb   = round(max_kb / 1024, 1),
            disk_read_mbs  = round(disk_r, 3),
            disk_write_mbs = round(disk_w, 3),
            net_rx_mbs     = round(net_rx, 3),
            net_tx_mbs     = round(net_tx, 3),
        )
    except Exception as e:
        return err(e, 500)

# ── Clone job store ──────────────────────────────────────────────────────────
_clone_jobs: dict = {}   # job_id → {status, name, result, error, started_at}
_clone_jobs_lock = threading.Lock()


@app.route("/api/vms/<vm_id>/clone", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_clone_vm(vm_id):
    data = request.get_json() or {}
    new_name = (data.get("new_name") or data.get("name") or "").strip()
    if not new_name:
        return err("Yeni VM adı zorunludur")

    import uuid as _clone_uuid
    job_id = str(_clone_uuid.uuid4())[:12]

    with _clone_jobs_lock:
        _clone_jobs[job_id] = {
            "status":     "running",
            "name":       new_name,
            "vm_id":      vm_id,
            "started_at": _time_mod.time(),
            "result":     None,
            "error":      None,
        }

    def _do_clone():
        try:
            result = vm_manager.clone_vm(vm_id, new_name)
            ev.info(f"VM klonlandı: {vm_id} → {new_name}", category="vm")
            with _clone_jobs_lock:
                _clone_jobs[job_id]["status"] = "done"
                _clone_jobs[job_id]["result"] = result
        except Exception as _ce:
            log.error("clone_vm failed: vm=%s new_name=%s: %s", vm_id, new_name, _ce)
            with _clone_jobs_lock:
                _clone_jobs[job_id]["status"] = "error"
                _clone_jobs[job_id]["error"]  = str(_ce)

    threading.Thread(target=_do_clone, daemon=True, name=f"clone-{job_id}").start()
    return ok(job_id=job_id, status="running", name=new_name), 202


@app.route("/api/vms/clone-jobs/<job_id>", methods=["GET"])
@require_auth
def api_clone_job_status(job_id):
    with _clone_jobs_lock:
        job = _clone_jobs.get(job_id)
    if not job:
        return err("Klon görevi bulunamadı", 404)
    return ok(**job)

# ── Hardware Tuning & Hot-Plug ────────────────────────────────────────────────

@app.route("/api/vms/<vm_id>/hardware", methods=["GET"])
@require_auth
def api_vm_hardware_get(vm_id):
    try:
        return ok(**vm_manager.get_hardware_config(vm_id))
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/hardware/vcpus", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_hot_vcpus(vm_id):
    data = request.get_json() or {}
    count = int(data.get("count", 1))
    if count < 1 or count > 128:
        return err("vCPU sayısı 1-128 arası olmalı")
    try:
        result = vm_manager.hot_set_vcpus(vm_id, count)
        ev.info(f"vCPU değiştirildi: {vm_id} → {count} ({'live' if result['live'] else 'config'})", category="vm")
        return ok(**result)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/hardware/memory", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_hot_memory(vm_id):
    data = request.get_json() or {}
    mb = int(data.get("mb", 512))
    if mb < 128:
        return err("Minimum 128 MB")
    try:
        result = vm_manager.hot_set_memory(vm_id, mb)
        ev.info(f"Bellek değiştirildi: {vm_id} → {mb} MB ({'live' if result['live'] else 'config'})", category="vm")
        return ok(**result)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/hardware/cpu-mode", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_cpu_mode(vm_id):
    data = request.get_json() or {}
    mode = data.get("mode", "host-passthrough")
    try:
        result = vm_manager.set_cpu_mode(vm_id, mode)
        ev.info(f"CPU modu değiştirildi: {vm_id} → {mode}", category="vm")
        return ok(**result)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/hardware/nested-virt", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_nested_virt(vm_id):
    data = request.get_json() or {}
    enabled = bool(data.get("enabled", False))
    try:
        result = vm_manager.set_nested_virt(vm_id, enabled)
        ev.info(f"Nested virt {'açıldı' if enabled else 'kapatıldı'}: {vm_id}", category="vm")
        return ok(**result)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/hardware/sound", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_sound(vm_id):
    """Ses kartı ekle/kaldır. model='' → kaldır."""
    data  = request.get_json() or {}
    model = data.get("model", "")
    _VALID = {"", "ich9", "ich6", "ac97", "usb-audio"}
    if model not in _VALID:
        return err(f"Geçersiz ses modeli: {model}", 400)
    try:
        conn   = vm_manager._libvirt_conn()
        domain = conn.lookupByName(vm_id)
        desc   = domain.XMLDesc()
        import xml.etree.ElementTree as _ET
        root = _ET.fromstring(desc)
        devices = root.find("devices")
        # Remove existing sound cards
        for s in devices.findall("sound"):
            devices.remove(s)
        if model:
            s_el = _ET.SubElement(devices, "sound")
            s_el.set("model", model)
        # Redefine (offline edit)
        new_xml = _ET.tostring(root, encoding="unicode")
        conn.defineXML(new_xml)
        conn.close()
        ev.info(f"Ses kartı güncellendi: {vm_id} model={model or 'kaldırıldı'}", category="vm")
        return ok(model=model, message="Ses kartı güncellendi. VM yeniden başlatılmalı.")
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/hardware/video", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_video(vm_id):
    """Sanal GPU/video adaptörünü güncelle."""
    data  = request.get_json() or {}
    model = data.get("model", "virtio")
    _VALID = {"virtio", "qxl", "vga", "cirrus", "vmvga"}
    if model not in _VALID:
        return err(f"Geçersiz video modeli: {model}", 400)
    try:
        conn   = vm_manager._libvirt_conn()
        domain = conn.lookupByName(vm_id)
        desc   = domain.XMLDesc()
        import xml.etree.ElementTree as _ET
        root = _ET.fromstring(desc)
        devices = root.find("devices")
        for v in devices.findall("video"):
            devices.remove(v)
        v_el = _ET.SubElement(devices, "video")
        m_el = _ET.SubElement(v_el, "model")
        m_el.set("type", model)
        m_el.set("vram", "16384")
        m_el.set("heads", "1")
        new_xml = _ET.tostring(root, encoding="unicode")
        conn.defineXML(new_xml)
        conn.close()
        ev.info(f"Video adapter güncellendi: {vm_id} model={model}", category="vm")
        return ok(model=model, message="Video adapter güncellendi.")
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/hardware/gpu-passthrough", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_vm_gpu_passthrough(vm_id):
    """PCI GPU passthrough ekle (IOMMU/VFIO gerekli)."""
    data = request.get_json() or {}
    pci  = data.get("pci_address", "")  # e.g. "0000:01:00.0"
    if not pci:
        return err("pci_address gerekli", 400)
    try:
        # Validate PCI address format
        import re as _re_pci
        if not _re_pci.match(r'^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]$', pci):
            return err("Geçersiz PCI adresi formatı (beklenen: DDDD:BB:DD.F)", 400)
        domain_part, bus, slot_fn = pci.split(":")
        slot, fn = slot_fn.split(".")
        conn   = vm_manager._libvirt_conn()
        domain = conn.lookupByName(vm_id)
        import xml.etree.ElementTree as _ET
        root = _ET.fromstring(domain.XMLDesc())
        devices = root.find("devices")
        h_el = _ET.SubElement(devices, "hostdev")
        h_el.set("mode", "subsystem"); h_el.set("type", "pci"); h_el.set("managed", "yes")
        src = _ET.SubElement(h_el, "source")
        addr = _ET.SubElement(src, "address")
        addr.set("type", "pci")
        addr.set("domain", "0x" + domain_part)
        addr.set("bus", "0x" + bus)
        addr.set("slot", "0x" + slot)
        addr.set("function", "0x" + fn)
        conn.defineXML(_ET.tostring(root, encoding="unicode"))
        conn.close()
        ev.info(f"GPU passthrough eklendi: {vm_id} pci={pci}", category="vm")
        return ok(pci=pci, message="GPU passthrough eklendi. IOMMU ve VFIO aktif olmalı.")
    except Exception as e:
        return err(e, 500)

@app.route("/api/system/gpus")
@require_auth
def api_system_gpus():
    """Host üzerindeki GPU'ları listele (lspci)."""
    try:
        r = subprocess.run(
            ["lspci", "-D"],
            capture_output=True, text=True, timeout=10
        )
        gpus = []
        for line in r.stdout.splitlines():
            if any(x in line.lower() for x in ["vga", "3d controller", "display controller", "nvidia", "amd/ati", "radeon"]):
                parts = line.split(" ", 1)
                pci   = parts[0].strip()
                name  = parts[1].strip() if len(parts) > 1 else line
                gpus.append({"pci": pci, "name": name})
        return ok(gpus=gpus)
    except Exception as e:
        return ok(gpus=[], error=str(e))

@app.route("/api/vms/<vm_id>/hardware/disk/attach", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_disk_attach(vm_id):
    data = request.get_json() or {}
    size_gb  = int(data.get("size_gb", 10))
    bus      = data.get("bus", "virtio")
    disk_fmt = data.get("format", "qcow2")
    try:
        disk_path = vm_manager.create_extra_disk(vm_id, size_gb, disk_fmt)
        result = vm_manager.hot_attach_disk(vm_id, disk_path, bus)
        ev.info(f"Disk eklendi: {vm_id} → {disk_path} ({size_gb}GB)", category="vm")
        return ok(**result, size_gb=size_gb), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/hardware/disk/<target_dev>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_disk_detach(vm_id, target_dev):
    try:
        result = vm_manager.hot_detach_disk(vm_id, target_dev)
        ev.info(f"Disk çıkarıldı: {vm_id} / {target_dev}", category="vm")
        return ok(**result)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/disk-backup", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_disk_backup(vm_id):
    """Clone a VM disk to a destination path using qemu-img convert."""
    data      = request.get_json() or {}
    device    = data.get("device", "vda")
    dest_path = data.get("dest_path", "")
    if not dest_path:
        return err("dest_path gerekli", 400)
    # Prevent path traversal — dest must be absolute and inside an allowed base
    import os, re as _re
    _ALLOWED_BACKUP_DIRS = [
        "/var/lib/libvirt/images",
        "/var/lib/oxware/backups",
        "/backups",
        "/mnt",
        "/srv",
    ]
    dest_path = os.path.realpath(dest_path)
    if not any(dest_path.startswith(d) for d in _ALLOWED_BACKUP_DIRS):
        return err(f"Hedef yol izin verilmeyen bir dizinde: {dest_path}", 403)
    # device must be safe alphanumeric (e.g. vda, sdb, hdc)
    if not _re.match(r'^[a-z]{2,4}\d*$', device):
        return err("Geçersiz disk aygıtı", 400)
    try:
        import subprocess, xml.etree.ElementTree as ET
        conn = vm_manager._connect()
        dom  = conn.lookupByName(vm_id)
        root = ET.fromstring(dom.XMLDesc(0))
        src  = None
        for disk in root.findall(".//disk[@type='file']"):
            tgt = disk.find("target")
            src_el = disk.find("source")
            if tgt is not None and tgt.get("dev") == device and src_el is not None:
                src = src_el.get("file")
                break
        conn.close()
        if not src:
            return err(f"Disk bulunamadı: {device}", 404)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        r = subprocess.run(
            ["qemu-img", "convert", "-O", "qcow2", src, dest_path],
            capture_output=True, text=True, timeout=3600
        )
        if r.returncode != 0:
            return err(r.stderr or "qemu-img hatası", 500)
        ev.info(f"Disk yedeği: {vm_id}/{device} → {dest_path}", category="vm")
        return ok(dest=dest_path, source=src)
    except Exception as e:
        return err(e, 500)


@app.route("/api/vms/<vm_id>/disk-wipe", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_vm_disk_wipe(vm_id):
    """Detach a secondary disk and zero-fill it, then delete the image file."""
    import re as _re2, os
    data   = request.get_json() or {}
    device = data.get("device", "")
    if not device or device in ("vda", "sda", "hda"):
        return err("Ana disk silinemez", 400)
    if not _re2.match(r'^[a-z]{2,4}\d*$', device):
        return err("Geçersiz disk aygıtı", 400)
    try:
        import subprocess, xml.etree.ElementTree as ET
        conn = vm_manager._connect()
        dom  = conn.lookupByName(vm_id)
        root = ET.fromstring(dom.XMLDesc(0))
        src  = None
        for disk in root.findall(".//disk[@type='file']"):
            tgt = disk.find("target")
            src_el = disk.find("source")
            if tgt is not None and tgt.get("dev") == device and src_el is not None:
                src = src_el.get("file")
                break
        conn.close()
        if not src:
            return err(f"Disk bulunamadı: {device}", 404)
        # Verify src is inside a known libvirt/oxware path before wiping
        src_real = os.path.realpath(src)
        _safe_roots = ["/var/lib/libvirt/images", "/var/lib/oxware", "/srv", "/mnt"]
        if not any(src_real.startswith(r) for r in _safe_roots):
            return err("Disk dosyası güvenli dizin dışında — silme engellendi", 403)
        # Detach first
        vm_manager.hot_detach_disk(vm_id, device)
        # Zero-fill then remove
        subprocess.run(["dd", "if=/dev/zero", f"of={src_real}", "bs=1M"], capture_output=True, timeout=300)
        if os.path.exists(src_real):
            os.remove(src_real)
        ev.info(f"Disk silindi: {vm_id}/{device} ({src_real})", category="vm")
        return ok(deleted=src_real)
    except Exception as e:
        return err(e, 500)


@app.route("/api/vms/<vm_id>/hardware/nic/attach", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_nic_attach(vm_id):
    data = request.get_json() or {}
    network = data.get("network", "default")
    model   = data.get("model", "virtio")
    try:
        result = vm_manager.hot_attach_nic(vm_id, network, model)
        ev.info(f"NIC eklendi: {vm_id} → {network}", category="vm")
        return ok(**result), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/hardware/nic/<path:mac>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_nic_detach(vm_id, mac):
    try:
        result = vm_manager.hot_detach_nic(vm_id, mac)
        ev.info(f"NIC çıkarıldı: {vm_id} / {mac}", category="vm")
        return ok(**result)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/autostart", methods=["PUT"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_autostart(vm_id):
    data = request.get_json() or {}
    return ok(**vm_manager.set_autostart(vm_id, bool(data.get("enabled", False))))

def _is_windows_vm(vm_name: str) -> bool:
    """Libvirt XML'de <hyperv> veya Windows işaretlerine göre Windows VM mi?"""
    try:
        r = subprocess.run(["virsh", "dumpxml", vm_name],
                           capture_output=True, text=True, timeout=5)
        xml = r.stdout.lower()
        return "<hyperv>" in xml or "windows" in xml or "win10" in xml or "win11" in xml
    except Exception:
        return False


@app.route("/api/vms/<vm_id>/enable-ssh", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_enable_ssh(vm_id):
    """QEMU Guest Agent üzerinden VM'de SSH (Linux) veya RDP (Windows) bilgisi döndür."""
    _GUEST_AGENT_INSTALL = (
        "apt update && apt install -y qemu-guest-agent openssh-server && "
        "systemctl enable --now qemu-guest-agent ssh"
    )
    try:
        vm = vm_manager.get_vm(vm_id)
        vm_name = vm.get("name", vm_id)

        # Windows VM ise RDP bilgisi döndür
        if _is_windows_vm(vm_name):
            # Public IP'yi IPAM'dan bul
            public_ip = None
            try:
                _nets = vm.get("networks", [])
                mac = vm.get("mac", "") or (_nets[0]["mac"] if _nets else "")
                assignments = ip_pool_mgr.list_assignments()
                public_ip = next(
                    (a["ip"] for a in assignments
                     if a.get("mac") == mac and a.get("pool") != "__internal__"),
                    None
                )
            except Exception:
                pass
            return jsonify({
                "success": True,
                "protocol": "rdp",
                "host": public_ip or vm.get("ip", ""),
                "port": 3389,
                "message": f"RDP ile bağlanın: {public_ip or ''}:3389 — Windows Uzak Masaüstü kullanın.",
            }), 200

        cmd_payload = json.dumps({
            "execute": "guest-exec",
            "arguments": {
                "path": "/bin/bash",
                "arg": ["-c", "systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null; echo done"],
                "capture-output": True
            }
        })
        result = subprocess.run(
            ["virsh", "qemu-agent-command", vm_name, cmd_payload],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            # Guest agent yüklü değil veya bağlı değil
            not_connected = any(x in stderr.lower() for x in [
                "not responding", "not connected", "agent is not", "no agent"
            ])
            return jsonify({
                "success": False,
                "needs_guest_agent": not_connected,
                "error": stderr or "Guest agent bağlı değil",
                "install_cmd": _GUEST_AGENT_INSTALL if not_connected else None,
                "vm_name": vm_name,
            }), 200  # 200 döndür ki frontend mesajı parse edebilsin

        # exec-status al
        try:
            exec_result = json.loads(result.stdout)
            pid = exec_result.get("return", {}).get("pid")
            if pid:
                time.sleep(1)
                status_payload = json.dumps({"execute": "guest-exec-status", "arguments": {"pid": pid}})
                status_result = subprocess.run(
                    ["virsh", "qemu-agent-command", vm_name, status_payload],
                    capture_output=True, text=True, timeout=10
                )
                status_data = json.loads(status_result.stdout) if status_result.returncode == 0 else {}
                ret = status_data.get("return", {})
                exitcode = ret.get("exitcode", 0)
                if exitcode != 0:
                    import base64
                    out_b64 = ret.get("err-data", "")
                    err_out = base64.b64decode(out_b64).decode("utf-8", errors="replace") if out_b64 else ""
                    return jsonify({"success": False, "error": f"exit {exitcode}: {err_out}",
                                    "needs_guest_agent": False}), 200
        except Exception:
            pass
        return ok(message="SSH servisi etkinleştirildi ve başlatıldı")
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/vms/<vm_id>/reset-password", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_reset_password(vm_id):
    """
    QEMU Guest Agent ile çalışan VM içinde şifre sıfırla.
    Ayrıca SSH password auth'u etkinleştirir.
    Body: { "username": "...", "password": "..." }
    """
    # request.json can be a string if frontend double-serializes the body
    raw = request.json
    if isinstance(raw, str):
        try:
            import json as _jsn
            raw = _jsn.loads(raw)
        except Exception:
            raw = {}
    data = raw if isinstance(raw, dict) else {}

    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"success": False, "error": "username ve password gerekli"}), 200

    try:
        vm      = vm_manager.get_vm(vm_id)
        vm_name = vm.get("name", vm_id)

        # Kabuk injection'a karşı: sadece güvenli karakterlere izin ver
        import re as _re
        if not _re.match(r'^[A-Za-z0-9_\-]+$', username):
            return jsonify({"success": False, "error": "Geçersiz kullanıcı adı karakteri"}), 200
        if len(password) > 128:
            return jsonify({"success": False, "error": "Şifre çok uzun (max 128)"}), 200

        # Şifreyi base64 ile geç — tek tırnak/özel karakter sorununu önler
        import base64 as _b64
        pw_b64   = _b64.b64encode(password.encode()).decode()
        user_b64 = _b64.b64encode(username.encode()).decode()

        script = (
            # Decode from base64 → safe to use in printf
            f"PW=$(echo {pw_b64} | base64 -d); "
            f"USER=$(echo {user_b64} | base64 -d); "
            # Set passwords
            f"printf \"$USER:$PW\\nroot:$PW\\n\" | chpasswd; "
            # Unlock accounts
            f"passwd -u \"$USER\" 2>/dev/null; passwd -u root 2>/dev/null; "
            # Enable SSH password auth
            f"SSHCFG=/etc/ssh/sshd_config; "
            f"sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' \"$SSHCFG\"; "
            f"grep -q '^PasswordAuthentication yes' \"$SSHCFG\" || echo 'PasswordAuthentication yes' >> \"$SSHCFG\"; "
            # Reload sshd
            f"systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || "
            f"service ssh reload 2>/dev/null || service sshd reload 2>/dev/null; "
            f"echo OXWARE_DONE"
        )

        cmd_payload = json.dumps({
            "execute": "guest-exec",
            "arguments": {
                "path": "/bin/bash",
                "arg": ["-c", script],
                "capture-output": True
            }
        })

        result = subprocess.run(
            ["virsh", "qemu-agent-command", vm_name, cmd_payload],
            capture_output=True, text=True, timeout=20
        )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            not_connected = any(x in stderr.lower() for x in [
                "not responding", "not connected", "agent is not", "no agent", "error: unable"
            ])
            return jsonify({
                "success": False,
                "needs_guest_agent": not_connected,
                "error": stderr or "Guest agent bağlı değil",
                "install_cmd": (
                    "apt update && apt install -y qemu-guest-agent && "
                    "systemctl enable --now qemu-guest-agent"
                ) if not_connected else None,
            }), 200

        # Read exec result and wait for completion
        try:
            pid = json.loads(result.stdout).get("return", {}).get("pid")
            if pid:
                time.sleep(1.5)
                status_payload = json.dumps({
                    "execute": "guest-exec-status",
                    "arguments": {"pid": pid}
                })
                sr = subprocess.run(
                    ["virsh", "qemu-agent-command", vm_name, status_payload],
                    capture_output=True, text=True, timeout=10
                )
                if sr.returncode == 0:
                    ret     = json.loads(sr.stdout).get("return", {})
                    exitcode = ret.get("exitcode", 0)
                    if exitcode != 0:
                        import base64 as _b64e
                        err_b64 = ret.get("err-data", "")
                        err_txt = _b64e.b64decode(err_b64).decode("utf-8", errors="replace") if err_b64 else ""
                        return jsonify({"success": False, "error": f"exit {exitcode}: {err_txt}"}), 200
        except Exception:
            pass

        return jsonify({
            "success": True,
            "message": f"'{username}' şifresi sıfırlandı, SSH password auth etkinleştirildi."
        }), 200

    except Exception as e:
        _log.error("reset-password hata vm=%s: %s", vm_id, e, exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 200


@app.route("/api/vms/<vm_id>/port-forwards", methods=["GET"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_port_forwards_list(vm_id):
    """VM için aktif port yönlendirme (DNAT) kurallarını listele."""
    try:
        vm = vm_manager.get_vm(vm_id)
        _vm_mac = vm.get("mac", "")
        _host_ips = set(_get_host_ips())
        # Find VM internal IP
        _int_ip = ""
        try:
            _int_assigns = ip_pool_mgr.list_assignments("__internal__")
            _int_entry = next((a for a in _int_assigns if a.get("mac") == _vm_mac), None)
            if _int_entry:
                _int_ip = _int_entry["ip"]
            if not _int_ip:
                for _n in (vm.get("networks") or []):
                    if _n.get("ip") and _n["ip"] not in _host_ips:
                        _int_ip = _n["ip"]
                        break
        except Exception:
            pass
        # Get current DNAT rules
        rules = []
        try:
            r = subprocess.run(["iptables", "-t", "nat", "-S", "PREROUTING"],
                               capture_output=True, text=True, timeout=5)
            import re as _re
            for line in r.stdout.splitlines():
                if "DNAT" not in line:
                    continue
                # Match: -A PREROUTING -p tcp -d HOST_IP --dport PORT -j DNAT --to-destination INTERNAL_IP:PORT
                m = _re.search(
                    r"-p (\w+).*?(?:-d ([\d.]+)\s)?.*?--dport (\d+).*?--to-destination ([\d.:]+)",
                    line
                )
                if m:
                    proto, dest_ip, host_port, to_dest = m.groups()
                    to_parts = to_dest.split(":")
                    vm_ip   = to_parts[0]
                    vm_port = to_parts[1] if len(to_parts) > 1 else host_port
                    # Only show rules relevant to this VM's internal IP
                    if not _int_ip or vm_ip == _int_ip:
                        rules.append({
                            "proto": proto,
                            "host_ip": dest_ip or "",
                            "host_port": host_port,
                            "vm_ip": vm_ip,
                            "vm_port": vm_port,
                            "rule": line.strip(),
                        })
        except Exception as _re_e:
            log.warning("port-forwards list hatası: %s", _re_e)
        return ok(rules=rules, internal_ip=_int_ip, host_ips=list(_host_ips))
    except Exception as e:
        return err(e)


@app.route("/api/vms/<vm_id>/port-forwards", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_vm_port_forwards_add(vm_id):
    """VM'e port yönlendirme (DNAT) kuralı ekle."""
    try:
        d = request.get_json(silent=True) or {}
        proto     = d.get("proto", "tcp").lower()
        host_ip   = d.get("host_ip", "")
        host_port = str(d.get("host_port", ""))
        vm_ip     = d.get("vm_ip", "")
        vm_port   = str(d.get("vm_port", host_port))

        if proto not in ("tcp", "udp"):
            return err("proto tcp veya udp olmalı", 400)
        if not host_port.isdigit() or not vm_port.isdigit():
            return err("Geçerli port numarası girin", 400)
        if not vm_ip:
            return err("vm_ip zorunlu", 400)

        # Auto-detect host IP if not specified
        if not host_ip:
            _hips = _get_host_ips()
            host_ip = _hips[0] if _hips else ""
        if not host_ip:
            return err("Host IP tespit edilemedi", 400)

        # Enable ip_forward
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                       capture_output=True, timeout=5)

        # Ensure MASQUERADE for VM network
        try:
            _vm_net = str(ipaddress.IPv4Network(f"{vm_ip}/24", strict=False))
            subprocess.run([
                "iptables", "-t", "nat", "-C", "POSTROUTING",
                "-s", _vm_net, "!", "-d", _vm_net, "-j", "MASQUERADE"
            ], capture_output=True, timeout=5)
        except Exception:
            try:
                _vm_net = str(ipaddress.IPv4Network(f"{vm_ip}/24", strict=False))
                subprocess.run([
                    "iptables", "-t", "nat", "-A", "POSTROUTING",
                    "-s", _vm_net, "!", "-d", _vm_net, "-j", "MASQUERADE"
                ], capture_output=True, timeout=5)
            except Exception:
                pass

        # Check if rule already exists
        check = subprocess.run([
            "iptables", "-t", "nat", "-C", "PREROUTING",
            "-p", proto, "-d", host_ip, "--dport", host_port,
            "-j", "DNAT", "--to-destination", f"{vm_ip}:{vm_port}"
        ], capture_output=True, timeout=5)

        if check.returncode == 0:
            return ok(message="Kural zaten mevcut", host_port=host_port, vm_ip=vm_ip, vm_port=vm_port)

        # Add DNAT rule
        r = subprocess.run([
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "-p", proto, "-d", host_ip, "--dport", host_port,
            "-j", "DNAT", "--to-destination", f"{vm_ip}:{vm_port}"
        ], capture_output=True, text=True, timeout=10)

        # Also add FORWARD rule to allow traffic
        subprocess.run([
            "iptables", "-A", "FORWARD",
            "-p", proto, "-d", vm_ip, "--dport", vm_port, "-j", "ACCEPT"
        ], capture_output=True, timeout=5)

        if r.returncode == 0:
            _bg_notify(
                f"Port yönlendirme eklendi: {host_ip}:{host_port} → {vm_ip}:{vm_port} ({proto.upper()})",
                level="INFO", category="network",
                details={"proto": proto, "host_port": host_port, "vm_ip": vm_ip, "vm_port": vm_port}
            )
            ev.info(f"Port yönlendirme eklendi: {host_ip}:{host_port} → {vm_ip}:{vm_port}", category="network")
            threading.Thread(target=_save_iptables_rules, daemon=True).start()
            return ok(
                added=True, proto=proto,
                host_ip=host_ip, host_port=host_port,
                vm_ip=vm_ip, vm_port=vm_port,
                message=f"{host_ip}:{host_port} → {vm_ip}:{vm_port} ({proto.upper()}) eklendi"
            )
        else:
            return err(f"iptables hatası: {r.stderr.strip()}", 500)
    except Exception as e:
        return err(e)


@app.route("/api/vms/<vm_id>/port-forwards", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_vm_port_forwards_delete(vm_id):
    """Port yönlendirme kuralını sil.

    OXW-2026-PF-001 fix: Frontend bazen host_ip göndermiyor → iptables komutuna
    `-d ''` geçirilince "host/network '' not found" hatası alıyorduk.
    Çözüm: host_ip boşsa iptables -S PREROUTING ile mevcut kuralı bul, gerçek
    -A satırını alıp -A→-D yaparak sil. Eşleşme bulunamazsa zaten silinmiştir.
    """
    try:
        d = request.get_json(silent=True) or {}
        proto     = (d.get("proto") or "tcp").lower().strip()
        host_ip   = (d.get("host_ip") or "").strip()
        host_port = str(d.get("host_port") or "").strip()
        vm_ip     = (d.get("vm_ip") or "").strip()
        vm_port   = str(d.get("vm_port") or host_port).strip()

        # host_ip artık ZORUNLU değil — listeden bulacağız
        if not all([proto, host_port, vm_ip, vm_port]):
            return err("proto/host_port/vm_ip/vm_port zorunlu", 400)
        if proto not in ("tcp", "udp"):
            return err("proto sadece tcp veya udp olabilir", 400)

        # Mevcut PREROUTING kurallarını çıkar, eşleşeni bul
        ls = subprocess.run(
            ["iptables", "-t", "nat", "-S", "PREROUTING"],
            capture_output=True, text=True, timeout=5
        )
        if ls.returncode != 0:
            return err(f"iptables list hatası: {ls.stderr.strip()}", 500)

        matched_line = None
        # Eşleşme kriteri: proto + --dport host_port + --to-destination vm_ip:vm_port
        needle_dest = f"--to-destination {vm_ip}:{vm_port}"
        needle_dport = f"--dport {host_port}"
        needle_proto = f"-p {proto}"
        for line in ls.stdout.splitlines():
            if not line.startswith("-A PREROUTING"):
                continue
            if needle_proto not in line:
                continue
            if needle_dport not in line:
                continue
            if needle_dest not in line:
                continue
            # host_ip belirtilmişse onu da doğrula (defense-in-depth)
            if host_ip and f"-d {host_ip}" not in line and f"-d {host_ip}/32" not in line:
                continue
            matched_line = line
            break

        if not matched_line:
            # Kural zaten yok — idempotent başarı
            ev.info(f"Port yönlendirme zaten yok (idempotent): :{host_port}→{vm_ip}:{vm_port}", category="network")
            # FORWARD ACCEPT'i de temizlemeyi dene (zararsız fail)
            subprocess.run(
                ["iptables", "-D", "FORWARD", "-p", proto, "-d", vm_ip, "--dport", vm_port, "-j", "ACCEPT"],
                capture_output=True, timeout=5
            )
            return ok(deleted=True, already_absent=True)

        # -A → -D çevir ve parçala
        del_parts = matched_line.replace("-A PREROUTING", "-D PREROUTING", 1).split()
        r = subprocess.run(
            ["iptables", "-t", "nat"] + del_parts,
            capture_output=True, text=True, timeout=10
        )

        # FORWARD chain ACCEPT kuralını da kaldır (varsa)
        subprocess.run(
            ["iptables", "-D", "FORWARD", "-p", proto, "-d", vm_ip, "--dport", vm_port, "-j", "ACCEPT"],
            capture_output=True, timeout=5
        )

        if r.returncode == 0:
            ev.info(f"Port yönlendirme silindi: :{host_port} → {vm_ip}:{vm_port}", category="network")
            threading.Thread(target=_save_iptables_rules, daemon=True).start()
            return ok(deleted=True)
        else:
            return err(f"iptables hatası: {r.stderr.strip() or 'bilinmeyen hata'}", 500)
    except Exception as e:
        return err(str(e))


_PF_RULES_FILE = "/var/lib/oxware/pf_rules.json"

def _save_iptables_rules():
    """iptables kurallarını dosyaya kaydet (reboot kalıcılığı)."""
    try:
        # iptables-save ile tüm kuralları dök
        r = subprocess.run(["iptables-save"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            # /etc/iptables/rules.v4 varsa oraya kaydet (iptables-persistent)
            rules_paths = [
                "/etc/iptables/rules.v4",
                "/etc/iptables.rules",
            ]
            for rp in rules_paths:
                import pathlib as _pl
                if _pl.Path(rp).parent.exists():
                    try:
                        _pl.Path(rp).write_text(r.stdout)
                        log.info("iptables kuralları kaydedildi: %s", rp)
                        break
                    except Exception:
                        pass
            # Ayrıca OXware'in kendi formatında da tut (restore için)
            os.makedirs(os.path.dirname(_PF_RULES_FILE), exist_ok=True)
            with open(_PF_RULES_FILE, "w") as f:
                f.write(r.stdout)
    except Exception as _pe:
        log.warning("iptables kaydetme hatası: %s", _pe)


def _restore_iptables_rules():
    """Kaydedilmiş iptables kurallarını yükle (servis başlangıcında çağrılır)."""
    try:
        rules_paths = [
            "/etc/iptables/rules.v4",
            "/etc/iptables.rules",
            _PF_RULES_FILE,
        ]
        for rp in rules_paths:
            if os.path.exists(rp):
                r = subprocess.run(["iptables-restore", rp],
                                   capture_output=True, timeout=10)
                if r.returncode == 0:
                    log.info("iptables kuralları yüklendi: %s", rp)
                    return True
    except Exception as _re:
        log.warning("iptables geri yükleme hatası: %s", _re)
    return False


@app.route("/api/vms/<vm_id>/nat-sync", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_nat_sync(vm_id):
    """VM'in mevcut IP'sini ARP'tan okuyup DNAT'ı hemen güncelle (manuel tetikleme)."""
    try:
        vm = vm_manager.get_vm(vm_id)
        vm_name = vm.get("name", vm_id)
        # MAC: networks listesinin ilk elemanından al
        nets = vm.get("networks", [])
        mac = vm.get("mac", "") or (nets[0]["mac"] if nets else "")
        if not mac:
            return err("VM MAC adresi bulunamadı", 400)

        # Public IP'yi IPAM'dan bul
        assignments = ip_pool_mgr.list_assignments()
        pub_entry = next(
            (a for a in assignments if a.get("mac") == mac and a.get("pool") != "__internal__"),
            None
        )
        if not pub_entry:
            return err("Bu VM için public IP ataması bulunamadı", 404)
        public_ip = pub_entry["ip"]

        # ARP tablosundan gerçek IP'yi bul
        actual_ip = None
        try:
            arp_r = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=5)
            for line in arp_r.stdout.splitlines():
                if mac.lower() in line.lower():
                    parts = line.split()
                    if parts and "." in parts[0]:
                        actual_ip = parts[0]
                        break
        except Exception as _ae:
            log.warning("ARP okuma hatası: %s", _ae)

        # ARP'ta yoksa lease dosyasına bak
        if not actual_ip:
            lease_paths = [
                "/var/lib/libvirt/dnsmasq/default.leases",
                "/var/lib/dnsmasq/default.leases",
                "/var/run/dnsmasq/dnsmasq.leases",
            ]
            for lp in lease_paths:
                try:
                    with open(lp) as f:
                        for line in f:
                            parts = line.split()
                            if len(parts) >= 3 and parts[1].lower() == mac.lower():
                                actual_ip = parts[2]
                                break
                except Exception:
                    pass
                if actual_ip:
                    break

        if not actual_ip:
            # virsh domifaddr ile de dene
            try:
                r2 = subprocess.run(
                    ["virsh", "domifaddr", vm_name, "--source", "arp"],
                    capture_output=True, text=True, timeout=10
                )
                for line in r2.stdout.splitlines():
                    if "." in line and "/" in line:
                        parts = line.split()
                        for p in parts:
                            if "/" in p and "." in p:
                                actual_ip = p.split("/")[0]
                                break
                    if actual_ip:
                        break
            except Exception:
                pass

        if not actual_ip:
            # __internal__ pool'dan kayıtlı IP'yi kontrol et
            try:
                _int_assigns = ip_pool_mgr.list_assignments("__internal__")
                _int_e = next((a for a in _int_assigns if a.get("mac") == mac), None)
                if _int_e:
                    actual_ip = _int_e["ip"]
                    log.info("NAT sync: __internal__ pool'dan IP bulundu: %s → %s", mac, actual_ip)
            except Exception:
                pass

        if not actual_ip:
            # MAC'den deterministik internal IP türet ve DHCP rezervasyonu ekle
            derived_ip = _mac_to_internal_ip(mac)
            try:
                vm_manager.add_dhcp_host("default", mac, derived_ip, vm_name)
                ip_pool_mgr.manual_assign(ip=derived_ip, mac=mac, vm_name=vm_name,
                                          pool_name="__internal__", vm_id=vm_id)
                log.info("NAT sync: DHCP rezervasyonu eklendi: %s → %s (VM restart gerekebilir)", mac, derived_ip)
                return jsonify({
                    "success": False,
                    "error": f"DHCP rezervasyonu eklendi ({derived_ip}). VM'yi yeniden başlatın, ardından NAT tekrar deneyin.",
                    "dhcp_reserved": derived_ip,
                    "public_ip": public_ip,
                    "needs_restart": True,
                }), 200
            except Exception as _dhcp_err:
                log.warning("NAT sync: DHCP rezervasyonu eklenemedi: %s", _dhcp_err)
            return jsonify({
                "success": False,
                "error": "VM henüz IP almamış. VM'yi yeniden başlatın — DHCP lease bekleniyor.",
                "public_ip": public_ip,
                "mac": mac,
            }), 200

        # Eski stale DNAT'ı temizle ve yeni DNAT kur
        try:
            r = subprocess.run(["iptables", "-t", "nat", "-S", "PREROUTING"],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if f"-d {public_ip}" in line and "-j DNAT" in line and f"--to-destination {actual_ip}" not in line:
                    del_parts = line.strip().replace("-A ", "-D ", 1).split()
                    subprocess.run(["iptables", "-t", "nat"] + del_parts, capture_output=True, timeout=5)
        except Exception:
            pass

        _setup_nat(public_ip, actual_ip)

        # IPAM __internal__ kaydını güncelle
        try:
            data = ip_pool_mgr._load()
            for ip, a in list(data["assignments"].items()):
                if a.get("pool") == "__internal__" and a.get("mac") == mac:
                    if ip != actual_ip:
                        del data["assignments"][ip]
                        data["assignments"][actual_ip] = {**a, "ip": actual_ip}
                        ip_pool_mgr._save(data)
                    break
        except Exception:
            pass

        log.info("Manuel NAT sync: %s → %s (public %s)", vm_name, actual_ip, public_ip)
        return jsonify({
            "success": True,
            "vm_name": vm_name,
            "internal_ip": actual_ip,
            "public_ip": public_ip,
            "message": f"NAT güncellendi: {public_ip} → {actual_ip}",
        }), 200
    except Exception as e:
        return err(str(e), 500)


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
@require_role("admin", "administrator", "operator", "vm-user", "viewer")
def api_start_console(vm_id):
    """
    Flask VNC proxy (/ws/vnc/<vm_id>) tüm WebSocket→VNC köprüsünü kendi yapıyor.
    Websockify artık kullanılmıyor — port 5900'e iki bağlantı açılırsa QEMU VNC
    RFB handshake'i tamamlayamıyor.
    Eski websockify varsa öldür, sadece VNC portunu dön.
    """
    _chk = _vmuser_check(vm_id)
    if _chk: return _chk
    try:
        # ── VNC port: query libvirt XML (stored vnc_port may be absent/stale) ──
        import libvirt as _lv_cs
        import xml.etree.ElementTree as _ET_cs
        _conn = _lv_cs.open(config.LIBVIRT_URI)
        _dom  = _conn.lookupByUUIDString(vm_id)
        _xml  = _dom.XMLDesc()
        _conn.close()
        _root   = _ET_cs.fromstring(_xml)
        _vnc_el = _root.find(".//graphics[@type='vnc']")
        vnc_port = int(_vnc_el.get("port", -1)) if _vnc_el is not None else -1
        if vnc_port < 5900:
            return err("VM çalışmıyor veya VNC aktif değil (virsh vncdisplay ile kontrol edin)")

        # Eski websockify varsa öldür — port 5900'e rakip bağlantı açmasın
        ws_port = getattr(config, 'WS_PORT', 6080)
        subprocess.run(["pkill", "-f", "websockify"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        log.info("VNC console/start: vm=%s vnc_port=%d (Flask proxy kullanılıyor, websockify yok)",
                 vm_id, vnc_port)
        return ok(vnc_port=vnc_port, ws_port=ws_port)
    except Exception as e:
        log.exception("console/start hata: vm=%s", vm_id)
        return err(str(e), 500)


@app.route("/api/vms/<vm_id>/console/token", methods=["GET"])
@require_auth
def api_console_token_validate(vm_id):
    """Validate noVNC session token. Frontend calls this before opening WebSocket."""
    token = request.args.get("token", "")
    _novnc_clean()
    session = _novnc_sessions.get(token)
    if not session:
        return err("Geçersiz veya süresi dolmuş noVNC token", 403)
    if session["vm_id"] != vm_id:
        return err("Token bu VM için geçerli değil", 403)
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    if session["ip"] and client_ip and session["ip"] != client_ip:
        log.warning("noVNC token IP mismatch: expected %s got %s", session["ip"], client_ip)
        return err("Token IP uyuşmazlığı", 403)
    return ok(valid=True, ws_port=session["ws_port"])

# ── Snapshot ──────────────────────────────────────────────────────────────────
# Snapshot v1 routes kaldırıldı — v2 (security validated) kullanılıyor (aşağıda)

@app.route("/api/vms/snapshots/all", methods=["GET"])
@require_auth
def api_all_snapshots():
    """Tüm VM'lerin snapshot'larını tek seferde döndür."""
    try:
        vms = vm_manager.list_vms()
        all_snaps = []
        for v in vms:
            try:
                snaps = vm_manager.list_snapshots(v["id"])
                for s in snaps:
                    s["vm_id"]   = v["id"]
                    s["vm_name"] = v.get("name", v["id"])
                all_snaps.extend(snaps)
            except Exception:
                pass
        return ok(snapshots=all_snaps)
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
@require_role("admin", "administrator", "operator")
def api_create_network():
    data = request.get_json() or {}
    if "name" not in data:
        return err("name zorunludur")
    try:
        # Frontend field mapping
        if "mode" in data and "forward_mode" not in data:
            data["forward_mode"] = data.pop("mode")
        if "gateway" in data and "ip_address" not in data:
            data["ip_address"] = data.pop("gateway")
        # Yalnızca create_network() parametrelerini geçir
        allowed = {"name","forward_mode","bridge_name","ip_address","netmask",
                   "dhcp_start","dhcp_end","bridge_iface"}
        filtered = {k: v for k, v in data.items() if k in allowed}
        return ok(**network_manager.create_network(**filtered)), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/networks/<net_uuid>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_delete_network(net_uuid):
    try:
        return ok(**network_manager.delete_network(net_uuid))
    except Exception as e:
        return err(e, 500)

@app.route("/api/networks/<net_uuid>/start", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_start_network(net_uuid):
    try:
        return ok(**network_manager.start_network(net_uuid))
    except Exception as e:
        return err(e, 500)

@app.route("/api/networks/<net_uuid>/stop", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_stop_network(net_uuid):
    try:
        return ok(**network_manager.stop_network(net_uuid))
    except Exception as e:
        return err(e, 500)

@app.route("/api/networks/<net_uuid>/autostart", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_network_autostart(net_uuid):
    data = request.get_json() or {}
    enabled = bool(data.get("enabled", False))
    try:
        return ok(**network_manager.set_network_autostart(net_uuid, enabled))
    except Exception as e:
        return err(e, 500)

@app.route("/api/networks/<net_uuid>", methods=["GET"])
@require_auth
def api_get_network(net_uuid):
    try:
        return ok(network=network_manager.get_network_info(net_uuid))
    except Exception as e:
        return err(e, 500)

@app.route("/api/networks/<net_uuid>/update", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_update_network(net_uuid):
    """Update network DHCP/IP config. Stops + redefines + restarts network."""
    d = request.get_json() or {}
    dhcp_start = d.get("dhcp_start") or None
    dhcp_end   = d.get("dhcp_end") or None
    ip_address = d.get("ip_address") or None
    netmask    = d.get("netmask") or None
    try:
        result = network_manager.update_network(
            net_uuid,
            dhcp_start=dhcp_start,
            dhcp_end=dhcp_end,
            ip_address=ip_address,
            netmask=netmask,
        )
        ev.info(f"Ağ güncellendi: {net_uuid} dhcp={dhcp_start}-{dhcp_end}", category="network")
        return ok(**result)
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/networks/host-interfaces")
@require_auth
def api_host_interfaces():
    return ok(interfaces=network_manager.get_host_interfaces())


@app.route("/api/networks/neighbors")
@require_auth
def api_network_neighbors():
    """
    Fiziksel komşu cihazlar — LLDP (lldpd kuruluysa) veya ARP tablosu.
    Switch, router, fiziksel NIC bağlantılarını gösterir.
    """
    try:
        neighbors = network_manager.get_lldp_neighbors()
        return ok(neighbors=neighbors, count=len(neighbors),
                  source="lldp" if neighbors and neighbors[0].get("source") == "lldp" else "arp")
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/networks/arp")
@require_auth
def api_arp_table():
    """Tam ARP tablosu — subnet'teki tüm IP-MAC eşleşmeleri."""
    try:
        return ok(entries=network_manager.get_arp_table())
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/networks/bridges")
@require_auth
def api_host_bridges():
    """Host üzerindeki Linux bridge listesi."""
    try:
        return ok(bridges=network_manager.list_host_bridges())
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/networks/bridge/setup", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_setup_bridge():
    """
    Host NIC üzerinde Linux bridge + libvirt bridge network kur.
    Body: {bridge_name, physical_iface, libvirt_net_name}
    Sonuç: VMs bu ağda gerçek, bağımsız IP adresiyle çalışır (host IP'sini paylaşmaz).
    """
    data = request.get_json() or {}
    bridge_name     = security.sanitize_str(data.get("bridge_name", "oxbr0"), 32)
    physical_iface  = security.sanitize_str(data.get("physical_iface", "enp1s0"), 32)
    libvirt_net     = security.sanitize_str(data.get("libvirt_net_name", "oxbridge"), 64)
    try:
        result = network_manager.setup_host_bridge(bridge_name, physical_iface, libvirt_net)
        ev.info(f"Bridge kurulumu: {bridge_name} ← {physical_iface}", category="network")
        return ok(**result)
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/system/routes")
@require_auth
def api_system_routes():
    """Return kernel routing table via `ip -j route`."""
    try:
        r = subprocess.run(["ip", "-j", "route"], capture_output=True, text=True, timeout=5)
        import json as _json2
        raw_routes = _json2.loads(r.stdout) if r.returncode == 0 else []
        routes = []
        for rt in raw_routes:
            routes.append({
                "dst":      rt.get("dst", "default"),
                "gateway":  rt.get("gateway", ""),
                "dev":      rt.get("dev", ""),
                "protocol": rt.get("protocol", ""),
                "metric":   rt.get("metric"),
                "scope":    rt.get("scope", ""),
                "type":     rt.get("type", ""),
            })
        return ok(routes=routes)
    except Exception as e:
        return err(str(e), 500)


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

@app.route("/api/storage/pools/<pool_uuid>/start", methods=["POST"])
@require_auth
def api_start_pool(pool_uuid):
    try:
        return ok(**storage_manager.start_pool(pool_uuid))
    except Exception as e:
        return err(e, 500)

@app.route("/api/storage/pools/<pool_uuid>/stop", methods=["POST"])
@require_auth
def api_stop_pool(pool_uuid):
    try:
        return ok(**storage_manager.stop_pool(pool_uuid))
    except Exception as e:
        return err(e, 500)

@app.route("/api/storage/pools/<pool_uuid>/autostart", methods=["POST"])
@require_auth
def api_pool_autostart(pool_uuid):
    data = request.get_json() or {}
    enabled = bool(data.get("enabled", False))
    try:
        return ok(**storage_manager.set_pool_autostart(pool_uuid, enabled))
    except Exception as e:
        return err(e, 500)

@app.route("/api/storage/pools/<pool_uuid>/refresh", methods=["POST"])
@require_auth
def api_refresh_pool(pool_uuid):
    try:
        return ok(**storage_manager.refresh_pool(pool_uuid))
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
@require_role("admin", "administrator", "operator")  # OXW-SEC-003: vm-user ISO upload blocked
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
    # OXW-SEC-003: disk space guard — en az 1 GB boş alan gerekli
    try:
        _st = os.statvfs(config.ISO_DIR) if hasattr(os, "statvfs") else None
        if _st and (_st.f_bavail * _st.f_frsize) < 1024 * 1024 * 1024:
            return err("Yetersiz disk alanı (minimum 1 GB gerekli)", 507)
    except Exception:
        pass
    dest = os.path.join(config.ISO_DIR, safe_name)
    try:
        os.makedirs(config.ISO_DIR, exist_ok=True)
        f.save(dest)
        os.chmod(dest, 0o640)
    except OSError as _iso_e:
        log.error("ISO kaydetme hatası: %s → %s", safe_name, _iso_e)
        if os.path.exists(dest):
            try: os.remove(dest)
            except OSError: pass
        return err(f"ISO kaydedilemedi: {_iso_e}"), 500
    ev.info(f"ISO yüklendi: {safe_name}", category="storage")
    return ok(name=safe_name, path=dest, size=os.path.getsize(dest)), 201

@app.route("/api/storage/isos/<name>", methods=["DELETE"])
@require_auth
def api_delete_iso(name):
    # rapor #43 fix: validate name to prevent path traversal
    try:
        name = security.validate_filename(name)
    except ValueError as e:
        return err(str(e), 400)
    try:
        return ok(**storage_manager.delete_iso(name))
    except FileNotFoundError as e:
        return err(e, 404)

@app.route("/api/storage/isos/<name>/rename", methods=["POST"])
@require_auth
def api_rename_iso(name):
    """ISO dosyasını yeniden adlandır."""
    # rapor #43 fix: validate both old and new names
    try:
        name = security.validate_filename(name)
    except ValueError as e:
        return err(str(e), 400)
    data = request.get_json(force=True, silent=True) or {}
    new_name = (data.get("new_name") or "").strip()
    if not new_name:
        return err("new_name zorunlu")
    try:
        new_name = security.validate_filename(new_name)
        if not new_name.lower().endswith(".iso"):
            new_name += ".iso"
    except ValueError as e:
        return err(str(e))
    old_path = os.path.join(config.ISO_DIR, name)
    new_path = os.path.join(config.ISO_DIR, new_name)
    if not os.path.exists(old_path):
        return err(f"ISO bulunamadı: {name}", 404)
    if os.path.exists(new_path):
        return err(f"Bu isimde ISO zaten var: {new_name}")
    try:
        os.rename(old_path, new_path)
        ev.info(f"ISO yeniden adlandırıldı: {name} → {new_name}", category="storage")
        return ok(old_name=name, new_name=new_name)
    except Exception as e:
        return err(str(e), 500)

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
        _known = {"name", "network", "gateway", "dns", "start_ip", "end_ip", "reserved"}
        pool = ip_pool_mgr.create_pool(**{k: v for k, v in data.items() if k in _known})
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

# ── IPAM Bridge (UI → ip_pool) ───────────────────────────────────────────────
def _read_dnsmasq_leases() -> list:
    """dnsmasq lease dosyasından DHCP kiralamalarını oku."""
    lease_files = [
        "/var/lib/misc/dnsmasq.leases",
        "/var/lib/dnsmasq/dnsmasq.leases",
        "/tmp/dnsmasq.leases",
    ]
    leases = []
    for lf in lease_files:
        if os.path.exists(lf):
            try:
                with open(lf) as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            import datetime as _dt
                            ts = int(parts[0]) if parts[0].isdigit() else 0
                            last_seen = _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "—"
                            leases.append({
                                "ip": parts[2],
                                "mac": parts[1],
                                "vm": parts[3] if parts[3] != "*" else "—",
                                "network": "dnsmasq",
                                "state": "bound",
                                "source": "dnsmasq",
                                "last_seen": last_seen,
                                "locked": False,
                                "pool": "",
                            })
            except Exception:
                pass
    return leases


@app.route("/api/ipam/leases")
@require_auth
def api_ipam_leases():
    """Tüm havuzlardaki IP atamalarını + dnsmasq kiralamalarını döndür."""
    try:
        assignments = ip_pool_mgr.list_assignments()
        pool_ips = {a["ip"] for a in assignments}
        leases = []
        for a in assignments:
            import datetime as _dt
            ts = a.get("assigned_at", 0)
            last_seen = _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "—"
            leases.append({
                "ip":        a["ip"],
                "mac":       a.get("mac", ""),
                "vm":        a.get("vm_name", "—"),
                "network":   a.get("network", "—"),
                "state":     "bound",
                "source":    "oxware",
                "last_seen": last_seen,
                "locked":    a.get("locked", False),
                "pool":      a.get("pool", ""),
            })
        # dnsmasq'tan gelen ama havuzda olmayan IP'leri de ekle
        for l in _read_dnsmasq_leases():
            if l["ip"] not in pool_ips:
                leases.append(l)
        # IP'ye göre sırala
        leases.sort(key=lambda x: [int(p) for p in x["ip"].split(".") if p.isdigit()] if x["ip"].count(".") == 3 else [0])
        return ok(leases=leases)
    except Exception as e:
        return err(e, 500)


@app.route("/api/ipam/stats")
@require_auth
def api_ipam_stats():
    """Tüm havuzlar toplamı istatistik."""
    try:
        return ok(**ip_pool_mgr.get_all_stats())
    except Exception as e:
        return err(e, 500)


@app.route("/api/ipam/pools")
@require_auth
def api_ipam_pools():
    return ok(pools=ip_pool_mgr.list_pools())


def _get_host_ips() -> list:
    """Sunucunun kendi IP adreslerini listele."""
    try:
        import socket as _sock, subprocess as _sp
        ips = []
        # hostname -I yöntemi
        r = _sp.run(["hostname", "-I"], capture_output=True, text=True, timeout=3)
        ips.extend(r.stdout.strip().split())
        # Fallback: socket
        try:
            ips.append(_sock.gethostbyname(_sock.gethostname()))
        except Exception:
            pass
        return list(set(ip for ip in ips if ip and "." in ip))
    except Exception:
        return []


@app.route("/api/ipam/host-ips")
@require_auth
def api_ipam_host_ips():
    """Sunucunun kendi IP adreslerini döndür — pool oluşturmada çakışma uyarısı için."""
    return ok(ips=_get_host_ips())


@app.route("/api/ipam/pools", methods=["POST"])
@require_auth
def api_ipam_create_pool():
    data = request.get_json() or {}
    required = ["name", "network", "gateway"]
    missing = [f for f in required if f not in data]
    if missing:
        return err(f"Zorunlu alanlar: {', '.join(missing)}")
    try:
        import ipaddress as _ipa
        _warnings = []

        # Ana sunucu IP'leri pool aralığında mı kontrol et
        try:
            _net = _ipa.IPv4Network(data["network"], strict=False)
            _host_ips = _get_host_ips()
            _conflicting = [ip for ip in _host_ips
                            if _ipa.IPv4Address(ip) in _net]
            if _conflicting:
                _warnings.append(
                    f"UYARI: Pool ağı ({data['network']}) sunucunun kendi IP'sini içeriyor: "
                    f"{', '.join(_conflicting)}. Bu IP'ler VM'lere atanmamalı — "
                    f"reserved listesine eklenmeleri önerilir."
                )
                # Otomatik olarak host IP'leri reserved listesine ekle
                _reserved = data.get("reserved", [])
                for _cip in _conflicting:
                    if _cip not in _reserved:
                        _reserved.append(_cip)
                data["reserved"] = _reserved
        except Exception as _val_e:
            log.warning("Pool validasyon hatası: %s", _val_e)

        _known = {"name", "network", "gateway", "dns", "start_ip", "end_ip", "reserved", "libvirt_network"}
        pool = ip_pool_mgr.create_pool(**{k: v for k, v in data.items() if k in _known})
        ev.info(f"IP havuzu oluşturuldu: {data['name']}", category="network")
        resp = {"pool": pool}
        if _warnings:
            resp["warnings"] = _warnings
        return ok(**resp), 201
    except Exception as e:
        return err(e, 500)


@app.route("/api/ipam/pools/<name>", methods=["DELETE"])
@require_auth
def api_ipam_delete_pool(name):
    try:
        ip_pool_mgr.delete_pool(name)
        ev.info(f"IP havuzu silindi: {name}", category="network")
        return ok(status="deleted")
    except Exception as e:
        return err(e, 500)


@app.route("/api/ipam/leases/<path:mac>/lock", methods=["POST"])
@require_auth
def api_ipam_lock(mac):
    try:
        # MAC'e göre IP bul
        assignments = ip_pool_mgr.list_assignments()
        entry = next((a for a in assignments if a.get("mac") == mac), None)
        if not entry:
            return err("Atama bulunamadı", 404)
        new_state = not entry.get("locked", False)
        ip_pool_mgr.lock_ip(entry["ip"], new_state)
        return ok(locked=new_state)
    except Exception as e:
        return err(e, 500)


@app.route("/api/ipam/leases/<path:mac>", methods=["DELETE"])
@require_auth
def api_ipam_delete_lease(mac):
    try:
        released = ip_pool_mgr.release_by_mac(mac)
        if not released:
            return err("Atama bulunamadı", 404)
        return ok(released=released)
    except Exception as e:
        return err(e, 500)


@app.route("/api/ipam/leases/<path:mac>/reassign", methods=["POST"])
@require_auth
def api_ipam_reassign(mac):
    data = request.get_json() or {}
    new_ip = data.get("ip")
    if not new_ip:
        return err("ip alanı zorunlu")
    try:
        result = ip_pool_mgr.reassign_ip(mac, new_ip)
        return ok(**result)
    except Exception as e:
        return err(e, 500)


@app.route("/api/ipam/pools/<name>", methods=["PATCH"])
@require_auth
def api_ipam_update_pool(name):
    """IP havuzu güncelle (gateway, start_ip, end_ip)."""
    data = request.get_json(force=True, silent=True) or {}
    try:
        pool = ip_pool_mgr.update_pool(name, **{k: v for k, v in data.items() if k in ("gateway", "start_ip", "end_ip", "dns")})
        return ok(pool=pool)
    except Exception as e:
        return err(e, 500)


@app.route("/api/ipam/leases", methods=["POST"])
@require_auth
def api_ipam_add_lease():
    """Manuel IP ataması ekle."""
    data = request.get_json(force=True, silent=True) or {}
    ip        = data.get("ip", "")
    mac       = data.get("mac", "")
    pool_name = data.get("pool", "")
    vm_name   = data.get("vm", "")
    if not ip or not mac:
        return err("ip ve mac zorunlu")
    try:
        entry = ip_pool_mgr.manual_assign(
            ip=ip, mac=mac, vm_name=vm_name, pool_name=pool_name,
        )
        # Libvirt DHCP static entry ekle
        try:
            pools = {p["name"]: p for p in ip_pool_mgr.list_pools()}
            dhcp_net = pools.get(pool_name, {}).get("libvirt_network", "default") if pool_name else "default"
            vm_manager.add_dhcp_host(dhcp_net, mac, ip, vm_name)
        except Exception as _e:
            log.warning("Manuel atama DHCP entry eklenemedi: %s", _e)
        return ok(entry=entry), 201
    except Exception as e:
        return err(e, 500)


def _mac_to_internal_ip(mac: str, base="192.168.122") -> str:
    """MAC'in son iki byte'ından deterministik internal IP türet (100-253 aralığı)."""
    parts = mac.split(":")
    last = int(parts[-1], 16) if len(parts) >= 1 else 0
    offset = 100 + (last % 153)   # 100-252
    return f"{base}.{offset}"


def _post_install_nat_sync(vm_uuid: str, vm_name: str, mac: str, public_ip: str):
    """
    Kurulum sonrası VM'in gerçek IP'sini ARP'tan oku ve DNAT'ı güncelle.
    _monitor_install on_complete callback'i tarafından çağrılır.
    """
    import time as _time
    log.info("Post-install NAT sync başladı: %s (%s)", vm_name, vm_uuid)

    actual_ip = None
    # Windows kurulumu uzun sürer (çoklu reboot) — 15dk bekle
    for attempt in range(180):   # 15dk: 180×5s
        try:
            arp_r = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=5)
            for line in arp_r.stdout.splitlines():
                if mac.lower() in line.lower():
                    parts = line.split()
                    if parts and "." in parts[0]:
                        actual_ip = parts[0]
                        break
        except Exception:
            pass
        if actual_ip:
            break
        # Her 60 denemede bir log yaz
        if attempt % 12 == 0:
            log.info("Post-install NAT sync: ARP bekleniyor... (%s) %ds", mac, attempt * 5)
        _time.sleep(5)

    if not actual_ip:
        log.warning("Post-install NAT sync: 15dk içinde ARP'ta IP bulunamadı (%s)", mac)
        return

    log.info("Post-install NAT sync: %s gerçek IP = %s", vm_name, actual_ip)

    try:
        r = subprocess.run(["iptables", "-t", "nat", "-S", "PREROUTING"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if f"-d {public_ip}" in line and "-j DNAT" in line and f"--to-destination {actual_ip}" not in line:
                del_parts = line.strip().replace("-A ", "-D ", 1).split()
                subprocess.run(["iptables", "-t", "nat"] + del_parts,
                               capture_output=True, timeout=5)
                log.info("Eski DNAT silindi: %s", line.strip())
    except Exception as _e:
        log.warning("DNAT temizleme hatası: %s", _e)

    _setup_nat(public_ip, actual_ip)
    log.info("Post-install NAT sync tamamlandı: %s → %s", public_ip, actual_ip)

    try:
        data = ip_pool_mgr._load()
        for ip, a in list(data["assignments"].items()):
            if a.get("pool") == "__internal__" and a.get("vm_id") in (vm_uuid, mac):
                if ip != actual_ip:
                    del data["assignments"][ip]
                    data["assignments"][actual_ip] = {**a, "ip": actual_ip}
                    ip_pool_mgr._save(data)
                    log.info("IPAM __internal__ güncellendi: %s → %s", ip, actual_ip)
                break
    except Exception as _ie:
        log.warning("IPAM update hatası: %s", _ie)


def _setup_nat(public_ip: str, internal_ip: str, host_iface: str = None) -> dict:
    """
    Public IP → Internal IP NAT kuralları ekle.
    - PREROUTING DNAT: dışarıdan gelen → internal_ip
    - POSTROUTING SNAT: internal_ip çıkışı → public_ip gibi görünsün
    - ip_forward etkinleştir
    """
    if not host_iface:
        # Ana çıkış interface'ini bul
        try:
            r = subprocess.run(["ip", "route", "get", "8.8.8.8"],
                               capture_output=True, text=True, timeout=5)
            for token in r.stdout.split():
                if token not in ("8.8.8.8", "via", "dev", "src", "uid"):
                    if not token.startswith("1") and "." not in token:
                        host_iface = token
                        break
        except Exception:
            pass
        host_iface = host_iface or "ens160"

    errors = []
    # ip_forward
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                   capture_output=True, timeout=5)
    # Public IP interface'te yoksa ekle (kernel drop etmesin)
    try:
        check = subprocess.run(["ip", "addr", "show", "dev", host_iface],
                               capture_output=True, text=True, timeout=5)
        if public_ip not in check.stdout:
            subprocess.run(["ip", "addr", "add", f"{public_ip}/24", "dev", host_iface],
                           capture_output=True, timeout=5)
            log.info("Secondary IP eklendi: %s → %s", public_ip, host_iface)
    except Exception as _ie:
        log.warning("Secondary IP eklenemedi: %s", _ie)

    # Aynı public_ip için eski DNAT kurallarını sil (önceki VM'den kalmış olabilir)
    try:
        r = subprocess.run(["iptables", "-t", "nat", "-S", "PREROUTING"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if f"-d {public_ip}" in line and "-j DNAT" in line and f"--to-destination {internal_ip}" not in line:
                del_parts = line.strip().replace("-A ", "-D ", 1).split()
                subprocess.run(["iptables", "-t", "nat"] + del_parts,
                               capture_output=True, timeout=5)
    except Exception as _fe:
        log.warning("Eski DNAT temizleme hatası: %s", _fe)

    rules = [
        # DNAT: dışarıdan public_ip'ye gelen → internal_ip
        ["iptables", "-t", "nat", "-A", "PREROUTING",
         "-d", public_ip, "-j", "DNAT", "--to-destination", internal_ip],
        # MASQUERADE: VM'in dışarı çıkışı
        ["iptables", "-t", "nat", "-A", "POSTROUTING",
         "-s", internal_ip, "-o", host_iface, "-j", "MASQUERADE"],
    ]
    for rule in rules:
        r = subprocess.run(rule, capture_output=True, text=True, timeout=10)
        if r.returncode != 0 and "already exists" not in r.stderr:
            errors.append(r.stderr.strip())

    # FORWARD: önce sil (duplicate önle), sonra pos 1'e ekle — LIBVIRT_FWI'dan önce
    for fwd_rule_args in [
        ["-d", internal_ip, "-j", "ACCEPT"],
        ["-s", internal_ip, "-j", "ACCEPT"],
    ]:
        subprocess.run(["iptables", "-D", "FORWARD"] + fwd_rule_args,
                       capture_output=True, timeout=10)
        r = subprocess.run(["iptables", "-I", "FORWARD", "1"] + fwd_rule_args,
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            errors.append(r.stderr.strip())

    # Kalıcı yap (varsa)
    subprocess.run(["netfilter-persistent", "save"],
                   capture_output=True, timeout=10)

    return {"ok": len(errors) == 0, "errors": errors,
            "public_ip": public_ip, "internal_ip": internal_ip}


def _remove_nat(public_ip: str, internal_ip: str, host_iface: str = None):
    """NAT kurallarını temizle. host_iface None ise _setup_nat ile aynı auto-detect."""
    if not host_iface:
        try:
            r = subprocess.run(["ip", "route", "get", "8.8.8.8"],
                               capture_output=True, text=True, timeout=5)
            for token in r.stdout.split():
                if token not in ("8.8.8.8", "via", "dev", "src", "uid"):
                    if not token.startswith("1") and "." not in token:
                        host_iface = token
                        break
        except Exception:
            pass
        host_iface = host_iface or "ens160"

    rules = [
        ["iptables", "-t", "nat", "-D", "PREROUTING",
         "-d", public_ip, "-j", "DNAT", "--to-destination", internal_ip],
        ["iptables", "-t", "nat", "-D", "POSTROUTING",
         "-s", internal_ip, "-o", host_iface, "-j", "MASQUERADE"],
        ["iptables", "-D", "FORWARD", "-d", internal_ip, "-j", "ACCEPT"],
        ["iptables", "-D", "FORWARD", "-s", internal_ip, "-j", "ACCEPT"],
    ]
    for rule in rules:
        subprocess.run(rule, capture_output=True, timeout=10)
    subprocess.run(["netfilter-persistent", "save"], capture_output=True, timeout=10)


def _pool_in_libvirt_subnet(pool_network: str, libvirt_network: str) -> bool:
    """Pool ağı libvirt ağıyla aynı subnet mi?"""
    try:
        return ipaddress.IPv4Network(pool_network, strict=False) == \
               ipaddress.IPv4Network(libvirt_network, strict=False)
    except Exception:
        return False


@app.route("/api/ipam/assign", methods=["POST"])
@require_auth
def api_ipam_assign_vm():
    """VM'e havuzdan IP ata + libvirt DHCP static entry ekle."""
    data         = request.get_json(force=True, silent=True) or {}
    pool         = data.get("pool", "")
    mac          = data.get("mac", "")
    vm_name      = data.get("vm", "")
    manual_ip    = data.get("ip", "")
    vm_id        = data.get("vm_id", "")       # restart için
    restart_after = data.get("restart_after", True)  # default: restart
    if not pool or not mac:
        return err("pool ve mac zorunlu")
    try:
        pools_map = {p["name"]: p for p in ip_pool_mgr.list_pools()}
        pool_info = pools_map.get(pool, {})
        dhcp_net  = pool_info.get("libvirt_network", "default")

        if manual_ip:
            entry = ip_pool_mgr.manual_assign(ip=manual_ip, mac=mac, vm_name=vm_name,
                                               pool_name=pool, vm_id=vm_id or mac)
            assigned_ip = manual_ip
        else:
            entry       = ip_pool_mgr.allocate_ip(pool_name=pool, vm_id=vm_id or mac,
                                                   vm_name=vm_name, mac=mac)
            assigned_ip = entry.get("ip")
            dhcp_net    = entry.get("libvirt_network", dhcp_net)

        # Libvirt ağ bilgisi al
        try:
            nets = network_manager.list_networks()
            libvirt_net_info = next((n for n in nets if n["name"] == dhcp_net), None)
            libvirt_subnet = libvirt_net_info.get("ip", "") if libvirt_net_info else ""
            libvirt_netmask = libvirt_net_info.get("netmask", "255.255.255.0") if libvirt_net_info else "255.255.255.0"
            libvirt_cidr = f"{libvirt_subnet}/{libvirt_netmask}" if libvirt_subnet else ""
        except Exception:
            libvirt_subnet = ""
            libvirt_cidr   = ""

        # Pool IP'si libvirt subnet'inde mi?
        pool_network = pool_info.get("network", "")
        nat_mode = False
        nat_result = None
        internal_ip = assigned_ip  # varsayılan: aynı

        if libvirt_subnet and pool_network:
            try:
                libvirt_net_obj = ipaddress.IPv4Network(
                    f"{libvirt_subnet}/{libvirt_netmask}", strict=False)
                assigned_addr = ipaddress.IPv4Address(assigned_ip)
                if assigned_addr not in libvirt_net_obj:
                    # Public IP libvirt subnet'i dışında → NAT gerekli
                    nat_mode = True
                    base = str(libvirt_net_obj.network_address).rsplit(".", 1)[0]

                    # 1. VM çalışıyorsa ARP'tan gerçek IP'yi oku (en güvenilir)
                    actual_ip = None
                    if mac:
                        try:
                            arp_r = subprocess.run(["arp", "-n"],
                                                   capture_output=True, text=True, timeout=5)
                            for arp_line in arp_r.stdout.splitlines():
                                if mac.lower() in arp_line.lower():
                                    arp_parts = arp_line.split()
                                    if arp_parts and "." in arp_parts[0]:
                                        actual_ip = arp_parts[0]
                                        break
                        except Exception:
                            pass

                    # 2. ARP'ta yoksa lease dosyasından bak
                    if not actual_ip and mac:
                        try:
                            for lf in ["/var/lib/libvirt/dnsmasq/default.leases"]:
                                if os.path.exists(lf):
                                    with open(lf) as _lf:
                                        for _ll in _lf:
                                            if mac.lower() in _ll.lower():
                                                _lparts = _ll.split()
                                                if len(_lparts) >= 3:
                                                    actual_ip = _lparts[2]
                                                    break
                        except Exception:
                            pass

                    # 3. Hiçbiri yoksa deterministic formula (VM henüz açılmadı)
                    internal_ip = actual_ip or _mac_to_internal_ip(mac, base)
                    log.info("NAT modu: %s → %s (internal: %s%s)",
                             assigned_ip, vm_name, internal_ip,
                             " [ARP]" if actual_ip else " [formula]")
            except Exception as _ne:
                log.warning("Subnet kontrol hatası: %s", _ne)

        # NAT modunda VM "default" ağındaki virbr0'dan IP alır — fabnet değil
        if nat_mode:
            dhcp_net = "default"

        # DHCP static entry: internal_ip ile (libvirt subnet'inde)
        dhcp_ok = vm_manager.add_dhcp_host(dhcp_net, mac, internal_ip, vm_name)

        # NAT kurulumu
        if nat_mode:
            nat_result = _setup_nat(assigned_ip, internal_ip)
            if nat_result["ok"]:
                log.info("NAT kuruldu: %s → %s", assigned_ip, internal_ip)
            else:
                log.warning("NAT hataları: %s", nat_result["errors"])
            # internal_ip'yi de kaydet
            ip_pool_mgr.manual_assign(ip=internal_ip, mac=mac, vm_name=vm_name,
                                       pool_name="__internal__", vm_id=vm_id or mac)
            # Post-install ARP sync: VM henüz formula IP ile kuruluyorsa arka planda güncelle
            _sync_mac  = mac
            _sync_pub  = assigned_ip
            _sync_uuid = vm_id or mac
            _sync_name = vm_name
            threading.Thread(
                target=_post_install_nat_sync,
                args=(_sync_uuid, _sync_name, _sync_mac, _sync_pub),
                daemon=True,
                name=f"post-install-nat-{vm_name}"
            ).start()

        # VM yeniden başlat → yeni DHCP lease alsın
        restarted = False
        restart_err = None
        if restart_after and vm_id:
            try:
                vm_manager.stop_vm(vm_id, force=True)
                time.sleep(2)
                vm_manager.start_vm(vm_id)
                restarted = True
            except Exception as re:
                restart_err = str(re)

        ev.info(f"IP atandı: {assigned_ip} → {vm_name} (internal: {internal_ip}, NAT: {nat_mode})", category="network")
        return ok(ip=assigned_ip, internal_ip=internal_ip, mac=mac, vm=vm_name, pool=pool,
                  dhcp_entry=dhcp_ok, nat=nat_mode, nat_result=nat_result,
                  restarted=restarted, restart_error=restart_err)
    except Exception as e:
        return err(e, 500)


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
# SECURITY: VM_USER rolü OXY AI'e erişemez (bilgi sızdırma riski).
# Sadece admin/administrator/operator erişebilir.
@app.route("/api/ai/agents")
@require_role("admin", "administrator", "operator")
def api_list_agents():
    return ok(agents=ai_agent.list_agents())

# OXW-2026-SEC-004: add/delete/update API anahtarı yönetimi → SADECE admin.
# Operator yalnızca list/query yapabilir, agent ekleyip/silemez/anahtar değiştiremez.
@app.route("/api/ai/agents", methods=["POST"])
@require_role("admin", "administrator")
def api_add_agent():
    data = request.get_json() or {}
    required = ["agent_id", "name", "provider", "api_key"]
    missing = [f for f in required if f not in data]
    if missing:
        return err(f"Zorunlu alanlar: {', '.join(missing)}")
    # agent_id sanitize — path/key injection önle
    import re as _re_ag
    if not _re_ag.match(r"^[a-zA-Z0-9_\-]{1,64}$", str(data.get("agent_id", ""))):
        return err("agent_id sadece harf/rakam/_/- içerebilir (1-64)")
    try:
        result = ai_agent.add_agent(**data)
        ev.info(f"AI Agent eklendi: {data['name']} (by {get_jwt_identity()})", category="ai")
        # API anahtarını yanıtta döndürme (sızıntı önle)
        result.pop("api_key", None)
        return ok(agent=result), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/ai/agents/<agent_id>", methods=["DELETE"])
@require_role("admin", "administrator")
def api_delete_agent(agent_id):
    try:
        ai_agent.delete_agent(agent_id)
        ev.info(f"AI Agent silindi: {agent_id} (by {get_jwt_identity()})", category="ai")
        return ok(status="deleted")
    except Exception as e:
        return err(e, 500)

@app.route("/api/ai/agents/<agent_id>", methods=["PUT"])
@require_role("admin", "administrator")
def api_update_agent(agent_id):
    data = request.get_json() or {}
    try:
        res = ai_agent.update_agent(agent_id, data)
        if isinstance(res, dict):
            res.pop("api_key", None)
        ev.info(f"AI Agent güncellendi: {agent_id} (by {get_jwt_identity()})", category="ai")
        return ok(agent=res)
    except Exception as e:
        return err(e, 500)

@app.route("/api/ai/agents/<agent_id>/query", methods=["POST"])
@require_role("admin", "administrator", "operator")
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
@require_role("admin", "administrator", "operator")
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
@require_role("admin", "administrator", "operator")
def api_agent_logs(agent_id):
    limit = int(request.args.get("limit", 20))
    return ok(logs=ai_agent.get_agent_logs(agent_id, limit=limit))

@app.route("/api/ai/providers")
@require_role("admin", "administrator", "operator")
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
# OXW-2026-014 fix: Tüm /api/update/* endpoint'leri administrator rolü gerektirir.
# Önceden yalnızca @require_auth vardı — herhangi bir kullanıcı kötü amaçlı
# repo_url ile supply-chain RCE yapabiliyordu (CVSS 9.9).
@app.route("/api/update/config")
@require_auth
@require_role("admin", "administrator")
def api_update_config_get():
    return ok(**updater.get_config())

@app.route("/api/update/config", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_update_config_save():
    data = request.get_json() or {}
    repo_url   = data.get("repo_url", updater.DEFAULT_REPO_URL).strip() or updater.DEFAULT_REPO_URL
    branch     = data.get("branch", updater.DEFAULT_BRANCH).strip() or updater.DEFAULT_BRANCH
    auto_check = bool(data.get("auto_check", False))
    # OXW-2026-015 fix: repo_url allow-list kontrolü
    if repo_url not in config.UPDATE_ALLOWED_REPOS:
        ev.warn(f"Güncelleme: izinsiz repo_url reddedildi: {repo_url}", category="system")
        return err(f"Bu repo URL'si güncelleme kanalı olarak izinli değil. "
                   f"İzinli URL'ler: {', '.join(config.UPDATE_ALLOWED_REPOS)}", 400)
    updater.save_config(repo_url, branch, auto_check)
    ev.info("Güncelleme yapılandırması kaydedildi", category="system")
    return ok(message="Kaydedildi")

@app.route("/api/update/check")
@require_auth
@require_role("admin", "administrator")
def api_update_check():
    result = updater.check_updates_with_ai()
    return ok(**result)

@app.route("/api/update/last")
@require_auth
@require_role("admin", "administrator")
def api_update_last():
    """Son otomatik kontrol sonucunu döndür (AI analizi dahil)."""
    return ok(**updater.get_last_check())

@app.route("/api/update/apply", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_update_apply():
    result = updater.apply_update()
    if result.get("success"):
        ev.info(f"Güncelleme uygulandı: {result.get('old_sha')} → {result.get('new_sha')}", category="system")
    else:
        ev.error(f"Güncelleme başarısız: {result.get('error')}", category="system")
    return ok(**result)

@app.route("/api/update/history")
@require_auth
@require_role("admin", "administrator")
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

@app.route("/api/events/list")
@require_auth
def api_events_list():
    """Alias for /api/events — used by OXY AI context builder."""
    limit    = int(request.args.get("limit", 100))
    level    = request.args.get("level")
    category = request.args.get("category")
    vm_id    = request.args.get("vm_id")
    since    = request.args.get("since")
    offset   = int(request.args.get("offset", 0))
    since_ts = float(since) if since else None
    events   = ev.get_events(limit=limit, level=level, category=category,
                              vm_id=vm_id, since=since_ts, offset=offset)
    return ok(events=events, count=len(events))

# ── Sistem ────────────────────────────────────────────────────────────────────
@app.route("/api/system/reboot", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_system_reboot():
    try:
        if os.geteuid() == 0:
            subprocess.Popen(["reboot"])
        else:
            r = subprocess.run(["sudo", "-n", "reboot"], capture_output=True)
            if r.returncode != 0:
                return err("Reboot başarısız: sudo yetkisi yok. Backend'i root olarak çalıştırın veya sudoers'a ekleyin.", 403)
        return ok(message="Yeniden başlatılıyor")
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/system/shutdown", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_system_shutdown():
    try:
        if os.geteuid() == 0:
            subprocess.Popen(["shutdown", "-h", "now"])
        else:
            r = subprocess.run(["sudo", "-n", "shutdown", "-h", "now"], capture_output=True)
            if r.returncode != 0:
                return err("Shutdown başarısız: sudo yetkisi yok. Backend'i root olarak çalıştırın veya sudoers'a ekleyin.", 403)
        return ok(message="Kapatılıyor")
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/system/info")
@require_auth
def api_system_info():
    return ok(
        host=system_monitor.get_host_info(),
        libvirt=system_monitor.get_libvirt_version(),
        oxware_version="2.8.1",
    )

@app.route("/api/system/stats")
@require_auth
def api_system_stats():
    stats = system_monitor._STATS_CACHE["data"] or system_monitor.get_system_stats()
    return ok(stats=stats)

@app.route("/api/system/processes")
@require_auth
@require_role("admin", "administrator")  # rapor #30 fix: process listesi hassas bilgi — sadece admin
def api_processes():
    return ok(processes=system_monitor.get_process_list(int(request.args.get("limit", 20))))

@app.route("/api/system/vmsummary")
@require_auth
def api_vm_summary():
    return ok(**system_monitor.get_vm_summary())


@app.route("/api/system/host-info")
@require_auth
@require_role("admin", "administrator", "operator")
def api_system_host_info():
    """Detaylı host bilgisi — CPU modeli, RAM, kernel, uptime, KVM durumu."""
    try:
        import platform, subprocess as _sp
        kvm_ok = os.path.exists("/dev/kvm")
        try:
            r = _sp.run(["kvm-ok"], capture_output=True, text=True, timeout=3)
            kvm_ok = r.returncode == 0
        except Exception:
            pass

        cpu_info = ""
        cpu_count = 0
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.startswith("model name") and not cpu_info:
                        cpu_info = line.split(":", 1)[1].strip()
                    if line.startswith("processor"):
                        cpu_count += 1
        except Exception:
            cpu_info = platform.processor()

        uptime_s = ""
        try:
            with open("/proc/uptime") as f:
                secs = float(f.read().split()[0])
            d_val, r_val = divmod(int(secs), 86400)
            h_val, r_val = divmod(r_val, 3600)
            m_val = r_val // 60
            uptime_s = (f"{d_val}g " if d_val else "") + f"{h_val:02d}:{m_val:02d}"
        except Exception:
            pass

        ram_gb = 0
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal"):
                        ram_kb = int(line.split()[1])
                        ram_gb = round(ram_kb / (1024**2), 1)
                        break
        except Exception:
            try:
                import psutil as _ps
                ram_gb = round(_ps.virtual_memory().total / (1024**3), 1)
            except Exception:
                pass

        try:
            if not cpu_count:
                import os as _os
                cpu_count = _os.cpu_count() or 0
        except Exception:
            pass

        return ok(
            hostname=platform.node(),
            os=f"{platform.system()} {platform.release()}",
            kernel=platform.uname().release,
            cpu_model=cpu_info,
            cpu_count=cpu_count,
            ram_total_gb=ram_gb,
            uptime=uptime_s,
            kvm_available=kvm_ok,
        )
    except Exception as e:
        return err(e)


@app.route("/api/system/cpu-governor", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_cpu_governor():
    """CPU governor oku/yaz."""
    if request.method == "GET":
        try:
            gov = open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read().strip()
            return ok(governor=gov)
        except Exception as e:
            return ok(governor="unknown", error=str(e))
    gov = (request.get_json(silent=True) or {}).get("governor", "")
    allowed = {"performance", "powersave", "ondemand", "schedutil", "conservative", "userspace"}
    if gov not in allowed:
        return err("Geçersiz governor", 400)
    try:
        count = 0
        import glob as _glob
        for f in _glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"):
            with open(f, "w") as fp:
                fp.write(gov)
            count += 1
        _bg_notify(f"CPU governor değiştirildi: {gov}", level="INFO", category="system",
                   details={"governor": gov, "cpu_count": count})
        return ok(governor=gov, cpus_updated=count)
    except Exception as e:
        return err(e)


@app.route("/api/system/sysctl", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_sysctl():
    """sysctl parametrelerini oku/yaz."""
    ALLOWED_KEYS = {
        "vm.swappiness", "net.ipv4.ip_forward", "net.core.somaxconn",
        "net.ipv4.tcp_fin_timeout", "kernel.shmmax", "net.core.rmem_max",
        "net.core.wmem_max", "vm.dirty_ratio", "vm.dirty_background_ratio",
    }
    if request.method == "GET":
        import subprocess as _sp
        results = {}
        for key in ALLOWED_KEYS:
            try:
                r = _sp.run(["sysctl", "-n", key], capture_output=True, text=True, timeout=3)
                results[key] = r.stdout.strip() if r.returncode == 0 else "?"
            except Exception:
                results[key] = "?"
        return ok(params=results)

    data = request.get_json(silent=True) or {}
    params = data.get("params", {})
    applied, errors = [], []
    import subprocess as _sp
    for key, val in params.items():
        if key not in ALLOWED_KEYS:
            errors.append(f"{key}: izin verilmiyor")
            continue
        try:
            r = _sp.run(["sysctl", "-w", f"{key}={val}"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                applied.append(key)
            else:
                errors.append(f"{key}: {r.stderr.strip()}")
        except Exception as e:
            errors.append(f"{key}: {e}")
    if applied:
        _bg_notify(f"sysctl güncellendi: {', '.join(applied)}", level="INFO", category="system")
    return ok(applied=applied, errors=errors)


@app.route("/api/system/ntp-status")
@require_auth
def api_ntp_status():
    """NTP senkronizasyon durumu ve sunucu saati."""
    import subprocess as _sp
    from datetime import datetime as _dt
    synchronized = False
    server = ""
    try:
        r = _sp.run(["timedatectl", "show", "--no-pager"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if "NTPSynchronized=yes" in line:
                synchronized = True
            if line.startswith("NTP="):
                server = line.split("=", 1)[1].strip()
    except Exception:
        pass
    return ok(
        synchronized=synchronized,
        server=server,
        time=_dt.now().strftime("%d.%m.%Y %H:%M:%S"),
    )


@app.route("/api/system/ntp-sync", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ntp_sync():
    """NTP sunucusunu ayarla ve senkronize et."""
    import subprocess as _sp
    server = (request.get_json(silent=True) or {}).get("server", "pool.ntp.org")
    if not server or len(server) > 100:
        return err("Geçersiz NTP sunucusu", 400)
    try:
        _sp.run(["timedatectl", "set-ntp", "true"], capture_output=True, timeout=5)
        _sp.run(["chronyc", "online"], capture_output=True, timeout=5)
        return ok(message=f"NTP senkronize edildi: {server}")
    except Exception as e:
        return err(e)


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
@require_role("admin", "administrator")
def api_create_user():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "viewer")
    if not username or not password:
        return err("Kullanıcı adı ve şifre zorunludur")
    # OXW-SEC-004: password strength enforcement
    import re as _re_usr
    if len(password) < 8:
        return err("Şifre en az 8 karakter olmalıdır")
    if len(username) < 3 or not _re_usr.match(r"^[a-zA-Z0-9_\-\.]{3,64}$", username):
        return err("Kullanıcı adı 3-64 karakter, sadece harf/rakam/_-. içerebilir")
    # Validate role
    _allowed_roles = {"administrator", "admin", "operator", "viewer", "vm-user"}
    if role not in _allowed_roles:
        return err(f"Geçersiz rol. İzin verilenler: {', '.join(sorted(_allowed_roles))}")
    try:
        result = user_manager.add_user(username, password, role)
        ev.info(f"Kullanıcı oluşturuldu: {username} ({role})", category="auth")
        return ok(user=result), 201
    except (ValueError, Exception) as e:
        return err(str(e))

@app.route("/api/users/<username>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_delete_user(username):
    primary_admin = cred_mgr.get_username()
    if username == primary_admin:
        return err("Ana yönetici silinemez", 403)
    try:
        user_manager.delete_user(username)
        user_manager.unassign_all_user_vms(username)
        # rapor #16 fix: kullanıcının tüm aktif JWT tokenları anında iptal et
        if sess_mgr:
            revoked = sess_mgr.revoke_all_user_sessions(username)
            ev.info(f"Kullanıcı silindi: {username} — {revoked} oturum iptal edildi", category="auth")
        else:
            ev.info(f"Kullanıcı silindi: {username}", category="auth")
        return ok(status="deleted")
    except KeyError as e:
        return err(str(e), 404)
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/users/<username>/role", methods=["PUT"])
@require_auth
@require_role("admin", "administrator")
def api_update_user_role(username):
    data = request.get_json() or {}
    role = data.get("role", "")
    try:
        user_manager.update_user_role(username, role)
        ev.info(f"Kullanıcı rolü güncellendi: {username} → {role}", category="auth")
        return ok(status="updated")
    except (ValueError, KeyError) as e:
        return err(str(e))

@app.route("/api/users/<username>", methods=["PUT"])
@require_auth
@require_role("admin", "administrator")
def api_update_user(username):
    """Kullanıcı güncelle (ad, şifre, rol)."""
    primary_admin = cred_mgr.get_username()
    if username == primary_admin:
        return err("Ana yönetici bu yolla düzenlenemez", 403)
    data = request.get_json() or {}
    try:
        user_manager.update_user(
            username,
            new_username=data.get("new_username", "").strip() or None,
            new_password=data.get("password") or None,
            new_role=data.get("role") or None,
        )
        ev.info(f"Kullanıcı güncellendi: {username}", category="auth")
        return ok(status="updated")
    except (ValueError, KeyError) as e:
        return err(str(e))
    except Exception as e:
        return err(str(e), 500)

# ── VM Assignment endpoints ──────────────────────────────────────────────────

@app.route("/api/vms/<vm_id>/assign", methods=["GET"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_get_vm_assignees(vm_id):
    """Get users assigned to this VM."""
    try:
        assignees = user_manager.get_vm_users(vm_id)
        return ok(assignees=assignees)
    except Exception as e:
        return err(e, 500)


@app.route("/api/vms/<vm_id>/assign", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_assign_vm(vm_id):
    """Assign VM to a user."""
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    if not username:
        return err("username gerekli")
    try:
        # Validate user exists
        all_users = user_manager.list_users()
        names = {u["username"] for u in all_users}
        primary = cred_mgr.get_username()
        if username not in names and username != primary:
            return err(f"Kullanıcı bulunamadı: {username}", 404)
        user_manager.assign_vm(username, vm_id)
        ev.info(f"VM atandı: {vm_id} → {username}", category="auth")
        return ok(status="assigned")
    except Exception as e:
        return err(e, 500)


@app.route("/api/vms/<vm_id>/assign/<username>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_unassign_vm(vm_id, username):
    """Remove VM assignment from user."""
    try:
        user_manager.unassign_vm(username, vm_id)
        ev.info(f"VM ataması kaldırıldı: {vm_id} → {username}", category="auth")
        return ok(status="unassigned")
    except Exception as e:
        return err(e, 500)


@app.route("/api/users/<username>/vms", methods=["GET"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_get_user_vms(username):
    """Get VMs assigned to a user."""
    try:
        vm_ids = user_manager.get_user_vms(username)
        return ok(vm_ids=vm_ids)
    except Exception as e:
        return err(e, 500)


# ── Shell Konsol ──────────────────────────────────────────────────────────────
# OXW-2026-003 fix: /api/system/execute — komut whitelist + re-auth
_EXECUTE_WHITELIST = [
    # Servis yönetimi
    r"^systemctl (status|start|stop|restart|reload|is-active|is-enabled) [a-zA-Z0-9@._-]+$",
    # Sistem bilgisi
    r"^(df -h|df -Th|free -h|free -m|uptime|hostname|uname -a|uname -r)$",
    r"^top -bn1$",
    r"^ps aux$",
    # Ağ
    r"^(ip addr|ip route|ip link|netstat -tlnp|ss -tlnp)$",
    r"^ping -c [1-5] [a-zA-Z0-9._-]+$",
    # libvirt / KVM
    r"^virsh (list|net-list|pool-list|dominfo|domstats|snapshot-list) .*$",
    r"^virsh (start|shutdown|reboot|destroy|suspend|resume) [a-zA-Z0-9_-]+$",
    # Disk / depolama
    r"^(lsblk|blkid|lsblk -f)$",
    r"^du -sh [/a-zA-Z0-9_.-]+$",
    # Log okuma
    r"^journalctl -u [a-zA-Z0-9@._-]+ -n [0-9]+$",
    r"^tail -n [0-9]+ /var/log/oxware/[a-zA-Z0-9_.-]+$",
    # Güvenlik duvarı
    r"^ufw (status|status verbose)$",
    r"^iptables -L( -n)?$",
]

import re as _re_exec

# ── Shell komut kısıtlama (admin olmayan kullanıcılar) ────────────────────────
_SHELL_BLOCKED_PATTERNS = [
    # Şifre / kullanıcı yönetimi
    _re_exec.compile(r'(?:^|[;&|`(\s])(?:[/\w]*/)?(?:passwd|chpasswd|useradd|userdel|usermod|groupadd|groupdel|groupmod|vipw|vigr|visudo)\b', _re_exec.I),
    # Sistem kapatma / yeniden başlatma
    _re_exec.compile(r'(?:^|[;&|`(\s])(?:[/\w]*/)?(?:shutdown|reboot|poweroff|halt|init\s+[016])\b', _re_exec.I),
    # Ayrıcalık yükseltme
    _re_exec.compile(r'(?:^|[;&|`(\s])(?:[/\w]*/)?(?:su|sudo)\b', _re_exec.I),
    # Disk / bölüm yönetimi
    _re_exec.compile(r'(?:^|[;&|`(\s])(?:[/\w]*/)?(?:fdisk|parted|gdisk|mkfs(?:\.\w+)?|dd)\b', _re_exec.I),
    # Güvenlik duvarı değiştirme
    _re_exec.compile(r'(?:^|[;&|`(\s])(?:[/\w]*/)?(?:iptables|ip6tables|nft)\b', _re_exec.I),
    _re_exec.compile(r'(?:^|[;&|`(\s])ufw\s+(?:disable|reset|delete|deny|allow|reject|limit)\b', _re_exec.I),
    # systemctl tehlikeli işlemler
    _re_exec.compile(r'systemctl\s+(?:stop|disable|mask|kill|daemon-reload|reboot|poweroff|halt|suspend|hibernate)\b', _re_exec.I),
    # Zamanlanmış görev değiştirme
    _re_exec.compile(r'(?:^|[;&|`(\s])(?:[/\w]*/)?crontab\b', _re_exec.I),
    _re_exec.compile(r'(?:^|[;&|`(\s])(?:[/\w]*/)?(?:at|atq|atrm)\b', _re_exec.I),
    # Uzaktan kod çalıştırma
    _re_exec.compile(r'(?:curl|wget)\s+.*\|\s*(?:ba)?sh', _re_exec.I),
    # Kritik dosyalara yazma
    _re_exec.compile(r'[>|]\s*/etc/(?:passwd|shadow|sudoers|crontab|hosts)\b', _re_exec.I),
]

_SHELL_RESTRICTED_BANNER = (
    "\r\n\x1b[31m╔══════════════════════════════════════════════════════════╗\x1b[0m\r\n"
    "\x1b[31m║  ⛔  YETKİ REDDEDİLDİ                                      ║\x1b[0m\r\n"
    "\x1b[31m║     Bu işlem için yeterli yetkiniz bulunmamaktadır.         ║\x1b[0m\r\n"
    "\x1b[31m║     Lütfen sistem yöneticinize başvurun.                    ║\x1b[0m\r\n"
    "\x1b[31m╚══════════════════════════════════════════════════════════╝\x1b[0m\r\n"
)

def _shell_is_blocked(cmd: str) -> bool:
    """Komutun kısıtlı listede olup olmadığını kontrol eder."""
    cmd = cmd.strip()
    if not cmd:
        return False
    for pat in _SHELL_BLOCKED_PATTERNS:
        if pat.search(cmd):
            return True
    return False

# Kısıtlı shell için bash rcfile içeriği (admin olmayan kullanıcılara uygulanır)
_RESTRICTED_SHELL_RC = r"""
# OXware Kısıtlı Shell — admin olmayan kullanıcılar için
export PS1='\[\e[33m\][KISITLI-SHELL]\[\e[0m\] \u@oxware:\w\$ '

_perm_denied() {
    printf '\r\n\033[31m╔══════════════════════════════════════════════════════════╗\033[0m\r\n'
    printf '\033[31m║  ⛔  YETKİ REDDEDİLDİ                                      ║\033[0m\r\n'
    printf '\033[31m║     Bu işlem için yeterli yetkiniz bulunmamaktadır.         ║\033[0m\r\n'
    printf '\033[31m║     Lütfen sistem yöneticinize başvurun.                    ║\033[0m\r\n'
    printf '\033[31m╚══════════════════════════════════════════════════════════╝\033[0m\r\n'
    return 1
}

passwd()     { _perm_denied; }
chpasswd()   { _perm_denied; }
useradd()    { _perm_denied; }
userdel()    { _perm_denied; }
usermod()    { _perm_denied; }
groupadd()   { _perm_denied; }
groupdel()   { _perm_denied; }
groupmod()   { _perm_denied; }
vipw()       { _perm_denied; }
vigr()       { _perm_denied; }
visudo()     { _perm_denied; }
shutdown()   { _perm_denied; }
reboot()     { _perm_denied; }
poweroff()   { _perm_denied; }
halt()       { _perm_denied; }
su()         { _perm_denied; }
sudo()       { _perm_denied; }
fdisk()      { _perm_denied; }
parted()     { _perm_denied; }
gdisk()      { _perm_denied; }
dd()         { _perm_denied; }
mkfs()       { _perm_denied; }
mkfs.ext4()  { _perm_denied; }
mkfs.xfs()   { _perm_denied; }
mkfs.btrfs() { _perm_denied; }
iptables()   { _perm_denied; }
ip6tables()  { _perm_denied; }
nft()        { _perm_denied; }
crontab()    { _perm_denied; }

ufw() {
    case "$1" in disable|reset|delete|deny|allow|reject|limit)
        _perm_denied; return ;;
    esac
    command ufw "$@"
}

systemctl() {
    case "$1" in
        stop|disable|mask|kill|daemon-reload|reboot|poweroff|halt|suspend|hibernate)
            _perm_denied; return ;;
    esac
    command systemctl "$@"
}

export -f _perm_denied passwd chpasswd useradd userdel usermod groupadd groupdel groupmod
export -f vipw vigr visudo shutdown reboot poweroff halt su sudo
export -f fdisk parted gdisk dd mkfs iptables ip6tables nft crontab ufw systemctl

printf '\033[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\r\n'
printf '\033[33m  OXware Kısıtlı Shell — Tehlikeli komutlar engellendi\033[0m\r\n'
printf '\033[33m  Tam yetki için ana yönetici hesabıyla giriş yapın.\033[0m\r\n'
printf '\033[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\r\n'
"""

@app.route("/api/system/execute", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_execute_command():
    """OXW-2026-003: Whitelist-only komut yürütme. shell=False, argüman listesi."""
    data = request.get_json() or {}
    command = data.get("command", "").strip()
    if not command:
        return err("command boş olamaz")

    # OXW-2026-003 fix: komut whitelist kontrolü
    allowed = any(_re_exec.match(pattern, command) for pattern in _EXECUTE_WHITELIST)
    if not allowed:
        log.warning("execute: whitelist dışı komut reddedildi: %s", command[:120])
        ev.warn(f"Reddedilen komut: {command[:80]}", category="system")
        return err(
            "Bu komuta izin verilmiyor. Yalnızca önceden tanımlanmış komutlar çalıştırılabilir.",
            403,
        )

    # shell=False — liste olarak geçir (injection önleme)
    import shlex as _shlex
    try:
        args = _shlex.split(command)
    except ValueError as e:
        return err(f"Komut ayrıştırma hatası: {e}", 400)

    try:
        result = subprocess.run(
            args,
            shell=False,  # OXW-2026-003: shell=False
            capture_output=True, text=True, timeout=30,
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
    except FileNotFoundError:
        return err(f"Komut bulunamadı: {args[0]}", 404)
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
@require_role("admin", "administrator", "operator")
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
        if plugin_sdk_mgr:
            try: plugin_sdk_mgr.emit_event("vm.snapshot_created", {"vm_id": vm_id, "snapshot": snap_name})
            except Exception as _pse: log.warning("plugin emit vm.snapshot_created: %s", _pse)
        return ok(**result), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/snapshots/<snap_name>/revert", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
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
@require_role("admin", "administrator", "operator")
def api_delete_snapshot_v2(vm_id, snap_name):
    try:
        vm_id     = security.validate_uuid(vm_id, "vm_id")
        snap_name = security.validate_vm_name(snap_name)
    except ValueError as e:
        return err(str(e))
    try:
        result = vm_manager.delete_snapshot(vm_id, snap_name)
        ev.vm_event(f"Snapshot silindi: {snap_name}", vm_id, level="INFO")
        if plugin_sdk_mgr:
            try: plugin_sdk_mgr.emit_event("vm.snapshot_deleted", {"vm_id": vm_id, "snapshot": snap_name})
            except Exception as _pse: log.warning("plugin emit vm.snapshot_deleted: %s", _pse)
        return ok(**result)
    except Exception as e:
        return err(e, 500)

# ── WebSocket ─────────────────────────────────────────────────────────────────

# VM event subscribers: sid → set of vm_ids (or "*" for all)
_vm_event_subscribers: dict = {}
_vm_event_subscribers_lock  = threading.Lock()


def _ws_emit_vm_event(vm_id: str, event_type: str, data: dict):
    """Tüm ilgili subscriber'lara VM event gönder."""
    with _vm_event_subscribers_lock:
        sids = list(_vm_event_subscribers.items())
    for sid, filter_ids in sids:
        if filter_ids == "*" or vm_id in filter_ids:
            try:
                sock.emit("vm_event", {
                    "vm_id": vm_id,
                    "type":  event_type,
                    **data
                }, to=sid, namespace="/")
            except Exception:
                pass


# Expose globally so vmAction endpoints can call it
app.ws_emit_vm_event = _ws_emit_vm_event


@sock.on("subscribe_vm_events")
def on_subscribe_vm_events(data):
    """
    Client VM durumu değişikliklerine abone olur.
    data: {vm_ids: ["uuid1", "uuid2", ...]}  or {vm_ids: "*"}
    Olaylar: vm_event {vm_id, type, state?, metric?}
    rapor #28 fix: vm-user rolü yalnızca kendine atanmış VM'lere abone olabilir,
    "*" wildcard yalnızca operator/admin'e açık.
    """
    sid = request.sid
    vm_ids = (data or {}).get("vm_ids", "*")

    # rapor #28 fix: rol bazlı wildcard kontrolü
    try:
        verify_jwt_in_request()
        _ws_username = get_jwt_identity()
        _ws_prim = cred_mgr.get_username() if hasattr(cred_mgr, "get_username") else ""
        if _ws_username == _ws_prim:
            _ws_role = "administrator"
        else:
            _ws_role = user_manager.get_user_role(_ws_username) if user_manager else "viewer"
        if _ws_role == "vm-user" and vm_ids == "*":
            # vm-user: yalnızca kendi VM'leri
            vm_ids = list(user_manager.get_user_vms(_ws_username) or [])
    except Exception:
        pass

    with _vm_event_subscribers_lock:
        _vm_event_subscribers[sid] = vm_ids if vm_ids == "*" else set(vm_ids)
    emit("vm_events_subscribed", {"vm_ids": vm_ids})

    # Immediately push current state for subscribed VMs
    try:
        all_vms = vm_manager.list_vms()
        target  = all_vms if vm_ids == "*" else [v for v in all_vms if v["id"] in set(vm_ids)]
        for v in target:
            sock.emit("vm_event", {
                "vm_id": v["id"],
                "type":  "state",
                "state": v.get("state", "unknown"),
                "name":  v.get("name", ""),
            }, to=sid, namespace="/")
    except Exception:
        pass


@sock.on("subscribe_vm_metrics")
def on_subscribe_vm_metrics(data):
    """
    Belirli bir VM için gerçek zamanlı metrik push.
    data: {vm_id: "<uuid>", interval: 3}
    Olaylar: vm_metrics {vm_id, cpu_pct, mem_mb, disk_rd, disk_wr, net_rx, net_tx}
    """
    sid      = request.sid
    vm_id    = (data or {}).get("vm_id", "")
    interval = max(1, int((data or {}).get("interval", 3)))
    if not vm_id:
        emit("error", {"message": "vm_id gerekli"})
        return

    def _push():
        while True:
            try:
                # Check if sid still subscribed
                with _vm_event_subscribers_lock:
                    still_connected = True  # rely on socketio disconnect to clean up
                stats = vm_manager.get_vm_stats(vm_id)
                sock.emit("vm_metrics", {
                    "vm_id":    vm_id,
                    "cpu_pct":  stats.get("cpu_pct", 0),
                    "mem_mb":   stats.get("memory_used_mb", 0),
                    "disk_rd":  stats.get("disk_read_bytes", 0),
                    "disk_wr":  stats.get("disk_write_bytes", 0),
                    "net_rx":   stats.get("net_rx_bytes", 0),
                    "net_tx":   stats.get("net_tx_bytes", 0),
                }, to=sid, namespace="/")
            except Exception:
                break
            time.sleep(interval)

    threading.Thread(target=_push, daemon=True).start()
    emit("vm_metrics_subscribed", {"vm_id": vm_id, "interval": interval})


@sock.on("subscribe_stats")
def on_subscribe_stats(data):
    sid = request.sid

    def push():
        for _ in range(720):
            try:
                stats = system_monitor._STATS_CACHE["data"] or system_monitor.get_system_stats()
                vm_sum = system_monitor.get_vm_summary()
                sock.emit("stats_update", {"stats": stats, "vms": vm_sum}, to=sid, namespace="/")
            except Exception:
                break
            time.sleep(5)

    try:
        stats = system_monitor._STATS_CACHE["data"] or system_monitor.get_system_stats()
        vm_sum = system_monitor.get_vm_summary()
        emit("stats_update", {"stats": stats, "vms": vm_sum})
    except Exception:
        pass
    threading.Thread(target=push, daemon=True).start()

# ── PTY Shell WebSocket ────────────────────────────────────────────────────────
_shell_sessions  = {}
_serial_sessions = {}  # sid → {proc, master_fd, vm_id}
_iso_fetch_jobs  = {}   # job_id → {status, filename, progress, ...}
_vnc_sessions    = {}   # sid    → tcp_socket

@sock.on("shell_open")
def ws_shell_open(data=None):
    sid = request.sid
    log.info("shell_open alındı: sid=%s", sid)

    def _shell_emit(text):
        sock.emit("shell_output", {"data": text}, to=sid, namespace="/")

    # ── Token doğrulama ──────────────────────────────────────────────────────
    try:
        from flask_jwt_extended import decode_token
        token = (data or {}).get("token", "")
        if not token:
            _shell_emit("\r\n[Hata: token gönderilmedi]\r\n")
            return
        decoded = decode_token(token)
        identity = decoded.get("sub") or decoded.get("identity", "")
        if not identity:
            _shell_emit("\r\n[Hata: geçersiz token kimliği]\r\n")
            return
        log.info("Shell yetkisi tamam: %s sid=%s", identity, sid)
    except Exception as e:
        log.error("Shell token hatası: %s", e)
        _shell_emit(f"\r\n[Yetkilendirme hatası: {e}]\r\n")
        return

    # ── Rol çözümle — primary admin tam yetki, diğerleri kısıtlı ─────────────
    try:
        _primary = cred_mgr.get_username() if hasattr(cred_mgr, "get_username") else ""
        if identity == _primary:
            _shell_role = "admin"
        elif hasattr(cred_mgr, "get_role"):
            _shell_role = cred_mgr.get_role(identity) or "viewer"
        elif user_manager:
            _shell_role = user_manager.get_user_role(identity) or "viewer"
        else:
            _shell_role = "viewer"
    except Exception:
        _shell_role = "viewer"
    _is_admin_shell = _shell_role in ("admin", "administrator")

    # rapor #38 fix: audit log PTY shell open
    _client_ip = request.remote_addr or "unknown"
    audit_log.log_action(identity, "shell_open", "host", "pty",
                         details={"sid": sid, "ip": _client_ip, "role": _shell_role})
    log.warning("PTY shell acildi: kullanici=%s ip=%s sid=%s rol=%s",
                identity, _client_ip, sid, _shell_role)

    # ── PTY + Bash ──────────────────────────────────────────────────────────
    try:
        import pty, fcntl, termios, resource as _res, eventlet

        master_fd, slave_fd = pty.openpty()

        # rapor #39 fix: fork bomb korumasi
        def _set_limits():
            os.setsid()
            try:
                _res.setrlimit(_res.RLIMIT_NPROC, (128, 256))
                _res.setrlimit(_res.RLIMIT_NOFILE, (1024, 1024))
            except Exception:
                pass

        # Admin olmayan kullanıcılar için kısıtlı rcfile oluştur
        _rcfile_path = None
        if not _is_admin_shell:
            import tempfile as _tmpf
            _rcfd, _rcfile_path = _tmpf.mkstemp(prefix="oxw-rc-", suffix=".sh")
            try:
                os.write(_rcfd, _RESTRICTED_SHELL_RC.encode())
            finally:
                os.close(_rcfd)
            os.chmod(_rcfile_path, 0o600)

        bash_cmd = ["/bin/bash"] if _is_admin_shell else ["/bin/bash", "--rcfile", _rcfile_path]
        proc = subprocess.Popen(
            bash_cmd,
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            close_fds=True, preexec_fn=_set_limits,
            env={**os.environ, "TERM": "xterm-256color", "PS1": r"\u@oxware:\w\$ "},
        )
        os.close(slave_fd)

        # Rcfile'ı hemen sil — bash zaten fd açtı, dosya silinse de çalışır
        if _rcfile_path:
            try:
                os.unlink(_rcfile_path)
            except Exception:
                pass

        _shell_sessions[sid] = {
            "proc":     proc,
            "master_fd": master_fd,
            "role":     _shell_role,
            "is_admin": _is_admin_shell,
            "cmd_buf":  "",   # input buffer — non-admin komut interception için
        }

        fl = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        def _read_loop():
            import eventlet as _ev
            while True:
                try:
                    out = os.read(master_fd, 4096)
                    if out:
                        sock.emit("shell_output",
                                  {"data": out.decode("utf-8", errors="replace")},
                                  to=sid, namespace="/")
                    else:
                        break
                except BlockingIOError:
                    _ev.sleep(0.05)
                    continue
                except OSError:
                    break
                except Exception as _ex:
                    log.error("_read_loop hatası: %s", _ex)
                    break
            sock.emit("shell_output", {"data": "\r\n[Oturum kapatıldı]\r\n"},
                      to=sid, namespace="/")

        eventlet.spawn(_read_loop)
        root_warn = "" if os.geteuid() == 0 else "\r\n\x1b[33m[Uyarı: Backend root değil — bazı komutlar çalışmayabilir]\x1b[0m"
        _shell_emit(f"\r\nOXware Host Shell — {'root' if os.geteuid() == 0 else os.getlogin() if hasattr(os, 'getlogin') else 'user'}{root_warn}\r\n")
        log.info("Shell başlatıldı: sid=%s pid=%d rol=%s", sid, proc.pid, _shell_role)

    except Exception as e:
        log.error("Shell açma hatası: %s", e)
        _shell_emit(f"\r\n[Shell açılamadı: {e}]\r\n")


@sock.on("shell_input")
def ws_shell_input(data):
    session_id = request.sid
    sess = _shell_sessions.get(session_id)
    if not sess:
        log.warning("shell_input: oturum bulunamadı %s", session_id)
        return
    try:
        raw = data.get("data", "")
        inp_str = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
        inp_bytes = inp_str.encode("utf-8") if isinstance(raw, str) else raw

        # Admin: tüm girdi kısıtsız geçer
        if sess.get("is_admin", True):
            os.write(sess["master_fd"], inp_bytes)
            return

        # Non-admin: karakter bazlı buffer + Enter'da komut kontrolü
        # (bash function override'ların yakalayamadığı tam yol bypass'larını engeller)
        for ch in inp_str:
            ch_bytes = ch.encode("utf-8")
            if ch in ("\r", "\n"):
                cmd = sess.get("cmd_buf", "").strip()
                sess["cmd_buf"] = ""
                if cmd and _shell_is_blocked(cmd):
                    # Engelle: PTY'ye Ctrl+C gönder (satırı iptal eder)
                    os.write(sess["master_fd"], b"\x03")
                    sock.emit("shell_output",
                              {"data": _SHELL_RESTRICTED_BANNER},
                              to=session_id, namespace="/")
                    log.warning("shell_input engellendi: sid=%s cmd=%r", session_id, cmd[:120])
                else:
                    os.write(sess["master_fd"], ch_bytes)
            elif ch in ("\x7f", "\x08"):  # Backspace
                buf = sess.get("cmd_buf", "")
                if buf:
                    sess["cmd_buf"] = buf[:-1]
                os.write(sess["master_fd"], ch_bytes)
            elif ch == "\x03":  # Ctrl+C — tamponu temizle
                sess["cmd_buf"] = ""
                os.write(sess["master_fd"], ch_bytes)
            elif ch == "\t" or ord(ch) >= 0x20:  # yazdırılabilir + tab
                sess["cmd_buf"] = sess.get("cmd_buf", "") + ch
                os.write(sess["master_fd"], ch_bytes)
            else:
                # Ok tuşları ve diğer kontrol karakterleri: buffer'a ekleme, geçir
                os.write(sess["master_fd"], ch_bytes)

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
    # VM serial console temizle
    ser = _serial_sessions.pop(session_id, None)
    if ser:
        try: ser["proc"].terminate()
        except Exception: pass
        try: os.close(ser["master_fd"])
        except Exception: pass
    # VNC proxy temizle
    tcp = _vnc_sessions.pop(session_id, None)
    if tcp:
        try:
            tcp.close()
        except Exception:
            pass
    # VM event subscriber temizle
    with _vm_event_subscribers_lock:
        _vm_event_subscribers.pop(session_id, None)


# (VNC WebSocket proxy now handled by _vnc_ws_middleware + eventlet.websocket above)


# ── VNC Console Proxy (SocketIO üzerinden — port 8006, SSL dahil) ─────────────

@sock.on("vnc_proxy_connect")
def ws_vnc_connect(data=None):
    """VM'in VNC portuna TCP bağlantısı aç, veriyi SocketIO üzerinden aktar."""
    import socket as _sock
    import base64 as _b64
    import xml.etree.ElementTree as _ET2

    sid = request.sid
    data = data or {}

    # ── Kimlik doğrulama ──────────────────────────────────────────────────────
    try:
        from flask_jwt_extended import decode_token
        token = data.get("token", "")
        if not token:
            emit("vnc_proxy_error", {"msg": "token eksik"})
            return
        decoded = decode_token(token)
        identity = decoded.get("sub") or decoded.get("identity", "")
        if not identity:
            emit("vnc_proxy_error", {"msg": "geçersiz token"})
            return
    except Exception as ex:
        emit("vnc_proxy_error", {"msg": f"auth: {ex}"})
        return

    # ── VNC portunu bul ───────────────────────────────────────────────────────
    vm_id = data.get("vm_id", "")
    try:
        import libvirt as _lv2
        conn = _lv2.open(config.LIBVIRT_URI)
        dom  = conn.lookupByUUIDString(vm_id)
        xml_str = dom.XMLDesc()
        conn.close()
        root    = _ET2.fromstring(xml_str)
        vnc_el  = root.find(".//graphics[@type='vnc']")
        vnc_port = int(vnc_el.get("port", -1)) if vnc_el is not None else -1
        if vnc_port < 5900:
            emit("vnc_proxy_error", {"msg": f"VM çalışmıyor veya VNC aktif değil (port={vnc_port})"})
            return
    except Exception as ex:
        emit("vnc_proxy_error", {"msg": f"VM hatası: {ex}"})
        return

    # ── TCP bağlantısı ────────────────────────────────────────────────────────
    try:
        tcp = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        tcp.settimeout(5)
        tcp.connect(("127.0.0.1", vnc_port))
        tcp.settimeout(None)
        # TCP keepalive — firewall/NAT sessiz drop'ları önler
        tcp.setsockopt(_sock.SOL_SOCKET, _sock.SO_KEEPALIVE, 1)
        try:
            tcp.setsockopt(_sock.IPPROTO_TCP, _sock.TCP_KEEPIDLE,  10)  # 10s idle → ilk probe
            tcp.setsockopt(_sock.IPPROTO_TCP, _sock.TCP_KEEPINTVL,  5)  # probe arası 5s
            tcp.setsockopt(_sock.IPPROTO_TCP, _sock.TCP_KEEPCNT,    3)  # 3 başarısız → kapat
        except AttributeError:
            pass  # Windows'ta TCP_KEEPIDLE yok, SO_KEEPALIVE yeterli
        _vnc_sessions[sid] = tcp
    except Exception as ex:
        emit("vnc_proxy_error", {"msg": f"VNC bağlanamadı (port {vnc_port}): {ex}"})
        return

    emit("vnc_proxy_ready", {"vnc_port": vnc_port})
    log.info("VNC proxy başladı: sid=%s vm=%s port=%d", sid, vm_id, vnc_port)

    # ── VNC → browser okuma thread'i ──────────────────────────────────────────
    def _reader():
        import base64 as _b64r
        try:
            while True:
                chunk = tcp.recv(65536)
                if not chunk:
                    break
                socketio.emit("vnc_proxy_data",
                              {"b": _b64r.b64encode(chunk).decode()},
                              room=sid)
        except Exception:
            pass
        socketio.emit("vnc_proxy_closed", {}, room=sid)
        _vnc_sessions.pop(sid, None)

    threading.Thread(target=_reader, daemon=True).start()


@sock.on("vnc_proxy_send")
def ws_vnc_send(data=None):
    """Browser'dan gelen VNC verisini TCP soketine yaz."""
    import base64 as _b64
    sid = request.sid
    tcp = _vnc_sessions.get(sid)
    if not tcp:
        return
    try:
        raw = _b64.b64decode((data or {}).get("b", ""))
        tcp.sendall(raw)
    except Exception:
        pass


@sock.on("vnc_proxy_close")
def ws_vnc_close(data=None):
    """VNC bağlantısını kapat."""
    sid = request.sid
    tcp = _vnc_sessions.pop(sid, None)
    if tcp:
        try:
            tcp.close()
        except Exception:
            pass


# ── VM Serial Console (xterm.js) ── virsh console proxy ──────────────────────
@sock.on("vm_serial_open")
def ws_vm_serial_open(data=None):
    """VM'in seri konsolunu aç — virsh console aracılığıyla PTY proxy."""
    sid = request.sid
    data = data or {}

    def _emit(text):
        sock.emit("vm_serial_output", {"data": text}, to=sid, namespace="/")

    # Token doğrulama
    try:
        from flask_jwt_extended import decode_token as _dt2
        token = data.get("token", "")
        if not token:
            _emit("\r\n[Hata: token gönderilmedi]\r\n"); return
        decoded = _dt2(token)
        identity = decoded.get("sub") or decoded.get("identity", "")
        if not identity:
            _emit("\r\n[Hata: geçersiz token]\r\n"); return
        # VM_USER sadece atanmış VM'e erişebilir
        _prim = cred_mgr.get_username() if hasattr(cred_mgr, "get_username") else ""
        if identity != _prim:
            try:
                _role = (cred_mgr.get_role(identity) if hasattr(cred_mgr, "get_role")
                         else user_manager.get_user_role(identity))
                vm_id = data.get("vm_id", "")
                if _role == "vm-user":
                    allowed = user_manager.get_user_vms(identity) if user_manager else []
                    if vm_id not in allowed:
                        _emit("\r\n[Erişim reddedildi: VM atanmamış]\r\n"); return
            except Exception:
                pass
    except Exception as e:
        _emit(f"\r\n[Yetkilendirme hatası: {e}]\r\n"); return

    vm_id = data.get("vm_id", "")
    if not vm_id:
        _emit("\r\n[Hata: vm_id eksik]\r\n"); return

    # VM çalışıyor mu?
    try:
        r_state = subprocess.run(["virsh", "domstate", vm_id], capture_output=True, text=True)
        if "running" not in r_state.stdout.lower():
            _emit(f"\r\n[VM çalışmıyor: {r_state.stdout.strip()}]\r\n"); return
    except Exception as e:
        _emit(f"\r\n[virsh domstate hatası: {e}]\r\n"); return

    try:
        import fcntl, termios, tty, xml.etree.ElementTree as _ET, eventlet as _ev2

        # ── Find QEMU serial PTY path from domain XML ─────────────────────────
        # Direct PTY access is far more reliable than virsh console over PTY
        pty_path = None
        try:
            _xml_r = subprocess.run(["virsh", "dumpxml", vm_id], capture_output=True, text=True)
            _root  = _ET.fromstring(_xml_r.stdout)
            for _serial in _root.findall(".//serial[@type='pty']") + _root.findall(".//console[@type='pty']"):
                _src = _serial.find("source")
                if _src is not None and _src.get("path"):
                    pty_path = _src.get("path")
                    break
        except Exception as _xe:
            log.warning("dumpxml PTY parse hatası: %s", _xe)

        if pty_path:
            # ── Direct PTY mode ───────────────────────────────────────────────
            serial_fd = os.open(pty_path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            # Set raw mode so input passes through byte-for-byte
            try:
                old_attrs = termios.tcgetattr(serial_fd)
                tty.setraw(serial_fd)
            except Exception:
                pass

            _serial_sessions[sid] = {"fd": serial_fd, "vm_id": vm_id, "proc": None, "master_fd": serial_fd}

            def _read_loop():
                while True:
                    try:
                        out = os.read(serial_fd, 4096)
                        if out:
                            sock.emit("vm_serial_output",
                                      {"data": out.decode("utf-8", errors="replace")},
                                      to=sid, namespace="/")
                        else:
                            _ev2.sleep(0.05)
                    except BlockingIOError:
                        _ev2.sleep(0.05)
                        continue
                    except OSError:
                        break
                    except Exception as _ex:
                        log.error("vm_serial read_loop (pty): %s", _ex); break
                sock.emit("vm_serial_output", {"data": "\r\n[Konsol bağlantısı kesildi]\r\n"},
                          to=sid, namespace="/")
                _serial_sessions.pop(sid, None)
                try: os.close(serial_fd)
                except Exception: pass

            _ev2.spawn(_read_loop)
            _emit(f"\r\nOXware VM Konsolu — {vm_id}\r\nBağlı ({pty_path})\r\nEscape: Ctrl+]\r\n")
            log.info("vm_serial_open (direct-pty): sid=%s vm=%s pty=%s", sid, vm_id, pty_path)

        else:
            # ── Fallback: virsh console via PTY ──────────────────────────────
            import pty as _pty
            master_fd, slave_fd = _pty.openpty()
            # Keep slave_fd open in parent so writes work (close after proc starts)
            try:
                # Set slave to raw mode before virsh reads it
                tty.setraw(slave_fd)
            except Exception:
                pass
            proc = subprocess.Popen(
                ["virsh", "console", vm_id, "--force"],
                stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                close_fds=True, preexec_fn=os.setsid,
            )
            os.close(slave_fd)
            fl = fcntl.fcntl(master_fd, fcntl.F_GETFL)
            fcntl.fcntl(master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            _serial_sessions[sid] = {"proc": proc, "master_fd": master_fd, "vm_id": vm_id, "fd": master_fd}

            def _read_loop():
                while True:
                    try:
                        out = os.read(master_fd, 4096)
                        if out:
                            sock.emit("vm_serial_output",
                                      {"data": out.decode("utf-8", errors="replace")},
                                      to=sid, namespace="/")
                        else:
                            break
                    except BlockingIOError:
                        _ev2.sleep(0.05)
                        continue
                    except OSError:
                        break
                    except Exception as _ex:
                        log.error("vm_serial read_loop (virsh): %s", _ex); break
                sock.emit("vm_serial_output", {"data": "\r\n[Konsol bağlantısı kesildi]\r\n"},
                          to=sid, namespace="/")
                _serial_sessions.pop(sid, None)

            _ev2.spawn(_read_loop)
            _emit(f"\r\nOXware VM Konsolu — {vm_id}\r\nBağlanıyor (Ctrl+] çıkış)...\r\n")
            log.info("vm_serial_open (virsh-pty): sid=%s vm=%s pid=%d", sid, vm_id, proc.pid)

    except Exception as e:
        log.error("vm_serial_open hata: %s", e)
        _emit(f"\r\n[Seri konsol açılamadı: {e}]\r\n")


@sock.on("vm_serial_input")
def ws_vm_serial_input(data):
    sess = _serial_sessions.get(request.sid)
    if not sess: return
    try:
        inp = data.get("data", "")
        if isinstance(inp, str):
            inp = inp.encode("utf-8")
        # Use "fd" key (direct PTY) or fall back to "master_fd" (virsh PTY)
        fd = sess.get("fd") or sess.get("master_fd")
        os.write(fd, inp)
    except Exception as e:
        log.error("vm_serial_input: %s", e)


@sock.on("vm_serial_resize")
def ws_vm_serial_resize(data):
    import fcntl, struct, termios
    sess = _serial_sessions.get(request.sid)
    if not sess: return
    try:
        cols = int(data.get("cols", 80))
        rows = int(data.get("rows", 24))
        fcntl.ioctl(sess["master_fd"], termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        pass


@sock.on("vm_serial_close")
def ws_vm_serial_close(data=None):
    sess = _serial_sessions.pop(request.sid, None)
    if sess:
        try: sess["proc"].terminate()
        except Exception: pass
        for _key in ("fd", "master_fd"):
            try: os.close(sess[_key])
            except Exception: pass


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
@app.route("/api/telemetry", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_telemetry():
    """Şifreli usage telemetry istatistikleri — sadece admin."""
    try:
        import sys as _s, os as _o
        _tp = _o.path.join(_o.path.dirname(__file__), "..", "..", "telemetry", "collector.py")
        if not _o.path.exists(_tp):
            return ok(enabled=False, message="Telemetry modülü kurulu değil")
        if "telemetry_collector" not in _s.modules:
            import importlib.util as _ilu
            _spec = _ilu.spec_from_file_location("telemetry_collector", _tp)
            _tele = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_tele)
            _s.modules["telemetry_collector"] = _tele
        _tc = _s.modules["telemetry_collector"]
        return ok(enabled=True, **_tc.get_stats())
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/telemetry/push", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_telemetry_push():
    """Şifreli veriyi GitHub Gist'e gönder."""
    try:
        import sys as _s, os as _o
        _tp = _o.path.join(_o.path.dirname(__file__), "..", "..", "telemetry", "collector.py")
        if not _o.path.exists(_tp):
            return err("Telemetry modülü kurulu değil")
        _tc = _s.modules.get("telemetry_collector")
        if not _tc:
            import importlib.util as _ilu
            _spec = _ilu.spec_from_file_location("telemetry_collector", _tp)
            _tc = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_tc)
            _s.modules["telemetry_collector"] = _tc
        result = _tc.push_to_gist()
        return ok(**result)
    except Exception as e:
        return err(str(e), 500)


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

# ── Backup Disk ───────────────────────────────────────────────────────────────
_BACKUP_DISK_REGISTRY_FILE = os.path.join(
    config.DATA_DIR if hasattr(config, "DATA_DIR") else "/var/lib/oxware",
    "backup_disks.json"
)

def _load_backup_disk_registry():
    try:
        if os.path.exists(_BACKUP_DISK_REGISTRY_FILE):
            with open(_BACKUP_DISK_REGISTRY_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return []

def _save_backup_disk_registry(lst):
    os.makedirs(os.path.dirname(_BACKUP_DISK_REGISTRY_FILE), exist_ok=True)
    with open(_BACKUP_DISK_REGISTRY_FILE, "w") as f:
        json.dump(lst, f, indent=2)

@app.route("/api/backup/disks", methods=["GET"])
@require_auth
def api_backup_disk_list():
    """Kayıtlı yedekleme disklerini listele."""
    disks = _load_backup_disk_registry()
    # Disk dosyası hâlâ var mı kontrol et
    for d in disks:
        d["exists"] = os.path.isfile(d.get("path", ""))
        if d["exists"]:
            try:
                d["size_bytes"] = os.path.getsize(d["path"])
            except Exception:
                d["size_bytes"] = 0
    return ok({"disks": disks})

@app.route("/api/backup/disks", methods=["POST"])
@require_auth
def api_backup_disk_create():
    """Yeni yedekleme diski oluştur ve VM'e bağla."""
    import time as _time
    data = request.get_json(force=True, silent=True) or {}
    vm_id   = (data.get("vm_id") or "").strip()
    size_gb = int(data.get("size_gb") or 50)
    label   = security.sanitize_str(data.get("label") or "backup", 64)
    bus     = data.get("bus", "sata")
    if bus not in ("sata", "virtio", "ide"):
        bus = "sata"
    if size_gb < 1 or size_gb > 8192:
        return err("Geçersiz disk boyutu (1-8192 GB)")

    try:
        vm = vm_manager.get_vm(vm_id)
        if not vm:
            return err("VM bulunamadı")
    except Exception as e:
        return err(str(e))

    import re as _re
    ts        = int(_time.time())
    safe_name = _re.sub(r"[^a-zA-Z0-9_\-]", "_", label)
    disk_name = f"{vm['name']}-{safe_name}-{ts}.qcow2"
    disk_path = os.path.join(config.DISK_DIR, disk_name)

    try:
        import subprocess as _sp
        _sp.run(
            ["qemu-img", "create", "-f", "qcow2", disk_path, f"{size_gb}G"],
            check=True, capture_output=True
        )
    except Exception as e:
        return err(f"Disk oluşturulamadı: {e}")

    try:
        result = vm_manager.hot_attach_disk(vm_id, disk_path, bus=bus)
    except Exception as e:
        # Disk oluşturuldu ama bağlanamadı — dosyayı sil
        try:
            os.unlink(disk_path)
        except Exception:
            pass
        return err(f"Disk bağlanamadı: {e}")

    import datetime as _dt
    entry = {
        "id":         f"bd-{ts}",
        "vm_id":      vm_id,
        "vm_name":    vm.get("name", vm_id),
        "label":      label,
        "size_gb":    size_gb,
        "path":       disk_path,
        "bus":        bus,
        "target_dev": result.get("target", ""),
        "created_at": _dt.datetime.utcnow().isoformat(),
    }
    registry = _load_backup_disk_registry()
    registry.append(entry)
    _save_backup_disk_registry(registry)

    ev.info(f"Yedekleme diski oluşturuldu: {disk_name} → VM {vm_id}", category="backup")
    return ok({"disk": entry}), 201

@app.route("/api/backup/disks/<disk_id>/restore", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_backup_disk_restore(disk_id):
    """
    Yedekleme diskinden VM'in ana diskini geri yükle.
    1. VM durdurulur (çalışıyorsa)
    2. qemu-img convert backup → ana disk
    3. İsteğe bağlı olarak VM yeniden başlatılır
    """
    import subprocess as _sp_r
    import xml.etree.ElementTree as _ET_r
    import libvirt as _lv_r

    data = request.get_json(force=True, silent=True) or {}
    restart_after = bool(data.get("restart_after", True))

    registry = _load_backup_disk_registry()
    entry = next((d for d in registry if d.get("id") == disk_id), None)
    if not entry:
        return err("Yedekleme diski kaydı bulunamadı", 404)

    backup_path = entry.get("path", "")
    vm_id       = entry.get("vm_id", "")

    if not backup_path or not os.path.isfile(backup_path):
        return err("Yedekleme dosyası bulunamadı: " + backup_path)
    if not vm_id:
        return err("Yedekleme kaydında vm_id yok")

    try:
        # VM'in ana diskini bul (ilk disk[@device='disk'] source)
        _conn_r = _lv_r.open(config.LIBVIRT_URI)
        _dom_r  = _conn_r.lookupByUUIDString(vm_id)
        _xml_r  = _dom_r.XMLDesc(0)
        _root_r = _ET_r.fromstring(_xml_r)

        main_disk_path = None
        for _disk in _root_r.findall(".//disk[@device='disk']"):
            _src = _disk.find("source")
            if _src is not None and _src.get("file"):
                # Yedekleme diskini skip et
                if _src.get("file") != backup_path:
                    main_disk_path = _src.get("file")
                    break

        if not main_disk_path:
            _conn_r.close()
            return err("VM'in ana diski bulunamadı (yedekleme diski hariç)")

        # VM çalışıyorsa durdur
        _was_running = bool(_dom_r.isActive())
        _conn_r.close()

        if _was_running:
            log.info("Geri yükleme: VM durduruluyor: %s", vm_id)
            _conn_s = _lv_r.open(config.LIBVIRT_URI)
            _dom_s  = _conn_s.lookupByUUIDString(vm_id)
            _dom_s.destroy()
            _conn_s.close()
            import time as _t_r
            _t_r.sleep(2)

        # qemu-img convert: backup → ana disk (üzerine yaz)
        log.info("Geri yükleme: %s → %s", backup_path, main_disk_path)
        _r = _sp_r.run(
            ["qemu-img", "convert", "-f", "qcow2", "-O", "qcow2",
             "-p", backup_path, main_disk_path],
            capture_output=True, timeout=7200
        )
        if _r.returncode != 0:
            stderr = _r.stderr.decode(errors="replace")
            return err(f"qemu-img convert başarısız: {stderr}", 500)

        ev.info(f"Yedek geri yüklendi: {backup_path} → {main_disk_path} (VM: {vm_id})",
                category="backup")

        # İstenirse VM'i yeniden başlat
        if restart_after and _was_running:
            import time as _t_r2
            _t_r2.sleep(1)
            _conn_rs = _lv_r.open(config.LIBVIRT_URI)
            _dom_rs  = _conn_rs.lookupByUUIDString(vm_id)
            _dom_rs.create()
            _conn_rs.close()
            log.info("Geri yükleme sonrası VM başlatıldı: %s", vm_id)

        return ok({
            "status":        "ok",
            "backup_path":   backup_path,
            "main_disk":     main_disk_path,
            "vm_restarted":  restart_after and _was_running,
        })
    except Exception as e:
        log.exception("Yedek geri yükleme hatası disk_id=%s", disk_id)
        return err(str(e), 500)


@app.route("/api/backup/disks/<disk_id>", methods=["DELETE"])
@require_auth
def api_backup_disk_delete(disk_id):
    """Yedekleme diskini kayıttan ve dosya sisteminden sil."""
    registry = _load_backup_disk_registry()
    entry    = next((d for d in registry if d.get("id") == disk_id), None)
    if not entry:
        return err("Disk kaydı bulunamadı", 404)
    path = entry.get("path", "")
    if path and os.path.isfile(path):
        try:
            os.unlink(path)
        except Exception as e:
            return err(f"Dosya silinemedi: {e}")
    registry = [d for d in registry if d.get("id") != disk_id]
    _save_backup_disk_registry(registry)
    ev.info(f"Yedekleme diski silindi: {path}", category="backup")
    return ok({"deleted": disk_id})

def _sftp_connect(host, port, user, key, pwd, timeout=15):
    """paramiko SSH/SFTP bağlantısı kur. (sftp, ssh) döner."""
    import paramiko
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {"hostname": host, "port": int(port or 22), "username": user, "timeout": timeout}
    if key:
        kwargs["key_filename"] = key
    elif pwd:
        kwargs["password"] = pwd
    ssh.connect(**kwargs)
    return ssh.open_sftp(), ssh


def _parse_vmdk_extents(vmdk_path):
    """
    VMDK descriptor dosyasından extent (flat/sparse) dosya adlarını çıkar.
    ESXi VMDK'ları iki dosyadan oluşur: descriptor (.vmdk) + flat veri (-flat.vmdk).
    qemu-img convert için flat dosyanın descriptor ile aynı dizinde olması gerekir.
    Returns list of filenames referenced as extents.
    """
    import re as _re_ext
    _ext_names = []
    try:
        with open(str(vmdk_path), "rb") as _fh:
            _head = _fh.read(8192).decode("latin-1", errors="replace")
        # Extent descriptor lines:
        #   RW 104857600 FLAT "testoxware-flat.vmdk" 0
        #   RW 2097152 SPARSE "testoxware-s001.vmdk" 0
        #   RW 104857600 VMFS "testoxware-flat.vmdk" 0
        for _m in _re_ext.finditer(
            r'(?:RW|RDONLY)\s+\d+\s+(?:FLAT|VMFS|VMFSSPARSE|SESPARSE|SPARSE)\s+"([^"]+)"',
            _head, _re_ext.IGNORECASE
        ):
            _name = _m.group(1).strip()
            if _name:
                _ext_names.append(_name)
    except Exception:
        pass
    return _ext_names


@app.route("/api/backup/sftp-test", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_backup_sftp_test():
    """SFTP bağlantısını test et."""
    d    = request.get_json() or {}
    host = d.get("host", "")
    port = int(d.get("port", 22))
    user = d.get("username", "")
    key  = d.get("private_key_path", "")
    pwd  = d.get("password", "")
    rdir = d.get("remote_dir", "/backups")
    if not host or not user:
        return err("host ve username gerekli", 400)
    try:
        sftp, ssh = _sftp_connect(host, port, user, key, pwd)
        try:
            try:
                sftp.stat(rdir)
            except FileNotFoundError:
                try:
                    sftp.mkdir(rdir)
                except Exception:
                    pass
        finally:
            sftp.close(); ssh.close()
        return ok(success=True, message=f"SFTP {host}:{port} bağlantısı başarılı")
    except ImportError:
        return ok(success=False, error="paramiko kurulu değil: pip install paramiko")
    except Exception as e:
        return ok(success=False, error=str(e))


@app.route("/api/backup/sftp-list", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_backup_sftp_list():
    """Uzak SFTP dizinindeki dosyaları listele (ESXi VMDK tarama için)."""
    d    = request.get_json() or {}
    host = d.get("host", "")
    port = int(d.get("port", 22))
    user = d.get("username", "")
    key  = d.get("private_key_path", "")
    pwd  = d.get("password", "")
    rdir = security.sanitize_str(d.get("remote_dir", "/vmfs/volumes"), 512)
    if not host or not user:
        return err("host ve username gerekli", 400)
    try:
        sftp, ssh = _sftp_connect(host, port, user, key, pwd)
        try:
            items = []
            _VMDK_EXTS = (".vmdk", ".qcow2", ".ova", ".ovf", ".zip", ".vhd", ".vhdx", ".raw", ".img")
            try:
                for attr in sftp.listdir_attr(rdir):
                    import stat as _stat_mod
                    is_dir = _stat_mod.S_ISDIR(attr.st_mode or 0)
                    name = attr.filename or ""
                    if is_dir or any(name.lower().endswith(e) for e in _VMDK_EXTS):
                        items.append({
                            "name": name,
                            "path": rdir.rstrip("/") + "/" + name,
                            "is_dir": is_dir,
                            "size": attr.st_size or 0,
                            "size_mb": round((attr.st_size or 0) / 1048576, 1),
                        })
            except Exception as _le:
                return ok(success=False, error=f"Dizin listelenemedi: {_le}", files=[])
        finally:
            sftp.close(); ssh.close()
        items.sort(key=lambda x: (not x["is_dir"], x["name"]))
        return ok(success=True, files=items, remote_dir=rdir)
    except ImportError:
        return ok(success=False, error="paramiko kurulu değil: pip install paramiko", files=[])
    except Exception as e:
        return ok(success=False, error=str(e), files=[])


@app.route("/api/backup/sftp-download", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_backup_sftp_download():
    """
    Uzak SFTP sunucusundan dosyayı indir → import kuyruğuna ekle.
    ESXi VMDK → OXware import için kullanılır.
    """
    d         = request.get_json() or {}
    host      = d.get("host", "")
    port      = int(d.get("port", 22))
    user      = d.get("username", "")
    key       = d.get("private_key_path", "")
    pwd       = d.get("password", "")
    rem_path  = d.get("remote_path", "")   # full remote path e.g. /vmfs/volumes/ds1/vm/vm.vmdk
    _sftp_import_network = (d.get("network") or "default").strip() or "default"
    if not host or not user or not rem_path:
        return err("host, username ve remote_path gerekli", 400)
    # Security: remote_path içinde traversal yok
    if ".." in rem_path or not rem_path.startswith("/"):
        return err("Geçersiz remote_path", 400)
    import uuid as _uuid2, pathlib as _pl2
    fname = _pl2.Path(rem_path).name or "import.vmdk"
    _ALLOWED_IMPORT_EXTS2 = (".vmdk", ".qcow2", ".ova", ".ovf", ".zip", ".vhd", ".vhdx", ".raw", ".img")
    if not any(fname.lower().endswith(e) for e in _ALLOWED_IMPORT_EXTS2):
        return err("Desteklenmeyen dosya formatı", 400)

    job_id   = _uuid2.uuid4().hex[:8]
    save_dir = _pl2.Path("/var/lib/oxware/imports")
    save_dir.mkdir(parents=True, exist_ok=True)
    save_path = save_dir / fname

    with _import_jobs_lock:
        _import_jobs[job_id] = {
            "id": job_id, "filename": fname, "vm_name": "",
            "status": "running", "step": "SFTP indirme başlıyor",
            "percent": 2, "started": time.time(), "finished": None, "message": "",
        }

    def _do_sftp_download():
        try:
            _import_job_update(job_id, step=f"SFTP bağlanılıyor {host}:{port}", percent=5)
            sftp, ssh = _sftp_connect(host, port, user, key, pwd, timeout=30)
            try:
                remote_size = sftp.stat(rem_path).st_size or 1
                downloaded  = [0]

                def _progress_cb(transferred, total):
                    downloaded[0] = transferred
                    pct = min(88, int(5 + 83 * transferred / max(total, 1)))
                    mb  = round(transferred / 1048576, 1)
                    tot_mb = round(total / 1048576, 1)
                    _import_job_update(job_id,
                                       step=f"İndiriliyor: {mb}/{tot_mb} MB",
                                       percent=pct)

                _import_job_update(job_id,
                                   step=f"İndiriliyor: {fname} ({round(remote_size/1048576,1)} MB)",
                                   percent=8)
                sftp.get(rem_path, str(save_path), callback=_progress_cb)

                # ── ESXi VMDK flat file: descriptor referans ettiği dosyaları da indir ──
                # Descriptor (.vmdk) sadece meta-data, asıl disk -flat.vmdk içinde.
                # qemu-img convert descriptor'ı okur ve flat'ı yan dizinde arar.
                if fname.lower().endswith(".vmdk") and not fname.lower().endswith("-flat.vmdk"):
                    _flat_names = _parse_vmdk_extents(save_path)
                    _rem_dir = rem_path.rsplit("/", 1)[0]
                    for _flat_name in _flat_names:
                        _flat_rem  = _rem_dir + "/" + _flat_name
                        _flat_local = save_dir / _flat_name
                        if _flat_local.exists():
                            log.info("VMDK flat zaten mevcut: %s", _flat_local)
                            continue
                        try:
                            _flat_sz = sftp.stat(_flat_rem).st_size or 1
                            _import_job_update(
                                job_id,
                                step=f"Flat disk indiriliyor: {_flat_name} ({round(_flat_sz/1048576,1)} MB)",
                                percent=50
                            )
                            sftp.get(_flat_rem, str(_flat_local))
                            log.info("VMDK flat indirildi: %s → %s", _flat_rem, _flat_local)
                            ev.info(f"VMDK flat download: {_flat_name} ({round(_flat_sz/1048576,1)} MB)", category="vm")
                        except Exception as _fe:
                            log.warning("VMDK flat indirilemedi: %s — %s", _flat_rem, _fe)
                            ev.warn(f"VMDK flat indirilemedi: {_flat_name} — {_fe}", category="vm")
            finally:
                sftp.close(); ssh.close()

            _import_job_update(job_id, step="İndirme tamamlandı — import başlıyor", percent=90)
            log.info("SFTP download tamamlandı: %s → %s", rem_path, save_path)
            ev.info(f"SFTP download: {host}:{rem_path} → {save_path}", category="vm")

            # ── Trigger full import pipeline inline ────────────────────────────
            try:
                # SEC-029: archive extraction via security_utils — path
                # traversal, symlink, and device-file members are rejected.
                import shutil as _sh2
                try:
                    from . import security_utils as _sec_ext  # type: ignore
                except Exception:
                    import security_utils as _sec_ext  # type: ignore
                extract_dir2 = save_dir / (fname + "_extracted")
                extract_dir2.mkdir(exist_ok=True)
                _fl2 = fname.lower()
                if _fl2.endswith((".ova", ".tar", ".tar.gz")):
                    _sec_ext.safe_tar_extract(str(save_path), str(extract_dir2))
                elif _fl2.endswith(".zip"):
                    _sec_ext.safe_zip_extract(str(save_path), str(extract_dir2))
                else:
                    _sh2.copy(str(save_path), str(extract_dir2 / fname))

                disk_files2 = []
                ovf2 = vmx2 = None
                for fp2 in extract_dir2.rglob("*"):
                    if not fp2.is_file(): continue
                    s2 = fp2.suffix.lower()
                    if s2 == ".ovf": ovf2 = fp2
                    elif s2 == ".vmx": vmx2 = fp2
                    elif s2 in (".vmdk",".qcow2",".img",".raw",".vhd",".vhdx"):
                        if not (fp2.name.lower().endswith("-flat.vmdk") or _re_vmdk_extent.search(fp2.name.lower())):
                            disk_files2.append(fp2)

                if not disk_files2:
                    _import_job_update(job_id, status="error",
                                       step="Hata: disk bulunamadı",
                                       percent=0, message="SFTP import: disk yok", finished=time.time())
                    return

                vm_name2 = fname
                for _e in (".tar.gz",".ova",".ovf",".tar",".vmdk",".qcow2",".raw",".img",".vhd",".vhdx",".zip"):
                    if vm_name2.lower().endswith(_e):
                        vm_name2 = vm_name2[:-len(_e)]; break
                vm_name2 = vm_name2.replace(" ","_").replace(".","_") or "imported-vm"
                # Name conflict dedup
                import libvirt as _lv_imp2
                _conn_chk2 = _lv_imp2.open(config.LIBVIRT_URI)
                try:
                    _chk_sfx2 = 0; _base2 = vm_name2
                    while True:
                        try:
                            _conn_chk2.lookupByName(vm_name2)
                            _chk_sfx2 += 1; vm_name2 = f"{_base2}-{_chk_sfx2}"
                        except _lv_imp2.libvirtError:
                            break
                finally:
                    _conn_chk2.close()

                specs2 = {"vcpus":2,"ram_mb":4096,"os_type":"unknown","firmware":"bios"}
                if vmx2:
                    vmx_s2 = _parse_vmx(vmx2)
                    specs2.update({k:v for k,v in vmx_s2.items() if v not in (None,"unknown")})
                if ovf2:
                    ovf_s2 = _parse_ovf(ovf2)
                    if not vmx2:
                        specs2["vcpus"] = ovf_s2["vcpus"]; specs2["ram_mb"] = ovf_s2["ram_mb"]
                    if ovf_s2.get("firmware")=="efi": specs2["firmware"]="efi"
                    if ovf_s2.get("os_type")!="unknown" and specs2["os_type"]=="unknown":
                        specs2["os_type"] = ovf_s2["os_type"]
                if specs2["os_type"]=="unknown":
                    specs2["os_type"] = _detect_os_from_name(fname)

                disk_path2 = _pathlib.Path("/var/lib/libvirt/images") / f"{vm_name2}.qcow2"
                src2 = disk_files2[0]; src_sz2 = max(src2.stat().st_size,1)
                _fmt2 = {".vmdk":"vmdk",".vhd":"vpc",".vhdx":"vhdx",".qcow2":"qcow2",".raw":"raw",".img":"raw"}
                _sf2 = _fmt2.get(src2.suffix.lower(),"")
                _cmd2 = ["qemu-img","convert","-p","-O","qcow2"]
                if _sf2: _cmd2 += ["-f",_sf2]
                _cmd2 += [str(src2), str(disk_path2)]

                _import_job_update(job_id, step=f"Disk dönüştürülüyor ({specs2['os_type']})", percent=92)
                proc2 = subprocess.Popen(_cmd2, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                while proc2.poll() is None:
                    time.sleep(1.5)
                    try:
                        out_sz2 = disk_path2.stat().st_size if disk_path2.exists() else 0
                        _import_job_update(job_id, percent=min(97, 92+int(5*out_sz2/src_sz2)))
                    except Exception: pass
                proc2.wait()
                if proc2.returncode != 0:
                    err2 = (proc2.stderr.read() or b"").decode(errors="ignore").strip()
                    _import_job_update(job_id, status="error",
                                       step="Hata: disk dönüştürme başarısız",
                                       message=err2[:200], finished=time.time())
                    return

                xml2 = _build_import_xml(vm_name2, disk_path2, specs2["vcpus"],
                                         specs2["ram_mb"], specs2["os_type"],
                                         specs2["firmware"], network=_sftp_import_network)
                import tempfile as _tmp4
                with _tmp4.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as xf2:
                    xf2.write(xml2); xml_path2 = xf2.name
                r_def2 = subprocess.run(["virsh","define",xml_path2], capture_output=True, text=True)
                os.unlink(xml_path2)
                if r_def2.returncode == 0:
                    _import_job_update(job_id, status="done", vm_name=vm_name2,
                                       step=f"Tamamlandı — {vm_name2} ({specs2['os_type']}, {specs2['vcpus']} vCPU, {specs2['ram_mb']} MB)",
                                       percent=100, finished=time.time())
                    ev.info(f"SFTP import tamamlandı: {vm_name2}", category="vm")
                else:
                    _import_job_update(job_id, status="error",
                                       step="virsh define hatası",
                                       message=r_def2.stderr[:200], finished=time.time())
            except Exception as imp_ex:
                _import_job_update(job_id, status="error",
                                   step="Import hatası",
                                   message=str(imp_ex)[:200], finished=time.time())
        except Exception as ex:
            _import_job_update(job_id, status="error", step="SFTP indirme hatası",
                               message=str(ex)[:200], finished=time.time())
            ev.warn(f"SFTP download hatası: {ex}", category="vm")

    threading.Thread(target=_do_sftp_download, daemon=True,
                     name=f"sftp-dl-{job_id}").start()
    return ok(ok=True, job_id=job_id, filename=fname,
              message=f"SFTP indirme başladı: {fname}")


# ── Auto-Snapshot ─────────────────────────────────────────────────────────────
@app.route("/api/auto-snapshot/config", methods=["GET"])
@require_auth
def api_autosnap_config_get():
    if not auto_snap: return ok({"available": False})
    return ok(auto_snap.get_config())

@app.route("/api/auto-snapshot/config", methods=["POST"])
@require_auth
def api_autosnap_config_set():
    if not auto_snap: return err("Auto-snapshot modülü yüklenemedi")
    d = request.get_json() or {}
    cfg = auto_snap.update_config(**{k: d[k] for k in d if k in ["enabled","hour","minute","keep_days","vm_filter"]})
    ev.info("Auto-snapshot konfigürasyonu güncellendi", category="system")
    return ok(cfg)

@app.route("/api/auto-snapshot/run", methods=["POST"])
@require_auth
def api_autosnap_run():
    if not auto_snap: return err("Auto-snapshot modülü yüklenemedi")
    import threading as _th
    _th.Thread(target=auto_snap.run_auto_snapshots, daemon=True).start()
    ev.info("Auto-snapshot manuel tetiklendi", category="vm")
    return ok({"triggered": True})

# ── Security Audit ────────────────────────────────────────────────────────────
@app.route("/api/security/audit", methods=["GET"])
@require_auth
def api_security_audit():
    if not sec_hard:
        return err("security_hardening modülü yüklenemedi")
    result = sec_hard.run_security_audit()
    return ok(result)

@app.route("/api/security/audit/fix/<check_id>", methods=["POST"])
@require_auth
def api_security_fix(check_id):
    if not sec_hard:
        return err("security_hardening modülü yüklenemedi")
    result = sec_hard.apply_fix(check_id)
    ev.info(f"Güvenlik düzeltmesi uygulandı: {check_id}", category="security")
    return ok(result)

@app.route("/api/security/lockouts", methods=["GET"])
@require_auth
def api_security_lockouts():
    if not sec_hard:
        return ok({"lockouts": []})
    return ok({"lockouts": sec_hard.get_lockout_status()})

@app.route("/api/security/lockouts/<username>", methods=["DELETE"])
@require_auth
def api_security_unlock(username):
    if not sec_hard:
        return err("security_hardening modülü yüklenemedi")
    success = sec_hard.unlock_account(username)
    if success:
        ev.info(f"Hesap kilidi açıldı: {username}", category="auth")
        return ok({"unlocked": True})
    return err(f"Kullanıcı bulunamadı veya kilitli değil: {username}", 404)

# ── Kernel Hardening Status ───────────────────────────────────────────────────
@app.route("/api/security/kernel-hardening", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_kernel_hardening_status():
    """Kernel security hardening katmanlarının durumunu döner."""
    import subprocess as _sp, os as _os

    def _run(cmd):
        try:
            r = _sp.run(cmd, capture_output=True, text=True, timeout=5)
            return r.returncode == 0, r.stdout.strip()
        except Exception:
            return False, ""

    # AppArmor
    aa_profile = "/etc/apparmor.d/opt.oxware.backend.app"
    aa_loaded = False
    aa_mode = "not installed"
    if _os.path.exists(aa_profile):
        ok_aa, aa_out = _run(["aa-status", "--json"])
        if not ok_aa:
            ok_aa, aa_out = _run(["aa-status"])
        aa_loaded = _os.path.exists(aa_profile)
        if ok_aa and "oxware" in aa_out:
            aa_mode = "enforce" if "enforce" in aa_out else "complain"
        elif aa_loaded:
            aa_mode = "profile exists (not loaded)"

    # systemd hardening drop-in
    dropin = "/etc/systemd/system/oxware.service.d/hardening.conf"
    dropin_active = _os.path.exists(dropin)

    # seccomp
    seccomp_file = "/etc/oxware/seccomp.json"
    seccomp_installed = _os.path.exists(seccomp_file)

    # eBPF/XDP — check if xdp_filter.o compiled
    xdp_obj = "/opt/oxware/kernel/ebpf/xdp_filter.o"
    xdp_compiled = _os.path.exists(xdp_obj)

    # XDP attached interfaces
    xdp_attached = []
    _, link_out = _run(["ip", "-j", "link", "show"])
    if link_out:
        try:
            import json as _json
            ifaces = _json.loads(link_out)
            xdp_attached = [i["ifname"] for i in ifaces if i.get("xdp")]
        except Exception:
            pass

    # Kernel modules
    _, lsmod_out = _run(["lsmod"])
    audit_loaded = "oxware_audit" in lsmod_out
    guard_loaded = "oxware_guard" in lsmod_out

    # /dev interfaces
    audit_dev = _os.path.exists("/dev/oxware_audit")
    guard_dev = _os.path.exists("/dev/oxware_guard")

    # Overall score (0-5)
    layers = [aa_mode in ("enforce","complain"), dropin_active,
              seccomp_installed, xdp_compiled, audit_loaded or guard_loaded]
    score = sum(1 for x in layers if x)

    return ok(
        score=score,
        max_score=5,
        layers={
            "apparmor":  {"active": aa_mode not in ("not installed","profile exists (not loaded)"), "mode": aa_mode, "profile": aa_profile if aa_loaded else None},
            "systemd":   {"active": dropin_active, "path": dropin if dropin_active else None},
            "seccomp":   {"active": seccomp_installed, "path": seccomp_file if seccomp_installed else None},
            "ebpf_xdp":  {"active": xdp_compiled, "compiled": xdp_compiled, "attached_interfaces": xdp_attached},
            "kernel_modules": {
                "active":       audit_loaded or guard_loaded,
                "oxware_audit": {"loaded": audit_loaded, "dev": audit_dev},
                "oxware_guard": {"loaded": guard_loaded, "dev": guard_dev},
            },
        }
    )

@app.route("/api/security/egress", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_egress_status():
    """Egress lockdown + Dark Site Mode durumu (UI banner + güvenlik paneli için)."""
    egress = {"installed": False}
    dark = {"enabled": False}
    try:
        import egress_guard
        egress = egress_guard.status()
    except Exception as e:
        egress = {"installed": False, "error": str(e)}
    try:
        import dark_site
        dark = dark_site.status()
    except Exception as e:
        dark = {"enabled": False, "error": str(e)}
    return ok(egress=egress, dark_site=dark)


@app.route("/api/security/kernel-hardening/install", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_kernel_hardening_install():
    """Kernel hardening kurulumunu tetikler.

    CRITICAL: --no-systemd zorunlu. systemd drop-in adımı `systemctl restart oxware`
    çalıştırır → Flask sürecini öldürür → HTTP yanıtı asla dönmez → UI 'Kuruluyor...'
    durumunda asılı kalır. Drop-in'i manuel uygulamak için SSH gerekir.
    """
    import subprocess as _sp
    script = "/opt/oxware/kernel/install-hardening.sh"
    if not __import__("os").path.exists(script):
        return err("install-hardening.sh bulunamadı: git pull yapın", 404)
    try:
        # --no-systemd: servisi yeniden başlatmaz (self-kill önler)
        # --no-modules: kernel modül derlemesi atlanır (uzun sürer)
        r = _sp.run(
            ["bash", script, "--no-modules", "--no-systemd"],
            capture_output=True, text=True, timeout=90
        )
        return ok(
            returncode=r.returncode,
            output=r.stdout[-3000:] if r.stdout else "",
            error=r.stderr[-1000:] if r.stderr else "",
            success=r.returncode == 0,
            note="systemd drop-in atlandı (servisi yeniden başlatmamak için). Manuel uygulamak: SSH → sudo bash kernel/install-hardening.sh"
        )
    except _sp.TimeoutExpired:
        return err("Kurulum zaman aşımı (90s) — clang/apparmor kurulumu uzun sürmüş olabilir, SSH ile manuel deneyin", 504)
    except Exception as e:
        return err(str(e), 500)

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


# ── BGP Tunneling ─────────────────────────────────────────────────────────────
@app.route("/api/bgp/status", methods=["GET"])
@require_auth
def api_bgp_status():
    if not bgp_mgr: return ok({"available": False, "backend": "none"})
    return ok(bgp_mgr.get_full_status())

@app.route("/api/bgp/peers", methods=["GET"])
@require_auth
def api_bgp_list_peers():
    if not bgp_mgr: return ok({"peers": []})
    return ok({"peers": bgp_mgr.list_peers()})

@app.route("/api/bgp/peers", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_bgp_add_peer():
    if not bgp_mgr: return err("BGP modülü yüklenemedi")
    d = request.get_json() or {}
    return ok(bgp_mgr.add_peer(
        peer_ip     = d["peer_ip"],
        peer_asn    = int(d["peer_asn"]),
        local_asn   = int(d["local_asn"]),
        description = d.get("description", ""),
        password    = d.get("password", ""),
        multihop    = int(d.get("multihop", 1)),
        soft_reconfig = bool(d.get("soft_reconfig", True)),
    ))

@app.route("/api/bgp/peers/<peer_ip>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_bgp_remove_peer(peer_ip):
    if not bgp_mgr: return err("BGP modülü yüklenemedi")
    d = request.get_json() or {}
    return ok(bgp_mgr.remove_peer(peer_ip, int(d.get("local_asn", 65000))))

@app.route("/api/bgp/peers/status", methods=["GET"])
@require_auth
def api_bgp_peer_status():
    if not bgp_mgr: return ok({"sessions": []})
    peer_ip = request.args.get("peer_ip")
    return ok({"sessions": bgp_mgr.get_peer_status(peer_ip)})

@app.route("/api/bgp/prefix/announce", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_bgp_announce():
    if not bgp_mgr: return err("BGP modülü yüklenemedi")
    d = request.get_json() or {}
    return ok(bgp_mgr.announce_prefix(d["prefix"], int(d["local_asn"])))

@app.route("/api/bgp/prefix/withdraw", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_bgp_withdraw():
    if not bgp_mgr: return err("BGP modülü yüklenemedi")
    d = request.get_json() or {}
    return ok(bgp_mgr.withdraw_prefix(d["prefix"], int(d["local_asn"])))

@app.route("/api/bgp/routes", methods=["GET"])
@require_auth
def api_bgp_routes():
    if not bgp_mgr: return ok({"routes": []})
    af = request.args.get("af", "ipv4")
    return ok({"routes": bgp_mgr.get_routes(af)})


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
    leases = []
    if dns_mgr:
        leases = dns_mgr.list_leases()
    # Fallback: libvirt dnsmasq lease files (covers default/NAT networks)
    if not leases:
        try:
            import glob as _g
            for pattern in [
                "/var/lib/libvirt/dnsmasq/*.leases",
                "/var/lib/misc/dnsmasq.leases",
                "/var/lib/dnsmasq/*.leases",
            ]:
                for lf in _g.glob(pattern):
                    try:
                        with open(lf) as f:
                            for line in f:
                                parts = line.strip().split()
                                if len(parts) >= 4:
                                    leases.append({
                                        "expires": int(parts[0]) if parts[0].isdigit() else 0,
                                        "mac":      parts[1],
                                        "ip":       parts[2],
                                        "hostname": parts[3] if parts[3] != "*" else "",
                                        "client_id": parts[4] if len(parts) > 4 else "",
                                        "source":   lf,
                                    })
                    except Exception:
                        pass
                if leases:
                    break
        except Exception as e:
            log.warning("DNS leases fallback: %s", e)
    return ok({"leases": leases})

# ── IPAM ─────────────────────────────────────────────────────────────────────
import glob as _glob

_IPAM_LOCKS_FILE = "/var/lib/oxware/ipam_locks.json"


def _ipam_load_locks() -> set:
    try:
        if os.path.exists(_IPAM_LOCKS_FILE):
            with open(_IPAM_LOCKS_FILE, "r") as f:
                return set(json.load(f))
    except Exception:
        pass
    return set()


def _ipam_save_locks(locks: set):
    try:
        os.makedirs(os.path.dirname(_IPAM_LOCKS_FILE), exist_ok=True)
        tmp = _IPAM_LOCKS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(list(locks), f)
        os.replace(tmp, _IPAM_LOCKS_FILE)
    except Exception as e:
        log.error("_ipam_save_locks: %s", e)


def _ipam_get_vm_nics() -> dict:
    """Returns {mac: {"vm": name, "network": bridge}} from virsh domiflist --all."""
    result = {}
    try:
        r = subprocess.run(
            ["virsh", "domiflist", "--all"],
            capture_output=True, text=True, timeout=10
        )
        # header: Interface  Type  Source  Model  MAC
        # We need domain name — use domiflist per VM instead
        # First get list of all domains
        r2 = subprocess.run(["virsh", "list", "--all", "--name"],
                            capture_output=True, text=True, timeout=10)
        vm_names = [n.strip() for n in r2.stdout.splitlines() if n.strip()]
        for vm in vm_names:
            r3 = subprocess.run(["virsh", "domiflist", vm],
                                capture_output=True, text=True, timeout=5)
            for line in r3.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    mac = parts[4].lower()
                    source = parts[2]
                    result[mac] = {"vm": vm, "network": f"bridge:{source}"}
    except Exception as e:
        log.warning("_ipam_get_vm_nics: %s", e)
    return result


def _ipam_parse_leases() -> list:
    """Parse all dnsmasq *.leases files under /var/lib/libvirt/dnsmasq/."""
    leases = []
    vm_nics = _ipam_get_vm_nics()
    locks   = _ipam_load_locks()
    seen_macs = set()
    try:
        patterns = [
            "/var/lib/libvirt/dnsmasq/*.leases",
            "/var/lib/misc/dnsmasq.leases",
            "/var/lib/dnsmasq/*.leases",
        ]
        files = []
        for p in patterns:
            files.extend(_glob.glob(p))
        for lf in files:
            try:
                with open(lf, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        if len(parts) < 4:
                            continue
                        expiry, mac, ip, hostname = parts[0], parts[1], parts[2], parts[3]
                        mac = mac.lower()
                        if mac in seen_macs:
                            continue
                        seen_macs.add(mac)
                        nic_info = vm_nics.get(mac, {})
                        vm_name  = nic_info.get("vm", "")
                        network  = nic_info.get("network", "bridge:virbr0")
                        state    = "bound" if vm_name else "released"
                        try:
                            ts = int(expiry)
                            last_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
                        except Exception:
                            last_seen = expiry
                        leases.append({
                            "ip":        ip,
                            "mac":       mac,
                            "hostname":  hostname if hostname != "*" else "",
                            "vm":        vm_name,
                            "network":   network,
                            "state":     state,
                            "source":    "dnsmasq",
                            "last_seen": last_seen,
                            "locked":    mac in locks,
                            "expires":   int(expiry) if expiry.isdigit() else 0,
                        })
            except Exception as e:
                log.warning("IPAM lease parse %s: %s", lf, e)
        # Also add bound VMs that may not have a lease yet (static/running)
        for mac, info in vm_nics.items():
            if mac not in seen_macs:
                leases.append({
                    "ip":        "—",
                    "mac":       mac,
                    "hostname":  "",
                    "vm":        info.get("vm", ""),
                    "network":   info.get("network", ""),
                    "state":     "bound",
                    "source":    "api",
                    "last_seen": "—",
                    "locked":    mac in locks,
                    "expires":   0,
                })
    except Exception as e:
        log.error("_ipam_parse_leases: %s", e)
    return leases


# ── App Install Scripts ────────────────────────────────────────────────────────
_VALID_APPS = {
    "portainer", "nextcloud", "vaultwarden", "n8n", "coolify",
    "docker-portainer", "gitea", "cyberpanel", "nginx-proxy-manager",
    "grafana", "uptime-kuma", "minio", "pihole", "wireguard", "plesk",
}

def _get_app_install_script(app_id: str) -> str:
    scripts = {
        "portainer": """#!/bin/bash
apt-get update -y && apt-get install -y docker.io
systemctl enable --now docker
docker volume create portainer_data
docker run -d -p 9000:9000 -p 9443:9443 --name portainer --restart=always \\
  -v /var/run/docker.sock:/var/run/docker.sock \\
  -v portainer_data:/data portainer/portainer-ce:latest
""",
        "nextcloud": """#!/bin/bash
apt-get update -y && apt-get install -y docker.io docker-compose-plugin
systemctl enable --now docker
mkdir -p /opt/nextcloud
cat > /opt/nextcloud/docker-compose.yml << 'NCEOF'
version: '3'
services:
  nextcloud:
    image: nextcloud:latest
    ports: ["80:80"]
    volumes: [nextcloud_data:/var/www/html]
    environment:
      MYSQL_HOST: db
      MYSQL_DATABASE: nextcloud
      MYSQL_USER: nextcloud
      MYSQL_PASSWORD: nextcloud_pass
    depends_on: [db]
  db:
    image: mariadb:10.6
    environment:
      MYSQL_ROOT_PASSWORD: root_pass
      MYSQL_DATABASE: nextcloud
      MYSQL_USER: nextcloud
      MYSQL_PASSWORD: nextcloud_pass
    volumes: [db_data:/var/lib/mysql]
volumes:
  nextcloud_data:
  db_data:
NCEOF
cd /opt/nextcloud && docker compose up -d
""",
        "vaultwarden": """#!/bin/bash
apt-get update -y && apt-get install -y docker.io
systemctl enable --now docker
mkdir -p /opt/vaultwarden/data
docker run -d --name vaultwarden --restart=always \\
  -v /opt/vaultwarden/data:/data -p 80:80 vaultwarden/server:latest
""",
        "n8n": """#!/bin/bash
apt-get update -y && apt-get install -y docker.io
systemctl enable --now docker
docker volume create n8n_data
docker run -d --name n8n --restart=always \\
  -p 5678:5678 -v n8n_data:/home/node/.n8n n8nio/n8n:latest
""",
        "coolify": """#!/bin/bash
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash
""",
        "docker-portainer": """#!/bin/bash
apt-get update -y && apt-get install -y docker.io
systemctl enable --now docker
docker volume create portainer_data
docker run -d -p 9000:9000 --name portainer --restart=always \\
  -v /var/run/docker.sock:/var/run/docker.sock \\
  -v portainer_data:/data portainer/portainer-ce:latest
""",
        "gitea": """#!/bin/bash
apt-get update -y && apt-get install -y docker.io
systemctl enable --now docker
mkdir -p /opt/gitea
docker run -d --name=gitea --restart=always \\
  -p 3000:3000 -p 222:22 -v /opt/gitea:/data gitea/gitea:latest
""",
        "cyberpanel": """#!/bin/bash
apt-get update -y && apt-get install -y wget
wget -O installer.sh https://cyberpanel.net/install.sh
printf '1\\n1\\nN\\nN\\nN\\nN\\nN\\nN\\nN\\n' | bash installer.sh
""",
        "nginx-proxy-manager": """#!/bin/bash
apt-get update -y && apt-get install -y docker.io docker-compose-plugin
systemctl enable --now docker
mkdir -p /opt/npm
cat > /opt/npm/docker-compose.yml << 'NPMEOF'
version: '3'
services:
  npm:
    image: jc21/nginx-proxy-manager:latest
    ports: ["80:80","443:443","81:81"]
    volumes: [data:/data, letsencrypt:/etc/letsencrypt]
volumes:
  data:
  letsencrypt:
NPMEOF
cd /opt/npm && docker compose up -d
""",
        "grafana": """#!/bin/bash
apt-get update -y && apt-get install -y docker.io
systemctl enable --now docker
docker volume create grafana_data
docker run -d --name grafana --restart=always \\
  -p 3000:3000 -v grafana_data:/var/lib/grafana grafana/grafana:latest
""",
        "uptime-kuma": """#!/bin/bash
apt-get update -y && apt-get install -y docker.io
systemctl enable --now docker
docker volume create uptime-kuma
docker run -d --name uptime-kuma --restart=always \\
  -p 3001:3001 -v uptime-kuma:/app/data louislam/uptime-kuma:latest
""",
        "minio": """#!/bin/bash
apt-get update -y && apt-get install -y docker.io
systemctl enable --now docker
mkdir -p /opt/minio/data
docker run -d --name minio --restart=always \\
  -p 9000:9000 -p 9001:9001 -v /opt/minio/data:/data \\
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \\
  quay.io/minio/minio server /data --console-address ':9001'
""",
        "pihole": """#!/bin/bash
apt-get update -y && apt-get install -y docker.io
systemctl enable --now docker
mkdir -p /opt/pihole/etc-pihole /opt/pihole/etc-dnsmasq.d
docker run -d --name pihole --restart=always \\
  -p 53:53/tcp -p 53:53/udp -p 80:80 \\
  -e TZ=Europe/Istanbul \\
  -v /opt/pihole/etc-pihole:/etc/pihole \\
  -v /opt/pihole/etc-dnsmasq.d:/etc/dnsmasq.d \\
  --dns=127.0.0.1 --dns=1.1.1.1 pihole/pihole:latest
""",
        "wireguard": """#!/bin/bash
apt-get update -y && apt-get install -y docker.io
systemctl enable --now docker
mkdir -p /opt/wireguard
docker run -d --name wg-easy --restart=always \\
  -e WG_HOST=$(curl -s ifconfig.me) \\
  -e PASSWORD=changeme123 \\
  -v /opt/wireguard:/etc/wireguard \\
  -p 51820:51820/udp -p 51821:51821/tcp \\
  --cap-add=NET_ADMIN --cap-add=SYS_MODULE ghcr.io/wg-easy/wg-easy:latest
""",
        "plesk": """#!/bin/bash
apt-get update -y && apt-get install -y curl wget
# Plesk One-Click Installer (Obsidian, latest stable)
sh <(curl https://autoinstall.plesk.com/one-click-installer || wget -O - https://autoinstall.plesk.com/one-click-installer)
# After install: https://<IP>:8443 for web UI, admin / check /etc/plesk-install.log for initial password
""",
    }
    return scripts.get(app_id, "")


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
    if not template_mgr: return err("Template modülü yüklenemedi — sunucu loglarını kontrol edin")
    d = request.json or {}
    if not d.get("vm_id") or not d.get("name"):
        return err("vm_id ve name zorunlu alanlardır", 400)
    try:
        # VM'in mevcut olduğunu doğrula
        try:
            _vm_check = vm_manager.get_vm(d["vm_id"])
            _vm_state = _vm_check.get("state", "")
            if _vm_state == "running":
                return err(f"VM çalışıyor ({_vm_state}). Template oluşturmak için VM'i durdurun.", 400)
        except Exception as _ve:
            return err(f"VM bulunamadı: {d['vm_id']} ({_ve})", 404)
        result = template_mgr.create_from_vm(d["vm_id"], d["name"], d.get("description",""), d.get("tags"))
        ev.info(f"Template oluşturuldu: {d['name']} (VM: {d['vm_id']})", category="template")
        return ok(result)
    except FileNotFoundError as e:
        return err(f"Disk dosyası bulunamadı: {e}", 404)
    except PermissionError as e:
        return err(f"İzin hatası: {e}", 403)
    except Exception as e:
        log.error("Template oluşturma hatası: %s", e, exc_info=True)
        return err(f"Template oluşturulamadı: {e}", 500)

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

@app.route("/api/templates/import-ova", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_template_import_ova():
    """OVA dosyasından şablon oluştur (sunucu yolunu alır)."""
    if not template_mgr: return err("Template modülü yüklenemedi")
    d = request.get_json(force=True, silent=True) or {}
    ova_path    = security.validate_path_safe(
        d.get("ova_path", ""),
        ["/var/lib/oxware/isos", "/var/lib/libvirt/images",
         "/tmp", config.ISO_DIR]
    )
    name        = security.sanitize_str(d.get("name", ""), 128) or os.path.basename(ova_path or "")
    description = security.sanitize_str(d.get("description", ""), 256)
    os_type     = d.get("os_type", "linux")
    tags        = [security.sanitize_str(t, 32) for t in (d.get("tags") or [])]
    if not ova_path:
        return err("ova_path zorunlu")

    # Uzun işlem — background thread
    import threading as _th_ova
    job = {"status": "running", "template_id": None, "error": None}
    def _do():
        r = template_mgr.import_from_ova(ova_path, name, description, tags, os_type)
        job["status"] = "done" if r.get("success") else "error"
        job["template_id"] = r.get("template_id")
        job["error"] = r.get("error")
        job["meta"]  = r.get("meta")
    _th_ova.Thread(target=_do, daemon=True).start()
    ev.info(f"OVA import başlatıldı: {ova_path} → {name}", category="template")
    return ok({"status": "running", "message": "OVA dönüştürme arka planda çalışıyor"}), 202

@app.route("/api/templates/import-qcow2", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_template_import_qcow2():
    """qcow2 dosyasından şablon oluştur."""
    if not template_mgr: return err("Template modülü yüklenemedi")
    d = request.get_json(force=True, silent=True) or {}
    qcow2_path  = security.validate_path_safe(
        d.get("qcow2_path", ""),
        ["/var/lib/oxware/disks", "/var/lib/oxware/isos",
         "/var/lib/libvirt/images", "/tmp", config.DISK_DIR]
    )
    name        = security.sanitize_str(d.get("name", ""), 128) or os.path.basename(qcow2_path or "")
    description = security.sanitize_str(d.get("description", ""), 256)
    os_type     = d.get("os_type", "linux")
    tags        = [security.sanitize_str(t, 32) for t in (d.get("tags") or [])]
    vcpus       = int(d.get("vcpus") or 2)
    memory_mb   = int(d.get("memory_mb") or 2048)
    if not qcow2_path:
        return err("qcow2_path zorunlu")

    import threading as _th_q
    job = {"status": "running"}
    def _do():
        r = template_mgr.import_from_qcow2(qcow2_path, name, description, tags,
                                            os_type, vcpus, memory_mb)
        job["status"] = "done" if r.get("success") else "error"
        job["error"]  = r.get("error")
        job["meta"]   = r.get("meta")
    _th_q.Thread(target=_do, daemon=True).start()
    ev.info(f"qcow2 import başlatıldı: {qcow2_path} → {name}", category="template")
    return ok({"status": "running", "message": "qcow2 kopyalanıyor arka planda"}), 202

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

@app.route("/api/ssl/autorenew/setup", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ssl_autorenew_setup():
    """Systemd timer kur — certbot günde 2x otomatik yenile."""
    if not ssl_mgr: return err("SSL modülü yüklenemedi")
    return ok(ssl_mgr.setup_systemd_timer())

@app.route("/api/ssl/autorenew/status", methods=["GET"])
@require_auth
def api_ssl_autorenew_status():
    """Systemd timer aktif mi?"""
    if not ssl_mgr: return ok({"active": False})
    return ok(ssl_mgr.get_timer_status())


@app.route("/api/ssl/generate-self-signed", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ssl_generate_self_signed():
    """Self-signed sertifika üret (openssl req -x509)."""
    if not ssl_mgr: return err("SSL modülü yüklenemedi")
    d  = request.get_json() or {}
    cn = d.get("common_name", "oxware-hypervisor")
    days = int(d.get("days", 3650))
    return ok(ssl_mgr.generate_self_signed(common_name=cn, days=days))


@app.route("/api/ssl/enforce-https", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ssl_enforce_https():
    """
    HTTPS zorunluluğunu etkinleştir/devre dışı bırak.
    body: {enabled: true|false}
    """
    if not ssl_mgr: return err("SSL modülü yüklenemedi")
    d       = request.get_json() or {}
    enabled = bool(d.get("enabled", True))
    result  = ssl_mgr.set_https_enforce(enabled)
    # Nginx'i yeniden yükle (redirect bloğu aktif olsun)
    if nginx_mgr:
        try:
            nginx_mgr.reload()
        except Exception:
            pass
    return ok(**result)


@app.route("/api/ssl/full-status", methods=["GET"])
@require_auth
def api_ssl_full_status():
    """SSL + HTTPS enforce durumu birlikte."""
    if not ssl_mgr: return ok({"ssl_enabled": False, "https_enforced": False})
    return ok(ssl_mgr.get_full_status())


# ── Nginx/OpenResty Lua middleware ────────────────────────────────────────────
@app.route("/api/nginx/lua-middleware", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_nginx_lua_middleware():
    """
    OpenResty Lua access middleware config'i üret + göster.
    body: {rate_limit_rps, auth_token, block_ips:[...]}
    """
    if not nginx_mgr: return err("nginx modülü yüklenemedi")
    d = request.get_json() or {}
    lua = nginx_mgr.generate_lua_middleware(
        rate_limit_rps = int(d.get("rate_limit_rps", 20)),
        auth_token     = d.get("auth_token", ""),
        block_ips      = d.get("block_ips", []),
    )
    return ok(lua_block=lua)


# ── Speedtest (#39) ───────────────────────────────────────────────────────────
_SPEEDTEST_SERVERS = [
    # Turkish servers
    {"id": "ist-superonline",  "name": "İstanbul — Superonline",       "country": "TR", "host": "speedtest.superonline.net",  "test_url": "http://speedtest.superonline.net/1GB.zip"},
    {"id": "ist-ttnet",        "name": "İstanbul — Türk Telekom",       "country": "TR", "host": "hiztest.turktelekom.com.tr", "test_url": "http://hiztest.turktelekom.com.tr/testfile1024"},
    {"id": "ank-vodafone",     "name": "Ankara — Vodafone TR",          "country": "TR", "host": "speedtest.vodafone.com.tr",  "test_url": "http://speedtest.vodafone.com.tr/speedtest/random1000x1000.jpg"},
    {"id": "izm-turkcell",     "name": "İzmir — Turkcell",              "country": "TR", "host": "speedtest.turkcell.com.tr",  "test_url": "http://speedtest.turkcell.com.tr/speedtest/random1000x1000.jpg"},
    # International
    {"id": "de-frankfurt",     "name": "Frankfurt — DE",                "country": "DE", "host": "speedtest.fra1.linode.com",  "test_url": "http://speedtest.fra1.linode.com/100MB-fra1.bin"},
    {"id": "nl-amsterdam",     "name": "Amsterdam — NL",                "country": "NL", "host": "speedtest.ams1.linode.com",  "test_url": "http://speedtest.ams1.linode.com/100MB-ams1.bin"},
    {"id": "uk-london",        "name": "London — UK",                   "country": "GB", "host": "speedtest.lon1.linode.com",  "test_url": "http://speedtest.lon1.linode.com/100MB-lon1.bin"},
    {"id": "us-newark",        "name": "New York/Newark — US",          "country": "US", "host": "speedtest.newark.linode.com","test_url": "http://speedtest.newark.linode.com/100MB-newark.bin"},
    {"id": "us-fremont",       "name": "Los Angeles — US",              "country": "US", "host": "speedtest.fremont.linode.com","test_url": "http://speedtest.fremont.linode.com/100MB-fremont.bin"},
    {"id": "sg-singapore",     "name": "Singapore — SG",                "country": "SG", "host": "speedtest.sgp1.linode.com",  "test_url": "http://speedtest.sgp1.linode.com/100MB-sgp1.bin"},
    {"id": "jp-tokyo",         "name": "Tokyo — JP",                    "country": "JP", "host": "speedtest.tokyo2.linode.com","test_url": "http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin"},
    {"id": "cf-global",        "name": "Cloudflare — Global CDN",       "country": "GLOBAL", "host": "speed.cloudflare.com",   "test_url": "https://speed.cloudflare.com/__down?bytes=10000000"},
]

def _run_ping(host: str, count: int = 3) -> dict:
    """Returns avg latency in ms or error."""
    try:
        r = subprocess.run(
            ["ping", "-c", str(count), "-W", "3", host],
            capture_output=True, text=True, timeout=15
        )
        # Parse avg from: rtt min/avg/max/mdev = 1.2/2.3/3.4/0.5 ms
        import re as _re_ping
        m = _re_ping.search(r"(\d+\.?\d*)/(\d+\.?\d*)/(\d+\.?\d*)", r.stdout)
        if m:
            return {"latency_ms": float(m.group(2)), "packet_loss": "0%"}
        # Check packet loss
        pl = _re_ping.search(r"(\d+)% packet loss", r.stdout)
        loss = pl.group(1) + "%" if pl else "100%"
        return {"latency_ms": None, "packet_loss": loss, "error": "Timeout / unreachable"}
    except subprocess.TimeoutExpired:
        return {"latency_ms": None, "packet_loss": "100%", "error": "Ping timeout"}
    except Exception as e:
        return {"latency_ms": None, "error": str(e)}


def _run_download(url: str, max_bytes: int = 10_000_000) -> dict:
    """Download up to max_bytes, measure speed. Returns speed_mbps or error."""
    try:
        import time as _time
        cmd = [
            "curl", "-s", "-L", "--max-time", "20",
            "--max-filesize", str(max_bytes),
            "-o", "/dev/null",
            "-w", "%{speed_download}|%{time_total}|%{http_code}",
            url
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        parts = r.stdout.strip().split("|")
        if len(parts) == 3:
            speed_bps = float(parts[0])   # bytes/sec
            time_s    = float(parts[1])
            http_code = parts[2]
            if http_code not in ("200", "206") and speed_bps == 0:
                return {"speed_mbps": None, "error": f"HTTP {http_code}"}
            speed_mbps = round(speed_bps * 8 / 1_000_000, 2)
            return {"speed_mbps": speed_mbps, "time_s": round(time_s, 2)}
        return {"speed_mbps": None, "error": "curl parse error: " + r.stdout[:80]}
    except subprocess.TimeoutExpired:
        return {"speed_mbps": None, "error": "Download timeout"}
    except Exception as e:
        return {"speed_mbps": None, "error": str(e)}


@app.route("/api/speedtest/servers", methods=["GET"])
@require_auth
def api_speedtest_servers():
    return ok(servers=_SPEEDTEST_SERVERS)


@app.route("/api/speedtest/run", methods=["POST"])
@require_auth
def api_speedtest_run():
    """
    Run ping + optional download test against a server.
    Body: { server_id: str, download: bool }
    Requires operator/admin — prevents abuse.
    """
    username = get_jwt_identity()
    _prim = cred_mgr.get_username() if hasattr(cred_mgr, "get_username") else ""
    if username != _prim:
        try:
            role = (cred_mgr.get_role(username) if hasattr(cred_mgr, "get_role")
                    else user_manager.get_user_role(username))
            if role not in ("admin", "administrator", "operator"):
                return err("Speedtest için operator yetkisi gerekli", 403)
        except Exception:
            return err("Yetki kontrol hatası", 403)

    data = request.get_json() or {}
    server_id = data.get("server_id", "")
    do_download = bool(data.get("download", True))

    srv = next((s for s in _SPEEDTEST_SERVERS if s["id"] == server_id), None)
    if not srv:
        return err("Geçersiz server_id")

    result = {
        "server_id":   srv["id"],
        "server_name": srv["name"],
        "country":     srv["country"],
    }

    # Ping
    ping_r = _run_ping(srv["host"])
    result["latency_ms"]   = ping_r.get("latency_ms")
    result["packet_loss"]  = ping_r.get("packet_loss", "?")
    result["ping_error"]   = ping_r.get("error")

    # Download
    if do_download:
        dl_r = _run_download(srv["test_url"])
        result["speed_mbps"]    = dl_r.get("speed_mbps")
        result["download_time"] = dl_r.get("time_s")
        result["download_error"]= dl_r.get("error")
    else:
        result["speed_mbps"] = None

    return ok(**result)


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

# ── Hook Scripts ──────────────────────────────────────────────────────────────
@app.route("/api/hooks", methods=["GET"])
@require_auth
def api_hooks_list():
    if not hook_mgr: return ok({"hooks": {}})
    return ok({"hooks": hook_mgr.list_hooks()})

@app.route("/api/hooks/<event>/<name>", methods=["GET"])
@require_auth
def api_hook_get(event, name):
    if not hook_mgr: return err("Hook yöneticisi kullanılamıyor")
    content = hook_mgr.get_hook(event, name)
    if content is None: return err("Hook bulunamadı", 404)
    return ok({"content": content})

@app.route("/api/hooks/<event>/<name>", methods=["POST", "PUT"])
@require_auth
def api_hook_save(event, name):
    if not hook_mgr: return err("Hook yöneticisi kullanılamıyor")
    d = request.get_json() or {}
    try:
        hook_mgr.save_hook(event, name, d.get("content", ""))
    except ValueError as ve:
        return err(str(ve), 400)
    return ok()

@app.route("/api/hooks/<event>/<name>", methods=["DELETE"])
@require_auth
def api_hook_delete(event, name):
    if not hook_mgr: return err("Hook yöneticisi kullanılamıyor")
    try:
        hook_mgr.delete_hook(event, name)
    except ValueError as ve:
        return err(str(ve), 400)
    return ok()

# ══════════════════════════════════════════════════════════════════════════════
#  VM TAGS
# ══════════════════════════════════════════════════════════════════════════════
tag_mgr = _safe_import("tag_manager")

@app.route("/api/vms/<vm_id>/tags", methods=["GET"])
@require_auth
def api_vm_tags_get(vm_id):
    if not tag_mgr: return ok({"tags": []})
    return ok({"tags": tag_mgr.get_tags(vm_id)})

@app.route("/api/vms/<vm_id>/tags", methods=["POST"])
@require_auth
def api_vm_tags_set(vm_id):
    d = request.get_json() or {}
    if not tag_mgr: return err("Tag manager unavailable")
    return ok({"tags": tag_mgr.set_tags(vm_id, d.get("tags", []))})

@app.route("/api/vms/<vm_id>/tags/add", methods=["POST"])
@require_auth
def api_vm_tag_add(vm_id):
    d = request.get_json() or {}
    if not tag_mgr: return err("Tag manager unavailable")
    return ok({"tags": tag_mgr.add_tag(vm_id, d.get("tag", ""))})

@app.route("/api/vms/<vm_id>/tags/<tag>", methods=["DELETE"])
@require_auth
def api_vm_tag_remove(vm_id, tag):
    if not tag_mgr: return err("Tag manager unavailable")
    tag_mgr.remove_tag(vm_id, tag)
    return ok()

@app.route("/api/tags", methods=["GET"])
@require_auth
def api_tags_all():
    if not tag_mgr: return ok({"tags": [], "vm_tags": {}})
    return ok({"tags": tag_mgr.list_all_unique_tags(), "vm_tags": tag_mgr.get_all_tags()})

@app.route("/api/tags/<tag>/vms", methods=["GET"])
@require_auth
def api_tag_vms(tag):
    if not tag_mgr: return ok({"vms": []})
    return ok({"vms": tag_mgr.get_vms_by_tag(tag)})

# ══════════════════════════════════════════════════════════════════════════════
#  VM NOTES
# ══════════════════════════════════════════════════════════════════════════════
notes_mgr = _safe_import("notes_manager")

@app.route("/api/vms/<vm_id>/note", methods=["GET"])
@require_auth
def api_vm_note_get(vm_id):
    if not notes_mgr: return ok({"note": None})
    return ok({"note": notes_mgr.get_note(vm_id)})

@app.route("/api/vms/<vm_id>/note", methods=["POST"])
@require_auth
def api_vm_note_save(vm_id):
    d = request.get_json() or {}
    if not notes_mgr: return err("Notes manager unavailable")
    return ok(notes_mgr.save_note(vm_id, d.get("content", "")))

@app.route("/api/vms/<vm_id>/note", methods=["DELETE"])
@require_auth
def api_vm_note_delete(vm_id):
    if not notes_mgr: return ok()
    notes_mgr.delete_note(vm_id)
    return ok()

# ══════════════════════════════════════════════════════════════════════════════
#  CREDENTIAL VAULT
# ══════════════════════════════════════════════════════════════════════════════
vault_mgr = _safe_import("vault_manager")

@app.route("/api/vms/<vm_id>/credentials", methods=["GET"])
@require_auth
def api_vault_list(vm_id):
    if not vault_mgr: return ok({"credentials": []})
    return ok({"credentials": vault_mgr.list_credentials(vm_id)})

@app.route("/api/vms/<vm_id>/credentials", methods=["POST"])
@require_auth
def api_vault_store(vm_id):
    d = request.get_json() or {}
    if not vault_mgr: return err("Vault unavailable")
    vault_mgr.store_credential(vm_id, d.get("cred_type","custom"),
                               d.get("username",""), d.get("password",""),
                               d.get("notes",""))
    return ok()

@app.route("/api/vms/<vm_id>/credentials/<cred_type>", methods=["GET"])
@require_auth
def api_vault_get(vm_id, cred_type):
    if not vault_mgr: return err("Vault unavailable")
    c = vault_mgr.get_credential(vm_id, cred_type)
    if not c: return err("Credential not found", 404)
    return ok(c)

@app.route("/api/vms/<vm_id>/credentials/<cred_type>", methods=["DELETE"])
@require_auth
def api_vault_delete(vm_id, cred_type):
    if not vault_mgr: return ok()
    vault_mgr.delete_credential(vm_id, cred_type)
    return ok()

@app.route("/api/vault", methods=["GET"])
@require_role("admin", "administrator")
def api_vault_all():
    if not vault_mgr: return ok({"vault": {}})
    return ok({"vault": vault_mgr.list_all()})

# ══════════════════════════════════════════════════════════════════════════════
#  COST TRACKER
# ══════════════════════════════════════════════════════════════════════════════
cost_mgr = _safe_import("cost_tracker")

@app.route("/api/cost/config", methods=["GET"])
@require_auth
def api_cost_config_get():
    if not cost_mgr: return ok({})
    return ok(cost_mgr.get_config())

@app.route("/api/cost/config", methods=["POST"])
@require_auth
def api_cost_config_save():
    if not cost_mgr: return err("Cost tracker unavailable")
    d = request.get_json() or {}
    return ok(cost_mgr.save_config(**d))

@app.route("/api/cost/estimate", methods=["GET"])
@require_auth
def api_cost_estimate():
    if not cost_mgr: return ok({"monthly": 0})
    return ok(cost_mgr.estimate_vm_cost(
        request.args.get("vm_id",""),
        request.args.get("vcpus",1),
        request.args.get("ram_mb",1024),
        request.args.get("disk_gb",10),
        request.args.get("hours",720)))

@app.route("/api/cost/summary", methods=["POST"])
@require_auth
def api_cost_summary():
    if not cost_mgr: return ok({"total_monthly": 0, "vms": []})
    d = request.get_json() or {}
    return ok(cost_mgr.get_all_vm_costs(d.get("vms", [])))

# ══════════════════════════════════════════════════════════════════════════════
#  ALERT RULES
# ══════════════════════════════════════════════════════════════════════════════
alert_mgr = _safe_import("alert_rules")

@app.route("/api/alerts/rules", methods=["GET"])
@require_auth
def api_alert_rules_list():
    if not alert_mgr: return ok({"rules": []})
    return ok({"rules": alert_mgr.list_rules()})

@app.route("/api/alerts/rules", methods=["POST"])
@require_auth
def api_alert_rule_create():
    d = request.get_json() or {}
    if not alert_mgr: return err("Alert manager unavailable")
    try:
        rule = alert_mgr.create_rule(**{k: d[k] for k in d if k in
               ["name","metric","operator","threshold","scope","vm_id",
                "action","action_config","cooldown_minutes"]})
        return ok(rule)
    except ValueError as e:
        return err(str(e))

@app.route("/api/alerts/rules/<rule_id>", methods=["PUT"])
@require_auth
def api_alert_rule_update(rule_id):
    d = request.get_json() or {}
    if not alert_mgr: return err("Alert manager unavailable")
    alert_mgr.update_rule(rule_id, **d)
    return ok()

@app.route("/api/alerts/rules/<rule_id>", methods=["DELETE"])
@require_auth
def api_alert_rule_delete(rule_id):
    if not alert_mgr: return ok()
    alert_mgr.delete_rule(rule_id)
    return ok()

@app.route("/api/alerts/history", methods=["GET"])
@require_auth
def api_alert_history():
    if not alert_mgr: return ok({"history": []})
    n = int(request.args.get("n", 50))
    return ok({"history": alert_mgr.get_history(n)})

# ══════════════════════════════════════════════════════════════════════════════
#  SECURITY SCORE
# ══════════════════════════════════════════════════════════════════════════════
sec_score = _safe_import("security_score")

@app.route("/api/security/score/<vm_id>", methods=["GET"])
@require_auth
def api_security_score_vm(vm_id):
    if not sec_score: return ok({"score": None})
    vm_info = {"ssh_port": 22, "root_login": False, "password_auth": True,
               "cve_count": 0, "has_recent_snapshot": False, "has_firewall_rules": False}
    try:
        if vm_manager:
            vm = vm_manager.get_vm(vm_id)
            if vm: vm_info["has_recent_snapshot"] = bool(vm.get("snapshots"))
    except Exception: pass
    return ok(sec_score.score_vm(vm_id, vm_info))

@app.route("/api/security/scores", methods=["GET"])
@require_auth
def api_security_scores_all():
    if not sec_score: return ok({"scores": []})
    vms = []
    try:
        if vm_manager: vms = vm_manager.list_vms() or []
    except Exception: pass
    return ok({"scores": sec_score.score_all_vms(vms)})

@app.route("/api/security/host", methods=["GET"])
@require_auth
def api_security_host_score():
    if not sec_score: return ok({"score": None})
    return ok(sec_score.get_host_score())

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
@app.route("/api/ai/forecast", methods=["GET", "POST"])
@require_auth
def api_ai_predict():
    if not ai_planner: return ok({})
    days = int(request.args.get("days", 30))
    if request.method == "POST":
        try:
            days = int((request.get_json(silent=True) or {}).get("days", days))
        except Exception:
            pass
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
    body = request.json or {}
    cmd  = body.get("command", "")
    force_execute = bool(body.get("force_execute", False))
    if force_execute:
        # Direct execution of confirmed action — bypass NL parsing
        action = body.get("action", "unknown")
        params = body.get("params", {})
        if action and action != "unknown":
            try:
                result = ai_planner.execute_nl_action(action, params)
                return ok({"action": action, "execution_result": result,
                           "human_response": "Komut çalıştırıldı."})
            except Exception as _ex:
                return err(f"Çalıştırma hatası: {_ex}")
        # fallback: re-process normally
    return ok(ai_planner.process_natural_language(cmd, username))

@app.route("/api/ai/plan", methods=["POST"])
@require_auth
def api_ai_plan():
    """VM creation planning endpoint — accepts {prompt} and returns vm_config suggestion."""
    if not ai_planner: return err("AI modülü yüklenemedi")
    username = get_jwt_identity()
    body = request.json or {}
    prompt = body.get("prompt", body.get("command", ""))
    try:
        result = ai_planner.process_natural_language(f"VM oluştur: {prompt}", username)
        return ok(result)
    except Exception as e:
        return err(str(e), 500)

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

@app.route("/api/autoscaler/status", methods=["GET"])
@require_auth
def api_scaler_status():
    """AutoElastic HVM durum özeti — tüm politikalar + son olaylar."""
    if not auto_scaler:
        return ok({"available": False})
    policies = auto_scaler.list_policies()
    events   = auto_scaler.get_scaling_events(limit=10)
    return ok({
        "available":   True,
        "policy_count": len(policies),
        "policies":    policies,
        "recent_events": events,
    })

@app.route("/api/autoscaler/trigger", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_scaler_trigger():
    """AutoElastic kontrolünü hemen çalıştır (cron beklemeden)."""
    if not auto_scaler: return err("Auto-scaler modülü yüklenemedi")
    try:
        auto_scaler.check_and_scale()
        return ok({"message": "AutoElastic kontrol tamamlandı"})
    except Exception as e:
        return err(str(e))

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
    all_uptimes = uptime_tracker.get_all_uptimes()
    # Filter: only return VMs that currently exist in libvirt
    try:
        existing  = vm_manager.list_vms() if vm_manager else []
        ex_ids    = {v.get("id",   "") for v in existing}
        ex_names  = {v.get("name", "") for v in existing}
        all_uptimes = [
            u for u in all_uptimes
            if u and (
                u.get("vm_id") in ex_ids   or
                u.get("vm_id") in ex_names or
                u.get("name",  "") in ex_names
            )
        ]
    except Exception as _ue:
        log.warning("uptime filter error: %s", _ue)
    return ok({"uptimes": all_uptimes})

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
    # POST: save config — administrator only
    _ldap_username = get_jwt_identity()
    try:
        _ldap_primary = cred_mgr.get_username() if hasattr(cred_mgr, "get_username") else ""
        if _ldap_username == _ldap_primary:
            _ldap_role = "administrator"
        else:
            _ldap_role = user_manager.get_user_role(_ldap_username)
    except Exception:
        _ldap_role = "viewer"
    if _ldap_role not in ("admin", "administrator"):
        return err("Bu işlem için yetki gerekli", 403)
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
@require_role("admin", "administrator", "operator")  # OXW-SEC-003
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
            audit_log.log_action("system", "iso_upload", resource_type="storage",
                                  resource_id=fname, result="success")
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


@app.route("/api/storage/iso/fetch", methods=["POST"])
@require_auth
def fetch_iso_url():
    """URL'den ISO indir (arka planda wget). Ubuntu ISO'ları için."""
    import re as _re, threading, uuid

    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url zorunlu"}), 400

    # Yalnızca http/https izin ver
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "Yalnızca http/https URL desteklenir"}), 400

    # Dosya adını URL'den çıkar; istemci filename sağlarsa onu kullan
    provided_name = (data.get("filename") or "").strip()
    if provided_name:
        fname = provided_name if provided_name.lower().endswith(".iso") else provided_name + ".iso"
    else:
        fname = url.split("?")[0].split("/")[-1]
        if not fname.lower().endswith(".iso") or len(fname) < 5:
            fname = "download.iso"
    safe_name = _re.sub(r"[^a-zA-Z0-9_\-\.]", "_", fname)

    iso_dir = config.ISO_DIR
    os.makedirs(iso_dir, exist_ok=True)
    dest = os.path.join(iso_dir, safe_name)

    job_id = str(uuid.uuid4())[:8]
    _iso_fetch_jobs[job_id] = {"status": "downloading", "filename": safe_name, "url": url, "progress": "0%"}

    def _do_fetch():
        import time as _time
        try:
            # ── 1. Content-Length al (curl redirect takip eder) ──
            total_size = 0
            try:
                head = subprocess.run(
                    ["curl", "-sIL", "--max-time", "15",
                     "-A", "Mozilla/5.0", url],
                    capture_output=True, text=True, timeout=20
                )
                for line in reversed(head.stdout.splitlines()):
                    if line.lower().startswith("content-length:"):
                        val = int(line.split(":", 1)[1].strip())
                        if val > 0:
                            total_size = val
                            break
            except Exception:
                pass

            # ── 2. wget sessiz indir (output okumaya gerek yok) ──
            cmd = ["wget", "-O", dest, "-q", url]
            proc = subprocess.Popen(cmd,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            _iso_fetch_jobs[job_id]["_proc"]    = proc
            _iso_fetch_jobs[job_id]["total_mb"] = round(total_size / 1048576, 1) if total_size else 0

            # ── 3. Dosya boyutu poll (main thread) ──
            while proc.poll() is None:
                try:
                    if os.path.exists(dest):
                        cur = os.path.getsize(dest)
                        _iso_fetch_jobs[job_id]["downloaded_mb"] = round(cur / 1048576, 1)
                        if total_size > 0:
                            pct = min(int(cur / total_size * 100), 99)
                            _iso_fetch_jobs[job_id]["progress"] = f"{pct}%"
                        else:
                            # total bilinmiyor — animasyonlu göster
                            _iso_fetch_jobs[job_id]["progress"] = "?"
                except Exception:
                    pass
                _time.sleep(1)

            # ── 4. Sonuç ──
            if proc.returncode == 0:
                size = os.path.getsize(dest) if os.path.exists(dest) else 0
                _iso_fetch_jobs[job_id]["status"]   = "done"
                _iso_fetch_jobs[job_id]["progress"] = "100%"
                _iso_fetch_jobs[job_id]["size"]     = size
                log.info("ISO indirildi: %s (%d bytes)", safe_name, size)
            else:
                _iso_fetch_jobs[job_id]["status"] = "error"
                _iso_fetch_jobs[job_id]["error"]  = f"wget hatası (kod: {proc.returncode})"
                if os.path.exists(dest):
                    os.unlink(dest)
        except Exception as ex:
            _iso_fetch_jobs[job_id]["status"] = "error"
            _iso_fetch_jobs[job_id]["error"]  = str(ex)

    threading.Thread(target=_do_fetch, daemon=True).start()
    return jsonify({"ok": True, "job_id": job_id, "filename": safe_name}), 202


@app.route("/api/storage/iso/fetch/<job_id>", methods=["GET"])
@require_auth
def fetch_iso_status(job_id):
    """ISO indirme işi durumu."""
    job = _iso_fetch_jobs.get(job_id)
    if not job:
        return jsonify({"error": "İş bulunamadı"}), 404
    # _proc Popen objesi JSON serialize edilemez — hariç tut
    safe = {k: v for k, v in job.items() if k != "_proc"}
    return jsonify(safe)


@app.route("/api/storage/iso/fetch/<job_id>/cancel", methods=["POST"])
@require_auth
def cancel_iso_fetch(job_id):
    """ISO indirme işini iptal et."""
    job = _iso_fetch_jobs.get(job_id)
    if not job:
        return jsonify({"error": "İş bulunamadı"}), 404
    proc = job.get("_proc")
    if proc:
        try:
            proc.kill()   # SIGKILL — terminate yerine kill (daha güvenilir)
        except Exception:
            pass
    job["status"] = "cancelled"
    # Yarım kalan dosyayı sil
    dest = os.path.join(config.ISO_DIR, job.get("filename", ""))
    if dest and os.path.exists(dest):
        try:
            os.unlink(dest)
        except Exception:
            pass
    return jsonify({"ok": True, "job_id": job_id})


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
                audit_log.log_action(username, "license_validate",
                                     resource_type="license", resource_id=code[:14],
                                     result="success" if result.get("valid") else "fail")
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
                audit_log.log_action(username, "license_deactivate",
                                     resource_type="license", result="success")
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


# ── Prometheus Metrics ────────────────────────────────────────────────────────
@app.route("/metrics")
@require_auth
def prometheus_metrics():
    """Prometheus text format metrics endpoint."""
    lines = []
    def gauge(name, value, labels=""):
        tag = f"{{{labels}}}" if labels else ""
        lines.append(f"oxware_{name}{tag} {value}")
    try:
        stats = system_monitor.get_system_stats()
        gauge("cpu_usage_percent",    stats.get("cpu",           {}).get("percent",  0))
        gauge("memory_usage_percent", stats.get("memory",        {}).get("percent",  0))
        gauge("disk_usage_percent",   stats.get("disk_capacity", {}).get("percent",  0))
        vms = vm_manager.list_vms()
        running = sum(1 for v in vms if v.get("state") == "running")
        gauge("vms_total", len(vms))
        gauge("vms_running", running)
        for vm in vms[:50]:
            lbl = f'vm_id="{vm["id"]}",vm_name="{vm.get("name","")}"'
            gauge("vm_cpu_percent", vm.get("cpu_percent", 0), lbl)
            gauge("vm_memory_mb", vm.get("memory_mb", 0), lbl)
            gauge("vm_state", 1 if vm.get("state") == "running" else 0, lbl)
    except Exception as e:
        lines.append(f"# ERROR {e}")
    from flask import Response
    return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")

# ── Bulk VM İşlemleri ─────────────────────────────────────────────────────────
@app.route("/api/vms/bulk", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vms_bulk():
    data    = request.get_json() or {}
    vm_ids  = data.get("vm_ids", [])
    action  = data.get("action", "")
    results = {}
    if not vm_ids or action not in ("start", "stop", "reboot", "snapshot"):
        return err("vm_ids ve geçerli action gerekli")
    for vid in vm_ids[:20]:
        try:
            if action == "start":
                vm_manager.start_vm(vid)
            elif action == "stop":
                vm_manager.stop_vm(vid)
            elif action == "reboot":
                vm_manager.reboot_vm(vid)
            elif action == "snapshot":
                import datetime as _dt
                ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
                vm_manager.take_snapshot(vid, f"bulk-{ts}")
            results[vid] = "ok"
        except Exception as e:
            results[vid] = str(e)
    ev.info(f"Toplu VM işlemi: {action} × {len(vm_ids)}", category="vm")
    return ok({"results": results, "action": action})

# ── VM Disk Genişletme ────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/disk/resize", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_disk_resize(vm_id):
    """
    VM diskini genişlet.
    Body: { "disk_path": "/var/lib/oxware/disks/vm.qcow2", "new_size_gb": 50 }
    veya: { "disk_index": 0, "new_size_gb": 50 }
    """
    data = request.get_json() or {}
    new_size_gb = data.get("new_size_gb")
    if not new_size_gb or int(new_size_gb) < 1:
        return err("new_size_gb gerekli")
    new_size_gb = int(new_size_gb)

    # Disk yolunu bul
    disk_path = data.get("disk_path")
    if not disk_path:
        try:
            info = vm_manager.get_vm(vm_id)
            disks = info.get("disks", [])
            idx = int(data.get("disk_index", 0))
            if not disks:
                return err("VM'de disk bulunamadı")
            disk_path = disks[idx].get("source") or disks[idx].get("path")
        except Exception as e:
            return err(f"Disk bilgisi alınamadı: {e}")

    if not disk_path:
        return err("disk_path belirlenemiyor")

    import subprocess, shutil
    if not shutil.which("qemu-img"):
        return err("qemu-img bulunamadı")

    import json as _json

    # Validate disk path exists
    if not os.path.exists(disk_path):
        return err(f"Disk dosyası bulunamadı: {disk_path}")

    try:
        # Current size via qemu-img info
        # -U / --force-share: bypass exclusive write lock (needed when VM is running)
        info_r = subprocess.run(
            ["qemu-img", "info", "--output=json", "-U", disk_path],
            capture_output=True, text=True, timeout=30
        )
        if info_r.returncode != 0:
            return err(f"qemu-img info başarısız: {info_r.stderr.strip() or info_r.stdout.strip()}")
        try:
            img_info = _json.loads(info_r.stdout)
        except Exception:
            return err(f"Disk bilgisi parse edilemedi. stderr: {info_r.stderr.strip()[:200]}")

        current_bytes = img_info.get("virtual-size", 0)
        current_gb = current_bytes / (1024 ** 3)

        if new_size_gb <= current_gb:
            return err(f"Yeni boyut ({new_size_gb}GB) mevcut boyuttan ({current_gb:.1f}GB) büyük olmalı")

        # VM running? → virsh blockresize (online), else qemu-img resize (offline)
        vm_info    = vm_manager.get_vm(vm_id)
        vm_name    = vm_info.get("name", vm_id)
        is_running = vm_info.get("state") == "running"

        if is_running:
            # Find block device name from disks list
            disks     = vm_info.get("disks", [])
            disk_name = "vda"
            for d in disks:
                src = d.get("source") or d.get("path") or ""
                if src == disk_path:
                    disk_name = d.get("device") or d.get("target") or "vda"
                    break
            disk_name = data.get("disk_name", disk_name)
            r = subprocess.run(
                ["virsh", "blockresize", vm_name, disk_name, f"{new_size_gb}G"],
                capture_output=True, text=True, timeout=60
            )
            if r.returncode != 0:
                # Fallback: try with disk path directly
                r2 = subprocess.run(
                    ["virsh", "blockresize", vm_name, disk_path, f"{new_size_gb}G"],
                    capture_output=True, text=True, timeout=60
                )
                if r2.returncode != 0:
                    return err(f"virsh blockresize başarısız: {r.stderr.strip()}")
        else:
            r = subprocess.run(
                ["qemu-img", "resize", disk_path, f"{new_size_gb}G"],
                capture_output=True, text=True, timeout=120
            )
            if r.returncode != 0:
                return err(f"qemu-img resize başarısız: {r.stderr.strip()}")

        ev.info(f"Disk genişletildi: {vm_name} {current_gb:.1f}GB → {new_size_gb}GB", category="vm")
        return ok({
            "vm_id":      vm_id,
            "disk_path":  disk_path,
            "old_size_gb": round(current_gb, 1),
            "new_size_gb": new_size_gb,
            "online":     is_running,
            "guest_steps": _disk_guest_steps(new_size_gb),
        })
    except subprocess.TimeoutExpired:
        return err("Disk genişletme zaman aşımına uğradı", 504)
    except Exception as e:
        return err(str(e), 500)


def _disk_guest_steps(new_size_gb: int) -> dict:
    """VM içinde partition ve filesystem büyütme adımları."""
    return {
        "linux_ext4": [
            "sudo growpart /dev/vda 1",
            "sudo resize2fs /dev/vda1",
            f"# Disk artık {new_size_gb}GB görünmeli: df -h",
        ],
        "linux_xfs": [
            "sudo growpart /dev/vda 1",
            "sudo xfs_growfs /",
            f"# Disk artık {new_size_gb}GB görünmeli: df -h",
        ],
        "linux_lvm": [
            "sudo pvresize /dev/vda",
            "sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv",
            "sudo resize2fs /dev/ubuntu-vg/ubuntu-lv",
        ],
        "windows": [
            "Disk Yönetimi (diskmgmt.msc) aç",
            "Genişletilmiş bölümü sağ tıkla → Birimi Genişlet",
        ],
        "note": "Host tarafında disk büyütüldü. VM içinde yukarıdaki komutları çalıştır.",
    }


# ── VM Zamanlama ──────────────────────────────────────────────────────────────
@app.route("/api/vm-schedules", methods=["GET"])
@require_auth
def api_vm_sched_list():
    if not vm_sched: return ok({"schedules": []})
    return ok({"schedules": vm_sched.get_schedules()})

@app.route("/api/vm-schedules", methods=["POST"])
@require_auth
def api_vm_sched_add():
    if not vm_sched: return err("vm_scheduler modülü yüklenemedi")
    d = request.get_json() or {}
    try:
        s = vm_sched.add_schedule(
            vm_id=d["vm_id"], vm_name=d.get("vm_name",""),
            action=d["action"], hour=int(d["hour"]), minute=int(d.get("minute",0)),
            days=d.get("days"), enabled=d.get("enabled", True)
        )
        ev.info(f"VM zamanlaması eklendi: {d.get('vm_name')} {d.get('action')} {d.get('hour')}:00", category="vm")
        return ok(s)
    except Exception as e:
        return err(str(e))

@app.route("/api/vm-schedules/<sched_id>", methods=["PUT"])
@require_auth
def api_vm_sched_update(sched_id):
    if not vm_sched: return err("vm_scheduler modülü yüklenemedi")
    d = request.get_json() or {}
    ok_flag = vm_sched.update_schedule(sched_id, **d)
    return ok({"updated": ok_flag}) if ok_flag else err("Zamanlama bulunamadı", 404)

@app.route("/api/vm-schedules/<sched_id>", methods=["DELETE"])
@require_auth
def api_vm_sched_delete(sched_id):
    if not vm_sched: return err("vm_scheduler modülü yüklenemedi")
    ok_flag = vm_sched.delete_schedule(sched_id)
    return ok({"deleted": ok_flag}) if ok_flag else err("Zamanlama bulunamadı", 404)

# ── Aktif Oturum Yönetimi ─────────────────────────────────────────────────────
@app.route("/api/sessions", methods=["GET"])
@require_auth
def api_sessions_list():
    username = get_jwt_identity()
    if not sess_mgr: return ok({"sessions": []})
    is_admin = cred_mgr.get_role(username) == "admin" if hasattr(cred_mgr, "get_role") else True
    sessions = sess_mgr.get_all_sessions() if is_admin else sess_mgr.get_active_sessions(username)
    return ok({"sessions": sessions})

@app.route("/api/sessions/<session_id>", methods=["DELETE"])
@require_auth
def api_session_revoke(session_id):
    if not sess_mgr: return err("session_manager modülü yüklenemedi")
    ok_flag = sess_mgr.revoke_by_short_id(session_id)
    if ok_flag:
        ev.info(f"Oturum iptal edildi: {session_id}", category="auth")
        return ok({"revoked": True})
    return err("Oturum bulunamadı", 404)

# NOTE: POST /api/ssl/letsencrypt is handled by api_ssl_letsencrypt() via ssl_mgr (~line 5291).
# Duplicate standalone certbot route removed — use ssl_mgr for proper cert management.

# ── VM Ağ Trafiği ─────────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/network-stats")
@require_auth
def api_vm_network_stats(vm_id):
    """VM'nin sanal ağ arayüzü trafik istatistikleri."""
    try:
        vm  = vm_manager.get_vm(vm_id)
        iface = None
        for net in vm.get("networks", []):
            if net.get("target"):
                iface = net["target"]
                break
        if not iface:
            return ok({"rx_bytes": 0, "tx_bytes": 0, "available": False})
        stats_file = f"/sys/class/net/{iface}/statistics"
        def _read(fname):
            try:
                with open(f"{stats_file}/{fname}") as f:
                    return int(f.read().strip())
            except Exception:
                return 0
        return ok({
            "interface": iface,
            "rx_bytes":   _read("rx_bytes"),
            "tx_bytes":   _read("tx_bytes"),
            "rx_packets": _read("rx_packets"),
            "tx_packets": _read("tx_packets"),
            "rx_errors":  _read("rx_errors"),
            "tx_errors":  _read("tx_errors"),
            "available":  True,
        })
    except Exception as e:
        return err(str(e))

# ── IP Allowlist Middleware ───────────────────────────────────────────────────
_IP_ALLOWLIST_FILE = "/var/lib/oxware/ip_allowlist.json"

def _load_ip_allowlist():
    try:
        if os.path.exists(_IP_ALLOWLIST_FILE):
            with open(_IP_ALLOWLIST_FILE) as f:
                d = json.load(f)
                return d.get("enabled", False), d.get("ips", [])
    except Exception:
        pass
    return False, []

@app.before_request
def _check_ip_allowlist():
    if not request.path.startswith("/api/"):
        return
    enabled, allowed_ips = _load_ip_allowlist()
    if not enabled or not allowed_ips:
        return
    # Login ve setup her zaman geçsin
    if request.path in ("/api/auth/login", "/api/setup/init", "/api/setup/status"):
        return
    remote = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    if remote not in allowed_ips and "127.0.0.1" not in remote:
        log.warning("IP allowlist engelledi: %s → %s", remote, request.path)
        return jsonify({"error": "IP adresi izin listesinde değil"}), 403

@app.route("/api/settings/ip-allowlist", methods=["GET"])
@require_auth
def api_ip_allowlist_get():
    enabled, ips = _load_ip_allowlist()
    return ok({"enabled": enabled, "ips": ips})

@app.route("/api/settings/ip-allowlist", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ip_allowlist_set():
    d       = request.get_json() or {}
    enabled = bool(d.get("enabled", False))
    ips     = [str(ip).strip() for ip in d.get("ips", []) if str(ip).strip()]
    os.makedirs(os.path.dirname(_IP_ALLOWLIST_FILE), exist_ok=True)
    with open(_IP_ALLOWLIST_FILE, "w") as f:
        json.dump({"enabled": enabled, "ips": ips}, f, indent=2)
    ev.info(f"IP allowlist güncellendi: enabled={enabled}, {len(ips)} IP", category="security")
    return ok({"enabled": enabled, "ips": ips})

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
        (auto_snap,      "start_scheduler",          {}),
        (updater,        "start_auto_check",         {"interval_seconds": 3600}),
        (sec_hard,       "start_audit_scheduler",    {"interval_hours": 24}),
        (vm_sched,       "start_scheduler",          {}),
        (sess_mgr,       "start_cleanup_thread",     {}),
    ]
    for mod, fn, kwargs in services:
        if mod and hasattr(mod, fn):
            try:
                getattr(mod, fn)(**kwargs)
                log.info("✓ %s.%s başlatıldı", mod.__name__, fn)
            except Exception as e:
                log.warning("✗ %s.%s başlatılamadı: %s", mod.__name__, fn, e)

if not os.environ.get("OXWARE_TEST_MODE") == "1":
    _start_background_services()

# ── Hassas dosya/dizin bloğu ──────────────────────────────────────────────────
_BLOCKED_PATHS = {
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.py", "/config.ini", "/config.yml", "/config.yaml", "/config.json",
    "/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
    "/.git/HEAD", "/.git/config", "/.gitignore",
    "/requirements.txt", "/Makefile", "/docker-compose.yml",
    "/.htaccess", "/wp-config.php", "/web.config",
    "/id_rsa", "/id_ecdsa", "/.ssh/id_rsa",
}
_BLOCKED_PREFIXES = ("/.git/", "/.svn/", "/__pycache__/", "/node_modules/")

@app.before_request
def _block_sensitive_paths():
    p = request.path
    if p in _BLOCKED_PATHS:
        return jsonify({"error": "Not found"}), 404
    for prefix in _BLOCKED_PREFIXES:
        if p.startswith(prefix):
            return jsonify({"error": "Not found"}), 404

# ── Global Security Headers ─────────────────────────────────────────────────
# ── IP-based login rate limit (brute-force koruması, ek bağımlılık yok) ───────
# Username lockout (security_hardening) credential stuffing'i durdurur;
# bu katman aynı IP'den gelen yüksek hızlı istekleri durdurur.
_ip_rl_lock  = threading.Lock()
_ip_rl_hits: dict = {}          # {ip: [timestamp, ...]}
_IP_RL_WINDOW = 60              # saniye
_IP_RL_MAX    = 20              # pencere başına max deneme

def _ip_check_login(ip: str) -> bool:
    """True → izin ver, False → rate limit aşıldı (429 döndür)."""
    now = time.time()
    with _ip_rl_lock:
        hits = _ip_rl_hits.get(ip, [])
        # Pencerenin dışındaki eski kayıtları temizle
        hits = [t for t in hits if now - t < _IP_RL_WINDOW]
        if len(hits) >= _IP_RL_MAX:
            _ip_rl_hits[ip] = hits
            return False
        hits.append(now)
        _ip_rl_hits[ip] = hits
        return True

# OXW-2026-SEC-001: Tüm yanıtlara güvenlik başlıkları ekle (noVNC route overrides hariç)
@app.after_request
def _add_security_headers(resp):
    # ── Clickjacking koruması ──────────────────────────────────────────────────
    if "X-Frame-Options" not in resp.headers:
        resp.headers["X-Frame-Options"] = "SAMEORIGIN"

    # ── Content-Security-Policy ────────────────────────────────────────────────
    # Panel inline script/style kullanıyor → unsafe-inline zorunlu.
    # Nonce tabanlı CSP büyük refactor gerektirir; bu aşamada unsafe-inline kabul edilebilir.
    if "Content-Security-Policy" not in resp.headers:
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdnjs.cloudflare.com data:; "
            "img-src 'self' data: blob: https:; "
            "connect-src 'self' wss: ws:; "
            "frame-src 'self'; "
            "frame-ancestors 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

    # ── MIME sniffing koruması ─────────────────────────────────────────────────
    if resp.content_type and not any(resp.content_type.startswith(x) for x in (
        "application/javascript", "text/javascript", "application/wasm"
    )):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")

    # ── HSTS (1 yıl) ──────────────────────────────────────────────────────────
    resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    # ── Referrer sızıntı koruması ──────────────────────────────────────────────
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

    # ── Permissions Policy ─────────────────────────────────────────────────────
    resp.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), bluetooth=()"
    )

    # ── Server parmak izi kaldır ───────────────────────────────────────────────
    resp.headers.pop("Server", None)
    resp.headers.pop("X-Powered-By", None)
    return resp

# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Kaynak bulunamadı"}), 404
    # SPA: sadece gerçek frontend rotaları için index.html dön
    # Dosya uzantısı olan istekler (*.py, *.sql, *.env vb.) 404 döner
    path = request.path
    if "." in path.split("/")[-1]:  # uzantılı istek → gerçek 404
        return jsonify({"error": "Not found"}), 404
    return render_template("index.html")

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Sunucu hatası"}), 500

# ── Live Migration ────────────────────────────────────────────────────────────
@app.route("/api/vms/migrate", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
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

# ── VM Metadata ───────────────────────────────────────────────────────────────
import pathlib as _pathlib

_META_FILE = _pathlib.Path("/var/lib/oxware/vm_metadata.json")

def _load_meta() -> dict:
    try:
        return json.loads(_META_FILE.read_text()) if _META_FILE.exists() else {}
    except Exception:
        return {}

def _save_meta(data: dict):
    _META_FILE.parent.mkdir(parents=True, exist_ok=True)
    _META_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2))

@app.route("/api/vms/<vm_id>/metadata", methods=["GET"])
@require_auth
def api_vm_metadata_get(vm_id):
    meta = _load_meta()
    return ok(meta.get(vm_id, {"notes": "", "tags": [], "locked": False}))

@app.route("/api/vms/<vm_id>/metadata", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_metadata_set(vm_id):
    d = request.get_json() or {}
    meta = _load_meta()
    if vm_id not in meta:
        meta[vm_id] = {"notes": "", "tags": [], "locked": False}
    if "notes" in d:
        meta[vm_id]["notes"] = str(d["notes"])[:2000]
    if "tags" in d:
        meta[vm_id]["tags"] = [str(t)[:30] for t in d["tags"][:10]]
    if "locked" in d:
        meta[vm_id]["locked"] = bool(d["locked"])
    _save_meta(meta)
    ev.info(f"VM metadata güncellendi: {vm_id}", category="vm")
    return ok(meta[vm_id])

@app.route("/api/vms/metadata/all", methods=["GET"])
@require_auth
def api_all_metadata():
    return ok({"metadata": _load_meta()})

# ── CD-ROM Hot-Swap ───────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/cdrom", methods=["PUT"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_cdrom(vm_id):
    import libvirt as _lv_cd
    import xml.etree.ElementTree as _ET_cd

    d = request.get_json(force=True, silent=True) or {}
    if not isinstance(d, dict):
        d = {}
    eject    = d.get("eject", False)
    iso_path = d.get("iso_path", "")
    device   = d.get("device", "")   # target dev name e.g. sdb, hdc

    try:
        _conn = _lv_cd.open(config.LIBVIRT_URI)
        _dom  = _conn.lookupByUUIDString(vm_id)
        _xml  = _dom.XMLDesc()
        _conn.close()

        # Find the CDROM disk element in domain XML
        _root = _ET_cd.fromstring(_xml)
        _cdrom_el = None
        for _disk in _root.findall(".//disk[@device='cdrom']"):
            _tgt = _disk.find("target")
            if _tgt is None:
                continue
            if not device or _tgt.get("dev") == device:
                _cdrom_el = _disk
                break

        if _cdrom_el is None:
            return err(f"CDROM cihazı bulunamadı: {device or 'herhangi bir cdrom'}")

        # Build updated disk XML
        if eject:
            # Remove <source> element (eject)
            _src = _cdrom_el.find("source")
            if _src is not None:
                _cdrom_el.remove(_src)
            # Remove readonly so libvirt doesn't complain on some configs
        else:
            if not iso_path or not os.path.exists(iso_path):
                return err("ISO dosyası bulunamadı")
            # Set/replace <source> element
            _src = _cdrom_el.find("source")
            if _src is None:
                _src = _ET_cd.SubElement(_cdrom_el, "source")
            _src.set("file", iso_path)

        _disk_xml = _ET_cd.tostring(_cdrom_el, encoding="unicode")

        # Apply via libvirt updateDeviceFlags — tries live + config, falls back to config-only
        _conn2 = _lv_cd.open(config.LIBVIRT_URI)
        _dom2  = _conn2.lookupByUUIDString(vm_id)
        _running = _dom2.isActive()
        _flags = 0
        try:
            if _running:
                # VIR_DOMAIN_DEVICE_MODIFY_LIVE | VIR_DOMAIN_DEVICE_MODIFY_CONFIG
                _dom2.updateDeviceFlags(_disk_xml,
                    _lv_cd.VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                    _lv_cd.VIR_DOMAIN_DEVICE_MODIFY_CONFIG)
            else:
                _dom2.updateDeviceFlags(_disk_xml,
                    _lv_cd.VIR_DOMAIN_DEVICE_MODIFY_CONFIG)
        except _lv_cd.libvirtError as _live_err:
            log.warning("CDROM live update başarısız, config-only deneniyor: %s", _live_err)
            # Fallback: config only
            _dom2.updateDeviceFlags(_disk_xml,
                _lv_cd.VIR_DOMAIN_DEVICE_MODIFY_CONFIG)
        finally:
            _conn2.close()

        action = "çıkarıldı" if eject else f"takıldı: {iso_path}"
        ev.info(f"CD-ROM {action}: {vm_id}", category="vm")
        return ok({"status": "ok", "ejected": eject,
                   "iso_path": iso_path if not eject else None})
    except Exception as e:
        log.exception("CDROM işlemi hatası vm=%s", vm_id)
        return err(str(e), 500)

# ── Inject Static IP (cloud-init ISO hot-swap) ───────────────────────────────
@app.route("/api/vms/<vm_id>/inject-ip", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_inject_ip(vm_id):
    """
    Çalışan bir VM'ye cloud-init ISO aracılığıyla statik IP enjekte eder.
    Body: { ip, gateway, netmask (veya prefix), dns (list veya string), interface (varsayılan eth0) }
    VM yeniden başlatıldığında cloud-init network-config devreye girer.
    """
    import libvirt as _lv_ip
    import xml.etree.ElementTree as _ET_ip

    d = request.get_json(force=True, silent=True) or {}
    ip_addr   = (d.get("ip") or "").strip()
    gateway   = (d.get("gateway") or "").strip()
    netmask   = (d.get("netmask") or "").strip()
    prefix    = str(d.get("prefix") or "").strip()
    interface = (d.get("interface") or "eth0").strip() or "eth0"
    dns_raw   = d.get("dns") or ["8.8.8.8", "1.1.1.1"]
    if isinstance(dns_raw, str):
        dns_list = [x.strip() for x in dns_raw.replace(",", " ").split() if x.strip()]
    else:
        dns_list = [str(x).strip() for x in dns_raw if str(x).strip()]
    if not dns_list:
        dns_list = ["8.8.8.8", "1.1.1.1"]

    if not ip_addr:
        return err("ip alanı zorunlu")
    if not gateway:
        return err("gateway alanı zorunlu")

    try:
        # VM adını bul
        _conn_ip = _lv_ip.open(config.LIBVIRT_URI)
        _dom_ip  = _conn_ip.lookupByUUIDString(vm_id)
        vm_name  = _dom_ip.name()
        _xml_ip  = _dom_ip.XMLDesc()
        _conn_ip.close()

        # cloud-init ISO oluştur (sadece network-config içerir)
        ci_params = {
            "hostname":   vm_name,
            "static_ip":  ip_addr,
            "gateway":    gateway,
            "netmask":    netmask,
            "prefix":     prefix,
            "dns":        dns_list,
            "interface":  interface,
            # user-data minimal — boş config, mevcut kullanıcıları değiştirme
            "user":       "",
            "password":   "",
            "ssh_key":    "",
        }
        iso_path = vm_manager._build_cloud_init_iso(vm_name + "-inject", ci_params)
        if not iso_path:
            return err("cloud-init ISO oluşturulamadı (genisoimage/mkisofs/cloud-localds yüklü mü?)", 500)

        # Mevcut CDROM cihazını bul
        _root_ip = _ET_ip.fromstring(_xml_ip)
        _cdrom_el = None
        for _disk in _root_ip.findall(".//disk[@device='cdrom']"):
            _cdrom_el = _disk
            break

        if _cdrom_el is None:
            # CDROM yoksa ekle (sata bus, sdb)
            _devices_el = _root_ip.find("devices")
            _cdrom_el = _ET_ip.SubElement(_devices_el, "disk")
            _cdrom_el.set("type", "file")
            _cdrom_el.set("device", "cdrom")
            _ET_ip.SubElement(_cdrom_el, "driver").set("name", "qemu")
            _tgt2 = _ET_ip.SubElement(_cdrom_el, "target")
            _tgt2.set("dev", "sdb")
            _tgt2.set("bus", "sata")
            _ET_ip.SubElement(_cdrom_el, "readonly")

        # ISO'yu source olarak set et
        _src_el = _cdrom_el.find("source")
        if _src_el is None:
            _src_el = _ET_ip.SubElement(_cdrom_el, "source")
        _src_el.set("file", iso_path)

        _disk_xml = _ET_ip.tostring(_cdrom_el, encoding="unicode")

        # Hot-swap: live + config
        _conn2_ip = _lv_ip.open(config.LIBVIRT_URI)
        _dom2_ip  = _conn2_ip.lookupByUUIDString(vm_id)
        _running  = _dom2_ip.isActive()
        try:
            if _running:
                _dom2_ip.updateDeviceFlags(
                    _disk_xml,
                    _lv_ip.VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                    _lv_ip.VIR_DOMAIN_DEVICE_MODIFY_CONFIG)
            else:
                _dom2_ip.updateDeviceFlags(
                    _disk_xml,
                    _lv_ip.VIR_DOMAIN_DEVICE_MODIFY_CONFIG)
        except _lv_ip.libvirtError as _le:
            log.warning("inject-ip live update başarısız, config-only: %s", _le)
            _dom2_ip.updateDeviceFlags(
                _disk_xml,
                _lv_ip.VIR_DOMAIN_DEVICE_MODIFY_CONFIG)
        finally:
            _conn2_ip.close()

        ev.info(f"Statik IP ISO enjekte edildi: {vm_id} → {ip_addr}", category="vm")
        return ok({
            "status": "ok",
            "iso_path": iso_path,
            "message": (
                "cloud-init ISO takıldı. "
                "VM'yi yeniden başlatın — açılışta cloud-init network-config devreye girecek."
            ),
            "needs_reboot": True,
        })
    except Exception as e:
        log.exception("inject-ip hatası vm=%s", vm_id)
        return err(str(e), 500)

# ── CPU Pinning ───────────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/cpu-pinning", methods=["GET"])
@require_auth
def api_cpu_pinning_get(vm_id):
    try:
        r = subprocess.run(
            ["virsh", "vcpuinfo", vm_id],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode != 0:
            return err(r.stderr or "vcpuinfo alınamadı")
        # Parse vcpuinfo output
        pinnings = []
        current = {}
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("VCPU:"):
                if current:
                    pinnings.append(current)
                current = {"vcpu": int(line.split(":")[1].strip()), "cpu_affinity": ""}
            elif line.startswith("CPU Affinity:") and current:
                current["cpu_affinity"] = line.split(":", 1)[1].strip()
        if current:
            pinnings.append(current)
        # Get host CPU count
        host_cpus = os.cpu_count() or 1
        return ok({"pinnings": pinnings, "host_cpu_count": host_cpus})
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/cpu-pinning", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_cpu_pinning_set(vm_id):
    d = request.get_json() or {}
    vcpu = d.get("vcpu", 0)
    cpulist = d.get("cpulist", "")  # "0-3" or "0,2,4" or "all"
    if not cpulist:
        return err("cpulist gerekli (örn: '0-3', '0,2')")
    try:
        r = subprocess.run(
            ["virsh", "vcpupin", vm_id, str(vcpu), str(cpulist), "--live", "--config"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            return err(r.stderr or "vcpupin başarısız")
        ev.info(f"CPU pinning: {vm_id} vCPU{vcpu}→pCPU{cpulist}", category="vm")
        return ok({"vm_id": vm_id, "vcpu": vcpu, "cpulist": cpulist})
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/cpu-pinning", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_cpu_pinning_clear(vm_id):
    """Tüm pinning'i kaldır — tüm vCPU'ları tüm pCPU'lara serbest bırak."""
    try:
        info = vm_manager.get_vm(vm_id)
        vcpus = info.get("vcpus", 1)
        host_cpus = os.cpu_count() or 1
        cpulist = f"0-{host_cpus-1}"
        for vcpu in range(vcpus):
            subprocess.run(
                ["virsh", "vcpupin", vm_id, str(vcpu), cpulist, "--live", "--config"],
                capture_output=True, timeout=10
            )
        ev.info(f"CPU pinning temizlendi: {vm_id}", category="vm")
        return ok({"status": "cleared"})
    except Exception as e:
        return err(e, 500)

# ── NIC Hot-Add/Remove ────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/nics", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_nic_add(vm_id):
    d = request.get_json() or {}
    network = d.get("network", "default")
    model = d.get("model", "virtio")
    try:
        r = subprocess.run(
            ["virsh", "attach-interface", vm_id, "network", network,
             "--model", model, "--live", "--config"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            return err(r.stderr or "NIC eklenemedi")
        ev.info(f"NIC eklendi: {vm_id} → {network}", category="vm")
        return ok({"status": "ok", "network": network, "model": model})
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/nics/<mac>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_nic_remove(vm_id, mac):
    try:
        r = subprocess.run(
            ["virsh", "detach-interface", vm_id, "network",
             "--mac", mac, "--live", "--config"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            return err(r.stderr or "NIC kaldırılamadı")
        ev.info(f"NIC kaldırıldı: {vm_id} MAC:{mac}", category="vm")
        return ok({"status": "ok", "mac": mac})
    except Exception as e:
        return err(e, 500)

# ── Disk Hot-Add ──────────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/disks/attach", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_disk_attach_v2(vm_id):
    d = request.get_json() or {}
    size_gb = int(d.get("size_gb", 10))
    fmt = d.get("format", "qcow2")
    import shutil, datetime as _dt
    ts = _dt.datetime.now().strftime("%Y%m%d%H%M%S")
    disk_path = f"/var/lib/oxware/disks/{vm_id}-extra-{ts}.{fmt}"
    os.makedirs("/var/lib/oxware/disks", exist_ok=True)
    try:
        # Disk oluştur
        r = subprocess.run(
            ["qemu-img", "create", "-f", fmt, disk_path, f"{size_gb}G"],
            capture_output=True, text=True, timeout=60
        )
        if r.returncode != 0:
            return err(r.stderr or "Disk oluşturulamadı")
        # Attach
        r2 = subprocess.run(
            ["virsh", "attach-disk", vm_id, disk_path, "vdb",
             "--driver", "qemu", "--subdriver", fmt,
             "--live", "--config"],
            capture_output=True, text=True, timeout=30
        )
        if r2.returncode != 0:
            os.remove(disk_path)
            return err(r2.stderr or "Disk bağlanamadı")
        ev.info(f"Disk eklendi: {vm_id} {size_gb}GB → {disk_path}", category="vm")
        return ok({"status": "ok", "disk_path": disk_path, "size_gb": size_gb})
    except Exception as e:
        return err(e, 500)

# ── OVA Export ────────────────────────────────────────────────────────────────
_EXPORT_JOBS = {}  # job_id -> {status, path, error, started, finished, vm_name}

@app.route("/api/vms/<vm_id>/export", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_export(vm_id):
    """VM'i OVA benzeri tar arşivine aktar (XML + disk)."""
    import threading as _thr, tarfile, datetime as _dt, uuid as _uu
    try:
        info = vm_manager.get_vm(vm_id)
        vm_name = info.get("name", vm_id)
        import re as _re_sec
        vm_name_safe = _re_sec.sub(r'[^\w\-.]', '_', str(vm_name))[:64]
        disks = info.get("disks", [])

        # Disk yollarını kontrol et
        accessible_disks = []
        missing_disks = []
        for disk in disks:
            src = disk.get("source") or disk.get("path", "")
            if not src:
                continue
            if os.path.exists(src):
                accessible_disks.append(src)
            else:
                missing_disks.append(src)

        if missing_disks:
            return err(f"Disk dosyaları erişilemiyor: {', '.join(missing_disks)}. VM çalışıyor olabilir veya dosyalar başka yerde.", 400)

        if not accessible_disks:
            return err("Export edilecek disk bulunamadı", 400)

        # Toplam disk boyutu (öngörü için)
        total_size = sum(os.path.getsize(d) for d in accessible_disks if os.path.exists(d))
        size_mb = total_size / (1024 * 1024)

        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        export_dir = "/var/lib/oxware/backups/exports"

        try:
            os.makedirs(export_dir, exist_ok=True)
        except PermissionError:
            return err(f"İzin hatası: {export_dir} oluşturulamadı. Servisi root ile çalıştırın.", 403)

        # Disk alanı kontrolü
        try:
            import shutil as _sh
            free = _sh.disk_usage(export_dir).free
            if free < total_size:
                return err(f"Yetersiz disk alanı: {free//(1024**2)} MB boş, {int(size_mb)} MB gerekli", 507)
        except Exception:
            pass

        output_path = f"{export_dir}/{vm_name_safe}-{ts}.tar.gz"
        job_id = _uu.uuid4().hex[:12]
        _EXPORT_JOBS[job_id] = {
            "status":   "running",
            "path":     output_path,
            "vm_name":  vm_name,
            "started":  time.time(),
            "size_mb":  round(size_mb, 1),
            "progress": 0,
        }

        def _do_export():
            try:
                # XML dump
                xr = subprocess.run(["virsh", "dumpxml", vm_id],
                    capture_output=True, text=True, timeout=30)
                if xr.returncode != 0:
                    raise RuntimeError(f"virsh dumpxml: {xr.stderr.strip()}")

                with tarfile.open(output_path, "w:gz") as tar:
                    import io
                    xml_bytes = xr.stdout.encode()
                    info_obj = tarfile.TarInfo(name=f"{vm_name_safe}.xml")
                    info_obj.size = len(xml_bytes)
                    tar.addfile(info_obj, io.BytesIO(xml_bytes))
                    for idx, src in enumerate(accessible_disks):
                        tar.add(src, arcname=os.path.basename(src))
                        _EXPORT_JOBS[job_id]["progress"] = int((idx + 1) / len(accessible_disks) * 100)

                final_size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
                _EXPORT_JOBS[job_id].update({
                    "status":     "done",
                    "finished":   time.time(),
                    "size_bytes": final_size,
                    "progress":   100,
                })
                ev.info(f"OVA export tamamlandı: {vm_name} → {output_path} ({final_size//(1024**2)} MB)", category="vm")
                _bg_notify(f"OVA export tamamlandı: {vm_name}", level="INFO", category="vm")
            except Exception as ex:
                _EXPORT_JOBS[job_id].update({
                    "status":   "error",
                    "error":    str(ex),
                    "finished": time.time(),
                })
                ev.info(f"OVA export hatası: {ex}", category="vm")
                log.error("OVA export hatası (%s): %s", vm_name, ex, exc_info=True)
                # Yarım kalan dosyayı sil
                if os.path.exists(output_path):
                    try: os.remove(output_path)
                    except: pass

        _thr.Thread(target=_do_export, daemon=True, name=f"ova-export-{job_id}").start()
        return ok({
            "status":      "started",
            "job_id":      job_id,
            "output_path": output_path,
            "vm_name":     vm_name,
            "size_mb":     round(size_mb, 1),
            "message":     f"Export başladı (~{int(size_mb)} MB). Job ID: {job_id}",
        })
    except Exception as e:
        log.error("OVA export başlatma hatası: %s", e, exc_info=True)
        return err(f"Export başlatılamadı: {e}", 500)


@app.route("/api/vms/export/jobs/<job_id>")
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_export_job(job_id):
    """OVA export job durumunu döndür."""
    job = _EXPORT_JOBS.get(job_id)
    if not job:
        return err("Job bulunamadı", 404)
    return ok(job)


@app.route("/api/vms/export/jobs")
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_export_jobs():
    """Tüm export job'ları listele."""
    return ok({"jobs": [{"id": k, **v} for k, v in _EXPORT_JOBS.items()]})

# ── SSH Watchdog ──────────────────────────────────────────────────────────────

@app.route("/api/ssh/status", methods=["GET"])
@require_auth
def api_ssh_status():
    if not ssh_watchdog:
        return ok({"available": False, "error": "ssh_watchdog modülü yüklenemedi"})
    return ok({"available": True, **ssh_watchdog.get_status()})


@app.route("/api/ssh/restart", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ssh_restart():
    if not ssh_watchdog:
        return err("ssh_watchdog modülü yüklenemedi")
    import subprocess as _sp
    r = _sp.run(["systemctl", "restart", "sshd"], capture_output=True, text=True, timeout=30)
    success = r.returncode == 0
    if success:
        ev.warn("SSH servisi manuel olarak yeniden başlatıldı.", category="system")
    return ok({"success": success, "stderr": r.stderr.strip() if not success else None})


# ── OpenAPI / Swagger Docs ────────────────────────────────────────────────────
@app.route("/api/docs", methods=["GET"])
@app.route("/api/swagger", methods=["GET"])
def api_swagger_ui():
    html = r"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OXware API Docs</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}
header{background:#161b22;border-bottom:1px solid #30363d;padding:14px 24px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:100}
header h1{font-size:18px;font-weight:700;color:#58a6ff}
header span{font-size:12px;background:#1f6feb33;color:#58a6ff;padding:2px 8px;border-radius:10px;border:1px solid #1f6feb}
#search{margin-left:auto;background:#21262d;border:1px solid #30363d;border-radius:6px;color:#e6edf3;padding:6px 12px;font-size:13px;width:240px;outline:none}
#search:focus{border-color:#58a6ff}
#search::placeholder{color:#8b949e}
.sidebar{position:fixed;top:57px;left:0;bottom:0;width:220px;background:#161b22;border-right:1px solid #30363d;overflow-y:auto;padding:12px 0}
.tag-group{padding:6px 16px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;margin-top:8px}
.sidebar-item{display:flex;align-items:center;gap:8px;padding:5px 16px;font-size:12px;cursor:pointer;color:#8b949e;text-decoration:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sidebar-item:hover,.sidebar-item.active{background:#21262d;color:#e6edf3}
.sidebar-item .method-badge{flex-shrink:0;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;min-width:34px;text-align:center}
.main{margin-left:220px;padding:24px;max-width:960px}
.endpoint{border:1px solid #30363d;border-radius:8px;margin-bottom:10px;overflow:hidden;background:#161b22}
.ep-header{display:flex;align-items:center;gap:12px;padding:12px 16px;cursor:pointer;user-select:none;transition:background .1s}
.ep-header:hover{background:#21262d}
.ep-header .path{font-family:'SFMono-Regular',Consolas,monospace;font-size:13px;font-weight:600;flex:1}
.ep-header .summary{font-size:12px;color:#8b949e;margin-left:8px}
.ep-header .chevron{color:#8b949e;transition:transform .2s;font-size:12px}
.ep-header.open .chevron{transform:rotate(90deg)}
.ep-body{display:none;padding:16px;border-top:1px solid #30363d;background:#0d1117}
.ep-body.open{display:block}
.ep-section{margin-bottom:12px;font-size:12px}
.ep-section label{font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#8b949e;display:block;margin-bottom:6px}
.param-row{display:flex;gap:8px;align-items:baseline;padding:4px 0;border-bottom:1px solid #21262d}
.param-name{font-family:monospace;font-size:12px;color:#79c0ff;min-width:120px}
.param-in{font-size:10px;background:#21262d;padding:1px 6px;border-radius:3px;color:#8b949e}
.param-req{font-size:10px;color:#f85149}
.param-desc{color:#8b949e;font-size:12px}
.try-section{margin-top:12px;background:#161b22;border:1px solid #30363d;border-radius:6px;overflow:hidden}
.try-header{padding:8px 12px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#8b949e;background:#21262d;display:flex;align-items:center;gap:8px}
.try-body{padding:12px}
.try-row{display:flex;gap:8px;margin-bottom:8px;align-items:center;flex-wrap:wrap}
.try-row label{font-size:11px;color:#8b949e;min-width:80px}
.try-row input,.try-row textarea,.try-row select{flex:1;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#e6edf3;padding:5px 8px;font-size:12px;font-family:monospace;outline:none;min-width:0}
.try-row input:focus,.try-row textarea:focus{border-color:#58a6ff}
.try-row textarea{resize:vertical;min-height:60px}
.btn-try{background:#238636;color:#fff;border:none;border-radius:6px;padding:7px 18px;font-size:12px;font-weight:600;cursor:pointer}
.btn-try:hover{background:#2ea043}
.response-box{margin-top:10px;background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px 12px;font-family:monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;max-height:320px;overflow-y:auto;color:#e6edf3}
.response-box.ok{border-color:#238636}
.response-box.err{border-color:#f85149;color:#ffa198}
.GET{background:#1a7f37;color:#fff}
.POST{background:#1f6feb;color:#fff}
.PUT{background:#7d4e00;color:#fff}
.PATCH{background:#5a3285;color:#fff}
.DELETE{background:#6e1c1c;color:#fff}
.badge-auth{font-size:10px;background:#6e1c1c33;color:#f85149;padding:2px 7px;border-radius:4px;border:1px solid #6e1c1c}
#no-results{display:none;text-align:center;padding:40px;color:#8b949e}
</style>
</head>
<body>
<header>
  <h1>⚡ OXware API</h1>
  <span id="ver-badge">v2.7.0</span>
  <span style="font-size:12px;color:#8b949e" id="ep-count"></span>
  <input id="search" type="search" placeholder="Endpoint ara...">
</header>
<nav class="sidebar" id="sidebar"></nav>
<main class="main">
  <div id="no-results">Eşleşen endpoint bulunamadı.</div>
  <div id="endpoints"></div>
</main>
<script>
const TOKEN_KEY = 'oxware_token';

async function loadSpec() {
  try {
    const r = await fetch('/api/openapi.json', {
      headers: { 'Authorization': 'Bearer ' + (localStorage.getItem(TOKEN_KEY) || '') }
    });
    if (!r.ok) {
      // Not logged in — show token input
      renderTokenPrompt();
      return;
    }
    const spec = await r.json();
    render(spec);
  } catch(e) {
    document.getElementById('endpoints').innerHTML =
      '<p style="color:#f85149;padding:20px">Spec yüklenemedi: ' + e.message + '</p>';
  }
}

function renderTokenPrompt() {
  document.getElementById('endpoints').innerHTML = `
    <div style="max-width:400px;margin:60px auto;text-align:center">
      <div style="font-size:40px;margin-bottom:16px">🔐</div>
      <p style="color:#8b949e;margin-bottom:16px;font-size:14px">API dökümantasyonunu görüntülemek için JWT token girin.</p>
      <input id="token-inp" type="text" placeholder="JWT token..." style="width:100%;background:#21262d;border:1px solid #30363d;border-radius:6px;color:#e6edf3;padding:10px;font-size:13px;outline:none;margin-bottom:10px">
      <button onclick="setToken()" style="background:#238636;color:#fff;border:none;border-radius:6px;padding:9px 24px;font-size:13px;cursor:pointer;width:100%">Giriş</button>
    </div>`;
}

function setToken() {
  const t = document.getElementById('token-inp').value.trim();
  if (t) { localStorage.setItem(TOKEN_KEY, t); loadSpec(); }
}

const METHOD_ORDER = ['GET','POST','PUT','PATCH','DELETE'];

function methodColor(m) {
  return m.toUpperCase();
}

function render(spec) {
  const paths = spec.paths || {};
  const info  = spec.info  || {};
  document.getElementById('ver-badge').textContent = 'v' + (info.version || '?');

  // Group by tags
  const groups = {};
  const items  = [];

  Object.entries(paths).forEach(([path, methods]) => {
    METHOD_ORDER.forEach(m => {
      const op = methods[m.toLowerCase()];
      if (!op) return;
      const tag = (op.tags && op.tags[0]) || 'General';
      if (!groups[tag]) groups[tag] = [];
      const item = { path, method: m, op, tag };
      groups[tag].push(item);
      items.push(item);
    });
  });

  document.getElementById('ep-count').textContent = items.length + ' endpoint';

  // Sidebar
  const sidebar = document.getElementById('sidebar');
  sidebar.innerHTML = Object.entries(groups).map(([tag, eps]) => `
    <div class="tag-group">${esc(tag)}</div>
    ${eps.map(e => `
      <a class="sidebar-item" href="#ep-${esc(e.method+e.path.replace(/[^a-z0-9]/gi,'_'))}" onclick="openEp(this)">
        <span class="method-badge ${e.method}">${e.method}</span>
        <span style="overflow:hidden;text-overflow:ellipsis">${esc(e.path)}</span>
      </a>`).join('')}
  `).join('');

  // Endpoints
  const container = document.getElementById('endpoints');
  container.innerHTML = Object.entries(groups).map(([tag, eps]) => `
    <h2 style="font-size:13px;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;margin:24px 0 10px;padding-bottom:6px;border-bottom:1px solid #30363d">${esc(tag)}</h2>
    ${eps.map(e => renderEndpoint(e)).join('')}
  `).join('');

  // Search
  document.getElementById('search').addEventListener('input', function() {
    const q = this.value.toLowerCase();
    let visible = 0;
    document.querySelectorAll('.endpoint').forEach(el => {
      const match = el.dataset.path.includes(q) || el.dataset.summary.includes(q) || el.dataset.tag.includes(q);
      el.style.display = match ? '' : 'none';
      if (match) visible++;
    });
    document.getElementById('no-results').style.display = visible ? 'none' : 'block';
  });
}

function renderEndpoint(e) {
  const op = e.op;
  const id = 'ep-' + (e.method + e.path).replace(/[^a-z0-9]/gi, '_');
  const params = op.parameters || [];
  const hasBody = ['POST','PUT','PATCH'].includes(e.method);
  const security = op.security !== undefined ? op.security : true;
  const needsAuth = security !== false && !(Array.isArray(security) && security.length === 0);

  return `<div class="endpoint" id="${id}" data-path="${esc(e.path.toLowerCase())}" data-summary="${esc((op.summary||'').toLowerCase())}" data-tag="${esc(e.tag.toLowerCase())}">
  <div class="ep-header" onclick="toggleEp(this)">
    <span class="method-badge ${e.method}" style="font-size:10px;font-weight:700;padding:3px 8px;border-radius:4px;min-width:52px;text-align:center">${e.method}</span>
    <span class="path">${esc(e.path)}</span>
    ${needsAuth ? '<span class="badge-auth">🔒 Auth</span>' : ''}
    <span class="summary">${esc(op.summary || '')}</span>
    <span class="chevron">▶</span>
  </div>
  <div class="ep-body">
    ${op.description ? `<p style="font-size:13px;color:#8b949e;margin-bottom:12px">${esc(op.description)}</p>` : ''}
    ${params.length ? `<div class="ep-section">
      <label>Parametreler</label>
      ${params.map(p => `<div class="param-row">
        <span class="param-name">${esc(p.name)}</span>
        <span class="param-in">${p.in}</span>
        ${p.required ? '<span class="param-req">*zorunlu</span>' : ''}
        <span class="param-desc">${esc(p.description || (p.schema && p.schema.type) || '')}</span>
      </div>`).join('')}
    </div>` : ''}
    <div class="try-section">
      <div class="try-header">▶ Dene <span style="font-weight:400;color:#58a6ff;font-size:10px">(Token otomatik eklenir)</span></div>
      <div class="try-body">
        ${params.filter(p => p.in === 'path').map(p => `
          <div class="try-row">
            <label>{${esc(p.name)}}</label>
            <input class="try-path-param" data-name="${esc(p.name)}" placeholder="${esc(p.name)}">
          </div>`).join('')}
        ${params.filter(p => p.in === 'query').map(p => `
          <div class="try-row">
            <label>${esc(p.name)}</label>
            <input class="try-query-param" data-name="${esc(p.name)}" placeholder="${esc(p.name)}">
          </div>`).join('')}
        ${hasBody ? `<div class="try-row">
          <label>Body (JSON)</label>
          <textarea class="try-body-inp" placeholder='{"key": "value"}'></textarea>
        </div>` : ''}
        <button class="btn-try" onclick="tryRequest(this,'${e.method}','${esc(e.path)}')">Gönder</button>
        <div class="response-box" style="display:none"></div>
      </div>
    </div>
  </div>
</div>`;
}

function toggleEp(hdr) {
  hdr.classList.toggle('open');
  hdr.nextElementSibling.classList.toggle('open');
}

function openEp(a) {
  const target = document.querySelector(a.getAttribute('href'));
  if (!target) return;
  const hdr = target.querySelector('.ep-header');
  if (!hdr.classList.contains('open')) {
    hdr.classList.add('open');
    hdr.nextElementSibling.classList.add('open');
  }
  setTimeout(() => target.scrollIntoView({behavior:'smooth', block:'start'}), 50);
}

async function tryRequest(btn, method, pathTemplate) {
  const wrap = btn.closest('.try-body');
  const respBox = wrap.querySelector('.response-box');
  respBox.style.display = 'block';
  respBox.className = 'response-box';
  respBox.textContent = 'Yükleniyor...';

  let url = '/api' + pathTemplate;
  wrap.querySelectorAll('.try-path-param').forEach(inp => {
    url = url.replace('{' + inp.dataset.name + '}', encodeURIComponent(inp.value || inp.dataset.name));
  });

  const queryParts = [];
  wrap.querySelectorAll('.try-query-param').forEach(inp => {
    if (inp.value) queryParts.push(encodeURIComponent(inp.dataset.name) + '=' + encodeURIComponent(inp.value));
  });
  if (queryParts.length) url += '?' + queryParts.join('&');

  const opts = {
    method,
    headers: {
      'Authorization': 'Bearer ' + (localStorage.getItem(TOKEN_KEY) || ''),
      'Content-Type': 'application/json',
    }
  };
  const bodyInp = wrap.querySelector('.try-body-inp');
  if (bodyInp && bodyInp.value.trim()) {
    try { opts.body = bodyInp.value.trim(); JSON.parse(opts.body); }
    catch(e) { respBox.className = 'response-box err'; respBox.textContent = 'JSON hatalı: ' + e.message; return; }
  }

  try {
    const r = await fetch(url, opts);
    const text = await r.text();
    let pretty = text;
    try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch(_) {}
    respBox.className = 'response-box' + (r.ok ? ' ok' : ' err');
    respBox.textContent = 'HTTP ' + r.status + '\n\n' + pretty;
  } catch(e) {
    respBox.className = 'response-box err';
    respBox.textContent = 'Bağlantı hatası: ' + e.message;
  }
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

loadSpec();
</script>
</body>
</html>"""
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}

@app.route("/api/openapi.json", methods=["GET"])
@require_auth
def api_openapi_spec():
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "OXware Hypervisor API",
            "version": "2.8.1",
            "description": "KVM tabanlı hypervisor yönetim API'si"
        },
        "servers": [{"url": "/api", "description": "OXware API"}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
            }
        },
        "security": [{"bearerAuth": []}],
        "paths": _autogen_openapi_paths(),
    }
    return jsonify(spec)


# OpenAPI paths auto-generated from Flask url_map — never goes stale, lists ALL /api/* routes
_OPENAPI_TAG_MAP = [
    ("/api/backup-adv", "Backup Advanced"), ("/api/backup", "Backup"),
    ("/api/vms", "VMs"), ("/api/storage-adv", "Storage Advanced"), ("/api/storage", "Storage"),
    ("/api/network-adv", "Network Advanced"), ("/api/networks", "Networking"),
    ("/api/drs", "Enterprise"), ("/api/affinity", "Enterprise"), ("/api/evc", "Enterprise"),
    ("/api/nioc", "Network Advanced"), ("/api/maintenance", "Lifecycle"), ("/api/lifecycle", "Lifecycle"),
    ("/api/dr/", "DR"), ("/api/boot-order", "DR"), ("/api/geo-dns", "DR"),
    ("/api/otel", "Observability"), ("/api/grafana", "Observability"), ("/api/topo-viz", "Observability"),
    ("/api/topology", "Observability"), ("/api/forecast", "Observability"), ("/api/drift", "Observability"),
    ("/api/capacity", "Observability"),
    ("/api/microseg", "Network Advanced 2"), ("/api/bfd", "Network Advanced 2"),
    ("/api/service-chain", "Network Advanced 2"), ("/api/mesh", "Network Advanced 2"),
    ("/api/pulumi", "Cloud/K8s"), ("/api/k8s-csi", "Cloud/K8s"), ("/api/k8s-operator", "Cloud/K8s"),
    ("/api/kubevirt", "Cloud/K8s"), ("/api/gitops", "Cloud/K8s"),
    ("/api/firecracker", "Modern Workloads"), ("/api/kata", "Modern Workloads"),
    ("/api/wasm", "Modern Workloads"), ("/api/edge", "Modern Workloads"),
    ("/api/workflow", "Automation"), ("/api/opa", "Automation"), ("/api/cloudevents", "Automation"),
    ("/api/automation", "Automation"), ("/api/webhooks", "Automation"),
    ("/api/desktop", "Clients"), ("/api/cloud-export", "Clients"),
    ("/api/vtpm", "Security"), ("/api/secureboot", "Security"), ("/api/vault", "Security"),
    ("/api/audit-chain", "Security"), ("/api/confidential", "Security"), ("/api/disk-encryption", "Security"),
    ("/api/compliance", "Security"), ("/api/dlp", "Security"), ("/api/forensics", "Security"),
    ("/api/mfa", "Security"), ("/api/sso", "Security"), ("/api/siem", "Security"),
    ("/api/sessions", "Security"), ("/api/security", "Security"),
    ("/api/tenants", "Multi-Tenancy"), ("/api/self-service", "Multi-Tenancy"),
    ("/api/chargeback", "Multi-Tenancy"), ("/api/service-catalog", "Multi-Tenancy"),
    ("/api/tenant-rate-limit", "Multi-Tenancy"),
    ("/api/hugepages", "Compute"), ("/api/sriov", "Network"), ("/api/vgpu", "Compute"),
    ("/api/numa", "Compute"), ("/api/cdp", "Storage"), ("/api/right-sizing", "Observability"),
    ("/api/alerts", "Observability"), ("/api/predict", "Observability"), ("/api/session", "Security"),
    ("/api/users", "Management"), ("/api/features", "Management"), ("/api/metrics", "Monitoring"),
    ("/api/vm-schedules", "Scheduling"), ("/api/settings", "Settings"), ("/api/auth", "Auth"),
    ("/api/", "General"),
]

def _autogen_openapi_paths():
    import re as _re_oa
    paths = {}
    def _tag(p):
        for pre, tag in _OPENAPI_TAG_MAP:
            if p.startswith(pre):
                return tag
        return "General"
    try:
        for rule in app.url_map.iter_rules():
            p = str(rule.rule)
            if not p.startswith("/api/"):
                continue
            if p in ("/api/openapi.json", "/api/docs"):
                continue
            op_path = _re_oa.sub(r"<(?:[^:>]+:)?([^>]+)>", r"{\1}", p)
            methods = sorted(m for m in (rule.methods or set())
                             if m in ("GET", "POST", "PUT", "DELETE", "PATCH"))
            if not methods:
                continue
            params = [{"name": v, "in": "path", "required": True, "schema": {"type": "string"}}
                      for v in _re_oa.findall(r"\{([^}]+)\}", op_path)]
            item = paths.setdefault(op_path, {})
            for m in methods:
                summary = rule.endpoint.replace("api_", "").replace("_", " ").strip().title()
                op = {"summary": summary or op_path, "tags": [_tag(p)],
                      "responses": {"200": {"description": "OK"}}}
                if params:
                    op["parameters"] = params
                item[m.lower()] = op
    except Exception as _oa_e:
        log.warning("openapi autogen hata: %s", _oa_e)
    return paths


def _api_openapi_spec_DEAD_legacy():
    # Eski hardcoded spec — kullanılmıyor (auto-gen aktif). Referans için tutuldu.
    return {
        "_legacy_paths": {
            "/vms": {
                "get": {"summary": "VM listesi", "tags": ["VMs"], "responses": {"200": {"description": "VM listesi"}}},
                "post": {"summary": "VM oluştur", "tags": ["VMs"], "responses": {"201": {"description": "Oluşturuldu"}}}
            },
            "/vms/{vm_id}": {
                "get": {"summary": "VM detayı", "tags": ["VMs"], "parameters": [{"name": "vm_id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "VM bilgisi"}}},
                "delete": {"summary": "VM sil", "tags": ["VMs"], "parameters": [{"name": "vm_id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "Silindi"}}}
            },
            "/vms/{vm_id}/start": {"post": {"summary": "VM başlat", "tags": ["VMs"], "parameters": [{"name": "vm_id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "Başlatıldı"}}}},
            "/vms/{vm_id}/stop": {"post": {"summary": "VM durdur", "tags": ["VMs"], "parameters": [{"name": "vm_id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "Durduruldu"}}}},
            "/vms/{vm_id}/clone": {"post": {"summary": "VM klonla", "tags": ["VMs"], "parameters": [{"name": "vm_id", "in": "path", "required": True, "schema": {"type": "string"}}], "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"new_name": {"type": "string"}}}}}}, "responses": {"201": {"description": "Klonlandı"}}}},
            "/vms/{vm_id}/metadata": {
                "get": {"summary": "VM metadata", "tags": ["VMs"], "parameters": [{"name": "vm_id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "Metadata"}}},
                "post": {"summary": "VM metadata güncelle", "tags": ["VMs"], "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"notes": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}, "locked": {"type": "boolean"}}}}}}, "parameters": [{"name": "vm_id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "Güncellendi"}}}
            },
            "/vms/{vm_id}/cdrom": {"put": {"summary": "CD-ROM hot-swap", "tags": ["VMs"], "parameters": [{"name": "vm_id", "in": "path", "required": True, "schema": {"type": "string"}}], "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"iso_path": {"type": "string"}, "eject": {"type": "boolean"}}}}}}, "responses": {"200": {"description": "CD-ROM değiştirildi"}}}},
            "/vms/{vm_id}/export": {"post": {"summary": "OVA export", "tags": ["VMs"], "parameters": [{"name": "vm_id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "Export başlatıldı"}}}},
            "/vms/bulk": {"post": {"summary": "Toplu VM işlemi", "tags": ["VMs"], "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"vm_ids": {"type": "array", "items": {"type": "string"}}, "action": {"type": "string", "enum": ["start", "stop", "reboot", "snapshot"]}}}}}}, "responses": {"200": {"description": "İşlemler tamamlandı"}}}},
            "/sessions": {
                "get": {"summary": "Aktif oturumlar", "tags": ["Auth"], "responses": {"200": {"description": "Oturum listesi"}}},
            },
            "/sessions/{session_id}": {
                "delete": {"summary": "Oturum iptal et", "tags": ["Auth"], "parameters": [{"name": "session_id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "İptal edildi"}}}
            },
            "/security/audit": {"post": {"summary": "Güvenlik denetimi çalıştır", "tags": ["Security"], "responses": {"200": {"description": "Denetim sonucu"}}}},
            "/metrics": {"get": {"summary": "Prometheus metrikleri", "tags": ["Monitoring"], "responses": {"200": {"description": "text/plain metrikler"}}}},
            "/storage/isos": {"get": {"summary": "ISO listesi", "tags": ["Storage"]}, "post": {"summary": "ISO yükle", "tags": ["Storage"]}},
            "/vm-schedules": {
                "get": {"summary": "VM zamanlamaları", "tags": ["Scheduling"]},
                "post": {"summary": "Zamanlama ekle", "tags": ["Scheduling"]}
            },
            "/settings/ip-allowlist": {
                "get": {"summary": "IP allowlist", "tags": ["Settings"]},
                "post": {"summary": "IP allowlist güncelle", "tags": ["Settings"]}
            },
        }
    }
    return jsonify(spec)

# ── Wake-on-LAN ───────────────────────────────────────────────────────────────
import struct as _struct

def _send_magic_packet(mac: str) -> None:
    """Send Wake-on-LAN magic packet."""
    mac_clean = mac.replace(":", "").replace("-", "").upper()
    if len(mac_clean) != 12:
        raise ValueError(f"Geçersiz MAC: {mac}")
    mac_bytes = bytes.fromhex(mac_clean)
    magic = b"\xff" * 6 + mac_bytes * 16
    import socket as _sock
    with _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM) as s:
        s.setsockopt(_sock.SOL_SOCKET, _sock.SO_BROADCAST, 1)
        s.sendto(magic, ("<broadcast>", 9))

@app.route("/api/vms/<vm_id>/wol", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_wol(vm_id):
    """Wake-on-LAN: kapalı VM'i uzaktan aç."""
    r = subprocess.run(["virsh", "dominfo", vm_id], capture_output=True, text=True)
    if r.returncode != 0:
        return jsonify({"error": "VM bulunamadı"}), 404
    nets = subprocess.run(["virsh", "domiflist", vm_id], capture_output=True, text=True)
    mac = None
    for line in nets.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and ":" in parts[2]:
            mac = parts[2]
            break
    if not mac:
        return jsonify({"error": "MAC adresi bulunamadı — VM ağ arayüzü yok"}), 400
    body = request.get_json(silent=True) or {}
    target_mac = body.get("mac", mac)
    try:
        _send_magic_packet(target_mac)
        ev.info(f"WoL gönderildi: {vm_id} → {target_mac}", category="vm")
        return jsonify({"ok": True, "mac": target_mac})
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500

# ── Per-VM Firewall ────────────────────────────────────────────────────────────
_VM_FW_FILE = _pathlib.Path("/var/lib/oxware/vm_firewall.json")

def _fw_load() -> dict:
    if _VM_FW_FILE.exists():
        try:
            return json.loads(_VM_FW_FILE.read_text())
        except Exception:
            pass
    return {}

def _fw_save(data: dict) -> None:
    _VM_FW_FILE.parent.mkdir(parents=True, exist_ok=True)
    _VM_FW_FILE.write_text(json.dumps(data, indent=2))

def _fw_apply_vm(vm_id: str, rules: list) -> None:
    """Apply iptables rules for VM IP (from virsh domifaddr)."""
    r = subprocess.run(["virsh", "domifaddr", vm_id], capture_output=True, text=True)
    vm_ips = []
    for line in r.stdout.splitlines():
        parts = line.split()
        for p in parts:
            if "/" in p and not p.startswith("ff"):
                ip = p.split("/")[0]
                vm_ips.append(ip)
    if not vm_ips:
        return
    for ip in vm_ips:
        subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["iptables", "-D", "FORWARD", "-d", ip, "-j", "ACCEPT"], capture_output=True)
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        proto = rule.get("proto", "tcp")
        port = rule.get("port", "")
        action = rule.get("action", "ACCEPT")
        direction = rule.get("direction", "in")
        for ip in vm_ips:
            cmd = ["iptables", "-I", "FORWARD", "1"]
            if direction == "in":
                cmd += ["-d", ip]
            else:
                cmd += ["-s", ip]
            if proto in ("tcp", "udp"):
                cmd += ["-p", proto]
                if port:
                    cmd += ["--dport" if direction == "in" else "--sport", str(port)]
            cmd += ["-j", action]
            subprocess.run(cmd, capture_output=True)

@app.route("/api/vms/<vm_id>/firewall", methods=["GET"])
@require_auth
def api_vm_fw_get(vm_id):
    data = _fw_load()
    return jsonify({"rules": data.get(vm_id, [])})

@app.route("/api/vms/<vm_id>/firewall", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_fw_post(vm_id):
    body = request.get_json(silent=True) or {}
    rules = body.get("rules", [])
    data = _fw_load()
    data[vm_id] = rules
    _fw_save(data)
    try:
        _fw_apply_vm(vm_id, rules)
    except Exception as ex:
        pass  # iptables hatası kritik değil, kurallar kaydedildi
    ev.info(f"VM firewall güncellendi: {vm_id} — {len(rules)} kural", category="vm")
    return jsonify({"ok": True, "rules": rules})

@app.route("/api/vms/<vm_id>/firewall", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_fw_delete(vm_id):
    data = _fw_load()
    data.pop(vm_id, None)
    _fw_save(data)
    ev.info(f"VM firewall silindi: {vm_id}", category="vm")
    return jsonify({"ok": True})

# ── Maintenance Mode ───────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/maintenance", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_maintenance(vm_id):
    """VM bakım modunu aç/kapat."""
    body = request.get_json(silent=True) or {}
    enabled = bool(body.get("enabled", True))
    data = _load_meta()
    if vm_id not in data:
        data[vm_id] = {}
    data[vm_id]["maintenance"] = enabled
    _save_meta(data)
    ev.info(f"VM bakım modu {'açıldı' if enabled else 'kapatıldı'}: {vm_id}", category="vm")
    return jsonify({"ok": True, "maintenance": enabled})

# ── PCI / USB Passthrough ──────────────────────────────────────────────────────
@app.route("/api/host/pci-devices", methods=["GET"])
@require_auth
def api_host_pci_devices():
    """Host PCI cihazlarını listele."""
    r = subprocess.run(["virsh", "nodedev-list", "--cap", "pci"], capture_output=True, text=True)
    devices = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        info = subprocess.run(["virsh", "nodedev-dumpxml", line], capture_output=True, text=True)
        desc = line
        for iline in info.stdout.splitlines():
            iline = iline.strip()
            if "<product " in iline and ">" in iline:
                import re as _re
                m = _re.search(r">([^<]+)<", iline)
                if m:
                    desc = m.group(1).strip() or desc
                break
        bus = dom = func = "?"
        for iline in info.stdout.splitlines():
            iline = iline.strip()
            if "<bus>" in iline:
                import re as _re2
                m = _re2.search(r">([^<]+)<", iline)
                if m: bus = m.group(1)
            elif "<slot>" in iline:
                m = _re2.search(r">([^<]+)<", iline)
                if m: dom = m.group(1)
            elif "<function>" in iline:
                m = _re2.search(r">([^<]+)<", iline)
                if m: func = m.group(1)
        devices.append({"id": line, "description": desc, "bus": bus, "slot": dom, "func": func})
    return jsonify({"devices": devices})

@app.route("/api/vms/<vm_id>/pci/attach", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_pci_attach(vm_id):
    body = request.get_json(silent=True) or {}
    device_id = body.get("device_id", "")
    if not device_id:
        return jsonify({"error": "device_id gerekli"}), 400
    r = subprocess.run(["virsh", "nodedev-dumpxml", device_id], capture_output=True, text=True)
    if r.returncode != 0:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    xml = r.stdout
    import re as _re3
    domain_m = _re3.search(r"<domain>(\w+)</domain>", xml)
    bus_m = _re3.search(r"<bus>(\w+)</bus>", xml)
    slot_m = _re3.search(r"<slot>(\w+)</slot>", xml)
    func_m = _re3.search(r"<function>(\w+)</function>", xml)
    if not all([domain_m, bus_m, slot_m, func_m]):
        return jsonify({"error": "PCI adresi parse edilemedi"}), 500
    hostdev_xml = f"""<hostdev mode='subsystem' type='pci' managed='yes'>
  <source>
    <address domain='{domain_m.group(1)}' bus='{bus_m.group(1)}' slot='{slot_m.group(1)}' function='{func_m.group(1)}'/>
  </source>
</hostdev>"""
    import tempfile as _tmp
    with _tmp.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(hostdev_xml)
        tmp_path = f.name
    r2 = subprocess.run(["virsh", "attach-device", vm_id, tmp_path, "--live", "--config"], capture_output=True, text=True)
    os.unlink(tmp_path)
    if r2.returncode != 0:
        return jsonify({"error": r2.stderr.strip()}), 500
    ev.info(f"PCI passthrough eklendi: {vm_id} → {device_id}", category="vm")
    return jsonify({"ok": True})

@app.route("/api/vms/<vm_id>/pci/<path:device_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_pci_detach(vm_id, device_id):
    r = subprocess.run(["virsh", "nodedev-dumpxml", device_id], capture_output=True, text=True)
    if r.returncode != 0:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    xml = r.stdout
    import re as _re4
    domain_m = _re4.search(r"<domain>(\w+)</domain>", xml)
    bus_m = _re4.search(r"<bus>(\w+)</bus>", xml)
    slot_m = _re4.search(r"<slot>(\w+)</slot>", xml)
    func_m = _re4.search(r"<function>(\w+)</function>", xml)
    if not all([domain_m, bus_m, slot_m, func_m]):
        return jsonify({"error": "PCI adresi parse edilemedi"}), 500
    hostdev_xml = f"""<hostdev mode='subsystem' type='pci' managed='yes'>
  <source>
    <address domain='{domain_m.group(1)}' bus='{bus_m.group(1)}' slot='{slot_m.group(1)}' function='{func_m.group(1)}'/>
  </source>
</hostdev>"""
    import tempfile as _tmp2
    with _tmp2.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(hostdev_xml)
        tmp_path = f.name
    r2 = subprocess.run(["virsh", "detach-device", vm_id, tmp_path, "--live", "--config"], capture_output=True, text=True)
    os.unlink(tmp_path)
    if r2.returncode != 0:
        return jsonify({"error": r2.stderr.strip()}), 500
    ev.info(f"PCI passthrough kaldırıldı: {vm_id} → {device_id}", category="vm")
    return jsonify({"ok": True})

# ── USB Passthrough ────────────────────────────────────────────────────────────

@app.route("/api/host/usb-devices", methods=["GET"])
@require_auth
def api_host_usb_devices():
    """Host USB cihazlarını listele."""
    import re as _re_u
    r = subprocess.run(["virsh", "nodedev-list", "--cap", "usb_device"], capture_output=True, text=True)
    devices = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        info = subprocess.run(["virsh", "nodedev-dumpxml", line], capture_output=True, text=True)
        vendor = product = ""
        bus = device = ""
        for il in info.stdout.splitlines():
            il = il.strip()
            if "<vendor " in il:
                m = _re_u.search(r">([^<]+)<", il)
                if m: vendor = m.group(1).strip()
            elif "<product " in il:
                m = _re_u.search(r">([^<]+)<", il)
                if m: product = m.group(1).strip()
            elif "<bus>" in il:
                m = _re_u.search(r">([^<]+)<", il)
                if m: bus = m.group(1).strip()
            elif "<device>" in il:
                m = _re_u.search(r">([^<]+)<", il)
                if m: device = m.group(1).strip()
        desc = f"{vendor} {product}".strip() or line
        devices.append({"id": line, "description": desc, "bus": bus, "device": device})
    return jsonify({"devices": devices})


@app.route("/api/vms/<vm_id>/usb/attach", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_usb_attach(vm_id):
    body = request.get_json(silent=True) or {}
    device_id = body.get("device_id", "")
    if not device_id:
        return jsonify({"error": "device_id gerekli"}), 400
    r = subprocess.run(["virsh", "nodedev-dumpxml", device_id], capture_output=True, text=True)
    if r.returncode != 0:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    import re as _re_u2
    bus_m = _re_u2.search(r"<bus>(\d+)</bus>", r.stdout)
    dev_m = _re_u2.search(r"<device>(\d+)</device>", r.stdout)
    if not bus_m or not dev_m:
        return jsonify({"error": "USB adresi parse edilemedi"}), 500
    hostdev_xml = f"""<hostdev mode='subsystem' type='usb' managed='yes'>
  <source>
    <address bus='{bus_m.group(1)}' device='{dev_m.group(1)}'/>
  </source>
</hostdev>"""
    import tempfile as _tmp_u
    with _tmp_u.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(hostdev_xml)
        tmp_path = f.name
    r2 = subprocess.run(["virsh", "attach-device", vm_id, tmp_path, "--live", "--config"], capture_output=True, text=True)
    os.unlink(tmp_path)
    if r2.returncode != 0:
        return jsonify({"error": r2.stderr.strip()}), 500
    ev.info(f"USB passthrough eklendi: {vm_id} → {device_id}", category="vm")
    return jsonify({"ok": True})


@app.route("/api/vms/<vm_id>/usb/<path:device_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_usb_detach(vm_id, device_id):
    r = subprocess.run(["virsh", "nodedev-dumpxml", device_id], capture_output=True, text=True)
    if r.returncode != 0:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    import re as _re_u3
    bus_m = _re_u3.search(r"<bus>(\d+)</bus>", r.stdout)
    dev_m = _re_u3.search(r"<device>(\d+)</device>", r.stdout)
    if not bus_m or not dev_m:
        return jsonify({"error": "USB adresi parse edilemedi"}), 500
    hostdev_xml = f"""<hostdev mode='subsystem' type='usb' managed='yes'>
  <source>
    <address bus='{bus_m.group(1)}' device='{dev_m.group(1)}'/>
  </source>
</hostdev>"""
    import tempfile as _tmp_u2
    with _tmp_u2.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(hostdev_xml)
        tmp_path = f.name
    r2 = subprocess.run(["virsh", "detach-device", vm_id, tmp_path, "--live", "--config"], capture_output=True, text=True)
    os.unlink(tmp_path)
    if r2.returncode != 0:
        return jsonify({"error": r2.stderr.strip()}), 500
    ev.info(f"USB passthrough kaldırıldı: {vm_id} → {device_id}", category="vm")
    return jsonify({"ok": True})

# ── SPICE Console ──────────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/spice", methods=["GET"])
@require_auth
def api_vm_spice(vm_id):
    """SPICE bağlantı bilgilerini döndür."""
    r = subprocess.run(["virsh", "domdisplay", "--type", "spice", vm_id], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        r2 = subprocess.run(["virsh", "domdisplay", "--type", "vnc", vm_id], capture_output=True, text=True)
        if r2.returncode == 0 and r2.stdout.strip():
            return jsonify({"type": "vnc", "url": r2.stdout.strip(), "note": "Bu VM SPICE değil VNC kullanıyor"})
        return jsonify({"error": "Bu VM'de SPICE veya VNC konsolu yapılandırılmamış"}), 404
    url = r.stdout.strip()
    import re as _re5
    m = _re5.match(r"spice://([^:]+):(\d+)", url)
    host_s = m.group(1) if m else "localhost"
    port_s = m.group(2) if m else "?"
    return jsonify({
        "type": "spice",
        "url": url,
        "host": host_s,
        "port": port_s,
        "note": "SPICE client veya web SPICE (spice-html5) gereklidir"
    })

# ── OVA / OVF Import ──────────────────────────────────────────────────────────
_IMPORT_DIR = _pathlib.Path("/var/lib/oxware/imports")
_import_jobs: dict = {}          # job_id → job dict
_import_jobs_lock = threading.Lock()
# ESXi SSH lockout prevention: limit concurrent SSH connections per host.
# ESXi vSphere locks accounts after N failed auth attempts (default 10-20).
# Paramiko with concurrent threads creates one SSH login per thread.
# Semaphore caps to 1 parallel ESXi SSH connection — ESXi locks root after
# ~5-18 failed auth attempts; serializing connections prevents lockout.
_esxi_ssh_sem = threading.Semaphore(1)
# Full pipeline concurrency: limit to 2 simultaneous ESXi migrations.
_esxi_pipeline_sem = threading.Semaphore(2)
# Lockout guard: when ESXi locks the account, block all new connections
# until the lockout window expires (ESXi default: 900s).
_esxi_lockout_until = [0.0]   # mutable: [epoch_seconds]; 0 = not locked
_esxi_lockout_lock = threading.Lock()

def _import_job_update(job_id: str, **kw):
    with _import_jobs_lock:
        if job_id in _import_jobs:
            _import_jobs[job_id].update(kw)


def _parse_ovf(ovf_path) -> dict:
    """Parse OVF file for CPU, RAM, OS type and firmware. Returns safe defaults on failure."""
    specs = {"vcpus": 2, "ram_mb": 4096, "os_type": "unknown", "os_desc": "", "firmware": "bios"}
    try:
        tree = ET.parse(str(ovf_path))
        root = tree.getroot()

        # ── OS type detection ──────────────────────────────────────────────────
        for os_el in root.iter():
            if os_el.tag.split("}")[-1] == "OperatingSystemSection":
                os_id_str = ""
                for attr_name, attr_val in os_el.attrib.items():
                    if attr_name.endswith("}id") or attr_name == "id":
                        os_id_str = attr_val
                try:
                    os_id_int = int(os_id_str)
                    if 65 <= os_id_int <= 120:
                        specs["os_type"] = "windows"
                    elif os_id_int > 0:
                        specs["os_type"] = "linux"
                except (ValueError, TypeError):
                    pass
                for child in os_el:
                    if child.tag.split("}")[-1] == "Description" and child.text:
                        specs["os_desc"] = child.text
                        dl = child.text.lower()
                        if "windows" in dl:
                            specs["os_type"] = "windows"
                        elif any(x in dl for x in ["linux","ubuntu","debian","centos",
                                                    "red hat","rhel","fedora","suse",
                                                    "kali","mint","arch","rocky","alma"]):
                            specs["os_type"] = "linux"
                break

        # ── Firmware: EFI vs BIOS ─────────────────────────────────────────────
        # VMware OVF: <vmw:Config ovf:required="false" vmw:key="firmware" vmw:value="efi"/>
        for el in root.iter():
            attribs = el.attrib
            key_val = next((v for k, v in attribs.items()
                            if k.endswith("}key") or k == "key"), "").lower()
            cfg_val = next((v for k, v in attribs.items()
                            if k.endswith("}value") or k == "value"), "").lower()
            if "firmware" in key_val and "efi" in cfg_val:
                specs["firmware"] = "efi"
                break

        # ── CPU / RAM from VirtualHardwareSection ─────────────────────────────
        for item in root.iter():
            if item.tag.split("}")[-1] != "Item":
                continue
            rt = qty = units = None
            for child in item:
                tag = child.tag.split("}")[-1]
                if tag == "ResourceType":
                    rt = child.text
                elif tag == "VirtualQuantity":
                    qty = child.text
                elif tag == "AllocationUnits":
                    units = (child.text or "").lower()
            if rt == "3" and qty:          # vCPU
                try:
                    specs["vcpus"] = max(1, min(128, int(qty)))
                except ValueError:
                    pass
            elif rt == "4" and qty:        # Memory
                try:
                    mb = int(qty)
                    if units and ("gb" in units or "gigabyte" in units):
                        mb *= 1024
                    elif units and "kb" in units:
                        mb //= 1024
                    elif units and "byte * 2^30" in units:
                        mb = mb // (1024 * 1024)
                    specs["ram_mb"] = max(512, min(262144, mb))
                except ValueError:
                    pass
    except Exception:
        pass
    return specs


def _parse_vmx(vmx_path) -> dict:
    """
    Parse VMware .vmx config file.
    Returns: {vcpus, ram_mb, os_type, firmware, disk_file}
    More reliable than OVF for firmware and guestOS detection.
    """
    specs = {"vcpus": 2, "ram_mb": 4096, "os_type": "unknown",
             "firmware": "bios", "disk_file": None}
    try:
        with open(str(vmx_path), "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip().lower()
                v = v.strip().strip('"')
                vl = v.lower()

                if k in ("numvcpus", "nummvcpus"):
                    try: specs["vcpus"] = max(1, min(128, int(v)))
                    except ValueError: pass
                elif k == "memsize":
                    try: specs["ram_mb"] = max(512, min(262144, int(v)))
                    except ValueError: pass
                elif k == "firmware":
                    specs["firmware"] = "efi" if vl == "efi" else "bios"
                elif k == "guestos":
                    if any(x in vl for x in ["win", "windows", "server"]):
                        specs["os_type"] = "windows"
                    elif any(x in vl for x in ["linux", "ubuntu", "centos", "rhel",
                                                "fedora", "debian", "suse", "rocky",
                                                "alma", "oracle", "freebsd"]):
                        specs["os_type"] = "linux"
                elif k.endswith(".filename") and vl.endswith(".vmdk"):
                    # First disk file found (e.g. scsi0:0.filename or sata0:0.filename)
                    # Skip flat/extent files
                    if "-flat" not in vl and not _re_vmdk_extent.search(vl):
                        if specs["disk_file"] is None:
                            specs["disk_file"] = v   # relative path
    except Exception:
        pass
    return specs


import re as _re
_re_vmdk_extent = _re.compile(r"-s\d{3}\.vmdk$", _re.IGNORECASE)


def _detect_os_from_name(name: str) -> str:
    """Guess OS type from filename when OVF/VMX absent."""
    n = name.lower()
    if any(x in n for x in ["win", "windows", "w10", "w11", "w7", "w8",
                             "server", "2016", "2019", "2022", "2012", "plesk"]):
        return "windows"
    if any(x in n for x in ["ubuntu", "debian", "centos", "rhel", "linux",
                             "fedora", "kali", "mint", "arch", "rocky", "alma",
                             "suse", "freebsd", "proxmox"]):
        return "linux"
    return "unknown"


def _build_import_xml(vm_name: str, disk_path, vcpus: int, ram_mb: int,
                      os_type: str, firmware: str = "bios",
                      network: str = "default") -> str:
    """Return OS-optimised libvirt domain XML for imported VM."""
    dp  = str(disk_path)
    efi = firmware.lower() == "efi"
    # Sanitize network name: only alnum, dash, underscore, dot
    import re as _re_net
    network = _re_net.sub(r'[^a-zA-Z0-9_\-\.]', '', network) or "default"

    # EFI os block — libvirt auto-selects OVMF (requires libvirt ≥6.0)
    # secure-boot disabled: imported VMs don't have enrolled SB keys
    os_efi_block = """  <os firmware='efi'>
    <type arch='x86_64' machine='q35'>hvm</type>
    <firmware>
      <feature enabled='no' name='secure-boot'/>
    </firmware>
    <boot dev='hd'/>
  </os>"""
    os_bios_block = """  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
  </os>"""
    os_block = os_efi_block if efi else os_bios_block

    if os_type == "windows":
        return f"""<domain type='kvm'>
  <name>{vm_name}</name>
  <memory unit='MiB'>{ram_mb}</memory>
  <vcpu placement='static'>{vcpus}</vcpu>
{os_block}
  <features>
    <acpi/><apic/>
    <hyperv mode='custom'>
      <relaxed state='on'/><vapic state='on'/>
      <spinlocks state='on' retries='8191'/>
      <vpindex state='on'/><runtime state='on'/>
      <synic state='on'/><stimer state='on'/>
      <reset state='on'/><frequencies state='on'/>
    </hyperv>
    <vmport state='off'/>
  </features>
  <cpu mode='host-passthrough' check='none' migratable='on'/>
  <clock offset='localtime'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
    <timer name='hypervclock' present='yes'/>
  </clock>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none' io='native'/>
      <source file='{dp}'/>
      <target dev='sda' bus='sata'/>
    </disk>
    <controller type='sata' index='0'/>
    <interface type='network'>
      <source network='{network}'/>
      <model type='e1000'/>
    </interface>
    <input type='tablet' bus='usb'/>
    <input type='keyboard' bus='usb'/>
    <graphics type='vnc' port='-1' listen='0.0.0.0'/>
    <video><model type='qxl' ram='65536' vram='65536' vgamem='16384' heads='1' primary='yes'/></video>
    <memballoon model='none'/>
  </devices>
</domain>"""

    elif os_type == "linux":
        return f"""<domain type='kvm'>
  <name>{vm_name}</name>
  <memory unit='MiB'>{ram_mb}</memory>
  <vcpu placement='static'>{vcpus}</vcpu>
{os_block}
  <features><acpi/><apic/></features>
  <cpu mode='host-passthrough' check='none' migratable='on'/>
  <clock offset='utc'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
  </clock>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none' io='native' discard='unmap'/>
      <source file='{dp}'/>
      <target dev='sda' bus='sata'/>
    </disk>
    <controller type='sata' index='0'/>
    <interface type='network'>
      <source network='{network}'/>
      <model type='virtio'/>
    </interface>
    <input type='tablet' bus='usb'/>
    <graphics type='vnc' port='-1' listen='0.0.0.0'/>
    <video><model type='vga' vram='16384' heads='1' primary='yes'/></video>
    <memballoon model='virtio'><stats period='10'/></memballoon>
    <rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>
  </devices>
</domain>"""

    else:
        return f"""<domain type='kvm'>
  <name>{vm_name}</name>
  <memory unit='MiB'>{ram_mb}</memory>
  <vcpu placement='static'>{vcpus}</vcpu>
{os_block}
  <features><acpi/><apic/></features>
  <cpu mode='host-passthrough' check='none' migratable='on'/>
  <clock offset='utc'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
  </clock>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none' io='native'/>
      <source file='{dp}'/>
      <target dev='sda' bus='sata'/>
    </disk>
    <controller type='sata' index='0'/>
    <interface type='network'>
      <source network='{network}'/>
      <model type='e1000'/>
    </interface>
    <input type='tablet' bus='usb'/>
    <graphics type='vnc' port='-1' listen='0.0.0.0'/>
    <video><model type='qxl' ram='65536' vram='65536' vgamem='16384'/></video>
    <memballoon model='none'/>
  </devices>
</domain>"""

@app.route("/api/import/ova", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_import_ova():
    """OVA/OVF/VMDK/VHD/ZIP dosyasından VM içe aktar. admin ve operator rolü gerekli."""
    if "file" not in request.files:
        return jsonify({"error": "file alanı gerekli"}), 400
    f = request.files["file"]
    fname = f.filename or "import.ova"
    # Optional: connect imported VM to a specific libvirt network (default: 'default')
    _import_network = (request.form.get("network") or "default").strip() or "default"
    _ALLOWED_IMPORT_EXTS = (
        ".ova", ".ovf", ".tar", ".tar.gz",
        ".vmdk", ".qcow2", ".raw", ".img",
        ".vhd", ".vhdx", ".nvr", ".nvrx",
        ".zip",   # VMware Workstation VM klasörü zip olarak
    )
    if not any(fname.lower().endswith(ext) for ext in _ALLOWED_IMPORT_EXTS):
        return jsonify({"error": "Desteklenen formatlar: .ova .vmdk .ovf .qcow2 .vhd .vhdx .raw .img .tar .zip"}), 400
    _IMPORT_DIR.mkdir(parents=True, exist_ok=True)
    save_path = _IMPORT_DIR / fname
    f.save(str(save_path))

    import uuid as _uuid
    job_id = _uuid.uuid4().hex[:8]
    with _import_jobs_lock:
        _import_jobs[job_id] = {
            "id": job_id,
            "filename": fname,
            "vm_name": "",
            "status": "running",
            "step": "Dosya kaydedildi",
            "percent": 5,
            "started": time.time(),
            "finished": None,
            "message": "",
        }

    def _do_import():
        try:
            _import_job_update(job_id, step="Arşiv açılıyor", percent=10)
            # SEC-029: archive extraction goes through security_utils.
            try:
                from . import security_utils as _sec_ext  # type: ignore
            except Exception:
                import security_utils as _sec_ext  # type: ignore
            extract_dir = _IMPORT_DIR / (fname + "_extracted")
            extract_dir.mkdir(exist_ok=True)

            _fl = fname.lower()
            if _fl.endswith((".ova", ".tar", ".tar.gz")):
                _sec_ext.safe_tar_extract(str(save_path), str(extract_dir))
            elif _fl.endswith(".zip"):
                _sec_ext.safe_zip_extract(str(save_path), str(extract_dir))
            else:
                import shutil as _sh
                _sh.copy(str(save_path), str(extract_dir / fname))

            # ── Tüm dosyaları recursive tara ──────────────────────────────────
            _import_job_update(job_id, step="Disk, OVF ve VMX aranıyor", percent=18)
            ovf_file  = None
            vmx_file  = None
            disk_files = []   # (path, is_descriptor) pairs

            for fp in extract_dir.rglob("*"):
                if not fp.is_file():
                    continue
                sfx = fp.suffix.lower()
                nm  = fp.name.lower()
                if sfx == ".ovf":
                    ovf_file = fp
                elif sfx == ".vmx":
                    vmx_file = fp
                elif sfx in (".vmdk", ".qcow2", ".img", ".raw",
                             ".vhd", ".vhdx", ".nvr", ".nvrx"):
                    # Skip VMware flat/extent files — they're raw data blocks,
                    # not standalone disk images. qemu-img needs the descriptor.
                    if nm.endswith("-flat.vmdk") or _re_vmdk_extent.search(nm):
                        continue
                    disk_files.append(fp)

            if not disk_files:
                _import_job_update(job_id, status="error", step="Hata: disk bulunamadı",
                                   percent=0, message="Disk dosyası bulunamadı", finished=time.time())
                ev.warn(f"OVA import: disk dosyası bulunamadı — {fname}", category="vm")
                return

            # ── VM name from filename ──────────────────────────────────────────
            _vm_strip_exts = (".tar.gz", ".ova", ".ovf", ".tar", ".vmdk", ".qcow2",
                              ".raw", ".img", ".vhd", ".vhdx", ".nvr", ".nvrx", ".zip")
            vm_name = fname
            for _ext in _vm_strip_exts:
                if vm_name.lower().endswith(_ext):
                    vm_name = vm_name[:-len(_ext)]
                    break
            vm_name = vm_name.replace(" ", "_").replace(".", "_") or "imported-vm"

            # ── Parse specs: VMX → OVF → fallback ────────────────────────────
            specs = {"vcpus": 2, "ram_mb": 4096, "os_type": "unknown",
                     "os_desc": "", "firmware": "bios", "disk_file": None}

            if vmx_file:
                _import_job_update(job_id, step="VMX okunuyor", percent=19)
                vmx_specs = _parse_vmx(vmx_file)
                specs.update({k: v for k, v in vmx_specs.items() if v not in (None, "unknown", "bios") or k in ("vcpus","ram_mb")})
                # If VMX gave os_type/firmware prefer those; keep bios default if still unknown
                if vmx_specs.get("firmware"): specs["firmware"] = vmx_specs["firmware"]
                if vmx_specs.get("os_type") != "unknown": specs["os_type"] = vmx_specs["os_type"]
                specs["vcpus"]  = vmx_specs["vcpus"]
                specs["ram_mb"] = vmx_specs["ram_mb"]
                # VMX disk file hint
                if vmx_specs.get("disk_file"):
                    _hint = vmx_file.parent / vmx_specs["disk_file"]
                    if _hint.exists():
                        disk_files = [_hint] + [d for d in disk_files if d != _hint]

            if ovf_file:
                _import_job_update(job_id, step="OVF okunuyor", percent=20)
                ovf_specs = _parse_ovf(ovf_file)
                # OVF takes precedence for CPU/RAM if VMX wasn't found
                if not vmx_file:
                    specs["vcpus"]  = ovf_specs["vcpus"]
                    specs["ram_mb"] = ovf_specs["ram_mb"]
                # OVF firmware overrides VMX only if explicitly "efi"
                if ovf_specs.get("firmware") == "efi":
                    specs["firmware"] = "efi"
                if ovf_specs.get("os_type") != "unknown" and specs["os_type"] == "unknown":
                    specs["os_type"] = ovf_specs["os_type"]
                specs["os_desc"] = ovf_specs.get("os_desc", "")

            # Final fallback: filename-based OS detection
            if specs["os_type"] == "unknown":
                specs["os_type"] = _detect_os_from_name(fname)

            vcpus    = specs["vcpus"]
            ram_mb   = specs["ram_mb"]
            os_type  = specs["os_type"]
            firmware = specs["firmware"]
            os_desc  = specs.get("os_desc", "") or os_type
            fw_label = "UEFI" if firmware == "efi" else "BIOS"

            _import_job_update(job_id, vm_name=vm_name,
                               step=f"Disk: {disk_files[0].name} | {os_desc or os_type} | "
                                    f"{fw_label} | {vcpus} vCPU {ram_mb} MB",
                               percent=22)

            # ── Name conflict dedup ──────────────────────────────────────────
            import libvirt as _lv_imp
            _conn_chk = _lv_imp.open(config.LIBVIRT_URI)
            try:
                _chk_suffix = 0
                _base_name  = vm_name
                while True:
                    try:
                        _conn_chk.lookupByName(vm_name)
                        # Name taken → try vm_name-1, -2, …
                        _chk_suffix += 1
                        vm_name = f"{_base_name}-{_chk_suffix}"
                    except _lv_imp.libvirtError:
                        break  # name available
            finally:
                _conn_chk.close()
            if vm_name != _base_name:
                _import_job_update(job_id, vm_name=vm_name,
                                   step=f"İsim çakışması → yeni isim: {vm_name}")

            disk_path = _pathlib.Path("/var/lib/libvirt/images") / f"{vm_name}.qcow2"
            src_disk  = disk_files[0]
            src_size  = max(src_disk.stat().st_size, 1)

            # rapor #70 fix: QCOW2 magic header doğrulama
            _MAGIC_QCOW2 = b"QFI\xfb"
            if src_disk.suffix.lower() == ".qcow2":
                try:
                    with open(src_disk, "rb") as _mf:
                        _magic = _mf.read(4)
                    if _magic != _MAGIC_QCOW2:
                        _import_job_update(job_id, status="error",
                                           step="Hata: geçersiz QCOW2 dosyası",
                                           percent=0,
                                           message=f"QCOW2 magic bytes geçersiz: {_magic!r}",
                                           finished=time.time())
                        ev.warn(f"Import: geçersiz QCOW2 magic — {src_disk.name}", category="vm")
                        return
                except Exception as _me:
                    ev.warn(f"Import: QCOW2 magic okuma hatası — {_me}", category="vm")

            # ── qemu-img convert ──────────────────────────────────────────────
            _fmt_map = {".vmdk": "vmdk", ".vhd": "vpc", ".vhdx": "vhdx",
                        ".qcow2": "qcow2", ".raw": "raw", ".img": "raw",
                        ".nvr": "raw", ".nvrx": "raw"}
            _src_fmt = _fmt_map.get(src_disk.suffix.lower(), "")
            _conv_cmd = ["qemu-img", "convert", "-p", "-O", "qcow2"]
            if _src_fmt:
                _conv_cmd += ["-f", _src_fmt]
            _conv_cmd += [str(src_disk), str(disk_path)]

            _import_job_update(job_id,
                               step=f"Disk dönüştürülüyor ({fw_label}, {os_type})",
                               percent=25)
            proc = subprocess.Popen(_conv_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            while proc.poll() is None:
                time.sleep(1.5)
                try:
                    out_sz = disk_path.stat().st_size if disk_path.exists() else 0
                    pct = min(89, 25 + int(64 * out_sz * 2 / src_size))
                    _import_job_update(job_id,
                                       step=f"Disk dönüştürülüyor ({fw_label}, {os_type})",
                                       percent=pct)
                except Exception:
                    pass
            _conv_stderr = (proc.stderr.read() or b"").decode(errors="ignore").strip()
            proc.wait()
            if proc.returncode != 0:
                _import_job_update(job_id, status="error",
                                   step="Hata: disk dönüştürme başarısız",
                                   percent=0,
                                   message=f"qemu-img hatası: {_conv_stderr[:200]}",
                                   finished=time.time())
                ev.warn(f"OVA import disk convert hatası (rc={proc.returncode}): {_conv_stderr[:200]}",
                        category="vm")
                return

            # ── Disk bütünlük kontrolü ─────────────────────────────────────────
            _chk = subprocess.run(["qemu-img", "check", str(disk_path)],
                                  capture_output=True, text=True)
            if _chk.returncode not in (0, 1):   # 1 = minor errors (fixed), 0 = ok
                ev.warn(f"OVA import: disk kontrolü uyarısı — {_chk.stdout[:200]}", category="vm")

            # ── OS-optimised libvirt XML ───────────────────────────────────────
            _import_job_update(job_id,
                               step=f"libvirt'e kaydediliyor ({os_type}, {fw_label}, "
                                    f"{vcpus} vCPU, {ram_mb} MB)",
                               percent=92)
            xml = _build_import_xml(vm_name, disk_path, vcpus, ram_mb, os_type, firmware,
                                    network=_import_network)

            import tempfile as _tmp3
            with _tmp3.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as xf:
                xf.write(xml)
                xml_path = xf.name
            r_def = subprocess.run(["virsh", "define", xml_path], capture_output=True, text=True)
            os.unlink(xml_path)
            if r_def.returncode == 0:
                _import_job_update(job_id, status="done",
                                   step=f"Tamamlandı — {vm_name} "
                                        f"({os_type}, {fw_label}, {vcpus} vCPU, {ram_mb} MB)",
                                   percent=100, finished=time.time())
                ev.info(f"OVA import tamamlandı: {vm_name} [{os_type}/{fw_label}, "
                        f"{vcpus}v, {ram_mb}MB]", category="vm")
            else:
                _import_job_update(job_id, status="error",
                                   step="Hata: virsh define başarısız",
                                   percent=92, message=r_def.stderr.strip()[:200],
                                   finished=time.time())
                ev.warn(f"OVA import virsh define hatası: {r_def.stderr}", category="vm")
        except Exception as ex:
            _import_job_update(job_id, status="error", step="Hata",
                               message=str(ex)[:200], finished=time.time())
            ev.warn(f"OVA import hatası: {ex}", category="vm")

    t = threading.Thread(target=_do_import, daemon=True)
    t.start()
    return jsonify({"ok": True, "message": f"Import başlatıldı: {fname}",
                    "filename": fname, "job_id": job_id})

@app.route("/api/import/status", methods=["GET"])
@require_auth
def api_import_status():
    """Import işlerinin durumunu döner."""
    with _import_jobs_lock:
        jobs = list(_import_jobs.values())
    jobs.sort(key=lambda j: j.get("started", 0), reverse=True)
    return jsonify({"imports": jobs[:30]})

# ── MAC Address Yönetimi ──────────────────────────────────────────────────────
import random as _random

def _generate_qemu_mac() -> str:
    """QEMU/KVM için geçerli rastgele MAC adresi üretir (52:54:00:xx:xx:xx)."""
    return "52:54:00:{:02x}:{:02x}:{:02x}".format(
        _random.randint(0, 255),
        _random.randint(0, 255),
        _random.randint(0, 255),
    )

def _validate_mac(mac: str) -> bool:
    """MAC adresinin geçerli formatta olup olmadığını kontrol eder."""
    import re
    return bool(re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac))

@app.route("/api/vms/<vm_id>/nics/macs", methods=["GET"])
@require_auth
def api_vm_mac_list(vm_id):
    """VM'in tüm NIC'lerini ve MAC adreslerini listele."""
    r = subprocess.run(["virsh", "domiflist", vm_id], capture_output=True, text=True)
    if r.returncode != 0:
        return err(f"domiflist hatası: {r.stderr.strip()}")
    lines = r.stdout.strip().splitlines()
    nics = []
    for line in lines[2:]:
        parts = line.split()
        if len(parts) >= 5:
            nics.append({
                "interface": parts[0],
                "type": parts[1],
                "source": parts[2],
                "model": parts[3],
                "mac": parts[4],
            })
    return ok(nics=nics)

@app.route("/api/vms/<vm_id>/nics/mac", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_mac_change(vm_id):
    """
    VM NIC MAC adresini değiştir.
    Body: {"mac": "52:54:00:xx:xx:xx", "interface": "vnet0"}
    mac boşsa rastgele üretir.
    VM kapalıyken XML doğrudan düzenlenir; açıksa hot-plug gerekir.
    """
    data = request.get_json() or {}
    new_mac = data.get("mac", "").strip()
    interface = data.get("interface", "").strip()

    if new_mac and not _validate_mac(new_mac):
        return err("Geçersiz MAC adresi formatı. Örnek: 52:54:00:ab:cd:ef")

    if not new_mac:
        new_mac = _generate_qemu_mac()

    # Mevcut NIC bilgilerini al
    r = subprocess.run(["virsh", "domiflist", vm_id], capture_output=True, text=True)
    if r.returncode != 0:
        return err(f"NIC listesi alınamadı: {r.stderr.strip()}")

    lines = r.stdout.strip().splitlines()
    nics = []
    for line in lines[2:]:
        parts = line.split()
        if len(parts) >= 5:
            nics.append({"interface": parts[0], "type": parts[1],
                         "source": parts[2], "model": parts[3], "mac": parts[4]})

    if not nics:
        return err("VM'de NIC bulunamadı")

    # Interface belirtilmediyse ilk NIC'i kullan
    target_nic = None
    if interface:
        target_nic = next((n for n in nics if n["interface"] == interface), None)
        if not target_nic:
            return err(f"Interface bulunamadı: {interface}")
    else:
        target_nic = nics[0]

    old_mac = target_nic["mac"]
    model   = target_nic["model"]
    source  = target_nic["source"]
    nic_type = target_nic["type"]

    # VM durumunu kontrol et
    state_r = subprocess.run(["virsh", "domstate", vm_id], capture_output=True, text=True)
    is_running = "running" in state_r.stdout.lower()

    if is_running:
        # Çalışıyorsa: eski NIC kaldır → yeni MAC ile ekle
        detach = subprocess.run(
            ["virsh", "detach-interface", vm_id, nic_type,
             "--mac", old_mac, "--live", "--config"],
            capture_output=True, text=True
        )
        if detach.returncode != 0:
            return err(f"NIC kaldırılamadı: {detach.stderr.strip()}")

        attach = subprocess.run(
            ["virsh", "attach-interface", vm_id, nic_type, source,
             "--mac", new_mac, "--model", model, "--live", "--config"],
            capture_output=True, text=True
        )
        if attach.returncode != 0:
            return err(f"Yeni NIC eklenemedi: {attach.stderr.strip()}")
    else:
        # Kapalıysa: XML'i doğrudan düzenle
        xml_r = subprocess.run(["virsh", "dumpxml", vm_id], capture_output=True, text=True)
        if xml_r.returncode != 0:
            return err("VM XML alınamadı")

        import re as _re
        xml = xml_r.stdout
        # MAC adresini XML'de değiştir
        new_xml = _re.sub(
            rf"<mac address=['\"]?{_re.escape(old_mac)}['\"]?/>",
            f"<mac address='{new_mac}'/>",
            xml, count=1, flags=_re.IGNORECASE
        )
        if new_xml == xml:
            return err(f"MAC adresi XML'de bulunamadı: {old_mac}")

        # Geçici dosyaya yaz ve define et
        import tempfile as _tmp
        with _tmp.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(new_xml)
            tmp_path = f.name
        try:
            define_r = subprocess.run(["virsh", "define", tmp_path], capture_output=True, text=True)
            if define_r.returncode != 0:
                return err(f"virsh define hatası: {define_r.stderr.strip()}")
        finally:
            import os as _os
            _os.unlink(tmp_path)

    ev.info(f"MAC değiştirildi: {vm_id} {old_mac} → {new_mac}", category="vm")
    return ok(old_mac=old_mac, new_mac=new_mac, interface=target_nic["interface"])

@app.route("/api/vms/<vm_id>/nics/mac/generate", methods=["GET"])
@require_auth
def api_vm_mac_generate(vm_id):
    """QEMU için geçerli rastgele MAC adresi üret."""
    return ok(mac=_generate_qemu_mac())

# ══════════════════════════════════════════════════════════════════════════════
#  RESOURCE POOLS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/pools", methods=["GET"])
@require_auth
def api_pools_list():
    if not pool_mgr: return ok({"pools": []})
    return ok({"pools": pool_mgr.list_pools()})

@app.route("/api/pools", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_pools_create():
    if not pool_mgr: return err("Resource pool manager unavailable")
    d = request.get_json() or {}
    return ok(pool_mgr.create_pool(**d))

@app.route("/api/pools/<pool_id>", methods=["PUT"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_pools_update(pool_id):
    if not pool_mgr: return err("Resource pool manager unavailable")
    d = request.get_json() or {}
    result = pool_mgr.update_pool(pool_id, **d)
    if result is None: return err("Pool bulunamadı", 404)
    return ok(result)

@app.route("/api/pools/<pool_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_pools_delete(pool_id):
    if not pool_mgr: return err("Resource pool manager unavailable")
    if pool_mgr.delete_pool(pool_id):
        return ok({"deleted": True})
    return err("Pool bulunamadı", 404)

@app.route("/api/pools/<pool_id>/vms", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_pools_add_vm(pool_id):
    if not pool_mgr: return err("Resource pool manager unavailable")
    d = request.get_json() or {}
    vm_id = d.get("vm_id")
    if not vm_id: return err("vm_id gerekli")
    return ok({"added": pool_mgr.add_vm_to_pool(pool_id, vm_id)})

@app.route("/api/pools/<pool_id>/vms/<vm_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_pools_remove_vm(pool_id, vm_id):
    if not pool_mgr: return err("Resource pool manager unavailable")
    return ok({"removed": pool_mgr.remove_vm_from_pool(pool_id, vm_id)})

# ══════════════════════════════════════════════════════════════════════════════
#  HOT-PLUG
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/vms/<vm_name>/hotplug", methods=["GET"])
@require_auth
def api_hotplug_info(vm_name):
    if not hotplug_mgr: return ok({"vcpu": {}, "memory": {}})
    return ok({
        "vcpu": hotplug_mgr.get_vcpu_info(vm_name),
        "memory": hotplug_mgr.get_mem_info(vm_name),
    })

@app.route("/api/vms/<vm_name>/hotplug/vcpu", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_hotplug_vcpu(vm_name):
    if not hotplug_mgr: return err("Hotplug manager unavailable")
    d = request.get_json() or {}
    count = d.get("count")
    if count is None: return err("count gerekli")
    return ok(hotplug_mgr.hotplug_vcpu(vm_name, count))

@app.route("/api/vms/<vm_name>/hotplug/memory", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_hotplug_memory(vm_name):
    if not hotplug_mgr: return err("Hotplug manager unavailable")
    d = request.get_json() or {}
    ram_mb = d.get("ram_mb")
    if ram_mb is None: return err("ram_mb gerekli")
    return ok(hotplug_mgr.hotplug_memory(vm_name, ram_mb))

# ══════════════════════════════════════════════════════════════════════════════
#  STORAGE MIGRATION
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/storage/pools/migration", methods=["GET"])
@require_auth
def api_storage_pools_migration():
    """Storage migration module pool list (distinct from /api/storage/pools)."""
    if not stor_mig: return ok({"pools": []})
    return ok({"pools": stor_mig.list_storage_pools()})

@app.route("/api/vms/<vm_name>/disks", methods=["GET"])
@require_auth
def api_vm_disks(vm_name):
    if not stor_mig: return ok({"disks": []})
    return ok({"disks": stor_mig.get_vm_disks(vm_name)})

@app.route("/api/vms/<vm_name>/migrate-disk", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_migrate_disk(vm_name):
    if not stor_mig: return err("Storage migration manager unavailable")
    d = request.get_json() or {}
    disk_target = d.get("disk_target")
    dest_path = d.get("dest_path")
    if not disk_target or not dest_path:
        return err("disk_target ve dest_path gerekli")
    fmt = d.get("format", "qcow2")
    return ok(stor_mig.start_migration(vm_name, disk_target, dest_path, fmt))

@app.route("/api/storage/migrations", methods=["GET"])
@require_auth
def api_storage_migrations_list():
    if not stor_mig: return ok({"migrations": []})
    return ok({"migrations": stor_mig.list_migrations()})

@app.route("/api/storage/migrations/<job_id>", methods=["GET"])
@require_auth
def api_storage_migration_status(job_id):
    if not stor_mig: return err("Storage migration manager unavailable")
    job = stor_mig.get_migration_status(job_id)
    if job is None: return err("Migration job bulunamadı", 404)
    return ok(job)

# ══════════════════════════════════════════════════════════════════════════════
#  NETWORK QOS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/vms/<vm_name>/nics", methods=["GET"])
@require_auth
def api_vm_nics_list(vm_name):
    if not net_qos: return ok({"nics": []})
    return ok({"nics": net_qos.list_vm_nics(vm_name)})

@app.route("/api/vms/<vm_name>/nics/<iface>/qos", methods=["GET"])
@require_auth
def api_vm_nic_qos_get(vm_name, iface):
    if not net_qos: return ok({})
    return ok(net_qos.get_nic_qos(vm_name, iface))

@app.route("/api/vms/<vm_name>/nics/<iface>/qos", methods=["PUT"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_nic_qos_set(vm_name, iface):
    if not net_qos: return err("Network QoS manager unavailable")
    d = request.get_json() or {}
    inbound_kbps = d.get("inbound_kbps", 0)
    outbound_kbps = d.get("outbound_kbps", 0)
    return ok(net_qos.set_nic_qos(vm_name, iface, inbound_kbps, outbound_kbps))

@app.route("/api/vms/<vm_name>/nics/<iface>/qos", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_nic_qos_clear(vm_name, iface):
    if not net_qos: return err("Network QoS manager unavailable")
    return ok(net_qos.clear_nic_qos(vm_name, iface))

# ── API Key yönetimi (UI) ─────────────────────────────────────────────────────
@app.route("/api/api-keys", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_list_api_keys():
    if not api_key_mgr:
        return err("API key manager mevcut değil", 503)
    return ok(keys=api_key_mgr.list_keys())

@app.route("/api/api-keys", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_create_api_key():
    if not api_key_mgr:
        return err("API key manager mevcut değil", 503)
    d = request.get_json() or {}
    name        = d.get("name", "key").strip()
    permissions = d.get("permissions", [])
    expires     = d.get("expires_days")
    username    = get_jwt_identity()
    result = api_key_mgr.create_key(username, name, permissions=permissions,
                                    expires_days=int(expires) if expires else None)
    if not result:
        return err("API key oluşturulamadı", 500)
    ev.info(f"API key oluşturuldu: {name}", category="auth")
    return ok(**result)

@app.route("/api/api-keys/<key_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_revoke_api_key(key_id):
    if not api_key_mgr:
        return err("API key manager mevcut değil", 503)
    ok_flag = api_key_mgr.revoke_key(key_id)
    return ok(revoked=ok_flag) if ok_flag else err("Key bulunamadı", 404)


# ── Hosting modül indirme ──────────────────────────────────────────────────────
@app.route("/api/hosting/download/<module_name>")
@require_auth
@require_role("admin", "administrator")
def api_hosting_download(module_name):
    import pathlib
    base = pathlib.Path(__file__).parent.parent.parent / "modules"
    paths = {
        "whmcs":  base / "whmcs" / "servers" / "oxware" / "oxware.php",
        "wisecp": base / "wisecp" / "oxware" / "oxware.php",
    }
    path = paths.get(module_name)
    if not path or not path.exists():
        return err("Modül bulunamadı veya henüz hazır değil", 404)
    from flask import send_file
    return send_file(str(path), as_attachment=True,
                     download_name=f"oxware_{module_name}.php",
                     mimetype="text/plain")



# ── Provisioning API (WiseCP / WHMCS / Billing entegrasyonu) ─────────────────
# API key auth: X-API-Key header, oxw_xxx prefix, permissions=["provisioning"]

def _require_provision_key():
    """X-API-Key header ile provisioning yetkisi doğrula. Hata varsa Response döner, None döner ise OK."""
    raw = request.headers.get("X-API-Key", "")
    info = api_key_mgr.validate_key(raw) if api_key_mgr else None
    if not info:
        return jsonify({"status": "error", "error": "Geçersiz API anahtarı"}), 401
    perms = info.get("permissions", [])
    if perms and "provisioning" not in perms and "all" not in perms:
        return jsonify({"status": "error", "error": "Bu anahtar provisioning yetkisine sahip değil"}), 403
    return None


@app.route("/api/provision/ping", methods=["GET"])
def api_provision_ping():
    """Billing panel baglantisini dogrula ve event log'a kaydet."""
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    client_ip  = request.headers.get("X-Forwarded-For", request.remote_addr or "?")
    user_agent = request.headers.get("User-Agent", "")
    ua_lower   = user_agent.lower()
    if "whmcs" in ua_lower:
        panel = "WHMCS"
    elif "wisecp" in ua_lower:
        panel = "WiseCP"
    elif "hostbill" in ua_lower:
        panel = "HostBill"
    elif "blesta" in ua_lower:
        panel = "Blesta"
    else:
        panel = "Billing Panel"
    ev.info(f"Provisioning: {panel} baglantisi dogrulandi — IP: {client_ip}", category="provision")
    return ok(status="ok", panel=panel, version="2.8.1", connected=True)


@app.route("/api/provision/create", methods=["POST"])
def api_provision_create():
    auth_err = _require_provision_key()
    if auth_err: return auth_err

    d = request.get_json() or {}
    name        = d.get("name", "").strip()
    # vcpus/cpu ve memory_mb/ram_mb her ikisini de kabul et
    cpu         = int(d.get("vcpus") or d.get("cpu") or 2)
    ram_mb      = int(d.get("memory_mb") or d.get("ram_mb") or 2048)
    disk_gb     = int(d.get("disk_gb", 50))
    os_template = d.get("os_template", "ubuntu-22.04").strip()
    network     = d.get("network", "default").strip()
    auto_start  = bool(d.get("auto_start", True))
    # cloud-init kimlik bilgileri (billing panel tarafından aktarılabilir)
    ci_username = d.get("username", "").strip()
    ci_password = d.get("password", "")
    ci_ssh_key  = d.get("ssh_key", "")
    # IP havuzu — oluşturma sonrası otomatik IP ata
    ip_pool_req = d.get("ip_pool", "").strip()

    if not name:
        return err("name zorunludur")
    if cpu < 1 or cpu > 256:
        return err("vcpus 1-256 arasında olmalı")
    if ram_mb < 512 or ram_mb > 1048576:
        return err("memory_mb 512-1048576 arasında olmalı")
    if disk_gb < 5 or disk_gb > 65536:
        return err("disk_gb 5-65536 arasında olmalı")

    # Template → ISO/cloud-init eşleşmesi
    template_map = getattr(config, "PROVISION_TEMPLATES", {})
    tpl = template_map.get(os_template, {})
    iso_path   = tpl.get("iso_path")
    os_variant = tpl.get("os_variant", "generic")
    cloud_init = dict(tpl.get("cloud_init") or {})

    # Billing panel'den gelen kimlik bilgilerini cloud-init'e ekle
    if ci_username:
        cloud_init["user"] = ci_username
    if ci_password:
        cloud_init["password"] = ci_password
    if ci_ssh_key:
        cloud_init.setdefault("ssh_keys", [])
        cloud_init["ssh_keys"].append(ci_ssh_key)
    if not cloud_init:
        cloud_init = None

    try:
        vm = vm_manager.create_vm(
            name=name,
            memory_mb=ram_mb,
            vcpus=cpu,
            disk_gb=disk_gb,
            iso_path=iso_path,
            network=network,
            os_variant=os_variant,
            cloud_init=cloud_init,
        )
    except Exception as e:
        log.error("provision/create hatası: %s", e)
        return err(str(e), 500)

    vm_id = vm["id"]

    if auto_start:
        try:
            vm_manager.start_vm(vm_id)
        except Exception:
            pass

    # Vault'a kimlik bilgilerini kaydet
    if vault_mgr and (ci_username or ci_password):
        try:
            vault_mgr.store_credential(vm_id, "ssh",
                                       ci_username or "root",
                                       ci_password, "cloud-init")
        except Exception:
            pass

    # Otomatik IP atama
    assigned_ip = vm.get("ip", "")
    if ip_pool_req:
        try:
            mac = (vm.get("networks") or [{}])[0].get("mac", "") if vm.get("networks") else ""
            alloc = ip_pool_mgr.allocate_ip(ip_pool_req, vm_id, name, mac)
            assigned_ip = alloc.get("ip", assigned_ip)
            vm["ip"] = assigned_ip
        except Exception as _ipe:
            log.warning("provision/create IP havuzu atama hatası: %s", _ipe)

    ev.info(f"Provisioning: VM oluşturuldu name={name}", category="provision")
    return ok(vm=vm)


@app.route("/api/provision/<vm_id>", methods=["DELETE"])
def api_provision_terminate(vm_id):
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    try:
        vm_manager.stop_vm(vm_id, force=True)
    except Exception:
        pass
    try:
        result = vm_manager.delete_vm(vm_id, delete_disk=True)
        ev.info(f"Provisioning: VM silindi id={vm_id}", category="provision")
        return ok(deleted=True)
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/provision/<vm_id>/suspend", methods=["POST"])
def api_provision_suspend(vm_id):
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    try:
        vm_manager.stop_vm(vm_id, force=False)
        ev.info(f"Provisioning: VM askıya alındı id={vm_id}", category="provision")
        return ok(suspended=True)
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/provision/<vm_id>/unsuspend", methods=["POST"])
def api_provision_unsuspend(vm_id):
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    try:
        vm_manager.start_vm(vm_id)
        ev.info(f"Provisioning: VM yeniden başlatıldı id={vm_id}", category="provision")
        return ok(unsuspended=True)
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/provision/<vm_id>/status", methods=["GET"])
def api_provision_status(vm_id):
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    try:
        vm = vm_manager.get_vm(vm_id)
        if not vm:
            return err("VM bulunamadı", 404)
        stats = vm_manager.get_vm_stats(vm_id) or {}
        # İç DHCP IP'si
        internal_ip = (vm.get("networks") or [{}])[0].get("ip", "") if vm.get("networks") else ""
        # IP havuzundan atanmış public IP (varsa tercih et)
        public_ip = ""
        try:
            _assignment = ip_pool_mgr.get_vm_assignment(vm_id)
            if _assignment and _assignment.get("pool") not in ("__internal__", "", None):
                public_ip = _assignment.get("ip", "")
        except Exception:
            pass
        ip = public_ip or internal_ip
        return ok(
            vm_id=vm_id,
            name=vm.get("name", ""),
            status=vm.get("status", "unknown"),
            ip=ip,
            public_ip=public_ip,
            internal_ip=internal_ip,
            cpu_percent=stats.get("cpu_percent", 0),
            mem_percent=stats.get("mem_percent", 0),
            mem_used_mb=stats.get("memory_used_mb", 0),
            mem_total_mb=vm.get("memory_mb", 0),
            disk_used_gb=stats.get("disk_used_gb", 0),
        )
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/provision/<vm_id>/resize", methods=["PUT"])
def api_provision_resize(vm_id):
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    d = request.get_json() or {}
    try:
        vm = vm_manager.get_vm(vm_id)
        if not vm:
            return err("VM bulunamadı", 404)

        notes = []

        # vCPU — DiyoCP modülü "vcpus" gönderir, eski uyumluluk için "cpu" da kabul et
        vcpu_val = d.get("vcpus") or d.get("cpu")
        if vcpu_val is not None:
            res = vm_manager.hot_set_vcpus(vm_id, int(vcpu_val))
            if not res.get("ok"):
                return err(res.get("message", "vCPU değiştirilemedi"), 500)
            notes.append(res.get("message", f"vCPU → {vcpu_val}"))

        # RAM — DiyoCP modülü "memory_mb" gönderir, eski uyumluluk için "ram_mb" da kabul et
        mem_val = d.get("memory_mb") or d.get("ram_mb")
        if mem_val is not None:
            res = vm_manager.hot_set_memory(vm_id, int(mem_val))
            if not res.get("ok"):
                return err(res.get("message", "RAM değiştirilemedi"), 500)
            notes.append(res.get("message", f"RAM → {mem_val} MB"))

        ev.info(f"Provisioning: VM yeniden boyutlandırıldı id={vm_id}", category="provision")
        return ok(resized=True, note="; ".join(notes) if notes else "Değişiklik yok")
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/provision/templates", methods=["GET"])
def api_provision_templates():
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    tpls = getattr(config, "PROVISION_TEMPLATES", {})
    return ok(templates=[
        {"id": k, "name": v.get("name", k), "os_variant": v.get("os_variant", "generic")}
        for k, v in tpls.items()
    ])


# ── Provision: OS Yeniden Kurulum (Reinstall) ─────────────────────────────────

@app.route("/api/provision/<vm_id>/reinstall", methods=["POST"])
def api_provision_reinstall(vm_id):
    """VM diski sıfırla ve yeni OS şablonuyla yeniden kur."""
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    d = request.get_json() or {}
    os_template = d.get("os_template", "").strip()
    if not os_template:
        return err("os_template zorunludur")

    template_map = getattr(config, "PROVISION_TEMPLATES", {})
    tpl = template_map.get(os_template)
    if tpl is None:
        return err(f"Bilinmeyen template: {os_template}", 404)

    iso_path = tpl.get("iso_path")

    try:
        import libvirt as _lv_r
        import xml.etree.ElementTree as _ET_r

        # 1. VM durdur
        try:
            vm_manager.stop_vm(vm_id, force=True)
            time.sleep(2)
        except Exception:
            pass

        conn = _lv_r.open(config.LIBVIRT_URI)
        dom  = conn.lookupByUUIDString(vm_id)
        xml_str = dom.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
        root = _ET_r.fromstring(xml_str)

        # 2. Birincil disk yolu bul ve sıfırla
        for disk_el in root.findall(".//disk[@device='disk']"):
            src = disk_el.find("source")
            if src is not None:
                disk_path = src.get("file", "")
                if disk_path and os.path.exists(disk_path):
                    try:
                        import json as _json_r
                        _sz_out = subprocess.run(
                            ["qemu-img", "info", "--output=json", disk_path],
                            capture_output=True, text=True
                        )
                        _sz = _json_r.loads(_sz_out.stdout).get("virtual-size", 50 * 1024 ** 3)
                        disk_gb_r = max(5, int(_sz / 1024 ** 3))
                    except Exception:
                        disk_gb_r = 50
                    os.remove(disk_path)
                    subprocess.run(
                        ["qemu-img", "create", "-f", "qcow2", disk_path, f"{disk_gb_r}G"],
                        check=True, capture_output=True
                    )
            break

        # 3. Mevcut CDROM'ları kaldır
        devices_el = root.find("devices")
        if devices_el is not None:
            for cdrom_el in list(devices_el.findall("disk[@device='cdrom']")):
                devices_el.remove(cdrom_el)

        # 4. Yeni ISO ekle
        if iso_path and os.path.exists(iso_path) and devices_el is not None:
            import html as _html_r
            _cdrom = _ET_r.fromstring(
                f"<disk type='file' device='cdrom'>"
                f"<driver name='qemu' type='raw'/>"
                f"<source file='{_html_r.escape(iso_path, quote=True)}'/>"
                f"<target dev='sdb' bus='sata'/>"
                f"<readonly/>"
                f"</disk>"
            )
            devices_el.append(_cdrom)

        # 5. Boot sırasını güncelle: cdrom önce
        os_el = root.find("os")
        if os_el is not None:
            for b in list(os_el.findall("boot")):
                os_el.remove(b)
            b1 = _ET_r.SubElement(os_el, "boot"); b1.set("dev", "cdrom")
            b2 = _ET_r.SubElement(os_el, "boot"); b2.set("dev", "hd")

        conn.defineXML(_ET_r.tostring(root, encoding="unicode"))
        conn.close()

        # 6. VM'i başlat
        try:
            vm_manager.start_vm(vm_id)
        except Exception as _se:
            log.warning("reinstall: VM başlatma hatası vm=%s: %s", vm_id, _se)

        ev.info(f"Provisioning: VM yeniden kuruldu id={vm_id} template={os_template}", category="provision")
        return ok(reinstalled=True, os_template=os_template)
    except Exception as e:
        log.error("provision/reinstall hatası vm=%s: %s", vm_id, e)
        return err(str(e), 500)


# ── Provision: Otomatik IP Atama ─────────────────────────────────────────────

@app.route("/api/provision/<vm_id>/assign-ip", methods=["POST"])
def api_provision_assign_ip(vm_id):
    """IP havuzundan VM'e otomatik IP ata."""
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    d = request.get_json() or {}
    pool_name = d.get("pool", "").strip()
    manual_ip = d.get("ip", "").strip()

    try:
        vm = vm_manager.get_vm(vm_id)
        if not vm:
            return err("VM bulunamadı", 404)
        mac = (vm.get("networks") or [{}])[0].get("mac", "") if vm.get("networks") else ""

        # Havuz belirtilmemişse ilk mevcut havuzu kullan
        if not pool_name:
            _pools = ip_pool_mgr.list_pools()
            _pools = [p for p in _pools if p.get("name") not in ("__internal__", "", None)]
            if not _pools:
                return err("Kullanılabilir IP havuzu bulunamadı")
            pool_name = _pools[0]["name"]

        if manual_ip:
            alloc = ip_pool_mgr.manual_assign(
                ip=manual_ip, mac=mac, vm_name=vm.get("name", ""),
                pool_name=pool_name, vm_id=vm_id
            )
        else:
            alloc = ip_pool_mgr.allocate_ip(pool_name, vm_id, vm.get("name", ""), mac)

        assigned_ip = alloc.get("ip", "")
        ev.info(f"Provisioning: IP atandı id={vm_id} ip={assigned_ip} pool={pool_name}", category="provision")
        return ok(ip=assigned_ip, pool=pool_name, mac=mac)
    except Exception as e:
        return err(str(e), 500)


# ── Provision: VM Kimlik Bilgileri (Vault) ────────────────────────────────────

@app.route("/api/provision/<vm_id>/credentials", methods=["GET"])
def api_provision_credentials_get(vm_id):
    """VM kimlik bilgilerini getir (provision key ile erişilebilir)."""
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    if not vault_mgr:
        return ok(credentials=[])
    return ok(credentials=vault_mgr.list_credentials(vm_id))


@app.route("/api/provision/<vm_id>/credentials", methods=["POST"])
def api_provision_credentials_set(vm_id):
    """VM kimlik bilgilerini kaydet (provision key ile erişilebilir)."""
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    d = request.get_json() or {}
    if not vault_mgr:
        return err("Vault kullanılamıyor")
    username  = d.get("username", "root")
    password  = d.get("password", "")
    cred_type = d.get("cred_type", "ssh")
    notes     = d.get("notes", "")
    try:
        vault_mgr.store_credential(vm_id, cred_type, username, password, notes)
        ev.info(f"Provisioning: Kimlik bilgisi kaydedildi id={vm_id} type={cred_type}", category="provision")
        return ok(stored=True, cred_type=cred_type, username=username)
    except Exception as e:
        return err(str(e), 500)


# ── Provision: Console Token (noVNC) ─────────────────────────────────────────

@app.route("/api/provision/<vm_id>/console-token", methods=["POST"])
def api_provision_console_token(vm_id):
    """Billing panel için kısa ömürlü noVNC console token üret."""
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    try:
        vm = vm_manager.get_vm(vm_id)
        if not vm:
            return err("VM bulunamadı", 404)

        import secrets as _sec_p
        token = _sec_p.token_urlsafe(32)
        with _vnc_token_lock:
            _vnc_one_time_tokens[token] = {
                "vm_id":    vm_id,
                "username": "provision-api",
                "role":     "operator",
                "expires":  _time_mod.time() + 300,  # 5 dakika
                "used":     False,
            }

        # Tam console URL — billing panel bu URL'yi müşteriye verebilir
        _scheme = "https" if request.is_secure else "http"
        _host   = request.host
        console_url = f"{_scheme}://{_host}/console/{vm_id}?vnc_token={token}"
        return ok(token=token, console_url=console_url, expires_in=300)
    except Exception as e:
        return err(str(e), 500)


# ── Provision: VM Güç Kontrolü (Start / Stop / Reboot) ───────────────────────

@app.route("/api/provision/<vm_id>/start", methods=["POST"])
def api_provision_start(vm_id):
    """Provision key ile VM başlat (WHMCS/WiseCP start butonu)."""
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    try:
        r = vm_manager.start_vm(vm_id)
        ev.info(f"Provisioning: VM başlatıldı id={vm_id}", category="provision")
        _extra = r if isinstance(r, dict) else {}
        return ok(status="started", **_extra)
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/provision/<vm_id>/stop", methods=["POST"])
def api_provision_stop(vm_id):
    """Provision key ile VM durdur (WHMCS/WiseCP stop butonu)."""
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    d = request.get_json() or {}
    force = bool(d.get("force", False))
    try:
        r = vm_manager.stop_vm(vm_id, force=force)
        ev.info(f"Provisioning: VM durduruldu id={vm_id} force={force}", category="provision")
        _extra = r if isinstance(r, dict) else {}
        return ok(status="stopped", **_extra)
    except Exception as e:
        return err(str(e), 500)


@app.route("/api/provision/<vm_id>/reboot", methods=["POST"])
def api_provision_reboot(vm_id):
    """Provision key ile VM yeniden başlat (WHMCS/WiseCP reboot butonu)."""
    auth_err = _require_provision_key()
    if auth_err: return auth_err
    try:
        r = vm_manager.reboot_vm(vm_id)
        ev.info(f"Provisioning: VM yeniden başlatıldı id={vm_id}", category="provision")
        _extra = r if isinstance(r, dict) else {}
        return ok(status="rebooted", **_extra)
    except Exception as e:
        return err(str(e), 500)


# ── Provision: Console Bilgisi (vnc_token ile, JWT gerekmez) ─────────────────

@app.route("/api/provision/<vm_id>/console-info", methods=["GET"])
def api_provision_console_info(vm_id):
    """
    console.html tarafından vnc_token ile çağrılır — JWT gerekmez.
    Token tüketilmez (WebSocket bağlantısında tüketilir).
    VM adı ve durumunu döner.
    """
    token = request.args.get("vnc_token", "")
    if not token:
        return err("vnc_token gerekli", 401)
    with _vnc_token_lock:
        ott = _vnc_one_time_tokens.get(token)
    if not ott or ott.get("used") or _time_mod.time() > ott.get("expires", 0):
        return err("Geçersiz veya süresi dolmuş token", 401)
    if ott["vm_id"] != vm_id:
        return err("Token bu VM için geçerli değil", 403)
    try:
        vm = vm_manager.get_vm(vm_id)
        if not vm:
            return err("VM bulunamadı", 404)
        return ok(
            name=vm.get("name", vm_id),
            state=vm.get("state", "unknown"),
        )
    except Exception as e:
        return err(str(e), 500)


# ── Main ──────────────────────────────────────────────────────────────────────
def _ensure_ssl_cert(cert_path: str, key_path: str) -> bool:
    """
    Auto-generate a self-signed TLS certificate if cert/key don't exist.
    Uses OpenSSL via subprocess. Returns True if cert is ready (existing or newly generated).
    """
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return True
    try:
        os.makedirs(os.path.dirname(cert_path), exist_ok=True)
        import socket as _sock_mod
        hostname = _sock_mod.gethostname() or "oxware-hypervisor"
        subj = (
            f"/C=TR/ST=OXware/L=OXware/O=OXware Hypervisor"
            f"/CN={hostname}"
        )
        result = subprocess.run(
            [
                "openssl", "req", "-x509",
                "-newkey", "rsa:4096",
                "-keyout", key_path,
                "-out",    cert_path,
                "-days",   "3650",
                "-nodes",
                "-subj",   subj,
            ],
            capture_output=True,
            timeout=60,
        )
        if result.returncode == 0:
            os.chmod(key_path,  0o600)
            os.chmod(cert_path, 0o644)
            log.info("SSL sertifikası otomatik oluşturuldu: %s", cert_path)
            return True
        else:
            log.error("SSL sertifikası oluşturulamadı: %s", result.stderr.decode())
            return False
    except FileNotFoundError:
        log.error("openssl bulunamadı — SSL devre dışı kalacak")
        return False
    except Exception as _ssl_e:
        log.error("SSL sertifikası oluşturma hatası: %s", _ssl_e)
        return False



# ═══════════════════════════════════════════════════════════════════════════════
# vTPM (Virtual Trusted Platform Module)
# ═══════════════════════════════════════════════════════════════════════════════
vtpm_mgr = _safe_import("vtpm_manager")

@app.route("/api/vms/<vm_id>/vtpm", methods=["GET"])
@require_auth
def api_get_vtpm(vm_id):
    if not vtpm_mgr: return err("vtpm_manager modülü yüklenemedi")
    return ok(**vtpm_mgr.list_vm_tpm(vm_id))

@app.route("/api/vms/<vm_id>/vtpm", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_add_vtpm(vm_id):
    if not vtpm_mgr: return err("vtpm_manager modülü yüklenemedi")
    d = request.get_json() or {}
    result = vtpm_mgr.add_vtpm(vm_id, model=d.get("model", "tpm-tis"), version=d.get("version", "2.0"))
    ev.info(f"vTPM eklendi: {vm_id}", category="vm")
    return ok(**result)

@app.route("/api/vms/<vm_id>/vtpm", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_remove_vtpm(vm_id):
    if not vtpm_mgr: return err("vtpm_manager modülü yüklenemedi")
    result = vtpm_mgr.remove_vtpm(vm_id)
    ev.info(f"vTPM kaldırıldı: {vm_id}", category="vm")
    return ok(**result)

@app.route("/api/system/swtpm-check")
@require_auth
def api_swtpm_check():
    if not vtpm_mgr: return err("vtpm_manager modülü yüklenemedi")
    return ok(**vtpm_mgr.check_swtpm())


# ═══════════════════════════════════════════════════════════════════════════════
# PCI Passthrough UI (tüm PCI cihazlar, sadece GPU değil)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/system/pci-devices")
@require_auth
@require_role("admin", "administrator")
def api_list_pci_devices():
    """Tüm PCI cihazları listele (IOMMU gruplarıyla birlikte)."""
    try:
        r = subprocess.run(["lspci", "-Dmmnn"], capture_output=True, text=True, timeout=10)
        devices = []
        for line in r.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) >= 3:
                pci_addr = parts[0].strip()
                class_name = parts[1].strip()
                vendor_device = parts[2].strip()
                # Get IOMMU group
                iommu_path = f"/sys/bus/pci/devices/{pci_addr}/iommu_group"
                iommu_group = ""
                if os.path.exists(iommu_path):
                    try:
                        iommu_group = os.path.basename(os.readlink(iommu_path))
                    except Exception:
                        pass
                # Check if bound to vfio-pci
                driver_path = f"/sys/bus/pci/devices/{pci_addr}/driver"
                driver = ""
                if os.path.exists(driver_path):
                    try:
                        driver = os.path.basename(os.readlink(driver_path))
                    except Exception:
                        pass
                devices.append({
                    "pci": pci_addr,
                    "class": class_name,
                    "name": vendor_device,
                    "iommu_group": iommu_group,
                    "driver": driver,
                    "vfio_ready": driver == "vfio-pci",
                })
        return ok(devices=devices)
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/vms/<vm_id>/hardware/pci-passthrough", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_vm_pci_passthrough(vm_id):
    """Generic PCI passthrough (any device, not just GPU)."""
    data = request.get_json() or {}
    pci = data.get("pci_address", "").strip()
    if not pci:
        return err("pci_address gerekli", 400)
    import re as _re_pci
    if not _re_pci.match(r'^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]$', pci):
        return err("Geçersiz PCI adresi (beklenen: DDDD:BB:DD.F)", 400)
    try:
        domain_part, bus, slot_fn = pci.split(":")
        slot, fn = slot_fn.split(".")
        conn = vm_manager._libvirt_conn()
        dom = conn.lookupByName(vm_id)
        root = ET.fromstring(dom.XMLDesc())
        devices = root.find("devices")
        # Check not already added
        for h in devices.findall("hostdev"):
            src = h.find("source/address")
            if src is not None:
                existing = f"{src.get('domain','')[2:]}:{src.get('bus','')[2:]}:{src.get('slot','')[2:]}.{src.get('function','')[2:]}"
                if existing.upper() == pci.upper():
                    return err("Bu PCI cihaz zaten eklenmiş", 409)
        h_el = ET.SubElement(devices, "hostdev")
        h_el.set("mode", "subsystem"); h_el.set("type", "pci"); h_el.set("managed", "yes")
        src = ET.SubElement(h_el, "source")
        addr = ET.SubElement(src, "address")
        addr.set("type", "pci")
        addr.set("domain", f"0x{domain_part}")
        addr.set("bus", f"0x{bus}")
        addr.set("slot", f"0x{slot}")
        addr.set("function", f"0x{fn}")
        conn.defineXML(ET.tostring(root, encoding="unicode"))
        conn.close()
        ev.info(f"PCI passthrough eklendi: {vm_id} pci={pci}", category="vm")
        return ok(pci=pci, message="PCI cihaz eklendi. IOMMU ve VFIO aktif olmalı.")
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/vms/<vm_id>/hardware/pci-passthrough/<path:pci>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_vm_pci_remove(vm_id, pci):
    """Remove PCI passthrough device from VM."""
    try:
        pci = pci.replace("_", ":")
        conn = vm_manager._libvirt_conn()
        dom = conn.lookupByName(vm_id)
        root = ET.fromstring(dom.XMLDesc())
        devices = root.find("devices")
        removed = 0
        for h in list(devices.findall("hostdev")):
            if h.get("type") == "pci":
                src = h.find("source/address")
                if src is not None:
                    d = src.get("domain","0x0000")[2:]
                    b = src.get("bus","0x00")[2:]
                    s = src.get("slot","0x00")[2:]
                    f = src.get("function","0x0")[2:]
                    addr_str = f"{d}:{b}:{s}.{f}"
                    if addr_str.lower() == pci.lower() or pci.lower() in addr_str.lower():
                        devices.remove(h)
                        removed += 1
        conn.defineXML(ET.tostring(root, encoding="unicode"))
        conn.close()
        return ok(removed=removed)
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/vms/<vm_id>/hardware/pci-devices", methods=["GET"])
@require_auth
def api_vm_pci_list(vm_id):
    """List PCI passthrough devices on a VM."""
    try:
        conn = vm_manager._libvirt_conn()
        dom = conn.lookupByName(vm_id)
        root = ET.fromstring(dom.XMLDesc())
        devices = []
        for h in root.findall(".//hostdev[@type='pci']"):
            src = h.find("source/address")
            if src is not None:
                d = src.get("domain","0x0000")[2:]
                b = src.get("bus","0x00")[2:]
                s = src.get("slot","0x00")[2:]
                f = src.get("function","0x0")[2:]
                devices.append({"pci": f"{d}:{b}:{s}.{f}", "managed": h.get("managed","yes")})
        conn.close()
        return ok(devices=devices)
    except Exception as e:
        return err(str(e), 500)


# ═══════════════════════════════════════════════════════════════════════════════
# USB Passthrough UI
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/system/usb-devices")
@require_auth
@require_role("admin", "administrator")
def api_list_usb_devices():
    """Tüm USB cihazları listele."""
    try:
        r = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=10)
        devices = []
        for line in r.stdout.splitlines():
            # Bus 001 Device 002: ID 8087:0024 Intel Corp. Integrated Rate Matching Hub
            parts = line.split()
            if len(parts) >= 6:
                bus = parts[1]
                dev = parts[3].rstrip(":")
                vid_pid = parts[5]
                name = " ".join(parts[6:])
                vid, pid = vid_pid.split(":") if ":" in vid_pid else (vid_pid, "0000")
                devices.append({
                    "bus": bus, "device": dev,
                    "vendor_id": vid, "product_id": pid,
                    "name": name,
                    "id": f"{bus}:{dev}",
                })
        return ok(devices=devices)
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/vms/<vm_id>/hardware/usb-passthrough", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_vm_usb_passthrough(vm_id):
    """Attach USB device to VM by vendor_id:product_id."""
    data = request.get_json() or {}
    vendor_id = data.get("vendor_id", "").strip().lower()
    product_id = data.get("product_id", "").strip().lower()
    if not vendor_id or not product_id:
        return err("vendor_id ve product_id gerekli", 400)
    try:
        conn = vm_manager._libvirt_conn()
        dom = conn.lookupByName(vm_id)
        root = ET.fromstring(dom.XMLDesc())
        devices = root.find("devices")
        h_el = ET.SubElement(devices, "hostdev")
        h_el.set("mode", "subsystem"); h_el.set("type", "usb"); h_el.set("managed", "yes")
        src = ET.SubElement(h_el, "source")
        v_el = ET.SubElement(src, "vendor"); v_el.set("id", f"0x{vendor_id}")
        p_el = ET.SubElement(src, "product"); p_el.set("id", f"0x{product_id}")
        conn.defineXML(ET.tostring(root, encoding="unicode"))
        conn.close()
        ev.info(f"USB passthrough eklendi: {vm_id} usb={vendor_id}:{product_id}", category="vm")
        return ok(vendor_id=vendor_id, product_id=product_id, message="USB cihaz eklendi.")
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/vms/<vm_id>/hardware/usb-devices", methods=["GET"])
@require_auth
def api_vm_usb_list(vm_id):
    """List USB passthrough devices on a VM."""
    try:
        conn = vm_manager._libvirt_conn()
        dom = conn.lookupByName(vm_id)
        root = ET.fromstring(dom.XMLDesc())
        devices = []
        for h in root.findall(".//hostdev[@type='usb']"):
            src = h.find("source")
            vendor = src.find("vendor").get("id","") if src is not None and src.find("vendor") is not None else ""
            product = src.find("product").get("id","") if src is not None and src.find("product") is not None else ""
            devices.append({"vendor_id": vendor, "product_id": product})
        conn.close()
        return ok(devices=devices)
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/vms/<vm_id>/hardware/usb-passthrough/<vendor_id>/<product_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_vm_usb_remove(vm_id, vendor_id, product_id):
    """Remove USB passthrough device."""
    try:
        conn = vm_manager._libvirt_conn()
        dom = conn.lookupByName(vm_id)
        root = ET.fromstring(dom.XMLDesc())
        devices = root.find("devices")
        removed = 0
        for h in list(devices.findall("hostdev")):
            if h.get("type") == "usb":
                src = h.find("source")
                if src is not None:
                    v = src.find("vendor")
                    p = src.find("product")
                    if v is not None and p is not None:
                        if vendor_id.lower() in v.get("id","").lower() and product_id.lower() in p.get("id","").lower():
                            devices.remove(h); removed += 1
        conn.defineXML(ET.tostring(root, encoding="unicode"))
        conn.close()
        return ok(removed=removed)
    except Exception as e:
        return err(str(e), 500)


# ═══════════════════════════════════════════════════════════════════════════════
# IPv6 Network Support
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/networks/<net_uuid>/ipv6", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_network_add_ipv6(net_uuid):
    """Add IPv6 address to existing libvirt network."""
    d = request.get_json() or {}
    ip6_addr = d.get("address", "fd00::1")
    prefix = int(d.get("prefix", 64))
    dhcp6_start = d.get("dhcp_start", "")
    dhcp6_end = d.get("dhcp_end", "")
    try:
        import libvirt as _lv
        conn = network_manager._connect()
        try:
            net = conn.networkLookupByUUIDString(net_uuid)
            was_active = bool(net.isActive())
            was_autostart = bool(net.autostart())
            root = ET.fromstring(net.XMLDesc(0))
            # Remove existing ipv6
            for ip in root.findall("ip"):
                if ip.get("family") == "ipv6":
                    root.remove(ip)
            # Add new ipv6
            ip6_el = ET.SubElement(root, "ip")
            ip6_el.set("family", "ipv6")
            ip6_el.set("address", ip6_addr)
            ip6_el.set("prefix", str(prefix))
            if dhcp6_start and dhcp6_end:
                dhcp_el = ET.SubElement(ip6_el, "dhcp")
                range_el = ET.SubElement(dhcp_el, "range")
                range_el.set("start", dhcp6_start)
                range_el.set("end", dhcp6_end)
            new_xml = ET.tostring(root, encoding="unicode")
            if was_active:
                net.destroy()
            net.undefine()
            new_net = conn.networkDefineXML(new_xml)
            new_net.setAutostart(1 if was_autostart else 0)
            if was_active:
                new_net.create()
            # Enable IPv6 forwarding on host
            subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], capture_output=True)
            subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.accept_ra=2"], capture_output=True)
            # Persist
            sysctl_line = "net.ipv6.conf.all.forwarding=1\n"
            sysctl_path = "/etc/sysctl.d/99-oxware-ipv6.conf"
            if not os.path.exists(sysctl_path) or sysctl_line not in open(sysctl_path).read():
                with open(sysctl_path, "a") as f:
                    f.write(sysctl_line)
                    f.write("net.ipv6.conf.all.accept_ra=2\n")
            ev.info(f"IPv6 eklendi: network={net_uuid} addr={ip6_addr}/{prefix}", category="network")
            return ok(ok=True, address=ip6_addr, prefix=prefix)
        finally:
            conn.close()
    except Exception as e:
        return err(str(e), 500)

# NOTE: POST /api/networks is handled by api_create_network() above (line ~2177).
# Duplicate stub removed.


# ═══════════════════════════════════════════════════════════════════════════════
# Memory Hot-Unplug
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/vms/<vm_id>/hardware/memory/hotunplug", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_memory_hotunplug(vm_id):
    """
    Hot-unplug memory from running VM via balloon device.
    Balloon driver must be installed in guest.
    """
    data = request.get_json() or {}
    target_mb = int(data.get("target_mb", 0))
    if target_mb <= 0:
        return err("target_mb gerekli (hedef RAM MB)", 400)
    try:
        conn = vm_manager._libvirt_conn()
        dom = conn.lookupByName(vm_id)
        if not dom.isActive():
            return err("VM çalışmıyor. Balloon hot-unplug için VM aktif olmalı.", 400)
        target_kib = target_mb * 1024
        dom.setMemory(target_kib)
        ev.info(f"Memory hot-unplug: {vm_id} → {target_mb}MB", category="vm")
        conn.close()
        return ok(target_mb=target_mb, message="Balloon bellek azaltıldı. Guest balloon driver gerekli.")
    except Exception as e:
        return err(str(e), 500)


# ═══════════════════════════════════════════════════════════════════════════════
# Bulk Snapshot
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/vms/snapshots/bulk", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_bulk_snapshot():
    """Create snapshot for multiple VMs at once."""
    data = request.get_json() or {}
    vm_ids = data.get("vm_ids", [])
    snap_name = data.get("name", "")
    description = data.get("description", "Bulk snapshot")
    if not vm_ids:
        return err("vm_ids listesi gerekli", 400)
    import re as _re_snap
    if snap_name and not _re_snap.match(r'^[a-zA-Z0-9_\-\.]+$', snap_name):
        return err("snap_name sadece harf/rakam/tire/nokta içerebilir", 400)
    results = {}
    for vm_id in vm_ids[:50]:  # max 50
        try:
            name = snap_name or f"bulk-{__import__('datetime').datetime.now().strftime('%Y%m%d-%H%M%S')}"
            snap = vm_manager.take_snapshot(vm_id, name, description)
            results[vm_id] = {"ok": True, "snap": snap}
            ev.info(f"Bulk snapshot: {vm_id} → {name}", category="vm")
        except Exception as e:
            results[vm_id] = {"ok": False, "error": str(e)}
    success = sum(1 for r in results.values() if r.get("ok"))
    return ok(results=results, total=len(vm_ids), success=success, failed=len(vm_ids)-success)


# ═══════════════════════════════════════════════════════════════════════════════
# ARM / RISC-V VM Architecture Support
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/system/architectures")
@require_auth
def api_list_architectures():
    """List QEMU-supported architectures on this host."""
    try:
        archs = []
        qemu_bins = [
            ("x86_64", "/usr/bin/qemu-system-x86_64"),
            ("aarch64", "/usr/bin/qemu-system-aarch64"),
            ("arm", "/usr/bin/qemu-system-arm"),
            ("riscv64", "/usr/bin/qemu-system-riscv64"),
            ("riscv32", "/usr/bin/qemu-system-riscv32"),
            ("ppc64", "/usr/bin/qemu-system-ppc64"),
            ("s390x", "/usr/bin/qemu-system-s390x"),
            ("mips64", "/usr/bin/qemu-system-mips64"),
        ]
        for arch, path in qemu_bins:
            if os.path.exists(path):
                archs.append({"arch": arch, "binary": path, "available": True})
        return ok(architectures=archs)
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/vms/<vm_id>/hardware/arch", methods=["GET"])
@require_auth
def api_vm_get_arch(vm_id):
    """Get VM architecture."""
    try:
        conn = vm_manager._libvirt_conn()
        dom = conn.lookupByName(vm_id)
        root = ET.fromstring(dom.XMLDesc(0))
        os_el = root.find("os")
        type_el = os_el.find("type") if os_el else None
        conn.close()
        return ok(
            arch=type_el.get("arch","x86_64") if type_el is not None else "x86_64",
            machine=type_el.get("machine","pc") if type_el is not None else "pc",
        )
    except Exception as e:
        return err(str(e), 500)


# ═══════════════════════════════════════════════════════════════════════════════
# SPICE + Audio Support
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/vms/<vm_id>/hardware/spice", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_enable_spice(vm_id):
    """Enable SPICE display with optional audio for a VM (must be stopped)."""
    data = request.get_json() or {}
    port = int(data.get("port", 5910))
    enable_audio = bool(data.get("audio", True))
    try:
        conn = vm_manager._libvirt_conn()
        dom = conn.lookupByName(vm_id)
        if dom.isActive():
            return err("VM çalışıyor. SPICE eklemek için VM'i durdurun.", 400)
        root = ET.fromstring(dom.XMLDesc(0))
        devices = root.find("devices")
        # Remove existing graphics
        for g in devices.findall("graphics"):
            devices.remove(g)
        # Add SPICE
        g_el = ET.SubElement(devices, "graphics")
        g_el.set("type", "spice")
        g_el.set("port", str(port))
        g_el.set("autoport", "yes")
        g_el.set("listen", "0.0.0.0")
        listen_el = ET.SubElement(g_el, "listen")
        listen_el.set("type", "address")
        listen_el.set("address", "0.0.0.0")
        # Add video QXL
        for v in devices.findall("video"):
            devices.remove(v)
        vid_el = ET.SubElement(devices, "video")
        model = ET.SubElement(vid_el, "model")
        model.set("type", "qxl")
        model.set("ram", "65536")
        model.set("vram", "65536")
        # Add audio if requested
        if enable_audio:
            for s in devices.findall("sound"):
                devices.remove(s)
            snd_el = ET.SubElement(devices, "sound")
            snd_el.set("model", "ich9")
            # Add audio backend
            for a in root.findall("devices/audio"):
                devices.remove(a)
            audio_el = ET.SubElement(devices, "audio")
            audio_el.set("id", "1")
            audio_el.set("type", "spice")
        conn.defineXML(ET.tostring(root, encoding="unicode"))
        conn.close()
        ev.info(f"SPICE+Audio etkinleştirildi: {vm_id} port={port}", category="vm")
        return ok(port=port, audio=enable_audio, message="SPICE etkinleştirildi. VM'i başlatın.")
    except Exception as e:
        return err(str(e), 500)


# ═══════════════════════════════════════════════════════════════════════════════
# iPXE / Network Boot Order
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/vms/<vm_id>/hardware/boot-order", methods=["GET"])
@require_auth
def api_vm_get_boot_order(vm_id):
    """Get current VM boot order."""
    try:
        conn = vm_manager._libvirt_conn()
        dom = conn.lookupByName(vm_id)
        root = ET.fromstring(dom.XMLDesc(0))
        os_el = root.find("os")
        boots = [b.get("dev") for b in os_el.findall("boot")] if os_el else []
        # Also check per-device boot order
        conn.close()
        return ok(boot_order=boots)
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/vms/<vm_id>/hardware/boot-order", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_set_boot_order(vm_id):
    """
    Set VM boot order. boot_order: list of 'hd', 'cdrom', 'network', 'fd'.
    network = PXE/iPXE boot.
    """
    data = request.get_json() or {}
    boot_order = data.get("boot_order", ["hd"])
    valid_devs = {"hd", "cdrom", "network", "fd"}
    for d in boot_order:
        if d not in valid_devs:
            return err(f"Geçersiz boot device: {d}. Geçerli: {valid_devs}", 400)
    try:
        conn = vm_manager._libvirt_conn()
        dom = conn.lookupByName(vm_id)
        root = ET.fromstring(dom.XMLDesc(0))
        os_el = root.find("os")
        if os_el is None:
            return err("OS elementi bulunamadı", 500)
        # Remove existing boot elements
        for b in os_el.findall("boot"):
            os_el.remove(b)
        # Add new boot order
        for dev in boot_order:
            b_el = ET.SubElement(os_el, "boot")
            b_el.set("dev", dev)
        # Enable network boot (iPXE) if requested
        if "network" in boot_order:
            # Add BIOS bootmenu
            bootmenu = os_el.find("bootmenu")
            if bootmenu is None:
                bootmenu = ET.SubElement(os_el, "bootmenu")
            bootmenu.set("enable", "yes")
            bootmenu.set("timeout", "3000")
        conn.defineXML(ET.tostring(root, encoding="unicode"))
        conn.close()
        ev.info(f"Boot order güncellendi: {vm_id} → {boot_order}", category="vm")
        return ok(boot_order=boot_order)
    except Exception as e:
        return err(str(e), 500)


# ═══════════════════════════════════════════════════════════════════════════════
# Guest File Browser (QEMU Guest Agent)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/vms/<vm_id>/files", methods=["GET"])
@require_auth
def api_vm_file_list(vm_id):
    """List files in guest via QEMU Guest Agent."""
    path = request.args.get("path", "/")
    # Sanitize path
    import posixpath
    path = posixpath.normpath("/" + path.lstrip("/"))
    try:
        conn = vm_manager._libvirt_conn()
        dom = conn.lookupByName(vm_id)
        if not dom.isActive():
            return err("VM çalışmıyor", 400)
        # Use guest-agent exec to list files
        import json as _json
        cmd_json = _json.dumps({
            "execute": "guest-exec",
            "arguments": {
                "path": "/bin/ls",
                "arg": ["-la", "--time-style=+%Y-%m-%d %H:%M", path],
                "capture-output": True,
            }
        })
        result = dom.qemuAgentCommand(cmd_json, 10, 0)
        result_data = _json.loads(result)
        pid = result_data.get("return", {}).get("pid")
        if pid is None:
            return err("Guest agent komutu başlatılamadı", 500)
        # Wait for result
        import time; time.sleep(0.5)
        status_json = _json.dumps({
            "execute": "guest-exec-status",
            "arguments": {"pid": pid}
        })
        status = _json.loads(dom.qemuAgentCommand(status_json, 10, 0))
        ret = status.get("return", {})
        import base64
        stdout = base64.b64decode(ret.get("out-data","")).decode("utf-8","replace") if ret.get("out-data") else ""
        conn.close()
        # Parse ls output
        files = []
        for line in stdout.splitlines()[1:]:  # skip "total N"
            parts = line.split()
            if len(parts) >= 9:
                perms = parts[0]; links = parts[1]; owner = parts[2]; group = parts[3]
                size = parts[4]; date = parts[5]; time_str = parts[6]; name = " ".join(parts[7:])
                if name in (".", ".."):
                    continue
                files.append({
                    "name": name, "perms": perms, "size": size,
                    "date": f"{date} {time_str}", "owner": owner,
                    "is_dir": perms.startswith("d"),
                    "path": f"{path.rstrip('/')}/{name}",
                })
        return ok(path=path, files=files)
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/vms/<vm_id>/files/exec", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_vm_exec(vm_id):
    """Execute command in guest via QEMU Guest Agent."""
    data = request.get_json() or {}
    cmd  = data.get("command", "")
    args = data.get("args", [])
    if not cmd:
        return err("command gerekli", 400)
    # rapor #71 fix: guest agent command injection önleme
    # Yalnızca belirli komutlara izin ver (allow-list)
    _GUEST_EXEC_ALLOWLIST = {
        "/bin/ls", "/usr/bin/ls", "/bin/cat", "/usr/bin/cat",
        "/bin/df", "/usr/bin/df", "/bin/free", "/usr/bin/free",
        "/bin/uname", "/usr/bin/uname", "/bin/hostname", "/usr/bin/hostname",
        "/usr/bin/systemctl", "/bin/systemctl",
        "/usr/sbin/reboot", "/sbin/reboot",
        "/usr/bin/apt", "/usr/bin/apt-get",
        "/bin/ps", "/usr/bin/ps",
    }
    # Kısmi eşleşme için sadece komut adı da kontrol
    _cmd_base = cmd.split("/")[-1]
    _dangerous = {"rm", "dd", "mkfs", "fdisk", "shred", "wipefs", "curl", "wget",
                  "bash", "sh", "python", "python3", "perl", "ruby", "nc", "ncat", "netcat"}
    if _cmd_base in _dangerous:
        return err(f"Tehlikeli komut yasak: {cmd}", 400)
    # Args içinde shell metachar kontrolü
    import shlex as _shlex
    for arg in (args or []):
        if any(c in str(arg) for c in [";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r"]):
            return err(f"Geçersiz argüman karakteri: {arg!r}", 400)
    try:
        import json as _json, base64
        conn = vm_manager._libvirt_conn()
        dom = conn.lookupByName(vm_id)
        cmd_json = _json.dumps({
            "execute": "guest-exec",
            "arguments": {"path": cmd, "arg": args, "capture-output": True}
        })
        result = dom.qemuAgentCommand(cmd_json, 30, 0)
        pid = _json.loads(result).get("return", {}).get("pid")
        import time; time.sleep(1)
        status_json = _json.dumps({"execute": "guest-exec-status", "arguments": {"pid": pid}})
        status = _json.loads(dom.qemuAgentCommand(status_json, 30, 0))
        ret = status.get("return", {})
        stdout = base64.b64decode(ret.get("out-data","")).decode("utf-8","replace") if ret.get("out-data") else ""
        stderr = base64.b64decode(ret.get("err-data","")).decode("utf-8","replace") if ret.get("err-data") else ""
        conn.close()
        ev.info(f"Guest exec: {vm_id} cmd={cmd}", category="vm")
        return ok(stdout=stdout, stderr=stderr, exitcode=ret.get("exitcode",0))
    except Exception as e:
        return err(str(e), 500)


# ═══════════════════════════════════════════════════════════════════════════════
# NUMA Topology
# ═══════════════════════════════════════════════════════════════════════════════
numa_mgr = _safe_import("numa_manager")

@app.route("/api/system/numa")
@require_auth
def api_host_numa():
    if not numa_mgr: return ok({"nodes": [], "raw": "numa_manager modülü yüklenemedi"})
    return ok(**numa_mgr.get_host_numa())

@app.route("/api/vms/<vm_id>/numa", methods=["GET"])
@require_auth
def api_vm_numa_get(vm_id):
    if not numa_mgr: return err("numa_manager modülü yüklenemedi")
    return ok(**numa_mgr.get_vm_numa(vm_id))

@app.route("/api/vms/<vm_id>/numa", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_vm_numa_set(vm_id):
    if not numa_mgr: return err("numa_manager modülü yüklenemedi")
    d = request.get_json() or {}
    cells = d.get("cells", [])
    if not cells:
        return err("cells listesi gerekli", 400)
    result = numa_mgr.set_vm_numa(vm_id, cells)
    ev.info(f"NUMA topology ayarlandı: {vm_id}", category="vm")
    return ok(**result)

@app.route("/api/vms/<vm_id>/numa", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_vm_numa_remove(vm_id):
    if not numa_mgr: return err("numa_manager modülü yüklenemedi")
    return ok(**numa_mgr.remove_vm_numa(vm_id))


# ═══════════════════════════════════════════════════════════════════════════════
# Container Management (Docker + LXC)
# ═══════════════════════════════════════════════════════════════════════════════
container_mgr = _safe_import("container_manager")

@app.route("/api/containers")
@require_auth
def api_containers_list():
    if not container_mgr: return ok(containers=[], docker=False, lxc=False)
    docker_available = container_mgr.docker_available()
    lxc_available = container_mgr.lxc_available()
    containers = []
    if docker_available:
        containers += container_mgr.list_docker_containers()
    if lxc_available:
        containers += container_mgr.list_lxc_containers()
    return ok(containers=containers, docker=docker_available, lxc=lxc_available)

@app.route("/api/containers/docker", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_docker_create():
    if not container_mgr: return err("container_manager modülü yüklenemedi")
    d = request.get_json() or {}
    name = d.get("name",""); image = d.get("image","")
    if not name or not image:
        return err("name ve image gerekli", 400)
    result = container_mgr.create_docker_container(
        name=name, image=image,
        ports=d.get("ports",""), env=d.get("env",[]),
        volumes=d.get("volumes",""), restart=d.get("restart","unless-stopped"),
        memory=d.get("memory",""), cpus=d.get("cpus",""),
    )
    ev.info(f"Docker container oluşturuldu: {name} ({image})", category="container")
    return ok(**result)

@app.route("/api/containers/docker/<container_id>/action", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_docker_action(container_id):
    if not container_mgr: return err("container_manager modülü yüklenemedi")
    d = request.get_json() or {}
    action = d.get("action","")
    result = container_mgr.docker_action(container_id, action)
    ev.info(f"Docker action: {container_id} → {action}", category="container")
    return ok(**result)

@app.route("/api/containers/docker/<container_id>/logs")
@require_auth
def api_docker_logs(container_id):
    if not container_mgr: return err("container_manager modülü yüklenemedi")
    lines = int(request.args.get("lines", 100))
    return ok(logs=container_mgr.docker_logs(container_id, lines))

@app.route("/api/containers/docker/images")
@require_auth
def api_docker_images():
    if not container_mgr: return ok(images=[])
    return ok(images=container_mgr.list_docker_images())

@app.route("/api/containers/docker/images/pull", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_docker_pull():
    if not container_mgr: return err("container_manager modülü yüklenemedi")
    d = request.get_json() or {}
    image = d.get("image","")
    if not image:
        return err("image gerekli", 400)
    result = container_mgr.pull_docker_image(image)
    return ok(**result)

@app.route("/api/containers/lxc", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_lxc_create():
    if not container_mgr: return err("container_manager modülü yüklenemedi")
    d = request.get_json() or {}
    result = container_mgr.create_lxc_container(
        name=d.get("name",""), template=d.get("template","ubuntu"),
        release=d.get("release","22.04"),
    )
    ev.info(f"LXC container oluşturuldu: {d.get('name')}", category="container")
    return ok(**result)

@app.route("/api/containers/lxc/<name>/action", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_lxc_action(name):
    if not container_mgr: return err("container_manager modülü yüklenemedi")
    d = request.get_json() or {}
    return ok(**container_mgr.lxc_action(name, d.get("action","")))

@app.route("/api/containers/lxc/<name>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_lxc_destroy(name):
    if not container_mgr: return err("container_manager modülü yüklenemedi")
    return ok(**container_mgr.destroy_lxc_container(name))


# ═══════════════════════════════════════════════════════════════════════════════
# Cloudflare Tunnel per VM
# ═══════════════════════════════════════════════════════════════════════════════
cf_tunnel_mgr = _safe_import("cloudflare_tunnel_manager")

@app.route("/api/cf-tunnels")
@require_auth
@require_role("admin", "administrator")
def api_cf_tunnel_list():
    if not cf_tunnel_mgr: return ok(tunnels=[], available=False)
    return ok(tunnels=cf_tunnel_mgr.list_tunnels(),
              available=cf_tunnel_mgr.cloudflared_available())

@app.route("/api/cf-tunnels", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_cf_tunnel_create():
    if not cf_tunnel_mgr: return err("cloudflare_tunnel_manager modülü yüklenemedi")
    d = request.get_json() or {}
    required = ["vm_id", "hostname", "target_ip", "target_port"]
    missing = [f for f in required if not d.get(f)]
    if missing:
        return err(f"Eksik alanlar: {missing}", 400)
    result = cf_tunnel_mgr.create_tunnel(
        vm_id=d["vm_id"], vm_name=d.get("vm_name", d["vm_id"]),
        hostname=d["hostname"], target_ip=d["target_ip"],
        target_port=int(d["target_port"]), protocol=d.get("protocol","http"),
    )
    ev.info(f"CF tunnel oluşturuldu: {d['vm_id']} → {d['hostname']}", category="network")
    return ok(**result)

@app.route("/api/cf-tunnels/<vm_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_cf_tunnel_delete(vm_id):
    if not cf_tunnel_mgr: return err("cloudflare_tunnel_manager modülü yüklenemedi")
    return ok(**cf_tunnel_mgr.delete_tunnel(vm_id))

@app.route("/api/cf-tunnels/<vm_id>/status")
@require_auth
def api_cf_tunnel_status(vm_id):
    if not cf_tunnel_mgr: return err("cloudflare_tunnel_manager modülü yüklenemedi")
    return ok(**cf_tunnel_mgr.tunnel_status(vm_id))

@app.route("/api/cf-tunnels/<vm_id>/start", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_cf_tunnel_start(vm_id):
    if not cf_tunnel_mgr: return err("cloudflare_tunnel_manager modülü yüklenemedi")
    return ok(**cf_tunnel_mgr.start_tunnel(vm_id))

@app.route("/api/cf-tunnels/<vm_id>/stop", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_cf_tunnel_stop(vm_id):
    if not cf_tunnel_mgr: return err("cloudflare_tunnel_manager modülü yüklenemedi")
    return ok(**cf_tunnel_mgr.stop_tunnel(vm_id))


# ═══════════════════════════════════════════════════════════════════════════════
# NFS / Ceph Storage Pool UI
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/storage/pools/nfs", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_create_nfs_pool():
    """Create NFS-backed libvirt storage pool."""
    d = request.get_json() or {}
    name = d.get("name","")
    host = d.get("host","")
    source_path = d.get("source_path","")
    target_path = d.get("target_path","")
    if not all([name, host, source_path, target_path]):
        return err("name, host, source_path, target_path gerekli", 400)
    import re as _re
    if not _re.match(r'^[a-zA-Z0-9_\-]+$', name):
        return err("Geçersiz pool adı", 400)
    xml = f"""<pool type='netfs'>
  <name>{name}</name>
  <source>
    <host name='{host}'/>
    <dir path='{source_path}'/>
    <format type='nfs'/>
  </source>
  <target>
    <path>{target_path}</path>
    <permissions>
      <mode>0755</mode>
    </permissions>
  </target>
</pool>"""
    try:
        import libvirt as _lv
        conn = libvirt.open(config.LIBVIRT_URI)
        pool = conn.storagePoolDefineXML(xml, 0)
        os.makedirs(target_path, exist_ok=True)
        pool.setAutostart(1)
        pool.build()
        pool.create()
        conn.close()
        ev.info(f"NFS pool oluşturuldu: {name} ({host}:{source_path})", category="storage")
        return ok(name=name, uuid=pool.UUIDString(), type="nfs")
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/storage/pools/ceph", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_create_ceph_pool():
    """Create Ceph RBD-backed libvirt storage pool."""
    d = request.get_json() or {}
    name = d.get("name","")
    hosts = d.get("hosts",[])  # list of mon hosts
    ceph_pool = d.get("ceph_pool","vms")
    auth_username = d.get("auth_username","admin")
    auth_uuid = d.get("auth_uuid","")  # libvirt secret UUID for ceph key
    if not name or not hosts:
        return err("name ve hosts gerekli", 400)
    hosts_xml = "\n".join([f"    <host name='{h}' port='6789'/>" for h in hosts])
    xml = f"""<pool type='rbd'>
  <name>{name}</name>
  <source>
{hosts_xml}
    <name>{ceph_pool}</name>
    <auth type='ceph' username='{auth_username}'>
      <secret uuid='{auth_uuid}'/>
    </auth>
  </source>
</pool>"""
    try:
        conn = libvirt.open(config.LIBVIRT_URI)
        pool = conn.storagePoolDefineXML(xml, 0)
        pool.setAutostart(1)
        pool.create()
        conn.close()
        ev.info(f"Ceph pool oluşturuldu: {name}", category="storage")
        return ok(name=name, uuid=pool.UUIDString(), type="ceph_rbd")
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/storage/ceph/status")
@require_auth
@require_role("admin", "administrator")
def api_ceph_status():
    """Get Ceph cluster status from host (requires ceph client tools)."""
    try:
        r = subprocess.run(["ceph", "status", "-f", "json"], capture_output=True, text=True, timeout=10)
        r2 = subprocess.run(["ceph", "df", "-f", "json"], capture_output=True, text=True, timeout=10)
        r3 = subprocess.run(["ceph", "osd", "stat", "-f", "json"], capture_output=True, text=True, timeout=10)
        status = json.loads(r.stdout) if r.returncode == 0 else {}
        df = json.loads(r2.stdout) if r2.returncode == 0 else {}
        osd_stat = json.loads(r3.stdout) if r3.returncode == 0 else {}
        return ok(status=status, df=df, osd_stat=osd_stat, available=r.returncode == 0)
    except Exception as e:
        return ok(available=False, error=str(e), status={}, df={}, osd_stat={})


# ═══════════════════════════════════════════════════════════════════════════════
# RBAC Fine-Grained (per-storage, per-network resource permissions)
# ═══════════════════════════════════════════════════════════════════════════════

_RESOURCE_PERMS_FILE = "/etc/oxware/resource_permissions.json"

def _load_resource_perms():
    if os.path.exists(_RESOURCE_PERMS_FILE):
        try:
            with open(_RESOURCE_PERMS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_resource_perms(perms):
    os.makedirs(os.path.dirname(_RESOURCE_PERMS_FILE), exist_ok=True)
    with open(_RESOURCE_PERMS_FILE, "w") as f:
        json.dump(perms, f, indent=2)

@app.route("/api/rbac/resources")
@require_auth
@require_role("admin", "administrator")
def api_rbac_resources():
    """List all resource-level permissions."""
    return ok(permissions=_load_resource_perms())

@app.route("/api/rbac/resources", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_rbac_set_resource():
    """Grant/revoke permission for user on specific resource."""
    d = request.get_json() or {}
    username = d.get("username","")
    resource_type = d.get("resource_type","")  # vm, storage, network
    resource_id = d.get("resource_id","")
    permissions = d.get("permissions", [])  # ["read","write","exec","delete"]
    if not all([username, resource_type, resource_id]):
        return err("username, resource_type, resource_id gerekli", 400)
    perms = _load_resource_perms()
    key = f"{resource_type}:{resource_id}"
    if key not in perms:
        perms[key] = {}
    perms[key][username] = permissions
    _save_resource_perms(perms)
    ev.info(f"RBAC resource permission: {username} on {key} = {permissions}", category="security")
    return ok(key=key, username=username, permissions=permissions)

@app.route("/api/rbac/resources/<resource_type>/<resource_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_rbac_remove_resource(resource_type, resource_id):
    perms = _load_resource_perms()
    key = f"{resource_type}:{resource_id}"
    d = request.get_json() or {}
    username = d.get("username","")
    if username:
        if key in perms and username in perms[key]:
            del perms[key][username]
    else:
        perms.pop(key, None)
    _save_resource_perms(perms)
    return ok(removed=key)

@app.route("/api/rbac/check", methods=["POST"])
@require_auth
def api_rbac_check():
    """Check if current user has permission on a resource."""
    from flask_jwt_extended import get_jwt_identity
    username = get_jwt_identity()
    d = request.get_json() or {}
    resource_type = d.get("resource_type","")
    resource_id = d.get("resource_id","")
    permission = d.get("permission","read")
    perms = _load_resource_perms()
    key = f"{resource_type}:{resource_id}"
    user_perms = perms.get(key, {}).get(username, [])
    # Admins have all permissions
    role = cred_mgr.get_role(username) if hasattr(cred_mgr, "get_role") else "viewer"
    if role in ("admin", "administrator"):
        return ok(allowed=True, role=role)
    allowed = permission in user_perms
    return ok(allowed=allowed, permissions=user_perms)


# ═══════════════════════════════════════════════════════════════════════════════
# Advanced VM Search & Filtering
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/vms/search")
@require_auth
def api_vm_search():
    """Advanced VM search with filtering by tag, state, arch, resource thresholds."""
    q = request.args.get("q","").strip().lower()
    state = request.args.get("state","")
    tag = request.args.get("tag","")
    min_cpu = request.args.get("min_cpu", type=float)
    max_cpu = request.args.get("max_cpu", type=float)
    min_ram = request.args.get("min_ram", type=int)  # MB
    max_ram = request.args.get("max_ram", type=int)  # MB
    try:
        vms = vm_manager.list_vms()
        results = []
        for vm in vms:
            # Text search: name, id
            if q and q not in vm.get("name","").lower() and q not in vm.get("id","").lower():
                continue
            # State filter
            if state and vm.get("state","") != state:
                continue
            # CPU filter
            cpu_pct = vm.get("cpu_percent", 0)
            if min_cpu is not None and cpu_pct < min_cpu:
                continue
            if max_cpu is not None and cpu_pct > max_cpu:
                continue
            # RAM filter
            ram = vm.get("memory_mb", 0)
            if min_ram is not None and ram < min_ram:
                continue
            if max_ram is not None and ram > max_ram:
                continue
            # Tag filter (check tag_manager)
            if tag:
                try:
                    vm_tags = tag_mgr.get_vm_tags(vm["id"]) if tag_mgr else []
                    if tag not in vm_tags:
                        continue
                except Exception:
                    pass
            results.append(vm)
        return ok(vms=results, count=len(results), query={
            "q": q, "state": state, "tag": tag,
            "min_cpu": min_cpu, "max_cpu": max_cpu,
            "min_ram": min_ram, "max_ram": max_ram,
        })
    except Exception as e:
        return err(str(e), 500)


# ═══════════════════════════════════════════════════════════════════════════════
# HA / Clustering Framework (stub + libvirt remote connection)
# ═══════════════════════════════════════════════════════════════════════════════

_HA_NODES_FILE = "/etc/oxware/ha_nodes.json"

@app.route("/api/ha/nodes")
@require_auth
@require_role("admin", "administrator")
def api_ha_nodes():
    """List configured HA cluster nodes."""
    nodes = []
    if os.path.exists(_HA_NODES_FILE):
        try:
            with open(_HA_NODES_FILE) as f:
                nodes = json.load(f)
        except Exception:
            pass
    # Probe each node
    for node in nodes:
        ip = node.get("ip","")
        r = subprocess.run(["ping","-c","1","-W","2",ip], capture_output=True, timeout=5)
        node["online"] = r.returncode == 0
        # Try libvirt connection
        try:
            import libvirt as _lv
            uri = f"qemu+ssh://{ip}/system"
            c = _lv.openReadOnly(uri)
            node["vms"] = len(c.listAllDomains())
            node["libvirt"] = True
            c.close()
        except Exception:
            node["libvirt"] = False
            node["vms"] = 0
    return ok(nodes=nodes, count=len(nodes))

@app.route("/api/ha/nodes", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ha_add_node():
    """Add a node to the HA cluster config."""
    d = request.get_json() or {}
    ip = d.get("ip",""); name = d.get("name","")
    if not ip:
        return err("ip gerekli", 400)
    nodes = []
    if os.path.exists(_HA_NODES_FILE):
        try:
            with open(_HA_NODES_FILE) as f:
                nodes = json.load(f)
        except Exception:
            pass
    if any(n.get("ip") == ip for n in nodes):
        return err("Bu node zaten ekli", 409)
    nodes.append({"ip": ip, "name": name or ip, "role": d.get("role","secondary")})
    os.makedirs(os.path.dirname(_HA_NODES_FILE), exist_ok=True)
    with open(_HA_NODES_FILE, "w") as f:
        json.dump(nodes, f, indent=2)
    ev.info(f"HA node eklendi: {ip}", category="cluster")
    return ok(ip=ip, name=name)

@app.route("/api/ha/nodes/<path:node_ip>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_ha_remove_node(node_ip):
    nodes = []
    if os.path.exists(_HA_NODES_FILE):
        try:
            with open(_HA_NODES_FILE) as f:
                nodes = json.load(f)
        except Exception:
            pass
    nodes = [n for n in nodes if n.get("ip") != node_ip]
    with open(_HA_NODES_FILE, "w") as f:
        json.dump(nodes, f, indent=2)
    return ok(removed=node_ip)

@app.route("/api/ha/migrate", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ha_migrate():
    """Live migrate VM to another node via libvirt."""
    d = request.get_json() or {}
    vm_id = d.get("vm_id","")
    target_ip = d.get("target_ip","")
    if not vm_id or not target_ip:
        return err("vm_id ve target_ip gerekli", 400)
    try:
        src_conn = libvirt.open(config.LIBVIRT_URI)
        dst_conn = libvirt.open(f"qemu+ssh://{target_ip}/system")
        dom = src_conn.lookupByName(vm_id)
        flags = libvirt.VIR_MIGRATE_LIVE | libvirt.VIR_MIGRATE_PEER2PEER | libvirt.VIR_MIGRATE_TUNNELLED
        dom.migrate(dst_conn, flags, None, None, 0)
        src_conn.close(); dst_conn.close()
        ev.info(f"Live migration: {vm_id} → {target_ip}", category="cluster")
        return ok(vm_id=vm_id, target=target_ip, status="migrated")
    except Exception as e:
        return err(str(e), 500)


# ── Bulk Migration (Proxmox / ESXi → OXware) ─────────────────────────────────

def _proxmox_request(px_host, px_port, px_token_id, px_token_secret,
                     path, method="GET", body=None, verify_ssl=False, timeout=20):
    """Proxmox REST API call with PVEAPIToken auth. Returns data field or raises."""
    import urllib.request as _ureq, urllib.error as _uerr, urllib.parse as _up, ssl as _ssl, json as _pjson
    url = f"https://{px_host}:{px_port}/api2/json{path}"
    ctx = _ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
    headers = {"Authorization": f"PVEAPIToken={px_token_id}={px_token_secret}"}
    data_bytes = None
    if body:
        data_bytes = _up.urlencode(body).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = _ureq.Request(url, data=data_bytes, headers=headers, method=method)
    try:
        with _ureq.urlopen(req, context=ctx, timeout=timeout) as resp:
            return _pjson.loads(resp.read().decode()).get("data", {})
    except _uerr.HTTPError as e:
        raise RuntimeError(f"Proxmox API HTTP {e.code}: {e.read().decode()[:300]}")


def _proxmox_get_disk_keys(cfg: dict) -> list:
    """Return list of (disk_key, volid) tuples from Proxmox VM config dict."""
    skip = {"cdrom", "none", "cloudinit"}
    keys = []
    for k, v in (cfg or {}).items():
        if not k.startswith(("scsi", "virtio", "ide", "sata")):
            continue
        if not isinstance(v, str):
            continue
        if any(s in v for s in skip):
            continue
        volid = v.split(",")[0].strip()
        if ":" in volid:
            keys.append((k, volid))
    return keys


def _proxmox_parse_networks(cfg: dict) -> list:
    """Parse net0/net1/... from Proxmox VM config. Returns list of dicts."""
    nets = []
    for k in sorted(cfg.keys()):
        if not (k.startswith("net") and k[3:].isdigit()):
            continue
        v = cfg[k]
        if not isinstance(v, str):
            continue
        parts = {}
        for p in v.split(","):
            if "=" in p:
                pk, pv = p.split("=", 1)
                parts[pk.strip()] = pv.strip()
        bridge = parts.get("bridge", "")
        vlan = parts.get("tag", "")
        if "virtio=" in v:
            model = "virtio"
        elif "e1000=" in v or "e1000e=" in v:
            model = "e1000"
        elif "vmxnet3=" in v:
            model = "virtio"
        else:
            model = "rtl8139"
        nets.append({"key": k, "bridge": bridge, "vlan": vlan, "model": model})
    return nets


def _map_source_network(name_or_bridge: str, fallback: str = "default") -> str:
    """Map Proxmox bridge / ESXi portgroup to a libvirt network name.
    Queries 'virsh net-list' and 'virsh net-info' to find a matching bridge.
    Falls back to 'fallback' if no match found."""
    if not name_or_bridge:
        return fallback
    try:
        r = subprocess.run(["virsh", "net-list", "--all"],
                           capture_output=True, text=True, timeout=10)
        net_names = [ln.split()[0] for ln in r.stdout.splitlines()[2:]
                     if ln.split()]
        # Exact network name match
        for nn in net_names:
            if nn.lower() == name_or_bridge.lower():
                return nn
        # Bridge name match via net-info
        for nn in net_names:
            r2 = subprocess.run(["virsh", "net-info", nn],
                                capture_output=True, text=True, timeout=5)
            for line in r2.stdout.splitlines():
                if "Bridge:" in line and name_or_bridge.lower() in line.lower():
                    return nn
    except Exception:
        pass
    return fallback


def _esxi_parse_vmx_ssh(client, vmx_dir: str, vm_name: str) -> dict:
    """SSH-cat the VMX file and parse networks, disks, CPU, RAM, firmware.
    Returns dict with: vcpus, ram_mb, firmware, os_type, networks, disks, disk_gb."""
    import re as _re_vmx
    result = {"vcpus": 2, "ram_mb": 2048, "firmware": "bios",
              "os_type": "unknown", "networks": [], "disks": [], "disk_gb": 0}

    # ── Step 1: resolve datastore symlink → real UUID path via readlink ───────
    # /vmfs/volumes/datastore1 is a symlink; BusyBox cat doesn't follow it
    # reliably inside exec_command. readlink is instant and always works.
    real_dir = vmx_dir.rstrip("/")
    _parts = vmx_dir.strip("/").split("/")
    if len(_parts) >= 3:
        _ds = _parts[2]  # e.g. "datastore1"
        try:
            _, _rl_o, _ = client.exec_command(
                f"readlink /vmfs/volumes/{_ds} 2>/dev/null", timeout=5)
            _rl = _rl_o.read().decode().strip()
            if _rl:
                _real_vol = _rl if _rl.startswith("/") else f"/vmfs/volumes/{_rl}"
                real_dir = vmx_dir.replace(
                    f"/vmfs/volumes/{_ds}", _real_vol, 1).rstrip("/")
        except Exception:
            pass

    vmx_path = real_dir + "/" + vm_name + ".vmx"
    try:
        _, out, _ = client.exec_command(f"cat '{vmx_path}' 2>/dev/null", timeout=10)
        content = out.read().decode(errors="replace")
        if not content.strip():
            # readlink didn't help — try find (no -maxdepth, works on BusyBox)
            _, _fo, _ = client.exec_command(
                f"find /vmfs/volumes -name '{vm_name}.vmx' 2>/dev/null | head -1",
                timeout=15)
            real_vmx = _fo.read().decode(errors="replace").strip()
            if real_vmx:
                real_dir = real_vmx.rsplit("/", 1)[0]
                _, out2, _ = client.exec_command(f"cat '{real_vmx}' 2>/dev/null", timeout=10)
                content = out2.read().decode(errors="replace")
        if not content.strip():
            # last resort: glob
            _, gl_out, _ = client.exec_command(
                f"ls '{vmx_dir}'/*.vmx 2>/dev/null | head -1", timeout=5)
            alt_path = gl_out.read().decode(errors="replace").strip()
            if alt_path:
                real_dir = alt_path.rsplit("/", 1)[0]
                _, out3, _ = client.exec_command(f"cat '{alt_path}' 2>/dev/null", timeout=10)
                content = out3.read().decode(errors="replace")
    except Exception:
        return result

    eth_data = {}  # "ethernetN" -> {networkName, virtualDev}
    disk_files = []

    for line in content.splitlines():
        line = line.strip()
        if not line or "=" not in line or line.startswith("#"):
            continue
        k, _, v = line.partition("=")
        k, v = k.strip().lower(), v.strip().strip('"')
        vl = v.lower()
        if k == "numvcpus":
            try: result["vcpus"] = max(1, min(128, int(v)))
            except Exception: pass
        elif k == "memsize":
            try: result["ram_mb"] = max(512, min(262144, int(v)))
            except Exception: pass
        elif k == "firmware":
            result["firmware"] = "efi" if vl == "efi" else "bios"
        elif k == "guestos":
            if any(x in vl for x in ["win", "windows", "server"]):
                result["os_type"] = "windows"
            elif any(x in vl for x in ["linux", "ubuntu", "centos", "rhel",
                                         "fedora", "debian", "suse", "oracle",
                                         "freebsd", "rocky", "alma"]):
                result["os_type"] = "linux"
        else:
            # ethernet0.networkname / ethernet0.virtualdev
            m_eth = _re_vmx.match(r'^(ethernet\d+)\.(networkname|virtualdev)$', k)
            if m_eth:
                idx, attr = m_eth.group(1), m_eth.group(2)
                eth_data.setdefault(idx, {})[attr] = v
                continue
            # scsi0:0.filename / sata0:0.filename / ide0:0.filename
            m_disk = _re_vmx.match(r'^(scsi|sata|ide|nvme)\d+:\d+\.filename$', k)
            if m_disk and vl.endswith(".vmdk"):
                if "-flat" not in vl and not _re_vmdk_extent.search(vl):
                    disk_files.append(v)  # relative path

    for idx in sorted(eth_data.keys()):
        d = eth_data[idx]
        vdev = d.get("virtualdev", "vmxnet3").lower()
        if "vmxnet" in vdev:
            model = "virtio"
        elif "e1000" in vdev:
            model = "e1000"
        else:
            model = "virtio"
        result["networks"].append({
            "key": idx,
            "network_name": d.get("networkname", "VM Network"),
            "model": model,
        })

    if result["os_type"] == "unknown":
        result["os_type"] = _detect_os_from_name(vm_name)

    # Deduplicate disk files, build absolute paths using real_dir
    seen = set()
    for df in disk_files:
        if df not in seen:
            abs_path = real_dir + "/" + df
            result["disks"].append(abs_path)
            seen.add(df)

    # Disk virtual size: read RW sector count from VMDK descriptor
    if result["disks"] and result["disk_gb"] == 0:
        try:
            _, _rw_out, _ = client.exec_command(
                f"grep '^RW' '{result['disks'][0]}' 2>/dev/null | head -1",
                timeout=8)
            _rw_line = _rw_out.read().decode(errors="replace").strip()
            # format: RW <sectors> VMFS "name-flat.vmdk"
            _rw_parts = _rw_line.split()
            if len(_rw_parts) >= 2 and _rw_parts[1].isdigit():
                result["disk_gb"] = round(int(_rw_parts[1]) * 512 / (1024 ** 3), 1)
        except Exception:
            pass

    return result


def _qcow2_ext4_fixup(qcow2_path: str, log_fn=None) -> str:
    """
    qcow2 içindeki tüm ext4 filesystemlerini tara (LVM dahil) ve
    metadata_csum + INODE_UNINIT flag'larını temizle.
    ESXi thin-VMDK → KVM migrate sonrası 'iget: checksum invalid' hatasını çözer.
    """
    import struct as _st
    import re as _re_lvm
    OMASK = 0x00fffffffffffe00
    CBIT  = 1 << 62  # compressed bit (bit 63 = COPIED, normal)
    results = []

    def _lg(msg):
        if log_fn:
            log_fn("ext4fixup: %s", msg)

    def _open_q(path):
        f = open(path, 'r+b')
        h = f.read(104)
        if h[:4] != b'QFI\xfb':
            raise ValueError("Not qcow2")
        cb = _st.unpack_from('>I', h, 20)[0]; cs = 1 << cb
        l1sz = _st.unpack_from('>I', h, 36)[0]
        l1of = _st.unpack_from('>Q', h, 40)[0]
        f.seek(l1of); l1r = f.read(l1sz * 8)
        l1 = [_st.unpack_from('>Q', l1r, i*8)[0] for i in range(l1sz)]
        return {'f': f, 'cb': cb, 'cs': cs, 'l2n': cs//8, 'l2b': cb-3, 'l1': l1, 'l2c': {}}

    def _v2p(q, v):
        l1i = v >> (q['cb'] + q['l2b'])
        l2i = (v >> q['cb']) & (q['l2n'] - 1)
        if l1i >= len(q['l1']): return None
        l2b = q['l1'][l1i] & OMASK
        if not l2b: return None
        if l2b not in q['l2c']:
            q['f'].seek(l2b); r = q['f'].read(q['l2n'] * 8)
            q['l2c'][l2b] = [_st.unpack_from('>Q', r, i*8)[0] for i in range(q['l2n'])]
        e = q['l2c'][l2b][l2i]
        if not e or (e & 1) or (e & CBIT): return None
        return (e & OMASK) + (v & (q['cs'] - 1))

    def _vr(q, virt, size):
        out = bytearray(); pos = virt; end = virt + size; cs = q['cs']
        while pos < end:
            chunk = min(cs - (pos % cs), end - pos); p = _v2p(q, pos)
            if p is None: out += b'\x00' * chunk
            else: q['f'].seek(p); out += q['f'].read(chunk)
            pos += chunk
        return bytes(out)

    def _vw(q, virt, data):
        pos = virt; src = 0; size = len(data); cs = q['cs']
        while src < size:
            chunk = min(cs - (pos % cs), size - src); p = _v2p(q, pos)
            if p is None: raise IOError(f"vw unallocated @ 0x{pos:x}")
            q['f'].seek(p); q['f'].write(data[src:src+chunk])
            pos += chunk; src += chunk

    EXT4_META_CSUM       = 0x400
    EXT4_BG_INODE_UNINIT = 0x0001
    EXT4_BG_BLOCK_UNINIT = 0x0002

    def _patch_ext4(q, base, label=""):
        sb_off = base + 1024
        sb = bytearray(_vr(q, sb_off, 1024))
        if _st.unpack_from('<H', sb, 56)[0] != 0xEF53:
            return False
        ro = _st.unpack_from('<I', sb, 100)[0]
        if not (ro & EXT4_META_CSUM):
            _lg(f"[{label}] already clear ro={ro:#x}")
            return True
        new_ro = ro & ~EXT4_META_CSUM & ~0x10000  # also clear orphan_present
        _st.pack_into('<I', sb, 100, new_ro)
        log_bs = _st.unpack_from('<I', sb, 24)[0]; bs = 1024 << log_bs
        total_blks = _st.unpack_from('<I', sb, 4)[0]
        bpg = _st.unpack_from('<I', sb, 32)[0]
        incompat = _st.unpack_from('<I', sb, 96)[0]
        gdt_esz = 64 if (incompat & 0x80) else 32
        ngroups = (total_blks + bpg - 1) // bpg
        gdt_blk = 1 if bs > 1024 else 2
        gdt_base = base + gdt_blk * bs
        fixed = 0
        for g in range(ngroups):
            gd_off = gdt_base + g * gdt_esz
            gd = bytearray(_vr(q, gd_off, gdt_esz))
            fl = _st.unpack_from('<H', gd, 18)[0]
            changed = False
            if fl & EXT4_BG_INODE_UNINIT: fl &= ~EXT4_BG_INODE_UNINIT; changed = True
            if fl & EXT4_BG_BLOCK_UNINIT: fl &= ~EXT4_BG_BLOCK_UNINIT; changed = True
            if changed:
                _st.pack_into('<H', gd, 18, fl)
                _st.pack_into('<H', gd, 30, 0)
                try: _vw(q, gd_off, bytes(gd)); fixed += 1
                except IOError: pass
        _vw(q, sb_off, bytes(sb))
        msg = f"[{label}] PATCHED ro={ro:#x}→{new_ro:#x} bgs={fixed}"
        _lg(msg); results.append(msg)
        return True

    def _lvm_lv_offsets(q, part_base):
        label_off = None
        for sec in range(4):
            if _vr(q, part_base + sec*512, 8) == b'LABELONE':
                label_off = part_base + sec*512; break
        if label_off is None: return {}
        label = _vr(q, label_off, 512)
        body_off = _st.unpack_from('<I', label, 20)[0]
        pvh = _vr(q, label_off + body_off, 512)
        pos = 40
        while True:
            da_off = _st.unpack_from('<Q', pvh, pos)[0]
            da_sz  = _st.unpack_from('<Q', pvh, pos+8)[0]
            pos += 16
            if da_off == 0 and da_sz == 0: break
        mda_abs = None
        while True:
            ma_off = _st.unpack_from('<Q', pvh, pos)[0]
            ma_sz  = _st.unpack_from('<Q', pvh, pos+8)[0]
            pos += 16
            if ma_off == 0 and ma_sz == 0: break
            if mda_abs is None: mda_abs = part_base + ma_off
        if mda_abs is None: return {}
        mdah = _vr(q, mda_abs, 512)
        if mdah[4:20] != b' LVM2 x[5A%r0N*>': return {}
        rl_pos = 40; raw_off = raw_sz = None
        while True:
            ro2 = _st.unpack_from('<Q', mdah, rl_pos)[0]
            rs  = _st.unpack_from('<Q', mdah, rl_pos+8)[0]
            fl  = _st.unpack_from('<I', mdah, rl_pos+20)[0]
            rl_pos += 24
            if ro2 == 0 and rs == 0: break
            if fl == 0: raw_off = ro2; raw_sz = rs; break
        if raw_off is None: return {}
        meta = _vr(q, mda_abs + raw_off, min(raw_sz, 2*1024*1024)).decode('ascii', errors='replace')
        m = _re_lvm.search(r'extent_size\s*=\s*(\d+)', meta)
        if not m: return {}
        extent_size = int(m.group(1))
        m2 = _re_lvm.search(r'pe_start\s*=\s*(\d+)', meta)
        pe_start = int(m2.group(1)) if m2 else 2048
        lv_offs = {}
        for lv_name, stripes_str in _re_lvm.findall(
                r'(\w[\w-]*)\s*\{[^}]*?segment\d+\s*\{.*?stripes\s*=\s*\[([^\]]+)\]',
                meta, _re_lvm.DOTALL):
            if lv_name in ('physical_volumes', 'logical_volumes', 'metadata', 'global'): continue
            nums = _re_lvm.findall(r'\b(\d+)\b', stripes_str)
            if nums:
                pvo = int(nums[0])
                lv_offs[lv_name] = part_base + (pe_start + pvo * extent_size) * 512
        return lv_offs

    try:
        q = _open_q(qcow2_path)
        step  = 1 * 1024 * 1024        # 1 MB
        limit = 64 * 1024 * 1024 * 1024  # 64 GB
        seen  = set()
        for off in range(0, limit, step):
            if _v2p(q, off) is None and _v2p(q, off + 1024) is None:
                continue
            # ext4 magic at off+1024+56
            if _st.unpack_from('<H', _vr(q, off + 1024 + 56, 2))[0] == 0xEF53:
                if off not in seen:
                    seen.add(off)
                    _patch_ext4(q, off, f"ext4@{off // 1024 // 1024}MB")
                continue
            # LVM LABELONE
            for _sec in range(4):
                if _vr(q, off + _sec*512, 8) == b'LABELONE':
                    if off not in seen:
                        seen.add(off)
                        for _lv_name, _lv_off in _lvm_lv_offsets(q, off).items():
                            _patch_ext4(q, _lv_off, f"lv:{_lv_name}")
                    break
        q['f'].flush(); q['f'].close()
    except Exception as _e:
        return f"fixup error: {_e}"

    return "; ".join(results) if results else "no ext4 patched"


def _build_import_xml_multi(vm_name: str, disk_paths: list, vcpus: int, ram_mb: int,
                             os_type: str, firmware: str = "bios",
                             networks: list = None) -> str:
    """Build libvirt domain XML with multiple disks and multiple NICs.
    disk_paths: list of (path_str, fmt_str) where fmt_str is 'qcow2' or 'raw'.
    networks: list of {libvirt_network, model} dicts."""
    import re as _re_net2
    efi = firmware.lower() == "efi"
    os_efi_block = """  <os firmware='efi'>
    <type arch='x86_64' machine='q35'>hvm</type>
    <firmware>
      <feature enabled='no' name='secure-boot'/>
    </firmware>
    <boot dev='hd'/>
  </os>"""
    os_bios_block = """  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
  </os>"""
    os_block = os_efi_block if efi else os_bios_block

    # ── Disks ──────────────────────────────────────────────────────────────────
    disk_xmls = []
    for idx, (dp, fmt) in enumerate(disk_paths):
        dev = "sd" + chr(ord("a") + idx)
        discard = ' discard="unmap"' if (os_type == "linux" and fmt == "qcow2") else ""
        disk_xmls.append(
            f"    <disk type='file' device='disk'>\n"
            f"      <driver name='qemu' type='{fmt}' cache='none' io='native'{discard}/>\n"
            f"      <source file='{dp}'/>\n"
            f"      <target dev='{dev}' bus='sata'/>\n"
            f"    </disk>"
        )
    disks_str = "\n".join(disk_xmls)

    # ── NICs ──────────────────────────────────────────────────────────────────
    if not networks:
        networks = [{"libvirt_network": "default",
                     "model": "virtio" if os_type == "linux" else "e1000"}]
    net_xmls = []
    for ni in networks:
        nw = _re_net2.sub(r'[^a-zA-Z0-9_\-\.]', '', ni.get("libvirt_network", "default")) or "default"
        md = ni.get("model", "virtio" if os_type == "linux" else "e1000")
        net_xmls.append(
            f"    <interface type='network'>\n"
            f"      <source network='{nw}'/>\n"
            f"      <model type='{md}'/>\n"
            f"    </interface>"
        )
    nets_str = "\n".join(net_xmls)

    # ── OS-specific ────────────────────────────────────────────────────────────
    if os_type == "windows":
        features_str = ("  <features>\n    <acpi/><apic/>\n"
                        "    <hyperv mode='custom'>\n"
                        "      <relaxed state='on'/><vapic state='on'/>\n"
                        "      <spinlocks state='on' retries='8191'/>\n"
                        "    </hyperv>\n    <vmport state='off'/>\n  </features>")
        clock_str = ("  <clock offset='localtime'>\n"
                     "    <timer name='rtc' tickpolicy='catchup'/>\n"
                     "    <timer name='pit' tickpolicy='delay'/>\n"
                     "    <timer name='hpet' present='no'/>\n"
                     "    <timer name='hypervclock' present='yes'/>\n  </clock>")
        extra_str = "    <input type='tablet' bus='usb'/>\n    <input type='keyboard' bus='usb'/>"
        video_str = "    <video><model type='qxl' ram='65536' vram='65536' vgamem='16384' heads='1' primary='yes'/></video>"
    else:
        features_str = "  <features><acpi/><apic/></features>"
        clock_str = ("  <clock offset='utc'>\n"
                     "    <timer name='rtc' tickpolicy='catchup'/>\n"
                     "    <timer name='pit' tickpolicy='delay'/>\n"
                     "    <timer name='hpet' present='no'/>\n  </clock>")
        extra_str = ("    <input type='tablet' bus='usb'/>\n"
                     "    <memballoon model='virtio'><stats period='10'/></memballoon>\n"
                     "    <rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>")
        video_str = "    <video><model type='vga' vram='16384' heads='1' primary='yes'/></video>"

    return (f"<domain type='kvm'>\n"
            f"  <name>{vm_name}</name>\n"
            f"  <memory unit='MiB'>{ram_mb}</memory>\n"
            f"  <vcpu placement='static'>{vcpus}</vcpu>\n"
            f"{os_block}\n"
            f"{features_str}\n"
            f"  <cpu mode='host-passthrough' check='none' migratable='on'/>\n"
            f"{clock_str}\n"
            f"  <devices>\n"
            f"{disks_str}\n"
            f"    <controller type='sata' index='0'/>\n"
            f"{nets_str}\n"
            f"{extra_str}\n"
            f"    <graphics type='vnc' port='-1' listen='0.0.0.0'/>\n"
            f"{video_str}\n"
            f"  </devices>\n"
            f"</domain>")


def _proxmox_ssh_export_all(ssh_host, ssh_port, ssh_user, ssh_password,
                             vmid, disk_keys, dest_dir, job_id) -> list:
    """SSH to Proxmox node, export ALL disks via 'qm disk export', SFTP download.
    disk_keys: list of (disk_key, volid) tuples.
    dest_dir: pathlib.Path directory to store qcow2 files.
    Returns list of (local_path, 'qcow2') tuples."""
    import paramiko as _pmp
    _import_job_update(job_id, step=f"Proxmox SSH: {ssh_host}", percent=8)
    client = _pmp.SSHClient()
    client.set_missing_host_key_policy(_pmp.AutoAddPolicy())
    client.connect(ssh_host, port=ssh_port, username=ssh_user,
                   password=ssh_password, timeout=30,
                   look_for_keys=False, allow_agent=False)
    local_disks = []
    try:
        sftp = client.open_sftp()
        try:
            total_keys = len(disk_keys)
            for dk_idx, (disk_key, _volid) in enumerate(disk_keys):
                remote_tmp = f"/tmp/oxw_export_{vmid}_{disk_key}.qcow2"
                pct_base = 10 + dk_idx * 70 // max(total_keys, 1)
                pct_end  = 10 + (dk_idx + 1) * 70 // max(total_keys, 1)
                _import_job_update(job_id,
                                   step=f"Disk export [{dk_idx+1}/{total_keys}]: vmid={vmid} {disk_key}",
                                   percent=pct_base)
                cmd = f"qm disk export {vmid} {disk_key} {remote_tmp} --format qcow2"
                _, stdout, stderr = client.exec_command(cmd, timeout=7200)
                exit_code = stdout.channel.recv_exit_status()
                if exit_code != 0:
                    err_txt = stderr.read().decode(errors="replace")[:400]
                    raise RuntimeError(f"qm disk export hata [{disk_key}] (code={exit_code}): {err_txt}")

                local_path = dest_dir / f"px_{vmid}_{disk_key}.qcow2"
                _import_job_update(job_id,
                                   step=f"Disk indirilıyor [{dk_idx+1}/{total_keys}]: {disk_key}",
                                   percent=pct_base + (pct_end - pct_base) // 2)

                def _make_prg(base, end):
                    def _prg(tx, tot):
                        pct = min(end, int(base + (end - base) * tx / max(tot, 1)))
                        mb = round(tx / 1048576, 1)
                        tot_mb = round(tot / 1048576, 1)
                        _import_job_update(job_id,
                                           step=f"İndirilıyor [{dk_idx+1}/{total_keys}]: {mb}/{tot_mb} MB",
                                           percent=pct)
                    return _prg

                sftp.get(remote_tmp, str(local_path), callback=_make_prg(pct_base, pct_end))
                try:
                    sftp.remove(remote_tmp)
                except Exception:
                    pass
                local_disks.append((str(local_path), "qcow2"))
        finally:
            sftp.close()
    finally:
        client.close()
    return local_disks


@app.route("/api/migration/proxmox/scan", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_migration_proxmox_scan():
    """Proxmox API ile node ve VM listesi döndür."""
    d = request.get_json() or {}
    px_host = d.get("host", "").strip()
    px_port = int(d.get("port", 8006))
    px_token_id = d.get("token_id", "").strip()
    px_token_secret = d.get("token_secret", "").strip()
    verify_ssl = bool(d.get("verify_ssl", False))
    if not px_host or not px_token_id or not px_token_secret:
        return err("host, token_id ve token_secret gerekli", 400)
    try:
        nodes_data = _proxmox_request(px_host, px_port, px_token_id, px_token_secret,
                                      "/nodes", verify_ssl=verify_ssl) or []
        vms = []
        import re as _re_px
        for node_info in nodes_data:
            node = node_info.get("node", "")
            if not node:
                continue
            try:
                node_vms = _proxmox_request(
                    px_host, px_port, px_token_id, px_token_secret,
                    f"/nodes/{node}/qemu", verify_ssl=verify_ssl) or []
                for vm in node_vms:
                    vmid = vm.get("vmid")
                    if not vmid:
                        continue
                    disk_gb = 0
                    disk_count = 0
                    networks_info = []
                    os_type_scan = "linux"
                    firmware_scan = "bios"
                    try:
                        cfg = _proxmox_request(
                            px_host, px_port, px_token_id, px_token_secret,
                            f"/nodes/{node}/qemu/{vmid}/config",
                            verify_ssl=verify_ssl) or {}
                        for k, v in cfg.items():
                            if k.startswith(("scsi", "virtio", "ide", "sata")) and isinstance(v, str):
                                if any(s in v for s in ("cdrom", "none", "cloudinit")):
                                    continue
                                m = _re_px.search(r"size=(\d+)([GMTgmt]?)", v)
                                if m:
                                    sz = int(m.group(1))
                                    unit = m.group(2).upper()
                                    if unit in ("G", ""): disk_gb += sz
                                    elif unit == "M": disk_gb += max(1, sz // 1024)
                                    elif unit == "T": disk_gb += sz * 1024
                                    disk_count += 1
                        networks_info = _proxmox_parse_networks(cfg)
                        ostype_val = (cfg.get("ostype") or "").lower()
                        if any(x in ostype_val for x in ["win", "w10", "w11", "wxp", "w2k"]):
                            os_type_scan = "windows"
                        firmware_scan = "efi" if (cfg.get("efidisk0") or
                                                   (cfg.get("bios", "") or "").lower() == "ovmf") else "bios"
                    except Exception:
                        pass
                    vms.append({
                        "vmid": vmid,
                        "name": vm.get("name", f"vm-{vmid}"),
                        "node": node,
                        "status": vm.get("status", "unknown"),
                        "vcpus": int(vm.get("cpus", 1)),
                        "memory_mb": int((vm.get("maxmem") or 0) // (1024 * 1024)),
                        "disk_gb": disk_gb,
                        "disk_count": disk_count,
                        "os_type": os_type_scan,
                        "firmware": firmware_scan,
                        "networks": networks_info,
                    })
            except Exception as _ne:
                ev.warn(f"Proxmox node {node} listelenemedi: {_ne}", category="migration")
        return ok(vms=vms, node_count=len(nodes_data))
    except Exception as e:
        return err(f"Proxmox bağlanamadı: {e}", 502)


@app.route("/api/migration/proxmox/import", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_migration_proxmox_import():
    """Proxmox VM'lerini OXware'e toplu aktar."""
    d = request.get_json() or {}
    px_host = d.get("host", "").strip()
    px_port = int(d.get("port", 8006))
    px_token_id = d.get("token_id", "").strip()
    px_token_secret = d.get("token_secret", "").strip()
    verify_ssl = bool(d.get("verify_ssl", False))
    ssh_host = d.get("ssh_host", "").strip() or px_host
    ssh_port = int(d.get("ssh_port", 22))
    ssh_user = d.get("ssh_user", "root").strip()
    ssh_password = d.get("ssh_password", "").strip()
    vms_req = d.get("vms", [])
    network = (d.get("network") or "default").strip() or "default"
    if not px_host or not px_token_id or not px_token_secret:
        return err("host, token_id, token_secret gerekli", 400)
    if not ssh_password:
        return err("ssh_password gerekli (Proxmox node SSH erişimi için)", 400)
    if not vms_req:
        return err("vms listesi boş", 400)

    import uuid as _uidpx
    job_ids = []
    _IMPORT_DIR.mkdir(parents=True, exist_ok=True)

    for vm_spec in vms_req[:20]:
        vmid = vm_spec.get("vmid")
        node = vm_spec.get("node", "")
        vm_name = (vm_spec.get("name") or f"vm-{vmid}").replace(" ", "_")
        if not vmid or not node:
            continue
        job_id = _uidpx.uuid4().hex[:8]
        with _import_jobs_lock:
            _import_jobs[job_id] = {
                "id": job_id, "filename": f"proxmox-{vmid}",
                "vm_name": vm_name, "source": "proxmox",
                "status": "running", "step": "Başlıyor...",
                "percent": 0, "started": time.time(),
                "finished": None, "message": "",
            }
        job_ids.append(job_id)

        def _run_px(j_id, j_vmid, j_node, j_vm_name, j_net_map):
            try:
                _import_job_update(j_id, step="VM config alınıyor", percent=3)
                cfg = _proxmox_request(
                    px_host, px_port, px_token_id, px_token_secret,
                    f"/nodes/{j_node}/qemu/{j_vmid}/config",
                    verify_ssl=verify_ssl) or {}
                disk_keys = _proxmox_get_disk_keys(cfg)
                if not disk_keys:
                    _import_job_update(j_id, status="error",
                                       step="Hata: export edilebilir disk yok",
                                       percent=0, finished=time.time())
                    return
                vcpus = int(cfg.get("sockets", 1)) * int(cfg.get("cores", 1))
                ram_mb = int(cfg.get("memory") or 2048)
                os_type = "linux"
                ostype_val = (cfg.get("ostype") or "").lower()
                if any(x in ostype_val for x in ["win", "w10", "w11", "wxp", "w2k"]):
                    os_type = "windows"
                firmware = "efi" if (cfg.get("efidisk0") or
                                     (cfg.get("bios", "") or "").lower() == "ovmf") else "bios"

                # Map Proxmox networks → libvirt networks
                px_nets = _proxmox_parse_networks(cfg)
                libvirt_nets = []
                for pn in px_nets:
                    bridge = pn["bridge"]
                    # User may supply explicit mapping via j_net_map {bridge: libvirt_net}
                    mapped = j_net_map.get(bridge) or _map_source_network(bridge, network)
                    libvirt_nets.append({"libvirt_network": mapped, "model": pn["model"]})
                if not libvirt_nets:
                    libvirt_nets = [{"libvirt_network": network,
                                     "model": "virtio" if os_type == "linux" else "e1000"}]

                # Export ALL disks
                _IMPORT_DIR.mkdir(parents=True, exist_ok=True)
                local_disks = _proxmox_ssh_export_all(
                    ssh_host, ssh_port, ssh_user, ssh_password,
                    j_vmid, disk_keys, _IMPORT_DIR, j_id)

                _import_job_update(j_id, step=f"libvirt'e kaydediliyor ({len(local_disks)} disk)", percent=82)

                # Deduplicate VM name
                import libvirt as _lv_px
                _conn_px = _lv_px.open(config.LIBVIRT_URI)
                final_name = j_vm_name
                sfx = 0
                try:
                    while True:
                        try:
                            _conn_px.lookupByName(final_name)
                            sfx += 1
                            final_name = f"{j_vm_name}-{sfx}"
                        except _lv_px.libvirtError:
                            break
                finally:
                    _conn_px.close()

                # Move disks to /var/lib/libvirt/images/
                import shutil as _shpx
                final_disks = []
                img_dir = _pathlib.Path("/var/lib/libvirt/images")
                for dk_i, (lp, lfmt) in enumerate(local_disks):
                    suffix = "" if dk_i == 0 else f"-disk{dk_i}"
                    dst = img_dir / f"{final_name}{suffix}.qcow2"
                    _shpx.move(lp, str(dst))
                    final_disks.append((str(dst), lfmt))

                xml_px = _build_import_xml_multi(final_name, final_disks, vcpus, ram_mb,
                                                 os_type, firmware, libvirt_nets)
                import libvirt as _lv_px2
                _conn_px2 = _lv_px2.open(config.LIBVIRT_URI)
                try:
                    _conn_px2.defineXML(xml_px)
                finally:
                    _conn_px2.close()

                disk_summary = f"{len(final_disks)} disk, {len(libvirt_nets)} NIC"
                _import_job_update(j_id, vm_name=final_name, status="completed",
                                   step=f"Tamamlandı: {final_name} ({disk_summary})",
                                   percent=100, finished=time.time())
                ev.info(f"Proxmox migration tamamlandı: {final_name} vmid={j_vmid} "
                        f"({len(final_disks)} disk, {len(libvirt_nets)} NIC)",
                        category="migration")
            except Exception as ex:
                _import_job_update(j_id, status="error",
                                   step=f"Hata: {ex}", percent=0,
                                   message=str(ex), finished=time.time())
                ev.error(f"Proxmox migration hata vmid={j_vmid}: {ex}", category="migration")

        # net_map: {proxmox_bridge: libvirt_network} from request, or empty
        net_map = vm_spec.get("net_map") or d.get("net_map") or {}
        threading.Thread(target=_run_px, args=(job_id, vmid, node, vm_name, net_map),
                         daemon=True).start()

    if not job_ids:
        return err("Geçerli VM bulunamadı", 400)
    ev.info(f"Proxmox bulk migration başlatıldı: {len(job_ids)} VM", category="migration")
    return ok(job_ids=job_ids, started=len(job_ids))


@app.route("/api/migration/esxi/scan", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_migration_esxi_scan():
    """ESXi SSH ile VM listesi döndür (vim-cmd vmsvc/getallvms)."""
    d = request.get_json() or {}
    host = d.get("host", "").strip()
    port = int(d.get("port", 22))
    user = d.get("username", "root").strip()
    password = d.get("password", "").strip()
    if not host or not password:
        return err("host ve password gerekli", 400)
    try:
        import paramiko as _pmesxi
        client = _pmesxi.SSHClient()
        client.set_missing_host_key_policy(_pmesxi.AutoAddPolicy())
        client.connect(host, port=port, username=user, password=password,
                       timeout=20, look_for_keys=False, allow_agent=False)
        try:
            _, stdout, _ = client.exec_command("vim-cmd vmsvc/getallvms 2>/dev/null", timeout=30)
            raw = stdout.read().decode(errors="replace")
            vms = []
            import re as _re_esxi
            for line in raw.strip().splitlines():
                parts = line.split(None, 5)
                if len(parts) < 4:
                    continue
                try:
                    vmid = int(parts[0])
                except ValueError:
                    continue
                name = parts[1]
                datastore = parts[2].strip("[]")
                vmx_path = parts[3] if len(parts) > 3 else ""
                guestid = parts[4] if len(parts) > 4 else ""
                # ── Resolve actual VMX directory ─────────────────────────────────
                # datastore1 is a symlink → UUID path. ESXi BusyBox SSH does not
                # follow symlinks with cat/grep; find -maxdepth also unreliable.
                # Shell glob expansion IS reliable: ls /vmfs/volumes/*/<rel> works
                # because the shell expands * over real UUID directories.
                # vmx_path (parts[3]) = relative path e.g. "vmname/vmname.vmx"
                _vmx_rel = vmx_path.strip() if vmx_path.strip() \
                    else f"{name}/{name}.vmx"
                _, _gl_out, _ = client.exec_command(
                    f"ls /vmfs/volumes/*/{_vmx_rel} 2>/dev/null | head -1",
                    timeout=8)
                _vmx_abs = _gl_out.read().decode(errors="replace").strip()
                if _vmx_abs:
                    vmx_dir = _vmx_abs.rsplit("/", 1)[0]
                else:
                    vmx_dir = "/vmfs/volumes/" + datastore + "/" + name
                # ── Power state ───────────────────────────────────────────────────
                _, ps_out, _ = client.exec_command(
                    f"vim-cmd vmsvc/power.getstate {vmid} 2>/dev/null", timeout=8)
                ps_text = ps_out.read().decode(errors="replace").lower()
                status = ("running" if "on" in ps_text
                          else ("off" if "off" in ps_text else "unknown"))

                import re as _re_vc

                # ── 1. vim-cmd vmsvc/get.config → CPU / RAM / firmware / guestId ──
                _, _cfg_out, _ = client.exec_command(
                    f"vim-cmd vmsvc/get.config {vmid} 2>/dev/null", timeout=15)
                _cfg_txt = _cfg_out.read().decode(errors="replace")
                # numCPU (VirtualHardware) or numCpus (ConfigInfo) — case-insensitive
                _m_cpu  = _re_vc.search(r'(?i)numcpus?\s*=\s*(\d+)', _cfg_txt)
                _m_ram  = _re_vc.search(r'memoryMB\s*=\s*(\d+)', _cfg_txt)
                _m_fw   = _re_vc.search(r'firmware\s*=\s*"([^"]+)"', _cfg_txt)
                _m_gos  = _re_vc.search(r'guestId\s*=\s*"([^"]+)"', _cfg_txt)
                # Networks: deviceName in NetworkBackingInfo
                _m_nets = _re_vc.findall(r'deviceName\s*=\s*"([^"]+)"', _cfg_txt)

                vcpus    = int(_m_cpu.group(1)) if _m_cpu else 2
                ram_mb   = int(_m_ram.group(1)) if _m_ram else 2048
                firmware = "efi" if (_m_fw and "efi" in _m_fw.group(1).lower()) else "bios"
                cfg_nets = [{"key": f"ethernet{i}",
                             "network_name": n, "model": "e1000"}
                            for i, n in enumerate(_m_nets)]

                # ── 2. vim-cmd vmsvc/get.filepaths → disk paths + virtual size ────
                # Most reliable: no filesystem access, no symlink issues,
                # returns diskDescriptor (path) and diskExtent (size in bytes).
                _, _fp_out, _ = client.exec_command(
                    f"vim-cmd vmsvc/get.filepaths {vmid} 2>/dev/null", timeout=15)
                _fp_txt = _fp_out.read().decode(errors="replace")
                cfg_disks = []
                disk_gb   = 0
                # Split on each FileInfo block, parse name/type/size within each
                _fp_blocks = _re_vc.split(
                    r'\(vim\.vm\.FileLayoutEx\.FileInfo\)', _fp_txt)
                for _blk in _fp_blocks[1:]:
                    _mn = _re_vc.search(r'name\s*=\s*"([^"]+)"', _blk)
                    _mt = _re_vc.search(r'type\s*=\s*"([^"]+)"', _blk)
                    _ms = _re_vc.search(r'\bsize\s*=\s*(\d+)', _blk)
                    if not (_mn and _mt):
                        continue
                    _fn, _ft = _mn.group(1), _mt.group(1)
                    _fs = int(_ms.group(1)) if _ms else 0
                    if _ft == "diskDescriptor":
                        _dm = _re_vc.match(r'\[([^\]]+)\]\s*(.+\.vmdk)', _fn)
                        if _dm and "-flat" not in _dm.group(2).lower():
                            cfg_disks.append(
                                f"/vmfs/volumes/{_dm.group(1)}/{_dm.group(2).strip()}")
                    elif _ft == "diskExtent" and disk_gb == 0 and _fs > 0:
                        disk_gb = round(_fs / (1024 ** 3), 1)

                # ── 3. VMX parse fallback (readlink resolves symlink) ─────────────
                vmx_info = _esxi_parse_vmx_ssh(client, vmx_dir, name)
                if not cfg_disks:
                    cfg_disks = vmx_info.get("disks", [])
                if not cfg_nets:
                    cfg_nets = vmx_info.get("networks", [])
                if not disk_gb:
                    disk_gb = vmx_info.get("disk_gb", 0)
                # get.config capacityInKB/Bytes
                if not disk_gb:
                    _m_db  = _re_vc.search(r'capacityInBytes\s*=\s*(\d+)', _cfg_txt)
                    _m_dkb = _re_vc.search(r'capacityInKB\s*=\s*(\d+)', _cfg_txt)
                    if _m_db:
                        disk_gb = round(int(_m_db.group(1)) / (1024 ** 3), 1)
                    elif _m_dkb:
                        disk_gb = round(int(_m_dkb.group(1)) / (1024 * 1024), 1)

                # ── 4. Derive VMDK path from getallvms data (vmkfstools accepts symlinks) ──
                # vmx_path = "ubuntuoxware/ubuntuoxware.vmx" → stem + ".vmdk"
                if not cfg_disks and vmx_path:
                    _stem = vmx_path.strip().rsplit(".", 1)[0]  # "ubuntuoxware/ubuntuoxware"
                    _derived = f"/vmfs/volumes/{datastore}/{_stem}.vmdk"
                    cfg_disks = [_derived]

                # ── 5. Disk size from flat VMDK ls -l ─────────────────────────────
                if not disk_gb and cfg_disks:
                    try:
                        _flat = cfg_disks[0].rsplit(".", 1)[0] + "-flat.vmdk"
                        _, _lz, _ = client.exec_command(
                            f"ls -la '{_flat}' 2>/dev/null | awk '{{print $5}}'",
                            timeout=6)
                        _sz = _lz.read().decode().strip()
                        if _sz.isdigit() and int(_sz) > 0:
                            disk_gb = round(int(_sz) / (1024 ** 3), 1)
                    except Exception:
                        pass

                disk_gb = disk_gb or 1

                # OS type
                _gos = (_m_gos.group(1) if _m_gos else guestid).lower()
                if any(x in _gos for x in ["win", "windows", "server2"]):
                    os_type = "windows"
                elif any(x in _gos for x in ["linux", "ubuntu", "centos", "rhel",
                                              "fedora", "debian", "suse", "oracle",
                                              "rocky", "alma", "freebsd"]):
                    os_type = "linux"
                else:
                    os_type = vmx_info.get("os_type") or _detect_os_from_name(name)

                vms.append({
                    "vmid": vmid, "name": name, "datastore": datastore,
                    "vmx_path": vmx_path, "vmx_dir": vmx_dir,
                    "status": status, "guestid": guestid,
                    "os_type": os_type, "disk_gb": disk_gb,
                    "vcpus": vcpus,
                    "memory_mb": ram_mb,
                    "firmware": firmware,
                    "networks": cfg_nets,
                    "disks": cfg_disks,
                    "disk_count": len(cfg_disks) or 1,
                })
        finally:
            client.close()
        return ok(vms=vms)
    except ImportError:
        return err("paramiko kurulu değil: pip install paramiko", 500)
    except Exception as e:
        return err(f"ESXi SSH bağlantı hatası: {e}", 502)


@app.route("/api/migration/esxi/import", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_migration_esxi_import():
    """ESXi VM'lerini OXware'e toplu aktar (SSH SFTP + qemu-img convert)."""
    d = request.get_json() or {}
    host = d.get("host", "").strip()
    port = int(d.get("port", 22))
    user = d.get("username", "root").strip()
    password = d.get("password", "").strip()
    vms_req = d.get("vms", [])
    network = (d.get("network") or "default").strip() or "default"
    if not host or not password or not vms_req:
        return err("host, password ve vms gerekli", 400)

    import uuid as _uidesxi
    job_ids = []
    _IMPORT_DIR.mkdir(parents=True, exist_ok=True)

    for vm_spec in vms_req[:20]:
        vmid = vm_spec.get("vmid", "x")
        vm_name = (vm_spec.get("name") or f"esxi-{vmid}").replace(" ", "_")
        vmx_dir = vm_spec.get("vmx_dir", "")
        os_type = vm_spec.get("os_type", "unknown")
        job_id = _uidesxi.uuid4().hex[:8]
        with _import_jobs_lock:
            _import_jobs[job_id] = {
                "id": job_id, "filename": f"esxi-{vmid}",
                "vm_name": vm_name, "source": "esxi",
                "status": "running", "step": "Başlıyor...",
                "percent": 0, "started": time.time(),
                "finished": None, "message": "",
            }
        job_ids.append(job_id)

        def _run_esxi(j_id, j_vmid, j_vm_name, j_vmx_dir, j_os_type,
                      j_vcpus, j_ram_mb, j_firmware, j_vmx_disks, j_vmx_nets, j_net_map):
            try:
                # Check cancellation before connecting
                with _import_jobs_lock:
                    if _import_jobs.get(j_id, {}).get("status") == "cancelled":
                        return
                # Limit total concurrent migrations (disk + network saturation guard)
                _import_job_update(j_id, step="Migration sırası bekleniyor...", percent=1)
                _esxi_pipeline_sem.acquire()
                _pipeline_held = True
                import paramiko as _pme2
                _import_job_update(j_id, step=f"ESXi SSH bekleniyor: {host}", percent=3)
                # Check lockout guard before acquiring semaphore
                with _esxi_lockout_lock:
                    _lo_remaining = _esxi_lockout_until[0] - time.time()
                if _lo_remaining > 0:
                    raise RuntimeError(
                        f"ESXi SSH hesabı kilitli — {int(_lo_remaining)}s sonra tekrar dene")
                # Limit concurrent ESXi SSH logins to prevent account lockout.
                _esxi_ssh_sem.acquire()
                _esxi_sem_held = True
                _import_job_update(j_id, step=f"ESXi SSH: {host}", percent=5)
                client2 = _pme2.SSHClient()
                client2.set_missing_host_key_policy(_pme2.AutoAddPolicy())
                try:
                    client2.connect(host, port=port, username=user, password=password,
                                    timeout=30, look_for_keys=False, allow_agent=False)
                except _pme2.AuthenticationException as _ae:
                    # Mark lockout: ESXi locks for 900s after repeated failures
                    with _esxi_lockout_lock:
                        _esxi_lockout_until[0] = time.time() + 900
                    raise RuntimeError(
                        f"ESXi SSH kimlik doğrulama hatası — hesap kilitlenmiş olabilir. "
                        f"15 dakika bekleyip tekrar dene. ({_ae})")
                local_raws = []  # [(local_raw_path, disk_size_bytes), ...]
                try:
                    # ── Auto-shutdown running VM ──────────────────────────────────────
                    # vmkfstools on a running VM can produce inconsistent disk snapshot.
                    # Graceful shutdown first; force-off after 90s if needed.
                    _, _ps_chk, _ = client2.exec_command(
                        f"vim-cmd vmsvc/power.getstate {j_vmid} 2>/dev/null", timeout=8)
                    _ps_chk_txt = _ps_chk.read().decode(errors="replace").lower()
                    if "on" in _ps_chk_txt:
                        _import_job_update(
                            j_id, step="VM çalışıyor — kapatılıyor...", percent=4)
                        ev.info(f"ESXi VM kapatılıyor: {j_vm_name} vmid={j_vmid}",
                                category="migration")
                        client2.exec_command(
                            f"vim-cmd vmsvc/power.shutdown {j_vmid} 2>/dev/null",
                            timeout=10)
                        for _wi in range(18):  # wait up to 90s
                            time.sleep(5)
                            _, _ps2, _ = client2.exec_command(
                                f"vim-cmd vmsvc/power.getstate {j_vmid} 2>/dev/null",
                                timeout=5)
                            if "off" in _ps2.read().decode(errors="replace").lower():
                                break
                        else:
                            client2.exec_command(
                                f"vim-cmd vmsvc/power.off {j_vmid} 2>/dev/null",
                                timeout=10)
                            time.sleep(5)

                    # ── Determine VMDK descriptor paths ──────────────────────────────
                    # j_vmx_disks: absolute paths from VMX scan (preferred).
                    # Fallback: resolve real VMFS path (skip datastore symlink), then ls.
                    if j_vmx_disks:
                        desc_paths = list(j_vmx_disks)
                    else:
                        _import_job_update(j_id, step="VMDK listesi alınıyor...", percent=6)
                        import re as _re_fb
                        desc_paths = []

                        # ── Primary: vim-cmd vmsvc/get.filepaths (no filesystem access) ──
                        _, _fp2_out, _ = client2.exec_command(
                            f"vim-cmd vmsvc/get.filepaths {j_vmid} 2>/dev/null",
                            timeout=15)
                        _fp2_txt = _fp2_out.read().decode(errors="replace")
                        _fp2_blocks = _re_fb.split(
                            r'\(vim\.vm\.FileLayoutEx\.FileInfo\)', _fp2_txt)
                        for _blk2 in _fp2_blocks[1:]:
                            _mn2 = _re_fb.search(r'name\s*=\s*"([^"]+)"', _blk2)
                            _mt2 = _re_fb.search(r'type\s*=\s*"([^"]+)"', _blk2)
                            if not (_mn2 and _mt2):
                                continue
                            if _mt2.group(1) == "diskDescriptor":
                                _dm2 = _re_fb.match(
                                    r'\[([^\]]+)\]\s*(.+\.vmdk)', _mn2.group(1))
                                if _dm2 and "-flat" not in _dm2.group(2).lower():
                                    desc_paths.append(
                                        f"/vmfs/volumes/{_dm2.group(1)}"
                                        f"/{_dm2.group(2).strip()}")

                        # ── Fallback: readlink → real dir → ls *.vmdk ──────────────
                        if not desc_paths:
                            _ds_name2 = j_vmx_dir.strip("/").split("/")[2] \
                                if j_vmx_dir.count("/") >= 3 else ""
                            _real_dir2 = j_vmx_dir.rstrip("/")
                            if _ds_name2:
                                _, _rl2_o, _ = client2.exec_command(
                                    f"readlink /vmfs/volumes/{_ds_name2} 2>/dev/null",
                                    timeout=5)
                                _rl2 = _rl2_o.read().decode().strip()
                                if _rl2:
                                    _rvol2 = _rl2 if _rl2.startswith("/") \
                                        else f"/vmfs/volumes/{_rl2}"
                                    _real_dir2 = j_vmx_dir.replace(
                                        f"/vmfs/volumes/{_ds_name2}", _rvol2, 1
                                    ).rstrip("/")
                            _, _ls2, _ = client2.exec_command(
                                f"ls '{_real_dir2}'/*.vmdk 2>/dev/null", timeout=15)
                            for _ln in _ls2.read().decode(errors="replace").splitlines():
                                _ln = _ln.strip()
                                if not _ln:
                                    continue
                                _bn = _ln.rsplit("/", 1)[-1].lower()
                                if "-flat" not in _bn and not _re_vmdk_extent.search(_bn):
                                    desc_paths.append(_ln)

                        # ── Last resort: derive from vmx_dir + vm_name ───────────
                        # vmkfstools is an ESXi-native tool — it CAN follow
                        # /vmfs/volumes/datastore1 symlinks directly.
                        if not desc_paths:
                            _derived2 = j_vmx_dir.rstrip("/") + "/" + j_vm_name + ".vmdk"
                            _, _dv, _ = client2.exec_command(
                                f"ls '{_derived2}' 2>/dev/null", timeout=5)
                            if _dv.read().decode().strip():
                                desc_paths = [_derived2]

                        if not desc_paths:
                            raise RuntimeError(
                                f"VMDK bulunamadı: vmid={j_vmid} "
                                f"dir={j_vmx_dir} "
                                f"derived={j_vmx_dir.rstrip('/')}/{j_vm_name}.vmdk"
                            )

                    total_disks = len(desc_paths)
                    for d_idx, desc_path in enumerate(desc_paths):
                        desc_dir  = desc_path.rsplit("/", 1)[0]
                        desc_name = desc_path.rsplit("/", 1)[-1]
                        # Unique names for the thick clone on ESXi
                        thick_stem = f"oxw_thick_{j_vmid}_{d_idx}"
                        thick_desc = f"{desc_dir}/{thick_stem}.vmdk"
                        thick_flat = f"{desc_dir}/{thick_stem}-flat.vmdk"
                        pct_base = 5 + d_idx * 60 // max(total_disks, 1)
                        pct_end  = 5 + (d_idx + 1) * 60 // max(total_disks, 1)

                        # ── Resolve datastore symlink → real UUID path ───────────────
                        # BusyBox cat/grep can't read file contents through
                        # /vmfs/volumes/datastore1 symlinks in exec_command context.
                        # readlink resolves to real UUID path; use that for all reads.
                        import re as _rw_re
                        _desc_ds = desc_dir.strip("/").split("/")[2] \
                            if desc_dir.count("/") >= 3 else ""
                        _real_desc_dir = desc_dir
                        if _desc_ds:
                            _, _rl_d, _ = client2.exec_command(
                                f"readlink /vmfs/volumes/{_desc_ds} 2>/dev/null",
                                timeout=5)
                            _rl_dv = _rl_d.read().decode().strip()
                            if _rl_dv:
                                _rl_vol = _rl_dv if _rl_dv.startswith("/") \
                                    else f"/vmfs/volumes/{_rl_dv}"
                                _real_desc_dir = desc_dir.replace(
                                    f"/vmfs/volumes/{_desc_ds}", _rl_vol, 1)
                        real_desc_path = _real_desc_dir.rstrip("/") + "/" + desc_name

                        # ── Find thin flat extent from VMDK descriptor ────────────────
                        # Read "RW <sectors> VMFS \"filename-flat.vmdk\"" line.
                        # No vmkfstools needed: VMFS returns zeros for unallocated thin
                        # blocks on read, so dd gives a complete raw image directly.
                        _import_job_update(
                            j_id,
                            step=f"VMDK descriptor okunuyor [{d_idx+1}/{total_disks}]",
                            percent=pct_base)
                        _, _rw_out, _ = client2.exec_command(
                            f"grep '^RW' '{real_desc_path}' 2>/dev/null | head -1",
                            timeout=8)
                        _rw_line = _rw_out.read().decode(errors="replace").strip()
                        _rw_m = _rw_re.search(
                            r'RW\s+(\d+)\s+\w+\s+"([^"]+)"', _rw_line)
                        if _rw_m:
                            disk_size = int(_rw_m.group(1)) * 512
                            thin_flat = _real_desc_dir.rstrip("/") + "/" + _rw_m.group(2)
                        else:
                            # Fallback: derive flat name, get size from ls -l (real path)
                            thin_flat = real_desc_path.rsplit(".", 1)[0] + "-flat.vmdk"
                            _, _lz, _ = client2.exec_command(
                                f"ls -l '{thin_flat}' 2>/dev/null | awk '{{print $5}}'",
                                timeout=6)
                            _lz_txt = _lz.read().decode().strip()
                            disk_size = int(_lz_txt) if _lz_txt.isdigit() else 0
                        if not disk_size:
                            raise RuntimeError(
                                f"Disk boyutu alınamadı: {real_desc_path} "
                                f"| RW='{_rw_line}' | readlink={_real_desc_dir}")
                        _sz_gb = round(disk_size / (1024 ** 3), 1)
                        log.info("thin flat: %s  size=%d (%.1f GB)",
                                 thin_flat, disk_size, _sz_gb)

                        # ── Stream thin flat → OXware (sparse write) ─────────────────
                        # VMFS transparently returns zeros for unallocated thin grains.
                        # Sparse write skips zero 4 MB blocks → compact local raw file.
                        local_raw = _IMPORT_DIR / f"esxi_{j_vmid}_disk{d_idx}.raw"
                        _import_job_update(
                            j_id,
                            step=f"SSH stream [{d_idx+1}/{total_disks}]: {_sz_gb} GB",
                            percent=pct_base + 5)
                        _dd_stdin, _dd_stdout, _dd_stderr = client2.exec_command(
                            f"dd if='{thin_flat}' bs=4M 2>/dev/null")
                        _dd_chan = _dd_stdout.channel
                        _dd_chan.settimeout(None)  # blocking recv — no channel timeout
                        _CHUNK = 4 * 1024 * 1024   # 4 MB
                        _ZERO  = b'\x00' * _CHUNK
                        _streamed = 0
                        with open(str(local_raw), 'wb') as _rf:
                            _buf = b''
                            while True:
                                _data = _dd_chan.recv(_CHUNK)
                                if not _data:
                                    break
                                _buf += _data
                                # Process complete 4 MB chunks
                                while len(_buf) >= _CHUNK:
                                    _blk  = _buf[:_CHUNK]
                                    _buf  = _buf[_CHUNK:]
                                    if _blk == _ZERO:
                                        _rf.seek(_CHUNK, 1)   # sparse skip
                                    else:
                                        _rf.write(_blk)
                                    _streamed += _CHUNK
                                    # Progress every 64 MB
                                    if (_streamed % (64 * 1024 * 1024)) == 0:
                                        _mb  = round(_streamed / 1048576, 1)
                                        _tmb = round(disk_size / 1048576, 1)
                                        _sp  = pct_base + 5 + int(
                                            55 * _streamed / max(disk_size, 1))
                                        _import_job_update(
                                            j_id,
                                            step=(f"Stream [{d_idx+1}/{total_disks}]:"
                                                  f" {_mb}/{_tmb} MB"),
                                            percent=min(pct_end - 2, _sp))
                            # Write remaining partial block
                            if _buf:
                                _rf.write(_buf)
                                _streamed += len(_buf)
                            # Ensure file is exactly disk_size bytes
                            _rf.truncate(disk_size)
                        _dd_chan.recv_exit_status()
                        log.info("SSH stream tamamlandı: %s → %s (%.1f GB)",
                                 thin_flat, local_raw, _sz_gb)
                        ev.info(
                            f"ESXi SSH stream: {_sz_gb} GB → {local_raw.name}",
                            category="vm")

                        local_raws.append((str(local_raw), disk_size))
                finally:
                    client2.close()
                    _esxi_ssh_sem.release()
                    _esxi_sem_held = False

                # Cancellation check after SSH session
                with _import_jobs_lock:
                    if _import_jobs.get(j_id, {}).get("status") == "cancelled":
                        return

                # Deduplicate VM name
                import libvirt as _lv_esxi
                _conn_esxi = _lv_esxi.open(config.LIBVIRT_URI)
                final_name = j_vm_name
                sfx = 0
                try:
                    while True:
                        try:
                            _conn_esxi.lookupByName(final_name)
                            sfx += 1
                            final_name = f"{j_vm_name}-{sfx}"
                        except _lv_esxi.libvirtError:
                            break
                finally:
                    _conn_esxi.close()

                # ── Convert raw → qcow2 + ext4 fixup ────────────────────────────
                img_dir = _pathlib.Path("/var/lib/libvirt/images")
                final_disks = []
                for vd_idx, (local_raw_path, _disk_sz) in enumerate(local_raws):
                    suffix = "" if vd_idx == 0 else f"-disk{vd_idx}"
                    final_qcow2 = img_dir / f"{final_name}{suffix}.qcow2"
                    pct_conv = 72 + vd_idx * 15 // max(len(local_raws), 1)
                    _import_job_update(
                        j_id,
                        step=f"qemu-img dönüştürülüyor [{vd_idx+1}/{len(local_raws)}]",
                        percent=pct_conv)
                    conv = subprocess.run(
                        ["qemu-img", "convert", "-f", "raw", "-O", "qcow2",
                         local_raw_path, str(final_qcow2)],
                        capture_output=True, text=True, timeout=7200)
                    try:
                        _pathlib.Path(local_raw_path).unlink()
                    except Exception:
                        pass
                    if conv.returncode != 0:
                        raise RuntimeError(
                            f"qemu-img [{vd_idx}]: {conv.stderr[:300]}")

                    # ext4 fixup: clear metadata_csum + INODE_UNINIT flags in qcow2
                    # (pure-Python qcow2 parser — no guestfish/python3 in appliance)
                    try:
                        _import_job_update(
                            j_id,
                            step=f"ext4 fixup [{vd_idx+1}/{len(local_raws)}]",
                            percent=min(91, pct_conv + 5))
                        _fx_result = _qcow2_ext4_fixup(
                            str(final_qcow2), log_fn=log.info)
                        if _fx_result and _fx_result != "no ext4 patched":
                            ev.info(
                                f"ESXi ext4 fixup: {_fx_result[:200]}",
                                category="vm")
                            log.info("ext4 fixup: %s", _fx_result)
                    except Exception as _fx_err:
                        log.warning("ESXi ext4 fixup (non-critical): %s", _fx_err)

                    final_disks.append((str(final_qcow2), "qcow2"))

                # Map ESXi networks → libvirt.
                # Force e1000: ESXi guests use vmxnet3 driver which has no KVM
                # equivalent; e1000 works out-of-box with any guest OS.
                libvirt_nets = []
                for en in j_vmx_nets:
                    pg = en.get("network_name", "VM Network")
                    mapped = j_net_map.get(pg) or _map_source_network(pg, network)
                    libvirt_nets.append({"libvirt_network": mapped, "model": "e1000"})
                if not libvirt_nets:
                    libvirt_nets = [{"libvirt_network": network, "model": "e1000"}]

                _import_job_update(
                    j_id,
                    step=(f"libvirt'e kaydediliyor"
                          f" ({len(final_disks)} disk, {len(libvirt_nets)} NIC)"),
                    percent=92)
                xml_esxi = _build_import_xml_multi(
                    final_name, final_disks, j_vcpus, j_ram_mb,
                    j_os_type, j_firmware, libvirt_nets)
                import libvirt as _lv_esxi2
                _conn_esxi2 = _lv_esxi2.open(config.LIBVIRT_URI)
                try:
                    _conn_esxi2.defineXML(xml_esxi)
                finally:
                    _conn_esxi2.close()

                disk_summary = f"{len(final_disks)} disk, {len(libvirt_nets)} NIC"
                _import_job_update(j_id, vm_name=final_name, status="completed",
                                   step=f"Tamamlandı: {final_name} ({disk_summary})",
                                   percent=100, finished=time.time())
                ev.info(
                    f"ESXi migration tamamlandı: {final_name} vmid={j_vmid}"
                    f" ({disk_summary})",
                    category="migration")
            except Exception as ex:
                if locals().get("_esxi_sem_held"):
                    _esxi_ssh_sem.release()
                _import_job_update(j_id, status="error",
                                   step=f"Hata: {ex}", percent=0,
                                   message=str(ex), finished=time.time())
                ev.error(f"ESXi migration hata vmid={j_vmid}: {ex}", category="migration")
            finally:
                if locals().get("_pipeline_held"):
                    _esxi_pipeline_sem.release()

        # Pass VMX scan data so import uses correct CPU/RAM/firmware/networks/disks
        esxi_net_map = vm_spec.get("net_map") or d.get("net_map") or {}
        threading.Thread(
            target=_run_esxi,
            args=(job_id, vmid, vm_name, vmx_dir, os_type,
                  vm_spec.get("vcpus", 2),
                  vm_spec.get("memory_mb", 2048),
                  vm_spec.get("firmware", "bios"),
                  vm_spec.get("disks", []),
                  vm_spec.get("networks", []),
                  esxi_net_map),
            daemon=True).start()

    if not job_ids:
        return err("Geçerli VM bulunamadı", 400)
    ev.info(f"ESXi bulk migration başlatıldı: {len(job_ids)} VM", category="migration")
    return ok(job_ids=job_ids, started=len(job_ids))


@app.route("/api/migration/jobs", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_migration_jobs_list():
    """Tüm migration job'larını listele (Proxmox + ESXi + OVA)."""
    with _import_jobs_lock:
        all_jobs = [dict(j) for j in _import_jobs.values()]
    all_jobs.sort(key=lambda x: x.get("started", 0), reverse=True)
    return ok(jobs=all_jobs, count=len(all_jobs))


@app.route("/api/migration/jobs/<job_id>", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_migration_job_get(job_id):
    """Tek migration job durumu."""
    with _import_jobs_lock:
        job = _import_jobs.get(job_id)
    if not job:
        return err("Job bulunamadı", 404)
    return ok(job=dict(job))


@app.route("/api/migration/jobs/<job_id>/cancel", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_migration_job_cancel(job_id):
    """Running migration job'unu iptal et.
    Thread'e sinyal: status='cancelled' → thread aktif adımı bitince durur."""
    with _import_jobs_lock:
        job = _import_jobs.get(job_id)
        if not job:
            return err("Job bulunamadı", 404)
        if job.get("status") not in ("running", "pending"):
            return err(f"Job iptal edilemez (durum: {job.get('status')})", 400)
        job["status"] = "cancelled"
        job["step"] = "İptal edildi"
        job["finished"] = time.time()
    log.info("Migration job iptal edildi: %s", job_id)
    ev.warn(f"Migration job iptal edildi: {job_id}", category="migration")
    return ok(message="Job iptal edildi")


# ── Auto SSL cert — runs at import time (works with systemd/gunicorn too) ──────
if config.SSL_ENABLED:
    _ensure_ssl_cert(config.SSL_CERT, config.SSL_KEY)


# ── Ensure physical passthrough network exists (runs at import time) ──────────
def _startup_ensure_physnet():
    try:
        _r = network_manager.ensure_physnet()
        if _r.get("ok"):
            if _r.get("existing"):
                log.info("physnet: mevcut passthrough ağ bulundu → %s (%s)",
                         _r.get("name"), _r.get("mode"))
            else:
                log.info("physnet oluşturuldu: %s üzerinde %s",
                         _r.get("iface"), _r.get("name", "physnet"))
        else:
            log.warning("physnet oluşturulamadı: %s", _r.get("error"))
    except Exception as _e:
        log.warning("ensure_physnet başlatma hatası: %s", _e)

_startup_ensure_physnet()

# Servis başlangıcında MASQUERADE + ip_forward + kayıtlı port yönlendirmeleri geri yükle
def _startup_iptables():
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                       capture_output=True, timeout=5)
        try:
            _virbr_nets = network_manager.list_networks()
        except Exception:
            _virbr_nets = []
        for _vn in _virbr_nets:
            _vn_ip = _vn.get("ip")
            _vn_nm = _vn.get("netmask", "255.255.255.0")
            if _vn_ip and _vn.get("forward_mode") in ("nat", "", None):
                try:
                    import ipaddress as _ipa2
                    _net2 = str(_ipa2.IPv4Network(f"{_vn_ip}/{_vn_nm}", strict=False))
                    chk = subprocess.run([
                        "iptables", "-t", "nat", "-C", "POSTROUTING",
                        "-s", _net2, "!", "-d", _net2, "-j", "MASQUERADE"
                    ], capture_output=True, timeout=3)
                    if chk.returncode != 0:
                        subprocess.run([
                            "iptables", "-t", "nat", "-A", "POSTROUTING",
                            "-s", _net2, "!", "-d", _net2, "-j", "MASQUERADE"
                        ], capture_output=True, timeout=5)
                        log.info("Startup MASQUERADE eklendi: %s", _net2)
                except Exception:
                    pass
        _restore_iptables_rules()
    except Exception as _se:
        log.warning("Startup iptables hatası: %s", _se)

threading.Thread(target=_startup_iptables, daemon=True, name="startup-iptables").start()


# ══════════════════════════════════════════════════════════════════════════════
# ESXi Parity Modules — vSAN, DVS, DPM, Syslog, Content Library, Host Profile, Datastore
# ══════════════════════════════════════════════════════════════════════════════

vsan_mgr     = _safe_import("vsan_manager")
dvs_mgr      = _safe_import("dvs_manager")
dpm_mgr      = _safe_import("dpm_manager")
syslog_mgr   = _safe_import("syslog_manager")
cl_mgr       = _safe_import("content_library_manager")
hprof_mgr    = _safe_import("host_profile_manager")
ds_browser   = _safe_import("datastore_browser")


# ── vSAN ─────────────────────────────────────────────────────────────────────
@app.route("/api/vsan/status")
@require_auth
@require_role("admin", "administrator", "operator")
def api_vsan_status():
    if not vsan_mgr: return ok(available=False, error="vSAN modülü yüklenemedi")
    return ok(**vsan_mgr.get_status())

@app.route("/api/vsan/config", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_vsan_config():
    if not vsan_mgr: return err("vSAN modülü yüklenemedi")
    if request.method == "GET":
        return ok(config=vsan_mgr.get_config())
    d = request.get_json(silent=True) or {}
    return ok(config=vsan_mgr.save_config(**d))

@app.route("/api/vsan/osds")
@require_auth
@require_role("admin", "administrator", "operator")
def api_vsan_osds():
    if not vsan_mgr: return ok(osds=[])
    return ok(osds=vsan_mgr.get_osds())

@app.route("/api/vsan/pools")
@require_auth
@require_role("admin", "administrator", "operator")
def api_vsan_ceph_pools():
    if not vsan_mgr: return ok(pools=[])
    return ok(pools=vsan_mgr.get_pools())

@app.route("/api/vsan/pools", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_vsan_create_pool():
    if not vsan_mgr: return err("vSAN modülü yüklenemedi")
    d = request.get_json(silent=True) or {}
    try:
        result = vsan_mgr.create_pool(d.get("name",""), d.get("pg_num", 32), d.get("replication", 2))
        return ok(pool=result)
    except Exception as e:
        return err(e)


# ── DVS (Distributed Virtual Switch) ─────────────────────────────────────────
@app.route("/api/dvs")
@require_auth
@require_role("admin", "administrator", "operator")
def api_dvs_list():
    if not dvs_mgr: return ok(switches=[])
    return ok(switches=dvs_mgr.list_dvs())

@app.route("/api/dvs", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_dvs_create():
    if not dvs_mgr: return err("DVS modülü yüklenemedi")
    d = request.get_json(silent=True) or {}
    try:
        result = dvs_mgr.create_dvs(
            d.get("name", ""), d.get("description", ""),
            int(d.get("vlan_id", 0)), int(d.get("mtu", 1500)),
            d.get("uplinks"), d.get("nodes")
        )
        return ok(dvs=result), 201
    except Exception as e:
        return err(e)

@app.route("/api/dvs/<dvs_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_dvs_delete(dvs_id):
    if not dvs_mgr: return err("DVS modülü yüklenemedi")
    try:
        dvs_mgr.delete_dvs(dvs_id)
        return ok(status="deleted")
    except Exception as e:
        return err(e)

@app.route("/api/dvs/<dvs_id>/portgroups", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_dvs_add_portgroup(dvs_id):
    if not dvs_mgr: return err("DVS modülü yüklenemedi")
    d = request.get_json(silent=True) or {}
    try:
        result = dvs_mgr.add_port_group(dvs_id, d.get("name",""), int(d.get("vlan_id",0)), d.get("type","vm"))
        return ok(portgroup=result)
    except Exception as e:
        return err(e)

@app.route("/api/dvs/<dvs_id>/portgroups/<pg_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_dvs_del_portgroup(dvs_id, pg_id):
    if not dvs_mgr: return err("DVS modülü yüklenemedi")
    return ok(deleted=dvs_mgr.delete_port_group(dvs_id, pg_id))

@app.route("/api/dvs/<dvs_id>/uplinks", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_dvs_set_uplinks(dvs_id):
    if not dvs_mgr: return err("DVS modülü yüklenemedi")
    d = request.get_json(silent=True) or {}
    res = dvs_mgr.set_uplinks(dvs_id, d.get("uplinks") or [],
                              d.get("teaming_mode", "active-backup"))
    return (ok(dvs=res) if res else err("DVS bulunamadı", 404))

@app.route("/api/dvs/ovs-bridges")
@require_auth
@require_role("admin", "administrator", "operator")
def api_dvs_ovs_bridges():
    if not dvs_mgr: return ok(bridges=[])
    return ok(bridges=dvs_mgr.get_ovs_bridges())


# ── DPM (Distributed Power Management) ───────────────────────────────────────
@app.route("/api/dpm/config", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_dpm_config():
    if not dpm_mgr: return err("DPM modülü yüklenemedi")
    if request.method == "GET":
        return ok(config=dpm_mgr.get_config())
    d = request.get_json(silent=True) or {}
    return ok(config=dpm_mgr.save_config(**d))

@app.route("/api/dpm/nodes", methods=["GET"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_dpm_nodes():
    if not dpm_mgr: return ok(nodes=[])
    return ok(nodes=dpm_mgr.get_config().get("nodes", []))

@app.route("/api/dpm/nodes", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_dpm_add_node():
    if not dpm_mgr: return err("DPM modülü yüklenemedi")
    d = request.get_json(silent=True) or {}
    added = dpm_mgr.add_node(d.get("ip",""), d.get("name",""), d.get("mac",""))
    return ok(added=added)

@app.route("/api/dpm/nodes/<path:ip>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_dpm_remove_node(ip):
    if not dpm_mgr: return err("DPM modülü yüklenemedi")
    return ok(removed=dpm_mgr.remove_node(ip))

@app.route("/api/dpm/analyze")
@require_auth
@require_role("admin", "administrator", "operator")
def api_dpm_analyze():
    if not dpm_mgr: return ok(nodes=[], timestamp="")
    return ok(**dpm_mgr.analyze())

@app.route("/api/dpm/wakeup/<path:ip>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_dpm_wakeup(ip):
    if not dpm_mgr: return err("DPM modülü yüklenemedi")
    return ok(**dpm_mgr.wakeup_node(ip))


# ── Syslog / Log Viewer ───────────────────────────────────────────────────────
@app.route("/api/syslog/journal")
@require_auth
@require_role("admin", "administrator", "operator")
def api_syslog_journal():
    if not syslog_mgr: return ok(entries=[])
    lines   = int(request.args.get("lines", 200))
    service = request.args.get("service")
    level   = request.args.get("level", "info")
    since   = request.args.get("since")
    until   = request.args.get("until")
    return ok(**syslog_mgr.get_journal_logs(lines, service, level, since, until))

@app.route("/api/syslog/syslog")
@require_auth
@require_role("admin", "administrator", "operator")
def api_syslog_file():
    if not syslog_mgr: return ok(entries=[])
    lines        = int(request.args.get("lines", 200))
    level_filter = request.args.get("level")
    grep         = request.args.get("grep")
    return ok(**syslog_mgr.get_syslog(lines, level_filter, grep))

@app.route("/api/syslog/kernel")
@require_auth
@require_role("admin", "administrator", "operator")
def api_syslog_kernel():
    if not syslog_mgr: return ok(entries=[])
    return ok(**syslog_mgr.get_kernel_logs(int(request.args.get("lines", 100))))

@app.route("/api/syslog/oxware")
@require_auth
@require_role("admin", "administrator", "operator")
def api_syslog_oxware():
    if not syslog_mgr: return ok(entries=[])
    return ok(**syslog_mgr.get_oxware_logs(int(request.args.get("lines", 200))))

@app.route("/api/syslog/services")
@require_auth
@require_role("admin", "administrator", "operator")
def api_syslog_services():
    if not syslog_mgr: return ok(services=[])
    return ok(services=syslog_mgr.get_services())

@app.route("/api/syslog/core-dumps")
@require_auth
@require_role("admin", "administrator")
def api_syslog_core_dumps():
    if not syslog_mgr: return ok(dumps=[])
    return ok(dumps=syslog_mgr.get_core_dumps())


# ── Content Library ───────────────────────────────────────────────────────────
@app.route("/api/content-library")
@require_auth
@require_role("admin", "administrator", "operator")
def api_cl_list():
    if not cl_mgr: return ok(items=[])
    return ok(items=cl_mgr.list_items(), stats=cl_mgr.get_stats())

@app.route("/api/content-library", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_cl_add():
    if not cl_mgr: return err("Content Library modülü yüklenemedi")
    d = request.get_json(silent=True) or {}
    result = cl_mgr.add_item(
        d.get("name",""), d.get("description",""),
        d.get("type","iso"), d.get("tags"),
        d.get("source_path"), d.get("url")
    )
    return ok(**result) if result.get("ok") else err(result.get("error","Hata"))

@app.route("/api/content-library/<item_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_cl_delete(item_id):
    if not cl_mgr: return err("Content Library modülü yüklenemedi")
    deleted = cl_mgr.delete_item(item_id)
    return ok(deleted=deleted) if deleted else err("Öğe bulunamadı", 404)

@app.route("/api/content-library/sync", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_cl_sync():
    if not cl_mgr: return err("Content Library modülü yüklenemedi")
    iso_dir = (request.get_json(silent=True) or {}).get("iso_dir", "/var/lib/libvirt/images")
    try:
        result = cl_mgr.sync_from_iso_pool(iso_dir)
        return ok(**result)
    except FileNotFoundError:
        return ok(imported=[], count=0,
                  message=f"ISO dizini bulunamadı: {iso_dir}")
    except PermissionError:
        return err(f"İzin hatası: {iso_dir} dizinine erişilemiyor")
    except Exception as e:
        return err(str(e), 500)


# ── Host Profiles ─────────────────────────────────────────────────────────────
@app.route("/api/host-profiles")
@require_auth
@require_role("admin", "administrator", "operator")
def api_hprof_list():
    if not hprof_mgr: return ok(profiles=[])
    return ok(profiles=hprof_mgr.list_profiles())

@app.route("/api/host-profiles", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_hprof_capture():
    if not hprof_mgr: return err("Host Profile modülü yüklenemedi")
    d = request.get_json(silent=True) or {}
    profile = hprof_mgr.capture_profile(d.get("name",""), d.get("description",""), d.get("tags"))
    return ok(profile=profile), 201

@app.route("/api/host-profiles/<profile_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_hprof_delete(profile_id):
    if not hprof_mgr: return err("Host Profile modülü yüklenemedi")
    return ok(deleted=hprof_mgr.delete_profile(profile_id))

@app.route("/api/host-profiles/<profile_id>/apply", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_hprof_apply(profile_id):
    if not hprof_mgr: return err("Host Profile modülü yüklenemedi")
    d = request.get_json(silent=True) or {}
    return ok(**hprof_mgr.apply_profile(profile_id, d.get("target_host","localhost")))


# ── Datastore Browser ─────────────────────────────────────────────────────────
@app.route("/api/datastore/browse")
@require_auth
@require_role("admin", "administrator", "operator")
def api_ds_browse():
    if not ds_browser: return ok(items=[])
    pool_path = request.args.get("pool", "/var/lib/libvirt/images")
    rel_path  = request.args.get("path", "")
    return ok(**ds_browser.list_directory(pool_path, rel_path))

@app.route("/api/datastore/info")
@require_auth
@require_role("admin", "administrator", "operator")
def api_ds_info():
    if not ds_browser: return ok()
    pool_path = request.args.get("pool", "/var/lib/libvirt/images")
    rel_path  = request.args.get("path", "")
    return ok(**ds_browser.get_file_info(pool_path, rel_path))

@app.route("/api/datastore/delete", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ds_delete():
    if not ds_browser: return err("Datastore modülü yüklenemedi")
    d = request.get_json(silent=True) or {}
    return ok(**ds_browser.delete_file(d.get("pool","/var/lib/libvirt/images"), d.get("path","")))

@app.route("/api/datastore/rename", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ds_rename():
    if not ds_browser: return err("Datastore modülü yüklenemedi")
    d = request.get_json(silent=True) or {}
    return ok(**ds_browser.rename_file(d.get("pool","/var/lib/libvirt/images"), d.get("path",""), d.get("new_name","")))

@app.route("/api/datastore/mkdir", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ds_mkdir():
    if not ds_browser: return err("Datastore modülü yüklenemedi")
    d = request.get_json(silent=True) or {}
    return ok(**ds_browser.create_directory(d.get("pool","/var/lib/libvirt/images"), d.get("path",""), d.get("name","")))

@app.route("/api/datastore/disk-usage")
@require_auth
@require_role("admin", "administrator", "operator")
def api_ds_disk_usage():
    if not ds_browser: return ok()
    pool_path = request.args.get("pool", "/var/lib/libvirt/images")
    return ok(**ds_browser.get_disk_usage(pool_path))


# ═══════════════════════════════════════════════════════════════════════════
# v2.5.3 Enterprise Modules — Routes
# ═══════════════════════════════════════════════════════════════════════════

# ── VM Thumbnails ───────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/thumbnail.png")
@require_auth
def api_vm_thumbnail(vm_id):
    if not vnc_thumb:
        return err("Thumbnail modülü yok", 503)
    try:
        vm = vm_manager.get_vm(vm_id)
        if vm.get("state") != "running":
            return err("VM çalışmıyor", 400)
        png = vnc_thumb.get_thumbnail(vm_id, vm.get("name"))
        if not png:
            return err("Yakalama başarısız (libvirt/virsh erişimi?)", 503)
        from flask import Response
        return Response(png, mimetype="image/png",
                        headers={"Cache-Control": "max-age=60"})
    except Exception as e:
        return err(e, 500)

@app.route("/api/thumbnails/stats")
@require_auth
@require_role("admin", "administrator")
def api_thumbnail_stats():
    if not vnc_thumb: return ok(available=False)
    return ok(**vnc_thumb.stats())


# ── Snapshot Cleanup ────────────────────────────────────────────────────────
@app.route("/api/snapshots/orphans")
@require_auth
@require_role("admin", "administrator")
def api_snap_orphans():
    if not snapshot_clean: return ok(orphans=[])
    return ok(orphans=snapshot_clean.find_orphans())

@app.route("/api/snapshots/cleanup", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_snap_cleanup():
    if not snapshot_clean: return err("Modül yok")
    dry = (request.get_json(silent=True) or {}).get("dry_run", True)
    return ok(**snapshot_clean.cleanup_orphans(dry_run=dry))

@app.route("/api/snapshots/policy", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_snap_policy():
    if not snapshot_clean: return err("Modül yok")
    if request.method == "GET":
        return ok(policy=snapshot_clean.get_policy())
    return ok(policy=snapshot_clean.set_policy(**(request.get_json(silent=True) or {})))


# ── Affinity Rules ──────────────────────────────────────────────────────────
@app.route("/api/affinity/rules", methods=["GET"])
@require_role("admin", "administrator")
def api_affinity_list():
    if not affinity_mgr: return ok(rules=[])
    return ok(rules=affinity_mgr.list_rules())

@app.route("/api/affinity/rules", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_affinity_create():
    if not affinity_mgr: return err("Modül yok")
    d = request.get_json(silent=True) or {}
    try:
        return ok(rule=affinity_mgr.add_rule(**d))
    except Exception as e:
        return err(e, 400)

@app.route("/api/affinity/rules/<rule_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_affinity_delete(rule_id):
    if not affinity_mgr: return err("Modül yok")
    return ok(deleted=affinity_mgr.delete_rule(rule_id))


# ── Backup Encryption ──────────────────────────────────────────────────────
@app.route("/api/backup/encrypt", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_backup_encrypt():
    if not backup_enc: return err("Modül yok")
    d = request.get_json(silent=True) or {}
    try:
        return ok(**backup_enc.encrypt_file(d["src"], d["dst"], d.get("passphrase")))
    except Exception as e:
        return err(e, 400)

@app.route("/api/backup/decrypt", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_backup_decrypt():
    if not backup_enc: return err("Modül yok")
    d = request.get_json(silent=True) or {}
    try:
        return ok(**backup_enc.decrypt_file(d["src"], d["dst"], d.get("passphrase")))
    except Exception as e:
        return err(e, 400)


# ── Linked Clones ──────────────────────────────────────────────────────────
@app.route("/api/linked-clones", methods=["GET"])
@require_role("admin", "administrator")
def api_lc_list():
    if not linked_clone: return ok(linked_clones=[])
    return ok(**linked_clone.stats())

@app.route("/api/linked-clones", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_lc_create():
    if not linked_clone: return err("Modül yok")
    d = request.get_json(silent=True) or {}
    try:
        return ok(**linked_clone.create_linked_clone(d["base_vm"], d["new_name"]))
    except Exception as e:
        return err(e, 400)


# ── SIEM Exporter ──────────────────────────────────────────────────────────
@app.route("/api/siem/config", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_siem_config():
    if not siem_exp: return err("Modül yok")
    if request.method == "GET":
        return ok(config=siem_exp.get_config())
    return ok(config=siem_exp.set_config(**(request.get_json(silent=True) or {})))

@app.route("/api/siem/test", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_siem_test():
    if not siem_exp: return err("Modül yok")
    return ok(**siem_exp.test_connection())


# ── Session Recording ──────────────────────────────────────────────────────
@app.route("/api/recordings")
@require_auth
@require_role("admin", "administrator")
def api_rec_list():
    if not session_rec: return ok(recordings=[])
    return ok(recordings=session_rec.list_recordings(),
              stats=session_rec.stats())

@app.route("/api/recordings/<rec_id>")
@require_auth
@require_role("admin", "administrator")
def api_rec_get(rec_id):
    if not session_rec: return err("Modül yok")
    try:
        data = session_rec.get_recording(rec_id)
        from flask import Response
        return Response(data, mimetype="application/x-asciicast",
                        headers={"Content-Disposition": f"attachment; filename={rec_id}.cast"})
    except Exception as e:
        return err(e, 404)

@app.route("/api/recordings/<rec_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_rec_delete(rec_id):
    if not session_rec: return err("Modül yok")
    return ok(deleted=session_rec.delete_recording(rec_id))


# ── Maintenance Mode ───────────────────────────────────────────────────────
@app.route("/api/maintenance/status")
@require_role("admin", "administrator")
def api_maint_status():
    if not maint_mode: return ok(in_maintenance=False)
    return ok(**maint_mode.get_status())

@app.route("/api/maintenance/enter", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_maint_enter():
    if not maint_mode: return err("Modül yok")
    d = request.get_json(silent=True) or {}
    return ok(**maint_mode.enter_maintenance(
        reason=d.get("reason", "Planned"),
        target_hosts=d.get("target_hosts"),
        dry_run=d.get("dry_run", False)
    ))

@app.route("/api/maintenance/exit", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_maint_exit():
    if not maint_mode: return err("Modül yok")
    d = request.get_json(silent=True) or {}
    return ok(**maint_mode.exit_maintenance(auto_start=d.get("auto_start", False)))


# ── EVC (CPU Compatibility) ────────────────────────────────────────────────
@app.route("/api/evc/baselines")
@require_role("admin", "administrator")
def api_evc_baselines():
    if not evc_mgr: return ok(baselines=[])
    return ok(baselines=evc_mgr.list_baselines(),
              current=evc_mgr.get_current_baseline(),
              host=evc_mgr.detect_host_capability())

@app.route("/api/evc/set-baseline", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_evc_set():
    if not evc_mgr: return err("Modül yok")
    name = (request.get_json(silent=True) or {}).get("name")
    return ok(config=evc_mgr.set_cluster_baseline(name))

@app.route("/api/evc/apply/<vm_id>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_evc_apply(vm_id):
    if not evc_mgr: return err("Modül yok")
    baseline = (request.get_json(silent=True) or {}).get("baseline")
    return ok(**evc_mgr.apply_baseline_to_vm(vm_id, baseline))


# ── NIOC (Network IO Control) ──────────────────────────────────────────────
@app.route("/api/nioc/profiles")
@require_role("admin", "administrator")
def api_nioc_profiles():
    if not nioc_mgr: return ok(profiles=[])
    return ok(profiles=nioc_mgr.list_profiles())

@app.route("/api/nioc/vm/<vm_id>", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_nioc_vm(vm_id):
    if not nioc_mgr: return err("Modül yok")
    if request.method == "GET":
        return ok(**nioc_mgr.get_vm_bandwidth(vm_id))
    d = request.get_json(silent=True) or {}
    if "profile" in d:
        return ok(**nioc_mgr.apply_profile_to_vm(vm_id, d["profile"]))
    return ok(**nioc_mgr.set_vm_bandwidth(
        vm_id, d.get("in_kbps", 0), d.get("out_kbps", 0), d.get("burst_kbps", 1024)
    ))


# ── OpenAPI spec ────────────────────────────────────────────────────────────
# Kayıtlı route'lardan minimal OpenAPI 3.0 üretir. Sadece yol + metot bilgisi
# (gövde şeması yok); gizli bilgi içermez. Otomasyon/keşif için public.
@app.route("/api/openapi")
def api_openapi():
    import re as _re
    paths = {}
    for rule in app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue
        # Flask <var> → OpenAPI {var}
        path = _re.sub(r"<(?:[^:>]+:)?([^>]+)>", r"{\1}", str(rule.rule))
        methods = sorted(m for m in (rule.methods or set())
                         if m not in ("HEAD", "OPTIONS"))
        if not methods:
            continue
        ops = paths.setdefault(path, {})
        for m in methods:
            ops[m.lower()] = {
                "operationId": rule.endpoint,
                "responses": {"200": {"description": "OK"}},
            }
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "OXware API", "version": "2.8.1"},
        "paths": paths,
    }
    from flask import jsonify as _jsonify
    return _jsonify(spec)


# ── Predictive Failure ─────────────────────────────────────────────────────
@app.route("/api/health/disks")
@require_auth
def api_health_disks():
    if not predictive_fail: return ok(disks=[])
    return ok(**predictive_fail.get_summary())

@app.route("/api/health/predictions")
@require_auth
def api_health_predictions():
    if not predictive_fail: return ok(predictions=[])
    threshold = int(request.args.get("threshold", 40))
    return ok(predictions=predictive_fail.get_predictions(threshold))


# ── Right-Sizing + Capacity Planning ───────────────────────────────────────
@app.route("/api/advisor/vm/<vm_id>")
@require_auth
def api_advisor_vm(vm_id):
    if not right_sizing: return err("Modül yok")
    period = request.args.get("period", "30d")
    return ok(**right_sizing.analyze_vm(vm_id, period))

@app.route("/api/advisor/recommendations")
@require_auth
@require_role("admin", "administrator", "operator")
def api_advisor_recs():
    if not right_sizing: return ok(recommendations=[])
    min_savings = int(request.args.get("min_savings", 10))
    return ok(recommendations=right_sizing.list_recommendations(min_savings))

@app.route("/api/advisor/capacity/<metric>")
@require_auth
def api_advisor_capacity(metric):
    if not right_sizing: return err("Modül yok")
    days = int(request.args.get("days", 90))
    return ok(**right_sizing.forecast_capacity(metric, days))


# ── Alert Correlation ──────────────────────────────────────────────────────
@app.route("/api/correlation/rules", methods=["GET"])
@require_auth
def api_corr_rules():
    if not alert_corr: return ok(rules=[])
    return ok(rules=alert_corr.list_rules())

@app.route("/api/correlation/incidents")
@require_auth
def api_corr_incidents():
    if not alert_corr: return ok(incidents=[])
    active = request.args.get("active_only", "1") == "1"
    return ok(incidents=alert_corr.list_incidents(active_only=active))

@app.route("/api/correlation/incidents/<inc_id>/resolve", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_corr_resolve(inc_id):
    if not alert_corr: return err("Modül yok")
    return ok(resolved=alert_corr.resolve_incident(inc_id))


# ── Site Recovery (DR) ─────────────────────────────────────────────────────
@app.route("/api/dr/plans", methods=["GET"])
@require_role("admin", "administrator")
def api_dr_plans():
    if not site_recovery: return ok(plans=[])
    return ok(plans=site_recovery.list_plans())

@app.route("/api/dr/plans", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_dr_create():
    if not site_recovery: return err("Modül yok")
    d = request.get_json(silent=True) or {}
    try:
        return ok(plan=site_recovery.create_dr_plan(**d))
    except Exception as e:
        return err(e, 400)

@app.route("/api/dr/plans/<plan_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_dr_delete(plan_id):
    if not site_recovery: return err("Modül yok")
    return ok(deleted=site_recovery.delete_plan(plan_id))

@app.route("/api/dr/plans/<plan_id>/execute", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_dr_execute(plan_id):
    if not site_recovery: return err("Modül yok")
    mode = (request.get_json(silent=True) or {}).get("mode", "test")
    return ok(**site_recovery.execute_plan(plan_id, mode))

@app.route("/api/dr/rpo-rto")
@require_role("admin", "administrator")
def api_dr_sla():
    if not site_recovery: return ok(plans=[])
    return ok(**site_recovery.get_rpo_rto_status())


# ── DRS ────────────────────────────────────────────────────────────────────
@app.route("/api/drs/analyze")
@require_role("admin", "administrator")
def api_drs_analyze():
    if not drs_mgr: return ok()
    return ok(**drs_mgr.analyze())

@app.route("/api/drs/policy", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_drs_policy():
    if not drs_mgr: return err("Modül yok")
    if request.method == "GET":
        return ok(policy=drs_mgr.get_policy())
    return ok(policy=drs_mgr.set_policy(**(request.get_json(silent=True) or {})))

@app.route("/api/drs/suggest")
@require_role("admin", "administrator")
def api_drs_suggest():
    if not drs_mgr: return ok(suggestions=[])
    return ok(suggestions=drs_mgr.suggest_moves())


# ── Lifecycle Manager ──────────────────────────────────────────────────────
@app.route("/api/lifecycle/updates")
@require_auth
@require_role("admin", "administrator")
def api_lc_updates():
    if not lifecycle_mgr: return err("Modül yok")
    return ok(**lifecycle_mgr.check_updates())

@app.route("/api/lifecycle/apply", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_lc_apply():
    if not lifecycle_mgr: return err("Modül yok")
    d = request.get_json(silent=True) or {}
    return ok(**lifecycle_mgr.apply_updates(
        packages=d.get("packages"),
        dry_run=d.get("dry_run", False),
        security_only=d.get("security_only", False)
    ))

@app.route("/api/lifecycle/baselines")
@require_auth
@require_role("admin", "administrator")
def api_lc_baselines():
    if not lifecycle_mgr: return ok(baselines=[])
    return ok(baselines=lifecycle_mgr.list_baselines())

@app.route("/api/lifecycle/baselines/<name>/capture", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_lc_capture(name):
    if not lifecycle_mgr: return err("Modül yok")
    return ok(baseline=lifecycle_mgr.capture_baseline(name))

@app.route("/api/lifecycle/drift/<name>")
@require_auth
@require_role("admin", "administrator")
def api_lc_drift(name):
    if not lifecycle_mgr: return err("Modül yok")
    return ok(**lifecycle_mgr.detect_drift(name))


# ── Compute Tuning ─────────────────────────────────────────────────────────
@app.route("/api/compute/hugepages", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_compute_hp():
    if not compute_tune: return err("Modül yok")
    if request.method == "GET":
        return ok(**compute_tune.hugepages_status())
    count = (request.get_json(silent=True) or {}).get("count", 0)
    return ok(**compute_tune.hugepages_configure(int(count)))

@app.route("/api/compute/ksm", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_compute_ksm():
    if not compute_tune: return err("Modül yok")
    if request.method == "GET":
        return ok(**compute_tune.ksm_status())
    d = request.get_json(silent=True) or {}
    return ok(**compute_tune.ksm_configure(
        d.get("enabled", True), d.get("pages_to_scan", 100), d.get("sleep_ms", 200)
    ))

@app.route("/api/compute/numa")
@require_auth
def api_compute_numa():
    if not compute_tune: return ok(available=False)
    return ok(**compute_tune.numa_topology())

@app.route("/api/compute/pcie")
@require_auth
@require_role("admin", "administrator")
def api_compute_pcie():
    if not compute_tune: return ok(devices=[])
    return ok(devices=compute_tune.list_pcie_devices(),
              iommu=compute_tune.list_iommu_groups())


# ── v2.8.2 Kernel pack: VM I/O performance ─────────────────────────────────────
@app.route("/api/io-perf/<vm_id>", methods=["GET"])
@require_auth
def api_io_perf_get(vm_id):
    if not io_perf: return err("Modül yok")
    return ok(**io_perf.get_io_config(vm_id))

@app.route("/api/io-perf/<vm_id>/recommend", methods=["GET"])
@require_auth
def api_io_perf_recommend(vm_id):
    if not io_perf: return err("Modül yok")
    return ok(**io_perf.recommend(vm_id))

@app.route("/api/io-perf/<vm_id>/iothreads", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_io_perf_iothreads(vm_id):
    if not io_perf: return err("Modül yok")
    d = request.get_json(silent=True) or {}
    return ok(**io_perf.set_iothreads(vm_id, int(d.get("count", 0))))

@app.route("/api/io-perf/<vm_id>/disk", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_io_perf_disk(vm_id):
    if not io_perf: return err("Modül yok")
    d = request.get_json(silent=True) or {}
    return ok(**io_perf.set_disk_perf(
        vm_id, d.get("target", ""), aio=d.get("aio"), cache=d.get("cache"),
        iothread=d.get("iothread"), queues=d.get("queues")))

@app.route("/api/io-perf/<vm_id>/net", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_io_perf_net(vm_id):
    if not io_perf: return err("Modül yok")
    d = request.get_json(silent=True) or {}
    return ok(**io_perf.set_net_multiqueue(
        vm_id, d.get("mac", ""), int(d.get("queues", 1)),
        vhost=bool(d.get("vhost", True))))


# ── v2.8.2 Kernel pack: eBPF observability ─────────────────────────────────────
@app.route("/api/ebpf/status", methods=["GET"])
@require_auth
def api_ebpf_status():
    if not ebpf_obs: return err("Modül yok")
    return ok(**ebpf_obs.status())

@app.route("/api/ebpf/vm/<vm_id>/syscalls", methods=["GET"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_ebpf_syscalls(vm_id):
    if not ebpf_obs: return err("Modül yok")
    return ok(**ebpf_obs.vm_syscalls(vm_id, int(request.args.get("seconds", 5))))

@app.route("/api/ebpf/block-latency", methods=["GET"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_ebpf_blat():
    if not ebpf_obs: return err("Modül yok")
    return ok(**ebpf_obs.block_latency(int(request.args.get("seconds", 5))))

@app.route("/api/ebpf/xdp", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_ebpf_xdp():
    if not ebpf_obs: return err("Modül yok")
    if request.method == "GET":
        return ok(**ebpf_obs.xdp_list())
    d = request.get_json(silent=True) or {}
    iface, action = d.get("iface", ""), d.get("action", "attach")
    fn = ebpf_obs.xdp_attach if action == "attach" else ebpf_obs.xdp_detach
    return ok(**fn(iface))


# ── v2.8.2 Kernel pack: host kernel ops ────────────────────────────────────────
@app.route("/api/kernel/zram", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_kernel_zram():
    if not kernel_ops: return err("Modül yok")
    if request.method == "GET":
        return ok(**kernel_ops.zram_status())
    d = request.get_json(silent=True) or {}
    return ok(**kernel_ops.zram_configure(
        int(d.get("size_mb", 0)), d.get("algorithm", "zstd")))

@app.route("/api/kernel/zswap", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_kernel_zswap():
    if not kernel_ops: return err("Modül yok")
    if request.method == "GET":
        return ok(**kernel_ops.zswap_status())
    d = request.get_json(silent=True) or {}
    return ok(**kernel_ops.zswap_configure(
        bool(d.get("enabled", True)), d.get("compressor", "zstd"),
        int(d.get("max_pool_percent", 20))))

@app.route("/api/kernel/cpu-power", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_kernel_cpu_power():
    if not kernel_ops: return err("Modül yok")
    if request.method == "GET":
        return ok(**kernel_ops.cpu_power_status())
    d = request.get_json(silent=True) or {}
    if "turbo" in d:
        return ok(**kernel_ops.cpu_set_turbo(bool(d["turbo"])))
    return ok(**kernel_ops.cpu_set_governor(d.get("governor", "")))

@app.route("/api/kernel/livepatch", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_kernel_livepatch():
    if not kernel_ops: return err("Modül yok")
    if request.method == "GET":
        return ok(**kernel_ops.livepatch_status())
    d = request.get_json(silent=True) or {}
    return ok(**kernel_ops.livepatch_apply(d.get("patch_path", "")))


# ── v2.8.2 Kernel pack: OXware LKM manager ─────────────────────────────────────
@app.route("/api/kernel/modules", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_kernel_modules():
    if not kernel_mods: return err("Modül yok")
    return ok(**kernel_mods.status())

@app.route("/api/kernel/modules/<name>/<action>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_kernel_modules_action(name, action):
    if not kernel_mods: return err("Modül yok")
    fn = {"build": kernel_mods.build, "load": kernel_mods.load,
          "unload": kernel_mods.unload}.get(action)
    if not fn:
        return err("geçersiz aksiyon")
    return ok(**fn(name))

@app.route("/api/kernel/modules/audit", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_kernel_modules_audit():
    if not kernel_mods: return err("Modül yok")
    return ok(**kernel_mods.audit_events())

@app.route("/api/kernel/modules/guard", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_kernel_modules_guard():
    if not kernel_mods: return err("Modül yok")
    return ok(**kernel_mods.guard_alerts())


# ── Storage Advanced ───────────────────────────────────────────────────────
@app.route("/api/storage-adv/zfs")
@require_role("admin", "administrator")
def api_sa_zfs():
    if not storage_adv: return ok(pools=[], btrfs={}, note="storage_advanced modülü yüklü değil")
    try:
        pools = storage_adv.zfs_pools()
    except Exception as e:
        log.warning("zfs_pools hata: %s", e)
        pools = []
    try:
        btrfs = storage_adv.btrfs_dedup_status()
    except Exception as e:
        log.warning("btrfs_dedup_status hata: %s", e)
        btrfs = {}
    return ok(pools=pools, btrfs=btrfs)

@app.route("/api/storage-adv/tiers", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_sa_tiers():
    if not storage_adv: return ok(tiers=[], note="storage_advanced modülü yüklü değil")
    try:
        if request.method == "GET":
            return ok(tiers=storage_adv.list_tier_policies())
        d = request.get_json(silent=True) or {}
        if "pool" in d and "tier" in d:
            return ok(**storage_adv.assign_pool_to_tier(d["pool"], d["tier"]))
        return ok(**storage_adv.save_tier_policies(d.get("tiers", [])))
    except Exception as e:
        log.warning("tier policies hata: %s", e)
        return ok(tiers=[], error=str(e))

@app.route("/api/storage-adv/spbm", methods=["GET", "POST"])
@require_role("admin", "administrator")
def api_sa_spbm():
    if not storage_adv: return ok(policies=[], note="storage_advanced modülü yüklü değil")
    try:
        if request.method == "GET":
            return ok(policies=storage_adv.list_spbm_policies())
        d = request.get_json(silent=True) or {}
        return ok(**storage_adv.save_spbm_policies(d.get("policies", [])))
    except Exception as e:
        log.warning("spbm hata: %s", e)
        return ok(policies=[], error=str(e))

@app.route("/api/storage-adv/iscsi/sessions")
@require_auth
@require_role("admin", "administrator")
def api_sa_iscsi():
    if not storage_adv: return ok(sessions=[], target_status={}, note="storage_advanced modülü yüklü değil")
    try:
        ses = storage_adv.iscsi_initiator_sessions()
    except Exception as e:
        log.warning("iscsi_initiator_sessions hata: %s", e)
        ses = []
    try:
        tgt = storage_adv.iscsi_target_status()
    except Exception as e:
        log.warning("iscsi_target_status hata: %s", e)
        tgt = {}
    return ok(sessions=ses, target_status=tgt)


# ── Network Advanced ───────────────────────────────────────────────────────
@app.route("/api/network-adv/vxlan", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_na_vxlan():
    if not network_adv: return ok(vxlans=[], note="network_advanced modülü yüklü değil")
    try:
        if request.method == "GET":
            return ok(vxlans=network_adv.vxlan_list())
        d = request.get_json(silent=True) or {}
        if not d.get("name") or not d.get("vni"):
            return err("name ve vni zorunludur", 400)
        return ok(**network_adv.vxlan_create(
            d["name"], int(d["vni"]), d.get("group", "239.1.1.1"),
            d.get("dev", "eth0"), int(d.get("mtu", 1450))
        ))
    except Exception as e:
        log.warning("vxlan hata: %s", e)
        return ok(vxlans=[], error=str(e))

@app.route("/api/network-adv/vxlan/<name>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_na_vxlan_delete(name):
    if not network_adv: return err("network_advanced modülü yüklü değil")
    try:
        return ok(**network_adv.vxlan_delete(name))
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/network-adv/ipv6")
@require_role("admin", "administrator")
def api_na_ipv6():
    if not network_adv: return ok(enabled=False, note="network_advanced modülü yüklü değil")
    try:
        return ok(**network_adv.ipv6_status())
    except Exception as e:
        log.warning("ipv6_status hata: %s", e)
        return ok(enabled=False, error=str(e))

@app.route("/api/network-adv/ddos", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_na_ddos():
    if not network_adv: return err("Modül yok")
    if request.method == "GET":
        return ok(config=network_adv.ddos_get_config())
    return ok(**network_adv.ddos_apply(request.get_json(silent=True) or {}))


# ── Automation Engine ──────────────────────────────────────────────────────
@app.route("/api/automation/rules", methods=["GET"])
@require_role("admin", "administrator")
def api_auto_rules():
    if not automation_eng: return ok(rules=[])
    return ok(rules=automation_eng.list_rules())

@app.route("/api/automation/rules", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_auto_create():
    if not automation_eng: return err("Modül yok")
    d = request.get_json(silent=True) or {}
    try:
        return ok(rule=automation_eng.create_rule(
            d["name"], d["trigger"], d.get("condition"), d.get("actions"),
            d.get("enabled", True), int(d.get("cooldown_sec", 60))
        ))
    except Exception as e:
        return err(e, 400)

@app.route("/api/automation/rules/<rule_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_auto_delete(rule_id):
    if not automation_eng: return err("Modül yok")
    return ok(deleted=automation_eng.delete_rule(rule_id))

@app.route("/api/automation/history")
@require_role("admin", "administrator")
def api_auto_history():
    if not automation_eng: return ok(history=[])
    return ok(history=automation_eng.get_history(int(request.args.get("limit", 50))))

@app.route("/api/policies", methods=["GET"])
@require_auth
def api_policies_list():
    if not automation_eng: return ok(policies=[])
    return ok(policies=automation_eng.list_policies())

@app.route("/api/policies", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_policies_create():
    if not automation_eng: return err("Modül yok")
    d = request.get_json(silent=True) or {}
    try:
        return ok(policy=automation_eng.add_policy(
            d["name"], d["rule"], d["scope"], d.get("enabled", True)
        ))
    except Exception as e:
        return err(e, 400)

@app.route("/api/policies/<policy_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_policies_delete(policy_id):
    if not automation_eng: return err("Modül yok")
    return ok(deleted=automation_eng.delete_policy(policy_id))


# ══════════════════════════════════════════════════════════════════════════════
#  v2.5.4 ENTERPRISE ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

# ── vTPM (new spec) ──────────────────────────────────────────────────────────
@app.route("/api/vtpm/<vm_id>/enable", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_vtpm_enable(vm_id):
    if not vtpm_mgr: return ok({"ok": False, "error": "module unavailable"})
    try:
        d = request.get_json(silent=True) or {}
        return ok(**vtpm_mgr.enable_vtpm(vm_id, version=d.get("version", "2.0")))
    except Exception as e:
        return err(e, 400)

@app.route("/api/vtpm/<vm_id>/disable", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_vtpm_disable(vm_id):
    if not vtpm_mgr: return ok({"ok": False, "error": "module unavailable"})
    try:
        return ok(**vtpm_mgr.disable_vtpm(vm_id))
    except Exception as e:
        return err(e, 400)

@app.route("/api/vtpm/<vm_id>", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_vtpm_status(vm_id):
    if not vtpm_mgr: return ok({"enabled": False, "version": "2.0"})
    try:
        return ok(**vtpm_mgr.vtpm_status(vm_id))
    except Exception as e:
        return ok({"enabled": False, "error": str(e)})

@app.route("/api/vtpm", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_vtpm_list():
    if not vtpm_mgr: return ok({"vms": []})
    try:
        return ok({"vms": vtpm_mgr.list_vtpm_vms()})
    except Exception as e:
        return ok({"vms": [], "error": str(e)})

# ── Secure Boot ──────────────────────────────────────────────────────────────
@app.route("/api/secureboot/<vm_id>/enable", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_secboot_enable(vm_id):
    if not secboot_mgr: return ok({"ok": False, "error": "module unavailable"})
    try:
        return ok(**secboot_mgr.enable_secureboot(vm_id))
    except Exception as e:
        return err(e, 400)

@app.route("/api/secureboot/<vm_id>/disable", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_secboot_disable(vm_id):
    if not secboot_mgr: return ok({"ok": False, "error": "module unavailable"})
    try:
        return ok(**secboot_mgr.disable_secureboot(vm_id))
    except Exception as e:
        return err(e, 400)

@app.route("/api/secureboot/<vm_id>", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_secboot_status(vm_id):
    if not secboot_mgr: return ok({"enabled": False, "firmware": "BIOS"})
    try:
        return ok(**secboot_mgr.secureboot_status(vm_id))
    except Exception as e:
        return ok({"enabled": False, "error": str(e)})

@app.route("/api/secureboot", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_secboot_list():
    if not secboot_mgr: return ok({"vms": []})
    try:
        return ok({"vms": secboot_mgr.list_secureboot_vms()})
    except Exception as e:
        return ok({"vms": [], "error": str(e)})

# ── Vault Integration ────────────────────────────────────────────────────────
@app.route("/api/vault/config", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_vault_config_get():
    if not vault_int_mgr: return ok({})
    try:
        return ok(vault_int_mgr.get_config())
    except Exception as e:
        return ok({"error": str(e)})

@app.route("/api/vault/config", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_vault_config_set():
    if not vault_int_mgr: return err("module unavailable")
    try:
        d = request.get_json() or {}
        return ok(**vault_int_mgr.configure_vault(
            d.get("url", ""), d.get("token", ""),
            d.get("mount_path", "secret/"),
            d.get("verify_ssl", True)))
    except Exception as e:
        return err(e, 400)

@app.route("/api/vault/test", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_vault_test():
    if not vault_int_mgr: return ok({"ok": False, "error": "module unavailable"})
    try:
        return ok(**vault_int_mgr.test_connection())
    except Exception as e:
        return ok({"ok": False, "error": str(e)})

@app.route("/api/vault/secrets/", defaults={"path": ""}, methods=["GET"])
@require_role("admin", "administrator")
def api_v254_vault_secret_get(path):
    if not vault_int_mgr: return ok({"ok": False, "data": {}})
    try:
        if request.args.get("list") == "1" or not path:
            return ok(**vault_int_mgr.list_secrets(path))
        return ok(**vault_int_mgr.read_secret(path))
    except Exception as e:
        return ok({"ok": False, "error": str(e), "data": {}})

@app.route("/api/vault/secrets/<path:path>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_vault_secret_set(path):
    if not vault_int_mgr: return err("module unavailable")
    try:
        d = request.get_json() or {}
        return ok(**vault_int_mgr.write_secret(path, d.get("data", d)))
    except Exception as e:
        return err(e, 400)

@app.route("/api/vault/secrets/<path:path>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_v254_vault_secret_del(path):
    if not vault_int_mgr: return err("module unavailable")
    try:
        return ok(**vault_int_mgr.delete_secret(path))
    except Exception as e:
        return err(e, 400)

# ── Audit Chain ──────────────────────────────────────────────────────────────
@app.route("/api/audit-chain/events", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_audit_events():
    if not audit_chain_mgr: return ok({"events": []})
    try:
        limit = int(request.args.get("limit", 100))
        return ok({"events": audit_chain_mgr.get_events(
            limit=limit,
            filter_user=request.args.get("user"),
            filter_event=request.args.get("event"))})
    except Exception as e:
        return ok({"events": [], "error": str(e)})

@app.route("/api/audit-chain/verify", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_audit_verify():
    if not audit_chain_mgr: return ok({"ok": False, "events": 0})
    try:
        return ok(**audit_chain_mgr.verify_chain())
    except Exception as e:
        return ok({"ok": False, "error": str(e)})

@app.route("/api/audit-chain/stats", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_audit_stats():
    if not audit_chain_mgr: return ok({"total": 0})
    try:
        return ok(audit_chain_mgr.get_stats())
    except Exception as e:
        return ok({"total": 0, "error": str(e)})

@app.route("/api/audit-chain/append", methods=["POST"])
@require_role("admin", "administrator")
def api_v254_audit_append():
    if not audit_chain_mgr: return ok({"ok": False})
    try:
        d = request.get_json() or {}
        return ok(**audit_chain_mgr.append_event(
            d.get("event", "manual"),
            user=d.get("user", "api"),
            ip=request.remote_addr or "",
            details=d.get("details") or {}))
    except Exception as e:
        return err(e, 400)

# ── HugePages ────────────────────────────────────────────────────────────────
@app.route("/api/hugepages/status", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_hp_status():
    if not hugepages_mgr: return ok({"nr_hugepages": 0, "free_hugepages": 0})
    try:
        return ok(hugepages_mgr.get_status())
    except Exception as e:
        return ok({"nr_hugepages": 0, "error": str(e)})

@app.route("/api/hugepages/configure", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_hp_configure():
    if not hugepages_mgr: return err("module unavailable")
    try:
        d = request.get_json() or {}
        return ok(**hugepages_mgr.configure(
            pages_2mb=int(d.get("pages_2mb", 0)),
            pages_1gb=int(d.get("pages_1gb", 0))))
    except Exception as e:
        return err(e, 400)

@app.route("/api/hugepages/vm/<vm_id>/apply", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_hp_apply(vm_id):
    if not hugepages_mgr: return err("module unavailable")
    try:
        d = request.get_json(silent=True) or {}
        return ok(**hugepages_mgr.apply_to_vm(vm_id, d.get("hugepage_size", "2M")))
    except Exception as e:
        return err(e, 400)

@app.route("/api/hugepages/vm/<vm_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_v254_hp_remove(vm_id):
    if not hugepages_mgr: return err("module unavailable")
    try:
        return ok(**hugepages_mgr.remove_from_vm(vm_id))
    except Exception as e:
        return err(e, 400)

# ── SR-IOV ───────────────────────────────────────────────────────────────────
@app.route("/api/sriov/devices", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_sriov_devices():
    if not sriov_mgr: return ok({"devices": []})
    try:
        return ok({"devices": sriov_mgr.list_pf_devices()})
    except Exception as e:
        return ok({"devices": [], "error": str(e)})

@app.route("/api/sriov/<pf>/vfs", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_sriov_create_vfs(pf):
    if not sriov_mgr: return err("module unavailable")
    try:
        d = request.get_json() or {}
        return ok(**sriov_mgr.create_vfs(pf, int(d.get("num_vfs", 0))))
    except Exception as e:
        return err(e, 400)

@app.route("/api/sriov/<pf>/vfs", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_sriov_list_vfs(pf):
    if not sriov_mgr: return ok({"vfs": []})
    try:
        return ok({"vfs": sriov_mgr.list_vfs(pf)})
    except Exception as e:
        return ok({"vfs": [], "error": str(e)})

@app.route("/api/sriov/assign", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_sriov_assign():
    if not sriov_mgr: return err("module unavailable")
    try:
        d = request.get_json() or {}
        return ok(**sriov_mgr.assign_vf_to_vm(d["vm_id"], d["vf_pci_addr"]))
    except Exception as e:
        return err(e, 400)

# ── vGPU ─────────────────────────────────────────────────────────────────────
@app.route("/api/vgpu/devices", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_vgpu_devices():
    if not vgpu_mgr: return ok({"devices": []})
    try:
        return ok({"devices": vgpu_mgr.detect_gpu()})
    except Exception as e:
        return ok({"devices": [], "error": str(e)})

@app.route("/api/vgpu/mdev-types", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_vgpu_mdev_types():
    if not vgpu_mgr: return ok({"types": []})
    try:
        return ok({"types": vgpu_mgr.list_mdev_types(),
                   "active": vgpu_mgr.list_active_mdevs()})
    except Exception as e:
        return ok({"types": [], "error": str(e)})

@app.route("/api/vgpu/mdev", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_vgpu_mdev_create():
    if not vgpu_mgr: return err("module unavailable")
    try:
        d = request.get_json() or {}
        return ok(**vgpu_mgr.create_mdev(d["parent_pci"], d["mdev_type"],
                                          d.get("uuid")))
    except Exception as e:
        return err(e, 400)

@app.route("/api/vgpu/assign", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_vgpu_assign():
    if not vgpu_mgr: return err("module unavailable")
    try:
        d = request.get_json() or {}
        return ok(**vgpu_mgr.assign_mdev_to_vm(d["vm_id"], d["mdev_uuid"]))
    except Exception as e:
        return err(e, 400)

# ── GPU Passthrough Wizard (tam-GPU VFIO) ────────────────────────────────────
@app.route("/api/gpu/wizard/overview", methods=["GET"])
@require_role("admin", "administrator")
def api_gpu_wizard_overview():
    """IOMMU durumu + passthrough'a uygun GPU listesi (wizard açılışı)."""
    if not gpu_pt: return ok({"iommu": {"enabled": False}, "gpus": []})
    try:
        return ok(**gpu_pt.wizard_overview())
    except Exception as e:
        return ok({"iommu": {"enabled": False}, "gpus": [], "error": str(e)})

@app.route("/api/gpu/wizard/preflight/<path:pci>", methods=["GET"])
@require_role("admin", "administrator")
def api_gpu_wizard_preflight(pci):
    """Seçilen GPU için hazırlık kontrolleri (IOMMU/vfio/grup temizliği)."""
    if not gpu_pt: return err("module unavailable")
    try:
        return ok(**gpu_pt.preflight(pci))
    except Exception as e:
        return err(e, 400)

@app.route("/api/gpu/wizard/plan/<path:pci>", methods=["GET"])
@require_role("admin", "administrator")
def api_gpu_wizard_plan(pci):
    """Otomatik remediation planı (kernel cmdline, modprobe, reboot)."""
    if not gpu_pt: return err("module unavailable")
    try:
        return ok(**gpu_pt.generate_plan(pci))
    except Exception as e:
        return err(e, 400)

@app.route("/api/gpu/wizard/bind/<path:pci>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_gpu_wizard_bind(pci):
    """GPU'yu canlı olarak vfio-pci'ye bağla (reboot'suz, mümkünse)."""
    if not gpu_pt: return err("module unavailable")
    try:
        return ok(**gpu_pt.bind_vfio(pci))
    except Exception as e:
        return err(e, 400)

@app.route("/api/vms/<vm_id>/gpu/attach", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_gpu_attach_vm(vm_id):
    """GPU'yu (+ses fonksiyonu) VM'e hostdev PCI olarak ekle."""
    if not gpu_pt: return err("module unavailable")
    try:
        d = request.get_json() or {}
        return ok(**gpu_pt.attach_to_vm(vm_id, d["pci"], d.get("with_audio", True)))
    except Exception as e:
        return err(e, 400)

@app.route("/api/vms/<vm_id>/gpu/detach", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_gpu_detach_vm(vm_id):
    if not gpu_pt: return err("module unavailable")
    try:
        d = request.get_json() or {}
        return ok(**gpu_pt.detach_from_vm(vm_id, d["pci"]))
    except Exception as e:
        return err(e, 400)

# ── CDP ──────────────────────────────────────────────────────────────────────
@app.route("/api/cdp/<vm_id>/enable", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_cdp_enable(vm_id):
    if not cdp_mgr: return err("module unavailable")
    try:
        d = request.get_json(silent=True) or {}
        return ok(**cdp_mgr.enable_cdp(vm_id,
                                       retention_minutes=int(d.get("retention_minutes", 60)),
                                       interval_sec=int(d.get("interval_sec", 60))))
    except Exception as e:
        return err(e, 400)

@app.route("/api/cdp/<vm_id>/disable", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_cdp_disable(vm_id):
    if not cdp_mgr: return err("module unavailable")
    try:
        return ok(**cdp_mgr.disable_cdp(vm_id))
    except Exception as e:
        return err(e, 400)

@app.route("/api/cdp/<vm_id>", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_cdp_status(vm_id):
    if not cdp_mgr: return ok({"enabled": False})
    try:
        return ok(**cdp_mgr.cdp_status(vm_id))
    except Exception as e:
        return ok({"enabled": False, "error": str(e)})

@app.route("/api/cdp/<vm_id>/points", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_cdp_points(vm_id):
    if not cdp_mgr: return ok({"points": []})
    try:
        return ok({"points": cdp_mgr.list_recovery_points(vm_id)})
    except Exception as e:
        return ok({"points": [], "error": str(e)})

@app.route("/api/cdp/<vm_id>/restore", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_cdp_restore(vm_id):
    if not cdp_mgr: return err("module unavailable")
    try:
        d = request.get_json() or {}
        return ok(**cdp_mgr.restore_to_point(vm_id, int(d.get("timestamp", 0))))
    except Exception as e:
        return err(e, 400)

# ── Boot Order ───────────────────────────────────────────────────────────────
@app.route("/api/boot-order", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_bo_get():
    if not boot_order_mgr: return ok({"order": []})
    try:
        return ok({"order": boot_order_mgr.get_boot_order()})
    except Exception as e:
        return ok({"order": [], "error": str(e)})

@app.route("/api/boot-order", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_bo_set():
    if not boot_order_mgr: return err("module unavailable")
    try:
        d = request.get_json() or {}
        return ok(**boot_order_mgr.set_boot_order(d.get("order") or []))
    except Exception as e:
        return err(e, 400)

@app.route("/api/boot-order/execute", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_bo_run():
    if not boot_order_mgr: return err("module unavailable")
    try:
        d = request.get_json(silent=True) or {}
        return ok(**boot_order_mgr.execute_boot_sequence(
            dry_run=bool(d.get("dry_run", False))))
    except Exception as e:
        return err(e, 400)

@app.route("/api/boot-order/validate", methods=["POST"])
@require_role("admin", "administrator")
def api_v254_bo_validate():
    if not boot_order_mgr: return ok({"ok": False})
    try:
        return ok(**boot_order_mgr.validate_dependencies())
    except Exception as e:
        return ok({"ok": False, "error": str(e)})

# ── Geo DNS ──────────────────────────────────────────────────────────────────
@app.route("/api/geo-dns/config", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_geodns_cfg_get():
    if not geo_dns_mgr: return ok({})
    try:
        return ok(geo_dns_mgr.get_config())
    except Exception as e:
        return ok({"error": str(e)})

@app.route("/api/geo-dns/config", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_geodns_cfg_set():
    if not geo_dns_mgr: return err("module unavailable")
    try:
        d = request.get_json() or {}
        return ok(**geo_dns_mgr.configure(
            provider=d.get("provider", "cloudflare"),
            api_token=d.get("api_token", ""),
            zone_id=d.get("zone_id", ""),
            hosted_zone_id=d.get("hosted_zone_id", "")))
    except Exception as e:
        return err(e, 400)

@app.route("/api/geo-dns/records", methods=["GET"])
@require_role("admin", "administrator")
def api_v254_geodns_records_list():
    if not geo_dns_mgr: return ok({"records": []})
    try:
        return ok({"records": geo_dns_mgr.list_records(),
                   "health": geo_dns_mgr.health_status()})
    except Exception as e:
        return ok({"records": [], "error": str(e)})

@app.route("/api/geo-dns/records", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_v254_geodns_records_add():
    if not geo_dns_mgr: return err("module unavailable")
    try:
        d = request.get_json() or {}
        return ok(**geo_dns_mgr.add_record(
            d["name"], d["primary_ip"],
            failover_ip=d.get("failover_ip", ""),
            health_check_url=d.get("health_check_url", ""),
            ttl=int(d.get("ttl", 60)),
            rtype=d.get("type", "A")))
    except Exception as e:
        return err(e, 400)

@app.route("/api/geo-dns/records/<name>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_v254_geodns_records_del(name):
    if not geo_dns_mgr: return err("module unavailable")
    try:
        return ok(**geo_dns_mgr.delete_record(name))
    except Exception as e:
        return err(e, 400)


# ════════════════════════════════════════════════════════════════════════════
# v2.5.5 — Security & Compliance Endpoints (admin-only)
# ════════════════════════════════════════════════════════════════════════════

# ── Confidential VM (SEV/TDX) ─────────────────────────────────────────────────
@app.route("/api/confidential-vm/support")
@require_auth
@require_role("admin", "administrator")
def api_cvm_support():
    if not confidential_vm: return ok(sev=False, tdx=False, note="modül yok")
    try: return ok(**confidential_vm.detect_support())
    except Exception as e: return ok(error=str(e))

@app.route("/api/confidential-vm/vms")
@require_auth
@require_role("admin", "administrator")
def api_cvm_list():
    if not confidential_vm: return ok(vms=[])
    return ok(vms=confidential_vm.list_protected_vms())

@app.route("/api/confidential-vm/vms/<vm_id>", methods=["GET", "POST", "DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_cvm_vm(vm_id):
    if not confidential_vm: return err("modül yok", 503)
    try:
        if request.method == "GET":
            return ok(**confidential_vm.get_vm_config(vm_id))
        if request.method == "DELETE":
            return ok(**confidential_vm.disable_for_vm(vm_id))
        d = request.get_json(silent=True) or {}
        return ok(**confidential_vm.enable_for_vm(vm_id, d.get("mode", "sev")))
    except Exception as e: return err(e, 400)

@app.route("/api/confidential-vm/vms/<vm_id>/vtpm", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_cvm_vtpm(vm_id):
    if not confidential_vm: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        return ok(**confidential_vm.set_vtpm(vm_id, bool(d.get("enabled", True))))
    except Exception as e: return err(e, 400)

@app.route("/api/confidential-vm/vms/<vm_id>/secure-boot", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_cvm_sb(vm_id):
    if not confidential_vm: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        return ok(**confidential_vm.set_secure_boot(vm_id, bool(d.get("enabled", True))))
    except Exception as e: return err(e, 400)

@app.route("/api/confidential-vm/vms/<vm_id>/attest", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_cvm_attest(vm_id):
    if not confidential_vm: return err("modül yok", 503)
    try:
        return ok(**confidential_vm.capture_attestation(vm_id))
    except Exception as e: return err(e, 400)

@app.route("/api/confidential-vm/vms/<vm_id>/attestation")
@require_auth
@require_role("admin", "administrator")
def api_cvm_get_attest(vm_id):
    if not confidential_vm: return err("modül yok", 503)
    return ok(**confidential_vm.get_attestation(vm_id))


# ── Runbook Executor (Auto-Remediation) ───────────────────────────────────────
@app.route("/api/runbooks", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_runbook_list():
    if not runbook_exec: return ok(runbooks=[])
    return ok(runbooks=runbook_exec.list_runbooks())

@app.route("/api/runbooks", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_runbook_upsert():
    if not runbook_exec: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        return ok(runbook=runbook_exec.upsert_runbook(d))
    except Exception as e: return err(e, 400)

@app.route("/api/runbooks/<rb_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_runbook_delete(rb_id):
    if not runbook_exec: return err("modül yok", 503)
    return ok(removed=runbook_exec.delete_runbook(rb_id))

@app.route("/api/runbooks/<rb_id>/run", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_runbook_run(rb_id):
    if not runbook_exec: return err("modül yok", 503)
    d = request.get_json(silent=True) or {}
    return ok(**runbook_exec.execute_runbook(rb_id, d.get("ctx"), force=bool(d.get("force"))))

@app.route("/api/runbooks/history")
@require_auth
@require_role("admin", "administrator")
def api_runbook_history():
    if not runbook_exec: return ok(history=[])
    try: limit = int(request.args.get("limit", 100))
    except Exception: limit = 100
    return ok(history=runbook_exec.history(limit=limit))


# ── Cluster Federation (Managed Clusters) ─────────────────────────────────────
@app.route("/api/federation/members", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_fed_list():
    if not federation_mgr: return ok(members=[])
    # strip tokens from listing
    members = []
    for m in federation_mgr.list_members():
        m2 = dict(m); m2["token"] = "***"; members.append(m2)
    return ok(members=members)

@app.route("/api/federation/members", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_fed_add():
    if not federation_mgr: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        m = federation_mgr.add_member(
            url=d.get("url", ""), token=d.get("token", ""),
            label=d.get("label", ""), region=d.get("region", ""),
            role=d.get("role", "follower"),
            verify_tls=bool(d.get("verify_tls", True)),
        )
        m = dict(m); m["token"] = "***"
        return ok(member=m)
    except Exception as e: return err(e, 400)

@app.route("/api/federation/members/<member_id>", methods=["PATCH", "DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_fed_update(member_id):
    if not federation_mgr: return err("modül yok", 503)
    try:
        if request.method == "DELETE":
            return ok(removed=federation_mgr.remove_member(member_id))
        d = request.get_json(silent=True) or {}
        m = federation_mgr.update_member(member_id, d)
        if not m: return err("not found", 404)
        m = dict(m); m["token"] = "***"
        return ok(member=m)
    except Exception as e: return err(e, 400)

@app.route("/api/federation/health")
@require_auth
@require_role("admin", "administrator", "operator")
def api_fed_health():
    if not federation_mgr: return ok(members=[])
    mid = request.args.get("member_id")
    return ok(health=federation_mgr.health(mid))

@app.route("/api/federation/inventory/vms")
@require_auth
@require_role("admin", "administrator", "operator")
def api_fed_inventory_vms():
    if not federation_mgr: return ok(total=0, members=[], vms=[])
    return ok(**federation_mgr.inventory_vms())

@app.route("/api/federation/forward/<member_id>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_fed_forward(member_id):
    if not federation_mgr: return err("modül yok", 503)
    d = request.get_json(silent=True) or {}
    return ok(**federation_mgr.forward(
        member_id, d.get("path", "/api/health"),
        method=d.get("method", "GET"), payload=d.get("payload"),
    ))

@app.route("/api/federation/bulk", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_fed_bulk():
    if not federation_mgr: return err("modül yok", 503)
    d = request.get_json(silent=True) or {}
    return ok(results=federation_mgr.bulk_action(
        member_ids=d.get("member_ids", []), path=d.get("path", "/api/health"),
        method=d.get("method", "POST"), payload=d.get("payload"),
    ))


# ── Disk Encryption ───────────────────────────────────────────────────────────
@app.route("/api/disk-encryption")
@require_auth
@require_role("admin", "administrator")
def api_de_list():
    if not disk_encryption: return ok(disks=[])
    return ok(disks=disk_encryption.list_encrypted_disks())

@app.route("/api/disk-encryption/<vm_id>", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_de_status(vm_id):
    if not disk_encryption: return ok(encrypted=False)
    return ok(**disk_encryption.get_status(vm_id))

@app.route("/api/disk-encryption/<vm_id>/encrypt", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_de_encrypt(vm_id):
    if not disk_encryption: return err("modül yok", 503)
    d = request.get_json(silent=True) or {}
    if not d.get("disk_path"): return err("disk_path zorunlu", 400)
    try:
        return ok(**disk_encryption.encrypt_disk(d["disk_path"], vm_id, d.get("passphrase")))
    except Exception as e: return err(e, 500)

@app.route("/api/disk-encryption/<vm_id>/rotate", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_de_rotate(vm_id):
    if not disk_encryption: return err("modül yok", 503)
    return ok(**disk_encryption.rotate_key(vm_id))


# ── Compliance Scanner ───────────────────────────────────────────────────────
@app.route("/api/compliance/frameworks")
@require_auth
@require_role("admin", "administrator")
def api_cmp_frameworks():
    if not compliance_scan: return ok(frameworks=[])
    return ok(frameworks=compliance_scan.list_frameworks())

@app.route("/api/compliance/scan", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_cmp_scan():
    if not compliance_scan: return err("modül yok", 503)
    fw = (request.get_json(silent=True) or {}).get("framework")
    try:
        return ok(**compliance_scan.run_scan(fw))
    except Exception as e: return err(e, 500)

@app.route("/api/compliance/last")
@require_auth
@require_role("admin", "administrator")
def api_cmp_last():
    if not compliance_scan: return ok()
    return ok(**compliance_scan.last_scan())


# ── DLP Engine ───────────────────────────────────────────────────────────────
@app.route("/api/dlp/rules", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_dlp_rules():
    if not dlp_engine: return ok(rules=[])
    return ok(rules=dlp_engine.list_rules())

@app.route("/api/dlp/rules", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_dlp_add_rule():
    if not dlp_engine: return err("modül yok", 503)
    d = request.get_json(silent=True) or {}
    return ok(**dlp_engine.add_rule(d))

@app.route("/api/dlp/rules/<rule_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_dlp_del_rule(rule_id):
    if not dlp_engine: return err("modül yok", 503)
    return ok(**dlp_engine.delete_rule(rule_id))

@app.route("/api/dlp/scan", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_dlp_scan():
    if not dlp_engine: return ok(matches=[])
    d = request.get_json(silent=True) or {}
    return ok(matches=dlp_engine.scan_text(d.get("text", ""), d.get("vm_id", "")))

@app.route("/api/dlp/events")
@require_auth
@require_role("admin", "administrator")
def api_dlp_events():
    if not dlp_engine: return ok(events=[])
    return ok(events=dlp_engine.get_events(int(request.args.get("limit", 100)),
                                          request.args.get("severity")))

@app.route("/api/dlp/stats")
@require_auth
@require_role("admin", "administrator")
def api_dlp_stats():
    if not dlp_engine: return ok()
    return ok(**dlp_engine.get_stats())


# ── Forensics ────────────────────────────────────────────────────────────────
@app.route("/api/forensics/memdump/<vm_id>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_forensics_memdump(vm_id):
    if not forensics: return err("modül yok", 503)
    mode = (request.get_json(silent=True) or {}).get("mode", "live")
    return ok(**forensics.memory_dump(vm_id, mode))

@app.route("/api/forensics/pcap/<vm_id>/start", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_forensics_pcap_start(vm_id):
    if not forensics: return err("modül yok", 503)
    d = request.get_json(silent=True) or {}
    return ok(**forensics.packet_capture_start(vm_id, int(d.get("duration", 60)),
                                               int(d.get("snaplen", 1500)),
                                               d.get("bpf_filter", "")))

@app.route("/api/forensics/pcap/jobs/<job_id>/stop", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_forensics_pcap_stop(job_id):
    if not forensics: return err("modül yok", 503)
    return ok(**forensics.packet_capture_stop(job_id))

@app.route("/api/forensics/pcap/jobs")
@require_auth
@require_role("admin", "administrator")
def api_forensics_jobs():
    if not forensics: return ok(jobs=[])
    return ok(jobs=forensics.list_jobs())

@app.route("/api/forensics/artifacts")
@require_auth
@require_role("admin", "administrator")
def api_forensics_artifacts():
    if not forensics: return ok(artifacts=[])
    return ok(artifacts=forensics.list_artifacts(request.args.get("vm_id")))

@app.route("/api/forensics/artifacts/<vm_id>/<name>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_forensics_delete(vm_id, name):
    if not forensics: return err("modül yok", 503)
    return ok(**forensics.delete_artifact(vm_id, name))

@app.route("/api/forensics/prune", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_forensics_prune():
    if not forensics: return ok()
    days = int((request.get_json(silent=True) or {}).get("days", 30))
    return ok(**forensics.prune(days))


# ── MFA per Role ─────────────────────────────────────────────────────────────
@app.route("/api/mfa-policy")
@require_auth
@require_role("admin", "administrator")
def api_mfa_get_policy():
    if not mfa_policy: return ok(policy={})
    return ok(policy=mfa_policy.get_policy())

@app.route("/api/mfa-policy", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_mfa_set_policy():
    if not mfa_policy: return err("modül yok", 503)
    d = request.get_json(silent=True) or {}
    role = d.get("role", "")
    pol  = d.get("policy", "optional")
    return ok(**mfa_policy.set_role_policy(role, pol))


# ── SSO (SAML / OIDC) ────────────────────────────────────────────────────────
@app.route("/api/sso/config")
@require_auth
@require_role("admin", "administrator")
def api_sso_get():
    if not sso_manager: return ok(config={})
    return ok(config=sso_manager.get_config())

@app.route("/api/sso/config", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_sso_set():
    if not sso_manager: return err("modül yok", 503)
    d = request.get_json(silent=True) or {}
    return ok(**sso_manager.update_config(saml=d.get("saml"),
                                          oidc=d.get("oidc"),
                                          role_map=d.get("role_map")))

@app.route("/api/sso/saml/authn")
def api_sso_saml_authn():
    if not sso_manager: return err("modül yok", 503)
    return ok(**sso_manager.saml_authn_request())

@app.route("/api/sso/saml/acs", methods=["POST"])
def api_sso_saml_acs():
    if not sso_manager: return err("modül yok", 503)
    d = request.get_json(silent=True) or {}
    return ok(**sso_manager.saml_process_acs(d.get("SAMLResponse", ""), d.get("RelayState", "")))

@app.route("/api/sso/oidc/authorize")
def api_sso_oidc_authorize():
    if not sso_manager: return err("modül yok", 503)
    return ok(**sso_manager.oidc_authorize_url(request.args.get("state", "")))

@app.route("/api/sso/oidc/callback", methods=["POST"])
def api_sso_oidc_callback():
    if not sso_manager: return err("modül yok", 503)
    d = request.get_json(silent=True) or {}
    return ok(**sso_manager.oidc_exchange_code(d.get("code", ""), d.get("state", "")))


# ── Feature Registry ────────────────────────────────────────────────────────
@app.route("/api/features")
@require_auth
@require_role("admin", "administrator")
def api_features_list():
    if not feature_reg: return ok(features=[])
    return ok(features=feature_reg.list_features(request.args.get("category"),
                                                 request.args.get("status")))

@app.route("/api/features/<feature_id>")
@require_auth
@require_role("admin", "administrator")
def api_features_get(feature_id):
    if not feature_reg: return ok()
    f = feature_reg.get_feature(feature_id)
    return ok(**(f or {"error": "not found"}))

@app.route("/api/features/<feature_id>/enable", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_features_enable(feature_id):
    if not feature_reg: return err("modül yok", 503)
    user = ""
    try:
        from flask_jwt_extended import get_jwt_identity
        user = get_jwt_identity() or ""
    except Exception: pass
    return ok(**feature_reg.enable(feature_id, by_user=user or "admin"))

@app.route("/api/features/<feature_id>/disable", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_features_disable(feature_id):
    if not feature_reg: return err("modül yok", 503)
    user = ""
    try:
        from flask_jwt_extended import get_jwt_identity
        user = get_jwt_identity() or ""
    except Exception: pass
    return ok(**feature_reg.disable(feature_id, by_user=user or "admin"))

@app.route("/api/features/summary")
@require_auth
@require_role("admin", "administrator")
def api_features_summary():
    if not feature_reg: return ok()
    return ok(**feature_reg.summary())

@app.route("/api/features/audit")
@require_auth
@require_role("admin", "administrator")
def api_features_audit():
    if not feature_reg: return ok(events=[])
    return ok(events=feature_reg.get_audit_log(int(request.args.get("limit", 100))))


# ─────────────────────────────────────────────────────────────────────────────
# v2.5.6 — Multi-tenancy endpoints
# All wrapped in try/except with safe defaults — modül yoksa boş döner.
# ─────────────────────────────────────────────────────────────────────────────

# ── Tenant Manager ──────────────────────────────────────────────────────────
@app.route("/api/tenants")
@require_auth
@require_role("admin", "administrator")
def api_tenants_list():
    if not tenant_mgr: return ok(tenants=[])
    try:
        return ok(tenants=tenant_mgr.list_tenants())
    except Exception as e:
        log.warning("tenants_list fail: %s", e)
        return ok(tenants=[], error=str(e))

@app.route("/api/tenants", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_tenants_create():
    if not tenant_mgr: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        name = (d.get("name") or "").strip()
        if not name:
            return err("name zorunlu", 400)
        t = tenant_mgr.create_tenant(name, d.get("quota") or {})
        return ok(tenant=t)
    except Exception as e:
        log.warning("tenants_create fail: %s", e)
        return err(str(e), 400)

@app.route("/api/tenants/<tid>")
@require_auth
@require_role("admin", "administrator")
def api_tenants_get(tid):
    if not tenant_mgr: return ok(tenant=None)
    try:
        t = tenant_mgr.get_tenant(tid)
        if not t: return err("tenant bulunamadı", 404)
        return ok(tenant=t)
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/tenants/<tid>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_tenants_delete(tid):
    if not tenant_mgr: return err("modül yok", 503)
    try:
        force = (request.args.get("force", "false").lower() == "true")
        return ok(**tenant_mgr.delete_tenant(tid, force=force))
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/tenants/<tid>/quota", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_tenants_update_quota(tid):
    if not tenant_mgr: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        return ok(**tenant_mgr.update_quota(tid, d.get("quota") or d))
    except Exception as e:
        return err(str(e), 400)

@app.route("/api/tenants/<tid>/usage")
@require_auth
@require_role("admin", "administrator")
def api_tenants_usage(tid):
    if not tenant_mgr: return ok(usage={})
    try:
        return ok(usage=tenant_mgr.get_tenant_usage(tid))
    except Exception as e:
        return ok(usage={}, error=str(e))

@app.route("/api/tenants/<tid>/quota-check", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_tenants_quota_check(tid):
    if not tenant_mgr: return ok(allowed=True)
    try:
        d = request.get_json(silent=True) or {}
        return ok(**tenant_mgr.check_quota(tid, d))
    except Exception as e:
        return err(str(e), 400)

@app.route("/api/tenants/<tid>/users/<username>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_tenants_assign_user(tid, username):
    if not tenant_mgr: return err("modül yok", 503)
    try:
        return ok(**tenant_mgr.assign_user_to_tenant(username, tid))
    except Exception as e:
        return err(str(e), 400)

@app.route("/api/tenants/<tid>/users/<username>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_tenants_unassign_user(tid, username):
    if not tenant_mgr: return err("modül yok", 503)
    try:
        return ok(**tenant_mgr.unassign_user(username))
    except Exception as e:
        return err(str(e), 400)

@app.route("/api/tenants/<tid>/vms/<vm_id>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_tenants_assign_vm(tid, vm_id):
    if not tenant_mgr: return err("modül yok", 503)
    try:
        return ok(**tenant_mgr.assign_vm_to_tenant(vm_id, tid))
    except Exception as e:
        return err(str(e), 400)

@app.route("/api/tenants/<tid>/vms/<vm_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_tenants_unassign_vm(tid, vm_id):
    if not tenant_mgr: return err("modül yok", 503)
    try:
        return ok(**tenant_mgr.unassign_vm(vm_id))
    except Exception as e:
        return err(str(e), 400)


# ── Self-Service Portal (auth-only — kullanıcı kendi tenant'ında işlem yapar) ─
def _current_user() -> str:
    try:
        from flask_jwt_extended import get_jwt_identity
        return get_jwt_identity() or ""
    except Exception:
        return ""

@app.route("/api/self-service/vms")
@require_auth
def api_ss_list_vms():
    if not self_service: return ok(vms=[])
    try:
        return ok(vms=self_service.list_user_vms(_current_user()))
    except Exception as e:
        return ok(vms=[], error=str(e))

@app.route("/api/self-service/vms", methods=["POST"])
@require_auth
def api_ss_create_vm():
    if not self_service: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        return ok(**self_service.request_vm_create(
            username=_current_user(),
            name=str(d.get("name", "")).strip(),
            vcpus=int(d.get("vcpus", 1) or 1),
            ram_mb=int(d.get("ram_mb", d.get("memory_mb", 1024)) or 1024),
            disk_gb=int(d.get("disk_gb", 20) or 20),
            template_id=d.get("template_id"),
            iso_path=d.get("iso_path"),
        ))
    except Exception as e:
        log.warning("self-service create fail: %s", e)
        return err(str(e), 400)

@app.route("/api/self-service/vms/<vm_id>/<action>", methods=["POST"])
@require_auth
def api_ss_vm_action(vm_id, action):
    if not self_service: return err("modül yok", 503)
    try:
        return ok(**self_service.request_vm_action(_current_user(), vm_id, action))
    except Exception as e:
        return err(str(e), 400)

@app.route("/api/self-service/quota")
@require_auth
def api_ss_quota():
    if not self_service: return ok(quota={})
    try:
        return ok(**self_service.get_user_quota(_current_user()))
    except Exception as e:
        return ok(quota={}, error=str(e))

@app.route("/api/self-service/console/<vm_id>", methods=["POST"])
@require_auth
def api_ss_console(vm_id):
    if not self_service: return err("modül yok", 503)
    try:
        return ok(**self_service.request_console(_current_user(), vm_id))
    except Exception as e:
        return err(str(e), 400)


# ── Chargeback / Billing ──────────────────────────────────────────────────────
@app.route("/api/chargeback/pricing")
@require_auth
@require_role("admin", "administrator")
def api_charge_get_pricing():
    if not chargeback: return ok(pricing={})
    try:
        return ok(pricing=chargeback.get_pricing())
    except Exception as e:
        return ok(pricing={}, error=str(e))

@app.route("/api/chargeback/pricing", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_charge_set_pricing():
    if not chargeback: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        return ok(**chargeback.set_pricing(d))
    except Exception as e:
        return err(str(e), 400)

@app.route("/api/chargeback/tenants/<tid>")
@require_auth
@require_role("admin", "administrator")
def api_charge_tenant_cost(tid):
    if not chargeback: return ok(total=0)
    try:
        period = request.args.get("period", "monthly")
        return ok(**chargeback.calculate_tenant_cost(tid, period))
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/chargeback/invoice", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_charge_invoice():
    if not chargeback: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        tid   = d.get("tenant") or d.get("tenant_id")
        if not tid:
            return err("tenant zorunlu", 400)
        return ok(invoice=chargeback.generate_invoice(tid, int(d.get("year", 0)), int(d.get("month", 0))))
    except Exception as e:
        return err(str(e), 400)

@app.route("/api/chargeback/all")
@require_auth
@require_role("admin", "administrator")
def api_charge_all_tenants():
    if not chargeback: return ok(billing=[])
    try:
        period = request.args.get("period", "monthly")
        return ok(billing=chargeback.get_all_tenants_billing(period))
    except Exception as e:
        return ok(billing=[], error=str(e))


# ── Service Catalog ───────────────────────────────────────────────────────────
@app.route("/api/service-catalog")
@require_auth
def api_catalog_list():
    if not svc_catalog: return ok(catalog=[])
    try:
        tid = None
        # kullanıcının tenant'ına göre filtre — admin değilse
        if tenant_mgr:
            try:
                tid = tenant_mgr.get_user_tenant(_current_user())
            except Exception:
                pass
        return ok(catalog=svc_catalog.list_catalog(tid))
    except Exception as e:
        return ok(catalog=[], error=str(e))

@app.route("/api/service-catalog", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_catalog_add():
    if not svc_catalog: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        return ok(**svc_catalog.add_catalog_item(d))
    except Exception as e:
        return err(str(e), 400)

@app.route("/api/service-catalog/<cid>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_catalog_delete(cid):
    if not svc_catalog: return err("modül yok", 503)
    try:
        return ok(**svc_catalog.delete_catalog_item(cid))
    except Exception as e:
        return err(str(e), 400)

@app.route("/api/service-catalog/<cid>/deploy", methods=["POST"])
@require_auth
def api_catalog_deploy(cid):
    if not svc_catalog: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        vm_name = (d.get("vm_name") or d.get("name") or "").strip()
        return ok(**svc_catalog.deploy_from_catalog(_current_user(), cid, vm_name))
    except Exception as e:
        return err(str(e), 400)


# ── Tenant Rate Limiting ──────────────────────────────────────────────────────
@app.route("/api/tenant-rate-limit/<tid>")
@require_auth
@require_role("admin", "administrator")
def api_rl_get(tid):
    if not tenant_rl: return ok(limit={})
    try:
        return ok(limit=tenant_rl.get_limit(tid))
    except Exception as e:
        return ok(limit={}, error=str(e))

@app.route("/api/tenant-rate-limit/<tid>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_rl_set(tid):
    if not tenant_rl: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        return ok(**tenant_rl.set_limit(tid,
                                        rpm=int(d.get("rpm", 100) or 100),
                                        burst=int(d.get("burst", 200) or 200)))
    except Exception as e:
        return err(str(e), 400)

@app.route("/api/tenant-rate-limit/<tid>/usage")
@require_auth
@require_role("admin", "administrator")
def api_rl_usage(tid):
    if not tenant_rl: return ok(usage={})
    try:
        return ok(usage=tenant_rl.get_usage(tid))
    except Exception as e:
        return ok(usage={}, error=str(e))


# ── Pool Reservations (resource_pool_manager v2.5.6 ek) ──────────────────────
@app.route("/api/pools/<pool_id>/reservations")
@require_auth
@require_role("admin", "administrator")
def api_pool_get_reservations(pool_id):
    if not pool_mgr or not hasattr(pool_mgr, "get_reservations"):
        return ok(reservations=None)
    try:
        return ok(reservations=pool_mgr.get_reservations(pool_id))
    except Exception as e:
        return ok(reservations=None, error=str(e))

@app.route("/api/pools/<pool_id>/reservations", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_pool_set_reservations(pool_id):
    if not pool_mgr or not hasattr(pool_mgr, "set_reservations"):
        return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        res = pool_mgr.set_reservations(pool_id,
                                        vcpu_min=int(d.get("vcpu_min", d.get("vcpu", 0)) or 0),
                                        ram_mb_min=int(d.get("ram_mb_min", d.get("ram_mb", 0)) or 0))
        if not res:
            return err("pool bulunamadı", 404)
        return ok(pool=res)
    except Exception as e:
        return err(str(e), 400)


# ════════════════════════════════════════════════════════════════════════════
# v2.5.7 — Backup Advanced Endpoints (admin-only)
# All wrapped in try/except with safe defaults — modül yoksa boş döner.
# ════════════════════════════════════════════════════════════════════════════

# ── App-Consistent Snapshots ─────────────────────────────────────────────────

@app.route("/api/backup-adv/consistent/<vm_id>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ba_consistent_create(vm_id):
    if not app_consistent: return ok(ok=False, error="modül yok")
    try:
        d    = request.get_json(silent=True) or {}
        name = (d.get("name") or f"snap-{vm_id}").strip()
        freeze = bool(d.get("freeze_fs", True))
        return ok(**app_consistent.create_consistent_snapshot(vm_id, name, freeze_fs=freeze))
    except Exception as e:
        log.warning("ba_consistent_create fail vm=%s: %s", vm_id, e)
        return err(str(e), 500)


@app.route("/api/backup-adv/consistent/<vm_id>")
@require_auth
@require_role("admin", "administrator")
def api_ba_consistent_list(vm_id):
    if not app_consistent: return ok(snapshots=[])
    try:
        return ok(snapshots=app_consistent.list_consistent_snapshots(vm_id))
    except Exception as e:
        log.warning("ba_consistent_list fail vm=%s: %s", vm_id, e)
        return ok(snapshots=[], error=str(e))


@app.route("/api/backup-adv/quiesce/<vm_id>")
@require_auth
@require_role("admin", "administrator")
def api_ba_quiesce_support(vm_id):
    if not app_consistent: return ok(agent=False, fsfreeze=False)
    try:
        return ok(**app_consistent.get_quiesce_support(vm_id))
    except Exception as e:
        log.warning("ba_quiesce_support fail vm=%s: %s", vm_id, e)
        return ok(agent=False, fsfreeze=False, error=str(e))


@app.route("/api/backup-adv/hooks/<vm_id>")
@require_auth
@require_role("admin", "administrator")
def api_ba_hooks_list(vm_id):
    if not app_consistent: return ok(hooks=[])
    try:
        return ok(hooks=app_consistent.list_app_hooks(vm_id))
    except Exception as e:
        log.warning("ba_hooks_list fail vm=%s: %s", vm_id, e)
        return ok(hooks=[], error=str(e))


@app.route("/api/backup-adv/hooks/<vm_id>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ba_hooks_register(vm_id):
    if not app_consistent: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        app_name = (d.get("app") or "").strip()
        if not app_name:
            return err("app zorunlu", 400)
        return ok(**app_consistent.register_app_hook(
            vm_id, app_name,
            d.get("pre_cmd", ""), d.get("post_cmd", "")
        ))
    except Exception as e:
        log.warning("ba_hooks_register fail vm=%s: %s", vm_id, e)
        return err(str(e), 400)


# ── 3-2-1 Backup ─────────────────────────────────────────────────────────────

@app.route("/api/backup-adv/321/<vm_id>")
@require_auth
@require_role("admin", "administrator")
def api_ba_321_get(vm_id):
    if not backup_321: return ok(policy=None)
    try:
        return ok(policy=backup_321.get_321_policy(vm_id))
    except Exception as e:
        log.warning("ba_321_get fail vm=%s: %s", vm_id, e)
        return ok(policy=None, error=str(e))


@app.route("/api/backup-adv/321/<vm_id>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ba_321_set(vm_id):
    if not backup_321: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        return ok(**backup_321.set_321_policy(vm_id, d))
    except Exception as e:
        log.warning("ba_321_set fail vm=%s: %s", vm_id, e)
        return err(str(e), 400)


@app.route("/api/backup-adv/321/<vm_id>/run", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ba_321_run(vm_id):
    if not backup_321: return err("modül yok", 503)
    try:
        return ok(**backup_321.run_321_backup(vm_id))
    except Exception as e:
        log.warning("ba_321_run fail vm=%s: %s", vm_id, e)
        return err(str(e), 500)


@app.route("/api/backup-adv/321/<vm_id>/status")
@require_auth
@require_role("admin", "administrator")
def api_ba_321_status(vm_id):
    if not backup_321: return ok(policy_set=False, compliant=False)
    try:
        return ok(**backup_321.get_321_status(vm_id))
    except Exception as e:
        log.warning("ba_321_status fail vm=%s: %s", vm_id, e)
        return ok(policy_set=False, compliant=False, error=str(e))


@app.route("/api/backup-adv/321")
@require_auth
@require_role("admin", "administrator")
def api_ba_321_list():
    if not backup_321: return ok(policies=[])
    try:
        return ok(policies=backup_321.list_321_policies())
    except Exception as e:
        log.warning("ba_321_list fail: %s", e)
        return ok(policies=[], error=str(e))


# ── Backup Verification ───────────────────────────────────────────────────────

@app.route("/api/backup-adv/verify", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ba_verify():
    if not backup_verify: return err("modül yok", 503)
    try:
        d    = request.get_json(silent=True) or {}
        path = (d.get("backup_path") or "").strip()
        mode = (d.get("mode") or "mount").strip()
        if not path:
            return err("backup_path zorunlu", 400)
        return ok(**backup_verify.verify_backup(path, mode=mode))
    except Exception as e:
        log.warning("ba_verify fail: %s", e)
        return err(str(e), 500)


@app.route("/api/backup-adv/verify/history")
@require_auth
@require_role("admin", "administrator")
def api_ba_verify_history():
    if not backup_verify: return ok(verifications=[])
    try:
        limit = int(request.args.get("limit", 50) or 50)
        return ok(verifications=backup_verify.list_verifications(limit=limit))
    except Exception as e:
        log.warning("ba_verify_history fail: %s", e)
        return ok(verifications=[], error=str(e))


# ── Cross-Site Replication ────────────────────────────────────────────────────

@app.route("/api/backup-adv/replication/<vm_id>")
@require_auth
@require_role("admin", "administrator")
def api_ba_replication_get(vm_id):
    if not cross_replication: return ok(replication=None)
    try:
        return ok(replication=cross_replication.get_replication(vm_id))
    except Exception as e:
        log.warning("ba_replication_get fail vm=%s: %s", vm_id, e)
        return ok(replication=None, error=str(e))


@app.route("/api/backup-adv/replication/<vm_id>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ba_replication_configure(vm_id):
    if not cross_replication: return err("modül yok", 503)
    try:
        d = request.get_json(silent=True) or {}
        return ok(**cross_replication.configure_replication(vm_id, d))
    except Exception as e:
        log.warning("ba_replication_configure fail vm=%s: %s", vm_id, e)
        return err(str(e), 400)


@app.route("/api/backup-adv/replication/<vm_id>/run", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ba_replication_run(vm_id):
    if not cross_replication: return err("modül yok", 503)
    try:
        d     = request.get_json(silent=True) or {}
        async_ = bool(d.get("async", False))
        if async_:
            return ok(**cross_replication.run_replication_async(vm_id))
        return ok(**cross_replication.run_replication(vm_id))
    except Exception as e:
        log.warning("ba_replication_run fail vm=%s: %s", vm_id, e)
        return err(str(e), 500)


@app.route("/api/backup-adv/replication/<vm_id>/status")
@require_auth
@require_role("admin", "administrator")
def api_ba_replication_status(vm_id):
    if not cross_replication: return ok(configured=False)
    try:
        return ok(**cross_replication.get_replication_status(vm_id))
    except Exception as e:
        log.warning("ba_replication_status fail vm=%s: %s", vm_id, e)
        return ok(configured=False, error=str(e))


@app.route("/api/backup-adv/replication/<vm_id>/promote", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ba_replication_promote(vm_id):
    if not cross_replication: return err("modül yok", 503)
    try:
        return ok(**cross_replication.promote_replica(vm_id))
    except Exception as e:
        log.warning("ba_replication_promote fail vm=%s: %s", vm_id, e)
        return err(str(e), 500)


@app.route("/api/backup-adv/replication")
@require_auth
@require_role("admin", "administrator")
def api_ba_replication_list():
    if not cross_replication: return ok(replications=[])
    try:
        return ok(replications=cross_replication.list_replications())
    except Exception as e:
        log.warning("ba_replication_list fail: %s", e)
        return ok(replications=[], error=str(e))


# ════════════════════════════════════════════════════════════════════════════
# v2.5.8 — Observability Endpoints (admin-only)
# All wrapped in try/except with safe defaults — modül yoksa boş döner.
# topology_viz uses /api/topo-viz/* to avoid clash with existing /api/topology
# ════════════════════════════════════════════════════════════════════════════

# ── OTel Tracing ──────────────────────────────────────────────────────────────

@app.route("/api/otel/traces")
@require_auth
@require_role("admin", "administrator")
def api_otel_traces():
    if not otel_tracing: return ok(traces=[])
    try:
        limit = int(request.args.get("limit", 100))
        return ok(traces=otel_tracing.get_traces(limit=limit))
    except Exception as e:
        log.warning("api_otel_traces fail: %s", e)
        return ok(traces=[], error=str(e))


@app.route("/api/otel/traces/<tid>")
@require_auth
@require_role("admin", "administrator")
def api_otel_trace(tid):
    if not otel_tracing: return ok(trace_id=tid, spans=[])
    try:
        return ok(**otel_tracing.get_trace(tid))
    except Exception as e:
        log.warning("api_otel_trace fail: %s", e)
        return err(str(e), 500)


@app.route("/api/otel/config", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_otel_config():
    if not otel_tracing: return ok(enabled=False, otlp_endpoint="")
    try:
        if request.method == "POST":
            d = request.get_json(silent=True) or {}
            cfg = otel_tracing.configure(
                otlp_endpoint=str(d.get("otlp_endpoint", "")),
                enabled=bool(d.get("enabled", True)),
            )
            return ok(**cfg)
        return ok(**otel_tracing.get_config())
    except Exception as e:
        log.warning("api_otel_config fail: %s", e)
        return err(str(e), 400)


@app.route("/api/otel/export")
@require_auth
@require_role("admin", "administrator")
def api_otel_export():
    if not otel_tracing: return ok(resourceSpans=[], spanCount=0)
    try:
        return ok(**otel_tracing.export_otlp())
    except Exception as e:
        log.warning("api_otel_export fail: %s", e)
        return err(str(e), 500)


# ── Grafana Embed ─────────────────────────────────────────────────────────────

@app.route("/api/grafana/config", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_grafana_config():
    if not grafana_embed: return ok(grafana_url="", api_key="***", org_id=1, dashboards=[])
    try:
        if request.method == "POST":
            d = request.get_json(silent=True) or {}
            cfg = grafana_embed.set_config(
                grafana_url=str(d.get("grafana_url", "")),
                api_key=str(d.get("api_key", "")),
                org_id=int(d.get("org_id", 1)),
                dashboards=d.get("dashboards"),
            )
            return ok(**cfg)
        return ok(**grafana_embed.get_config())
    except Exception as e:
        log.warning("api_grafana_config fail: %s", e)
        return err(str(e), 400)


@app.route("/api/grafana/dashboards")
@require_auth
@require_role("admin", "administrator")
def api_grafana_dashboards():
    if not grafana_embed: return ok(dashboards=[])
    try:
        return ok(dashboards=grafana_embed.list_dashboards())
    except Exception as e:
        log.warning("api_grafana_dashboards fail: %s", e)
        return ok(dashboards=[], error=str(e))


@app.route("/api/grafana/embed-url")
@require_auth
@require_role("admin", "administrator")
def api_grafana_embed_url():
    if not grafana_embed: return ok(url="")
    try:
        uid      = request.args.get("uid", "")
        panel_id = request.args.get("panel_id")
        from_    = request.args.get("from", "now-1h")
        to_      = request.args.get("to", "now")
        if panel_id is not None:
            panel_id = int(panel_id)
        url = grafana_embed.get_embed_url(uid, panel_id=panel_id, from_=from_, to_=to_)
        return ok(url=url)
    except Exception as e:
        log.warning("api_grafana_embed_url fail: %s", e)
        return err(str(e), 400)


@app.route("/api/grafana/test")
@require_auth
@require_role("admin", "administrator")
def api_grafana_test():
    if not grafana_embed: return ok(ok=False, status="module_unavailable")
    try:
        result = grafana_embed.test_connection()
        return ok(**result)
    except Exception as e:
        log.warning("api_grafana_test fail: %s", e)
        return ok(ok=False, status=str(e)[:120], latency_ms=0)


# ── Topology Viz (/api/topo-viz/* — avoids clash with existing /api/topology) ─

@app.route("/api/topo-viz/graph")
@require_auth
@require_role("admin", "administrator")
def api_topo_graph():
    if not topology_viz: return ok(nodes=[], edges=[])
    try:
        return ok(**topology_viz.get_topology())
    except Exception as e:
        log.warning("api_topo_graph fail: %s", e)
        return ok(nodes=[], edges=[], error=str(e))


@app.route("/api/topo-viz/lldp")
@require_auth
@require_role("admin", "administrator")
def api_topo_lldp():
    if not topology_viz: return ok(neighbors=[])
    try:
        return ok(neighbors=topology_viz.get_lldp_neighbors())
    except Exception as e:
        log.warning("api_topo_lldp fail: %s", e)
        return ok(neighbors=[], error=str(e))


@app.route("/api/topo-viz/flows")
@require_auth
@require_role("admin", "administrator")
def api_topo_flows():
    if not topology_viz: return ok(flows=[])
    try:
        return ok(flows=topology_viz.get_flow_matrix())
    except Exception as e:
        log.warning("api_topo_flows fail: %s", e)
        return ok(flows=[], error=str(e))


# ── ML Forecaster ─────────────────────────────────────────────────────────────

@app.route("/api/forecast/resource")
@require_auth
@require_role("admin", "administrator")
def api_fc_resource():
    if not ml_forecaster: return ok(metric=None, predicted=None, trend="unknown")
    try:
        metric  = request.args.get("metric", "cpu")
        horizon = int(request.args.get("horizon", 30))
        return ok(**ml_forecaster.forecast_resource(metric=metric, horizon_days=horizon))
    except Exception as e:
        log.warning("api_fc_resource fail: %s", e)
        return err(str(e), 400)


@app.route("/api/forecast/heatmap")
@require_auth
@require_role("admin", "administrator")
def api_fc_heatmap():
    if not ml_forecaster: return ok(matrix=[], hours=[], days=[])
    try:
        metric = request.args.get("metric", "cpu")
        period = request.args.get("period", "24h")
        return ok(**ml_forecaster.get_heatmap(metric=metric, period=period))
    except Exception as e:
        log.warning("api_fc_heatmap fail: %s", e)
        return err(str(e), 400)


@app.route("/api/forecast/capacity")
@require_auth
@require_role("admin", "administrator")
def api_fc_capacity():
    if not ml_forecaster: return ok(disk={}, ram={})
    try:
        return ok(**ml_forecaster.capacity_forecast())
    except Exception as e:
        log.warning("api_fc_capacity fail: %s", e)
        return ok(disk={}, ram={}, error=str(e))


# ── Config Drift ──────────────────────────────────────────────────────────────

@app.route("/api/drift/baselines", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_drift_baselines():
    if not drift_capacity: return ok(baselines=[])
    try:
        if request.method == "POST":
            d    = request.get_json(silent=True) or {}
            name = str(d.get("name", "")).strip()
            if not name:
                return err("baseline name required", 400)
            result = drift_capacity.capture_baseline(name)
            return ok(**result)
        return ok(baselines=drift_capacity.list_baselines())
    except Exception as e:
        log.warning("api_drift_baselines fail: %s", e)
        return err(str(e), 400)


@app.route("/api/drift/check/<name>")
@require_auth
@require_role("admin", "administrator")
def api_drift_check(name):
    if not drift_capacity: return ok(drifted_keys=[], added=[], removed=[])
    try:
        return ok(**drift_capacity.check_drift(name))
    except KeyError as e:
        return err(str(e), 404)
    except Exception as e:
        log.warning("api_drift_check fail name=%s: %s", name, e)
        return err(str(e), 500)


# ── Capacity Planning ─────────────────────────────────────────────────────────

@app.route("/api/capacity/whatif", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_cap_whatif():
    if not drift_capacity: return ok(fits=None)
    try:
        d = request.get_json(silent=True) or {}
        result = drift_capacity.whatif_add_vms(
            count=int(d.get("count", 1)),
            vcpus=int(d.get("vcpus", 2)),
            ram_mb=int(d.get("ram_mb", 2048)),
            disk_gb=float(d.get("disk_gb", 20)),
        )
        return ok(**result)
    except Exception as e:
        log.warning("api_cap_whatif fail: %s", e)
        return err(str(e), 400)


@app.route("/api/capacity/summary")
@require_auth
@require_role("admin", "administrator")
def api_cap_summary():
    if not drift_capacity: return ok(cpu={}, ram={}, disk={})
    try:
        return ok(**drift_capacity.capacity_summary())
    except Exception as e:
        log.warning("api_cap_summary fail: %s", e)
        return ok(cpu={}, ram={}, disk={}, error=str(e))


# ════════════════════════════════════════════════════════════════════════════
# v2.5.9 — Network Advanced 2 Endpoints (admin-only)
# microseg / bfd / service_chain / service_mesh
# All wrapped in try/except with safe defaults — modül yoksa boş döner.
# ════════════════════════════════════════════════════════════════════════════

# ── Microsegmentation ─────────────────────────────────────────────────────────

@app.route("/api/microseg")
@require_auth
@require_role("admin", "administrator")
def api_microseg_list():
    if not microseg: return ok(policies=[])
    try:
        return ok(policies=microseg.list_policies())
    except Exception as e:
        log.warning("api_microseg_list fail: %s", e)
        return ok(policies=[], error=str(e))


@app.route("/api/microseg/<vm_id>", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_microseg_vm(vm_id):
    if not microseg: return ok(policy=None)
    try:
        if request.method == "POST":
            d     = request.get_json(silent=True) or {}
            rules = d.get("rules", [])
            if not isinstance(rules, list):
                return err("rules must be a list", 400)
            return ok(**microseg.set_vm_policy(vm_id, rules))
        policy = microseg.get_vm_policy(vm_id)
        if policy is None:
            return err("No policy for vm_id", 404)
        return ok(policy=policy)
    except Exception as e:
        log.warning("api_microseg_vm fail vm=%s: %s", vm_id, e)
        return err(str(e), 500)


@app.route("/api/microseg/<vm_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_microseg_delete(vm_id):
    if not microseg: return ok(ok=False, error="module unavailable")
    try:
        return ok(**microseg.delete_vm_policy(vm_id))
    except Exception as e:
        log.warning("api_microseg_delete fail vm=%s: %s", vm_id, e)
        return err(str(e), 500)


@app.route("/api/microseg/<vm_id>/zero-trust", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_microseg_zero_trust(vm_id):
    if not microseg: return ok(ok=False, error="module unavailable")
    try:
        return ok(**microseg.apply_zero_trust(vm_id))
    except Exception as e:
        log.warning("api_microseg_zero_trust fail vm=%s: %s", vm_id, e)
        return err(str(e), 500)


# ── BFD Manager ───────────────────────────────────────────────────────────────

@app.route("/api/bfd", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_bfd_sessions():
    if not bfd_mgr: return ok(sessions=[])
    try:
        if request.method == "POST":
            d           = request.get_json(silent=True) or {}
            peer_ip     = str(d.get("peer_ip", "")).strip()
            interval_ms = int(d.get("interval_ms", 300))
            multiplier  = int(d.get("multiplier", 3))
            if not peer_ip:
                return err("peer_ip required", 400)
            return ok(**bfd_mgr.configure_bfd(peer_ip, interval_ms, multiplier))
        return ok(sessions=bfd_mgr.get_bfd_sessions())
    except Exception as e:
        log.warning("api_bfd fail: %s", e)
        return err(str(e), 500)


@app.route("/api/bfd/sessions")
@require_auth
@require_role("admin", "administrator")
def api_bfd_sessions_list():
    if not bfd_mgr: return ok(sessions=[])
    try:
        return ok(sessions=bfd_mgr.get_bfd_sessions())
    except Exception as e:
        log.warning("api_bfd_sessions_list fail: %s", e)
        return ok(sessions=[], error=str(e))


@app.route("/api/bfd/<path:peer>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_bfd_remove(peer):
    if not bfd_mgr: return ok(ok=False, error="module unavailable")
    try:
        return ok(**bfd_mgr.remove_bfd(peer))
    except Exception as e:
        log.warning("api_bfd_remove fail peer=%s: %s", peer, e)
        return err(str(e), 500)


@app.route("/api/bfd/check/<path:peer>")
@require_auth
@require_role("admin", "administrator")
def api_bfd_check(peer):
    if not bfd_mgr: return ok(reachable=False, rtt_ms=None)
    try:
        return ok(**bfd_mgr.check_peer(peer))
    except Exception as e:
        log.warning("api_bfd_check fail peer=%s: %s", peer, e)
        return ok(reachable=False, rtt_ms=None, error=str(e))


# ── Service Chain ─────────────────────────────────────────────────────────────

@app.route("/api/service-chain", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_svcchain_list_or_create():
    if not service_chain: return ok(chains=[])
    try:
        if request.method == "POST":
            d       = request.get_json(silent=True) or {}
            name    = str(d.get("name", "")).strip()
            hops    = d.get("hops", [])
            ingress = str(d.get("ingress", "")).strip()
            egress  = str(d.get("egress", "")).strip()
            if not name or not ingress or not egress:
                return err("name, ingress, egress required", 400)
            if not isinstance(hops, list):
                return err("hops must be a list", 400)
            return ok(**service_chain.create_chain(name, hops, ingress, egress))
        return ok(chains=service_chain.list_chains())
    except Exception as e:
        log.warning("api_svcchain fail: %s", e)
        return err(str(e), 500)


@app.route("/api/service-chain/<name>", methods=["GET", "DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_svcchain_detail(name):
    if not service_chain: return ok(chain=None)
    try:
        if request.method == "DELETE":
            return ok(**service_chain.delete_chain(name))
        chain = service_chain.get_chain(name)
        if chain is None:
            return err("Chain not found", 404)
        return ok(chain=chain)
    except Exception as e:
        log.warning("api_svcchain_detail fail name=%s: %s", name, e)
        return err(str(e), 500)


@app.route("/api/service-chain/<name>/stats")
@require_auth
@require_role("admin", "administrator")
def api_svcchain_stats(name):
    if not service_chain: return ok(ok=False, hops=[])
    try:
        return ok(**service_chain.get_chain_stats(name))
    except Exception as e:
        log.warning("api_svcchain_stats fail name=%s: %s", name, e)
        return ok(ok=False, hops=[], error=str(e))


# ── Service Mesh ──────────────────────────────────────────────────────────────

@app.route("/api/mesh/detect")
@require_auth
@require_role("admin", "administrator")
def api_mesh_detect():
    if not service_mesh: return ok(available=False, istio={}, linkerd={})
    try:
        return ok(**service_mesh.detect_mesh())
    except Exception as e:
        log.warning("api_mesh_detect fail: %s", e)
        return ok(available=False, error=str(e))


@app.route("/api/mesh/services", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_mesh_services():
    if not service_mesh: return ok(services=[])
    try:
        if request.method == "POST":
            d        = request.get_json(silent=True) or {}
            name     = str(d.get("name", "")).strip()
            vm_id    = str(d.get("vm_id", "")).strip()
            port     = int(d.get("port", 80))
            protocol = str(d.get("protocol", "tcp")).strip()
            if not name or not vm_id:
                return err("name and vm_id required", 400)
            return ok(**service_mesh.register_service(name, vm_id, port, protocol))
        return ok(services=service_mesh.list_services())
    except Exception as e:
        log.warning("api_mesh_services fail: %s", e)
        return err(str(e), 500)


@app.route("/api/mesh/services/<name>", methods=["GET", "DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_mesh_service_detail(name):
    if not service_mesh: return ok(service=None)
    try:
        if request.method == "DELETE":
            return ok(**service_mesh.delete_service(name))
        svc = service_mesh.get_service(name)
        if svc is None:
            return err("Service not found", 404)
        return ok(service=svc)
    except Exception as e:
        log.warning("api_mesh_service_detail fail name=%s: %s", name, e)
        return err(str(e), 500)


@app.route("/api/mesh/services/<name>/sidecar")
@require_auth
@require_role("admin", "administrator")
def api_mesh_sidecar(name):
    if not service_mesh: return ok(ok=False, yaml="")
    try:
        return ok(**service_mesh.generate_sidecar_config(name))
    except Exception as e:
        log.warning("api_mesh_sidecar fail name=%s: %s", name, e)
        return err(str(e), 500)


@app.route("/api/mesh/mtls")
@require_auth
@require_role("admin", "administrator")
def api_mesh_mtls():
    if not service_mesh: return ok(mtls=False, mesh="none")
    try:
        return ok(**service_mesh.get_mtls_status())
    except Exception as e:
        log.warning("api_mesh_mtls fail: %s", e)
        return ok(mtls=False, mesh="none", error=str(e))


# ════════════════════════════════════════════════════════════════════════════
# v2.5.10 — Cloud/K8s Endpoints (admin-only)
# pulumi_provider / k8s_csi / k8s_operator / kubevirt_int / gitops_sync
# All wrapped in try/except with safe defaults — modül yoksa boş döner.
# ════════════════════════════════════════════════════════════════════════════

# ── Pulumi Provider ───────────────────────────────────────────────────────────

@app.route("/api/pulumi/generate", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_pulumi_generate():
    if not pulumi_provider: return ok(code=None, language=None, count=0)
    try:
        d        = request.get_json(silent=True) or {}
        vms      = d.get("vms")
        language = d.get("language", "typescript")
        if language not in ("typescript", "python"):
            return err("language must be 'typescript' or 'python'", 400)
        return ok(**pulumi_provider.generate_pulumi_program(vms=vms, language=language))
    except Exception as e:
        log.warning("api_pulumi_generate fail: %s", e)
        return err(str(e), 500)


@app.route("/api/pulumi/state")
@require_auth
@require_role("admin", "administrator")
def api_pulumi_state():
    if not pulumi_provider: return ok(state=None)
    try:
        return ok(state=pulumi_provider.export_state())
    except Exception as e:
        log.warning("api_pulumi_state fail: %s", e)
        return err(str(e), 500)


@app.route("/api/pulumi/schema")
@require_auth
@require_role("admin", "administrator")
def api_pulumi_schema():
    if not pulumi_provider: return ok(schema=None)
    try:
        return ok(schema=pulumi_provider.get_provider_schema())
    except Exception as e:
        log.warning("api_pulumi_schema fail: %s", e)
        return err(str(e), 500)


# ── Kubernetes CSI ────────────────────────────────────────────────────────────

@app.route("/api/k8s-csi/manifests")
@require_auth
@require_role("admin", "administrator")
def api_csi_manifests():
    if not k8s_csi: return ok(daemonset_yaml=None, storageclass_yaml=None)
    try:
        return ok(**k8s_csi.generate_csi_manifests())
    except Exception as e:
        log.warning("api_csi_manifests fail: %s", e)
        return err(str(e), 500)


@app.route("/api/k8s-csi/volumes", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_csi_volumes():
    if not k8s_csi: return ok(volumes=[])
    try:
        if request.method == "POST":
            d    = request.get_json(silent=True) or {}
            name = d.get("name")
            if not name:
                return err("name is required", 400)
            size_gb       = int(d.get("size_gb", 10))
            storage_class = d.get("storage_class", "oxware-standard")
            return ok(**k8s_csi.create_volume_claim(name=name, size_gb=size_gb, storage_class=storage_class))
        return ok(volumes=k8s_csi.list_volumes())
    except Exception as e:
        log.warning("api_csi_volumes fail: %s", e)
        return err(str(e), 500)


@app.route("/api/k8s-csi/status")
@require_auth
@require_role("admin", "administrator")
def api_csi_status():
    if not k8s_csi: return ok(healthy=False, registered=False)
    try:
        return ok(**k8s_csi.get_csi_status())
    except Exception as e:
        log.warning("api_csi_status fail: %s", e)
        return ok(healthy=False, registered=False, error=str(e))


# ── Kubernetes Operator ───────────────────────────────────────────────────────

@app.route("/api/k8s-operator/crd")
@require_auth
@require_role("admin", "administrator")
def api_k8sop_crd():
    if not k8s_operator: return ok(crd_yaml=None)
    try:
        return ok(crd_yaml=k8s_operator.generate_crd())
    except Exception as e:
        log.warning("api_k8sop_crd fail: %s", e)
        return err(str(e), 500)


@app.route("/api/k8s-operator/manifests")
@require_auth
@require_role("admin", "administrator")
def api_k8sop_manifests():
    if not k8s_operator: return ok(deployment_yaml=None, rbac_yaml=None)
    try:
        return ok(**k8s_operator.generate_operator_manifests())
    except Exception as e:
        log.warning("api_k8sop_manifests fail: %s", e)
        return err(str(e), 500)


@app.route("/api/k8s-operator/managed")
@require_auth
@require_role("admin", "administrator")
def api_k8sop_managed():
    if not k8s_operator: return ok(vms=[])
    try:
        return ok(vms=k8s_operator.list_managed_vms())
    except Exception as e:
        log.warning("api_k8sop_managed fail: %s", e)
        return ok(vms=[], error=str(e))


@app.route("/api/k8s-operator/reconcile")
@require_auth
@require_role("admin", "administrator")
def api_k8sop_reconcile():
    if not k8s_operator: return ok(operator_running=False)
    try:
        return ok(**k8s_operator.reconcile_status())
    except Exception as e:
        log.warning("api_k8sop_reconcile fail: %s", e)
        return ok(operator_running=False, error=str(e))


# ── KubeVirt Integration ──────────────────────────────────────────────────────

@app.route("/api/kubevirt/detect")
@require_auth
@require_role("admin", "administrator")
def api_kubevirt_detect():
    if not kubevirt_int: return ok(detected=False)
    try:
        return ok(**kubevirt_int.detect_kubevirt())
    except Exception as e:
        log.warning("api_kubevirt_detect fail: %s", e)
        return ok(detected=False, error=str(e))


@app.route("/api/kubevirt/import", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_kubevirt_import():
    if not kubevirt_int: return ok(ok=False, error="module unavailable")
    try:
        d         = request.get_json(silent=True) or {}
        vmi_name  = d.get("vmi_name")
        namespace = d.get("namespace", "default")
        if not vmi_name:
            return err("vmi_name is required", 400)
        return ok(**kubevirt_int.import_from_kubevirt(vmi_name=vmi_name, namespace=namespace))
    except Exception as e:
        log.warning("api_kubevirt_import fail: %s", e)
        return err(str(e), 500)


@app.route("/api/kubevirt/export/<vm_id>")
@require_auth
@require_role("admin", "administrator")
def api_kubevirt_export(vm_id):
    if not kubevirt_int: return ok(ok=False, yaml=None, error="module unavailable")
    try:
        return ok(**kubevirt_int.export_to_kubevirt(vm_id=vm_id))
    except Exception as e:
        log.warning("api_kubevirt_export fail vm=%s: %s", vm_id, e)
        return err(str(e), 500)


@app.route("/api/kubevirt/vms")
@require_auth
@require_role("admin", "administrator")
def api_kubevirt_vms():
    if not kubevirt_int: return ok(vms=[])
    try:
        return ok(vms=kubevirt_int.list_kubevirt_vms())
    except Exception as e:
        log.warning("api_kubevirt_vms fail: %s", e)
        return ok(vms=[], error=str(e))


# ── GitOps Sync ───────────────────────────────────────────────────────────────

@app.route("/api/gitops/config", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_gitops_config():
    if not gitops_sync: return ok(configured=False)
    try:
        if request.method == "POST":
            d        = request.get_json(silent=True) or {}
            repo_url = d.get("repo_url")
            if not repo_url:
                return err("repo_url is required", 400)
            branch   = d.get("branch", "main")
            path     = d.get("path", ".")
            provider = d.get("provider", "argocd")
            ssh_key  = d.get("ssh_key")
            return ok(**gitops_sync.configure_gitops(
                repo_url=repo_url, branch=branch,
                path=path, provider=provider, ssh_key=ssh_key
            ))
        return ok(**gitops_sync.get_config())
    except Exception as e:
        log.warning("api_gitops_config fail: %s", e)
        return err(str(e), 500)


@app.route("/api/gitops/sync", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_gitops_sync():
    if not gitops_sync: return ok(ok=False, error="module unavailable")
    try:
        return ok(**gitops_sync.sync_now())
    except Exception as e:
        log.warning("api_gitops_sync fail: %s", e)
        return err(str(e), 500)


@app.route("/api/gitops/status")
@require_auth
@require_role("admin", "administrator")
def api_gitops_status():
    if not gitops_sync: return ok(configured=False, sync_status="unknown")
    try:
        return ok(**gitops_sync.get_sync_status())
    except Exception as e:
        log.warning("api_gitops_status fail: %s", e)
        return ok(configured=False, sync_status="error", error=str(e))


@app.route("/api/gitops/manifest")
@require_auth
@require_role("admin", "administrator")
def api_gitops_manifest():
    if not gitops_sync: return ok(manifest_yaml=None, provider=None)
    try:
        return ok(**gitops_sync.generate_app_manifest())
    except Exception as e:
        log.warning("api_gitops_manifest fail: %s", e)
        return err(str(e), 500)


# ════════════════════════════════════════════════════════════════════════════
# v2.5.11 — Modern Workloads Endpoints (admin-only)
# firecracker_mgr / kata_runtime / wasm_runtime / edge_mode
# All wrapped in try/except with safe defaults — modül yoksa boş döner.
# ════════════════════════════════════════════════════════════════════════════

# ── Firecracker microVM ───────────────────────────────────────────────────────

@app.route("/api/firecracker/detect")
@require_auth
@require_role("admin", "administrator")
def api_fcvm_detect():
    if not firecracker_mgr: return ok(available=False, error="module unavailable")
    try:
        return ok(**firecracker_mgr.detect_firecracker())
    except Exception as e:
        log.warning("api_fcvm_detect fail: %s", e)
        return err(str(e), 500)


@app.route("/api/firecracker/vms", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_fcvm_vms():
    if not firecracker_mgr: return ok(vms=[])
    try:
        if request.method == "GET":
            return ok(vms=firecracker_mgr.list_microvms())
        d         = request.get_json(silent=True) or {}
        name      = d.get("name", "oxvm")
        vcpus     = int(d.get("vcpus", 1))
        mem_mb    = int(d.get("mem_mb", 512))
        kernel    = d.get("kernel_path", "/opt/oxware/vmlinux")
        rootfs    = d.get("rootfs_path", "/opt/oxware/rootfs.ext4")
        return ok(**firecracker_mgr.create_microvm(name, vcpus, mem_mb, kernel, rootfs))
    except Exception as e:
        log.warning("api_fcvm_vms fail: %s", e)
        return err(str(e), 500)


@app.route("/api/firecracker/vms/<vm_id>", methods=["GET", "DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_fcvm_vm(vm_id):
    if not firecracker_mgr: return ok(vm=None)
    try:
        if request.method == "DELETE":
            return ok(**firecracker_mgr.stop_microvm(vm_id))
        vm = firecracker_mgr.get_microvm(vm_id)
        if vm is None:
            return err("vm not found", 404)
        return ok(vm=vm)
    except Exception as e:
        log.warning("api_fcvm_vm fail: %s", e)
        return err(str(e), 500)


# ── Kata Containers ───────────────────────────────────────────────────────────

@app.route("/api/kata/detect")
@require_auth
@require_role("admin", "administrator")
def api_kata_detect():
    if not kata_runtime: return ok(available=False, error="module unavailable")
    try:
        return ok(**kata_runtime.detect_kata())
    except Exception as e:
        log.warning("api_kata_detect fail: %s", e)
        return err(str(e), 500)


@app.route("/api/kata/containers")
@require_auth
@require_role("admin", "administrator")
def api_kata_containers():
    if not kata_runtime: return ok(containers=[])
    try:
        return ok(containers=kata_runtime.list_kata_containers())
    except Exception as e:
        log.warning("api_kata_containers fail: %s", e)
        return err(str(e), 500)


@app.route("/api/kata/runtime-class")
@require_auth
@require_role("admin", "administrator")
def api_kata_runtime_class():
    if not kata_runtime: return ok(runtime_class_yaml=None)
    try:
        return ok(**kata_runtime.generate_runtime_class())
    except Exception as e:
        log.warning("api_kata_runtime_class fail: %s", e)
        return err(str(e), 500)


@app.route("/api/kata/config")
@require_auth
@require_role("admin", "administrator")
def api_kata_config():
    if not kata_runtime: return ok(config_path=None, error="module unavailable")
    try:
        return ok(**kata_runtime.get_kata_config())
    except Exception as e:
        log.warning("api_kata_config fail: %s", e)
        return err(str(e), 500)


# ── WASM Runtime ──────────────────────────────────────────────────────────────

@app.route("/api/wasm/detect")
@require_auth
@require_role("admin", "administrator")
def api_wasm_detect():
    if not wasm_runtime: return ok(available=False, error="module unavailable")
    try:
        return ok(**wasm_runtime.detect_wasm())
    except Exception as e:
        log.warning("api_wasm_detect fail: %s", e)
        return err(str(e), 500)


@app.route("/api/wasm/modules", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_wasm_modules():
    if not wasm_runtime: return ok(modules=[])
    try:
        if request.method == "GET":
            return ok(modules=wasm_runtime.list_wasm_modules())
        d           = request.get_json(silent=True) or {}
        name        = d.get("name", "")
        path        = d.get("path", "")
        description = d.get("description", "")
        if not name or not path:
            return err("name and path required", 400)
        return ok(**wasm_runtime.register_module(name, path, description))
    except Exception as e:
        log.warning("api_wasm_modules fail: %s", e)
        return err(str(e), 500)


@app.route("/api/wasm/run", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_wasm_run():
    if not wasm_runtime: return ok(success=False, error="module unavailable")
    try:
        d         = request.get_json(silent=True) or {}
        wasm_path = d.get("wasm_path", "")
        args      = d.get("args", [])
        env       = d.get("env", {})
        timeout   = int(d.get("timeout", 30))
        if not wasm_path:
            return err("wasm_path required", 400)
        return ok(**wasm_runtime.run_wasm_module(wasm_path, args, env, timeout))
    except Exception as e:
        log.warning("api_wasm_run fail: %s", e)
        return err(str(e), 500)


# ── Edge Deployment ───────────────────────────────────────────────────────────

@app.route("/api/edge/status")
@require_auth
@require_role("admin", "administrator")
def api_edge_status():
    if not edge_mode: return ok(enabled=False, error="module unavailable")
    try:
        return ok(**edge_mode.get_edge_status())
    except Exception as e:
        log.warning("api_edge_status fail: %s", e)
        return err(str(e), 500)


@app.route("/api/edge/config", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_edge_config():
    if not edge_mode: return ok(configured=False)
    try:
        if request.method == "GET":
            return ok(**edge_mode.get_edge_status())
        d                   = request.get_json(silent=True) or {}
        central_url         = d.get("central_url")
        node_id             = d.get("node_id")
        heartbeat_interval  = int(d.get("heartbeat_interval", 60))
        low_resource        = bool(d.get("low_resource", False))
        return ok(**edge_mode.configure_edge(central_url, node_id, heartbeat_interval, low_resource))
    except Exception as e:
        log.warning("api_edge_config fail: %s", e)
        return err(str(e), 500)


@app.route("/api/edge/heartbeat", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_edge_heartbeat():
    if not edge_mode: return ok(sent=False, error="module unavailable")
    try:
        return ok(**edge_mode.send_heartbeat())
    except Exception as e:
        log.warning("api_edge_heartbeat fail: %s", e)
        return err(str(e), 500)


@app.route("/api/edge/profile")
@require_auth
@require_role("admin", "administrator")
def api_edge_profile():
    if not edge_mode: return ok(low_resource_mode=False, recommended_disabled=[])
    try:
        return ok(**edge_mode.get_resource_profile())
    except Exception as e:
        log.warning("api_edge_profile fail: %s", e)
        return err(str(e), 500)


# ════════════════════════════════════════════════════════════════════════════
# v2.7.0 — IaC + Clients Endpoints (admin-only)
# workflow_engine / opa_policy / cloudevents / electron_client / cloud_export
# All wrapped in try/except with safe defaults — modül yoksa boş döner.
# ════════════════════════════════════════════════════════════════════════════

# ── Workflow Engine ───────────────────────────────────────────────────────────

@app.route("/api/workflow", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_wf_list_create():
    if not workflow_engine: return ok(workflows=[])
    try:
        if request.method == "GET":
            return ok(workflows=workflow_engine.list_workflows())
        d = request.get_json(silent=True) or {}
        name        = d.get("name", "")
        steps       = d.get("steps", [])
        description = d.get("description", "")
        enabled     = bool(d.get("enabled", True))
        if not name:
            return err("name required", 400)
        if not isinstance(steps, list):
            return err("steps must be a list", 400)
        return ok(workflow=workflow_engine.create_workflow(name, steps, description, enabled))
    except ValueError as ve:
        return err(str(ve), 400)
    except Exception as e:
        log.warning("api_wf_list_create fail: %s", e)
        return err(str(e), 500)


@app.route("/api/workflow/<wf_id>", methods=["GET", "DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_wf_get_delete(wf_id):
    if not workflow_engine: return ok(workflow=None)
    try:
        if request.method == "DELETE":
            return ok(**workflow_engine.delete_workflow(wf_id))
        wf = workflow_engine.get_workflow(wf_id)
        if wf is None:
            return err("workflow not found", 404)
        return ok(workflow=wf)
    except Exception as e:
        log.warning("api_wf_get_delete fail: %s", e)
        return err(str(e), 500)


@app.route("/api/workflow/<wf_id>/run", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_wf_run(wf_id):
    if not workflow_engine: return ok(ok=False, error="module unavailable")
    try:
        d       = request.get_json(silent=True) or {}
        dry_run = bool(d.get("dry_run", False))
        return ok(**workflow_engine.run_workflow(wf_id, dry_run=dry_run))
    except Exception as e:
        log.warning("api_wf_run fail: %s", e)
        return err(str(e), 500)


@app.route("/api/workflow/<wf_id>/history")
@require_auth
@require_role("admin", "administrator")
def api_wf_history(wf_id):
    if not workflow_engine: return ok(history=[])
    try:
        limit = int(request.args.get("limit", 50))
        return ok(history=workflow_engine.get_run_history(wf_id, limit=limit))
    except Exception as e:
        log.warning("api_wf_history fail: %s", e)
        return err(str(e), 500)


# ── OPA Policy Engine ─────────────────────────────────────────────────────────

@app.route("/api/opa/policies", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_opa_policies():
    if not opa_policy: return ok(policies=[])
    try:
        if request.method == "GET":
            return ok(policies=opa_policy.list_policies())
        d           = request.get_json(silent=True) or {}
        name        = d.get("name", "")
        rego_source = d.get("rego_source", "")
        description = d.get("description", "")
        if not name:
            return err("name required", 400)
        if not rego_source:
            return err("rego_source required", 400)
        return ok(policy=opa_policy.set_policy(name, rego_source, description))
    except ValueError as ve:
        return err(str(ve), 400)
    except Exception as e:
        log.warning("api_opa_policies fail: %s", e)
        return err(str(e), 500)


@app.route("/api/opa/policies/<name>", methods=["GET", "DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_opa_policy(name):
    if not opa_policy: return ok(policy=None)
    try:
        if request.method == "DELETE":
            return ok(**opa_policy.delete_policy(name))
        policy = opa_policy.get_policy(name)
        if policy is None:
            return err("policy not found", 404)
        return ok(policy=policy)
    except Exception as e:
        log.warning("api_opa_policy fail: %s", e)
        return err(str(e), 500)


@app.route("/api/opa/evaluate", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_opa_evaluate():
    if not opa_policy: return ok(allowed=False, error="module unavailable")
    try:
        d           = request.get_json(silent=True) or {}
        policy_name = d.get("policy_name", d.get("policy", ""))
        input_json  = d.get("input", {})
        if not policy_name:
            return err("policy_name required", 400)
        return ok(**opa_policy.evaluate(policy_name, input_json))
    except Exception as e:
        log.warning("api_opa_evaluate fail: %s", e)
        return err(str(e), 500)


@app.route("/api/opa/test", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_opa_test():
    if not opa_policy: return ok(allowed=False, test=True, error="module unavailable")
    try:
        d           = request.get_json(silent=True) or {}
        policy_name = d.get("policy_name", d.get("policy", ""))
        test_input  = d.get("input", {})
        if not policy_name:
            return err("policy_name required", 400)
        return ok(**opa_policy.test_policy(policy_name, test_input))
    except Exception as e:
        log.warning("api_opa_test fail: %s", e)
        return err(str(e), 500)


# ── CloudEvents ───────────────────────────────────────────────────────────────

@app.route("/api/cloudevents/emit", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ce_emit():
    if not cloudevents_mod: return ok(emitted=False, error="module unavailable")
    try:
        d          = request.get_json(silent=True) or {}
        event_type = d.get("type", "")
        source     = d.get("source", "oxware/api")
        data       = d.get("data", {})
        subject    = d.get("subject")
        if not event_type:
            return err("type required", 400)
        event = cloudevents_mod.emit_event(event_type, source, data, subject)
        return ok(emitted=True, event=event)
    except Exception as e:
        log.warning("api_ce_emit fail: %s", e)
        return err(str(e), 500)


@app.route("/api/cloudevents")
@require_auth
@require_role("admin", "administrator")
def api_ce_list():
    if not cloudevents_mod: return ok(events=[])
    try:
        limit = int(request.args.get("limit", 100))
        return ok(events=cloudevents_mod.list_events(limit=limit))
    except Exception as e:
        log.warning("api_ce_list fail: %s", e)
        return err(str(e), 500)


@app.route("/api/cloudevents/sink", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_ce_sink():
    if not cloudevents_mod: return ok(sink=None)
    try:
        if request.method == "GET":
            return ok(sink=cloudevents_mod.get_sink())
        d   = request.get_json(silent=True) or {}
        url = d.get("url", "")
        fmt = d.get("format", "structured")
        if not url:
            return err("url required", 400)
        return ok(sink=cloudevents_mod.configure_sink(url, fmt))
    except ValueError as ve:
        return err(str(ve), 400)
    except Exception as e:
        log.warning("api_ce_sink fail: %s", e)
        return err(str(e), 500)


@app.route("/api/cloudevents/types")
@require_auth
@require_role("admin", "administrator")
def api_ce_types():
    if not cloudevents_mod: return ok(types=[])
    try:
        return ok(types=cloudevents_mod.get_event_types())
    except Exception as e:
        log.warning("api_ce_types fail: %s", e)
        return err(str(e), 500)


# ── Desktop / Electron Client ─────────────────────────────────────────────────

@app.route("/api/desktop/config")
@require_auth
@require_role("admin", "administrator")
def api_desktop_config():
    if not electron_client: return ok(config=None, error="module unavailable")
    try:
        server_url = request.args.get("server_url") or \
                     f"{'https' if config.SSL_ENABLED else 'http'}://{config.HOST}:{config.PORT}"
        return ok(config=electron_client.generate_client_config(server_url))
    except Exception as e:
        log.warning("api_desktop_config fail: %s", e)
        return err(str(e), 500)


@app.route("/api/desktop/clients", methods=["GET", "POST"])
@require_auth
@require_role("admin", "administrator")
def api_desktop_clients():
    if not electron_client: return ok(clients=[])
    try:
        if request.method == "GET":
            return ok(clients=electron_client.list_clients())
        d           = request.get_json(silent=True) or {}
        name        = d.get("name", "")
        platform    = d.get("platform", "other")
        description = d.get("description", "")
        if not name:
            return err("name required", 400)
        return ok(client=electron_client.register_client(name, platform, description))
    except ValueError as ve:
        return err(str(ve), 400)
    except Exception as e:
        log.warning("api_desktop_clients fail: %s", e)
        return err(str(e), 500)


@app.route("/api/desktop/clients/<client_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_desktop_client_revoke(client_id):
    if not electron_client: return ok(ok=False, error="module unavailable")
    try:
        return ok(**electron_client.revoke_client(client_id))
    except Exception as e:
        log.warning("api_desktop_client_revoke fail: %s", e)
        return err(str(e), 500)


@app.route("/api/desktop/downloads")
@require_auth
@require_role("admin", "administrator")
def api_desktop_downloads():
    if not electron_client: return ok(downloads=None)
    try:
        return ok(downloads=electron_client.get_download_links())
    except Exception as e:
        log.warning("api_desktop_downloads fail: %s", e)
        return err(str(e), 500)


# ── Cloud Export ──────────────────────────────────────────────────────────────

@app.route("/api/cloud-export/aws", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_cexport_aws():
    if not cloud_export: return ok(ok=False, error="module unavailable")
    try:
        d      = request.get_json(silent=True) or {}
        vm_id  = d.get("vm_id", "")
        region = d.get("region", "us-east-1")
        if not vm_id:
            return err("vm_id required", 400)
        return ok(**cloud_export.export_to_aws(vm_id, region=region))
    except Exception as e:
        log.warning("api_cexport_aws fail: %s", e)
        return err(str(e), 500)


@app.route("/api/cloud-export/azure", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_cexport_azure():
    if not cloud_export: return ok(ok=False, error="module unavailable")
    try:
        d     = request.get_json(silent=True) or {}
        vm_id = d.get("vm_id", "")
        if not vm_id:
            return err("vm_id required", 400)
        return ok(**cloud_export.export_to_azure(vm_id))
    except Exception as e:
        log.warning("api_cexport_azure fail: %s", e)
        return err(str(e), 500)


@app.route("/api/cloud-export/gcp", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_cexport_gcp():
    if not cloud_export: return ok(ok=False, error="module unavailable")
    try:
        d     = request.get_json(silent=True) or {}
        vm_id = d.get("vm_id", "")
        if not vm_id:
            return err("vm_id required", 400)
        return ok(**cloud_export.export_to_gcp(vm_id))
    except Exception as e:
        log.warning("api_cexport_gcp fail: %s", e)
        return err(str(e), 500)


@app.route("/api/cloud-export")
@require_auth
@require_role("admin", "administrator")
def api_cexport_list():
    if not cloud_export: return ok(exports=[])
    try:
        return ok(exports=cloud_export.list_exports())
    except Exception as e:
        log.warning("api_cexport_list fail: %s", e)
        return err(str(e), 500)


@app.route("/api/cloud-export/targets")
@require_auth
@require_role("admin", "administrator")
def api_cexport_targets():
    if not cloud_export: return ok(targets={})
    try:
        return ok(targets=cloud_export.get_supported_targets())
    except Exception as e:
        log.warning("api_cexport_targets fail: %s", e)
        return err(str(e), 500)


# ══════════════════════════════════════════════════════════════════════════════
# v2.7.0 — Enterprise Expansion Endpoints (admin-only)
# ══════════════════════════════════════════════════════════════════════════════

# ── Fault Tolerance ───────────────────────────────────────────────────────────
@app.route("/api/ft/pairs", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_ft_list():
    if not fault_tolerance_mgr: return ok(pairs=[])
    return ok(pairs=fault_tolerance_mgr.list_ft_pairs())

@app.route("/api/ft/pairs", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ft_create():
    if not fault_tolerance_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    try:
        result = fault_tolerance_mgr.create_ft_pair(
            d.get("primary_vm_id", ""),
            d.get("secondary_pool", "default"),
            int(d.get("sync_interval_minutes", 15))
        )
        return ok(**result), 201
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/ft/<vm_id>/status", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_ft_status(vm_id):
    if not fault_tolerance_mgr: return ok(status="unprotected")
    return ok(**fault_tolerance_mgr.get_ft_status(vm_id))

@app.route("/api/ft/<vm_id>/failover", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ft_failover(vm_id):
    if not fault_tolerance_mgr: return err("modül yok", 503)
    try:
        return ok(**fault_tolerance_mgr.trigger_failover(vm_id))
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/ft/<vm_id>/sync", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_ft_sync(vm_id):
    if not fault_tolerance_mgr: return err("modül yok", 503)
    try:
        return ok(**fault_tolerance_mgr.sync_checkpoint(vm_id))
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/ft/<vm_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_ft_remove(vm_id):
    if not fault_tolerance_mgr: return err("modül yok", 503)
    try:
        return ok(**fault_tolerance_mgr.remove_ft(vm_id))
    except Exception as e:
        return err(str(e), 500)

# ── Storage DRS ───────────────────────────────────────────────────────────────
@app.route("/api/storage-drs/analyze", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_storage_drs_analyze():
    if not storage_drs_mgr: return ok(pools=[])
    return ok(**storage_drs_mgr.analyze_pools())

@app.route("/api/storage-drs/recommendations", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_storage_drs_recommendations():
    if not storage_drs_mgr: return ok(recommendations=[])
    return ok(recommendations=storage_drs_mgr.get_recommendations())

@app.route("/api/storage-drs/rebalance", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_storage_drs_rebalance():
    if not storage_drs_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    dry_run = bool(d.get("dry_run", True))
    try:
        return ok(**storage_drs_mgr.auto_rebalance(dry_run=dry_run))
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/storage-drs/migrate", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_storage_drs_migrate():
    if not storage_drs_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    try:
        return ok(**storage_drs_mgr.migrate_disk(d.get("vm_id",""), d.get("disk_path",""), d.get("target_pool","")))
    except Exception as e:
        return err(str(e), 500)

# ── Console Recording (VNC→WebM) — /api/console-recordings/* ─────────────────
# NOTE: /api/recordings/* is used by session_recorder (SSH/VNC session replay)
@app.route("/api/console-recordings", methods=["GET"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_console_recordings_list():
    if not console_recorder_mgr: return ok(recordings=[])
    vm_id = request.args.get("vm_id")
    return ok(recordings=console_recorder_mgr.list_recordings(vm_id))

@app.route("/api/console-recordings/start", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_console_recording_start():
    if not console_recorder_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    try:
        return ok(**console_recorder_mgr.start_recording(
            d.get("vm_id",""), int(d.get("vnc_port", 5900)),
            int(d.get("duration_seconds", 3600))
        )), 201
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/console-recordings/<recording_id>/stop", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_console_recording_stop(recording_id):
    if not console_recorder_mgr: return err("modül yok", 503)
    try:
        return ok(**console_recorder_mgr.stop_recording(recording_id))
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/console-recordings/<recording_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_console_recording_delete(recording_id):
    if not console_recorder_mgr: return err("modül yok", 503)
    try:
        return ok(**console_recorder_mgr.delete_recording(recording_id))
    except Exception as e:
        return err(str(e), 500)

# ── 2FA Recovery Codes ────────────────────────────────────────────────────────
@app.route("/api/recovery-codes/generate", methods=["POST"])
@require_auth
def api_recovery_codes_generate():
    if not recovery_codes_mgr: return err("modül yok", 503)
    from flask_jwt_extended import get_jwt_identity
    username = get_jwt_identity()
    codes = recovery_codes_mgr.generate_codes(username)
    return ok(codes=codes, warning="Bu kodları güvenli bir yerde saklayın. Tekrar gösterilmeyecek.")

@app.route("/api/recovery-codes/status", methods=["GET"])
@require_auth
def api_recovery_codes_status():
    if not recovery_codes_mgr: return ok(has_codes=False, count=0)
    from flask_jwt_extended import get_jwt_identity
    username = get_jwt_identity()
    return ok(**recovery_codes_mgr.get_status(username))

@app.route("/api/recovery-codes/revoke", methods=["DELETE"])
@require_auth
def api_recovery_codes_revoke():
    if not recovery_codes_mgr: return err("modül yok", 503)
    from flask_jwt_extended import get_jwt_identity
    username = get_jwt_identity()
    return ok(**recovery_codes_mgr.revoke_all(username))

@app.route("/api/auth/recovery", methods=["POST"])
def api_auth_recovery():
    """Authenticate with recovery code (no JWT needed)."""
    if not recovery_codes_mgr: return err("Recovery codes not enabled", 503)
    d = request.get_json() or {}
    username = d.get("username", "").strip().lower()
    code     = d.get("code", "").strip()
    if not username or not code:
        return err("username ve code zorunludur")
    if recovery_codes_mgr.verify_code(username, code):
        from flask_jwt_extended import create_access_token
        token = create_access_token(identity=username)
        ev.info(f"Recovery code kullanıldı: {username}", category="auth")
        return ok(access_token=token, message="Recovery code geçerli. Yeni şifre belirleyin.")
    return err("Geçersiz veya kullanılmış recovery code", 401)

# ── Plugin SDK ────────────────────────────────────────────────────────────────
@app.route("/api/plugins", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_plugins_list():
    if not plugin_sdk_mgr: return ok(plugins=[])
    return ok(plugins=plugin_sdk_mgr.list_plugins())

@app.route("/api/plugins/<plugin_id>/enable", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_plugin_enable(plugin_id):
    if not plugin_sdk_mgr: return err("modül yok", 503)
    return ok(**plugin_sdk_mgr.enable_plugin(plugin_id))

@app.route("/api/plugins/<plugin_id>/disable", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_plugin_disable(plugin_id):
    if not plugin_sdk_mgr: return err("modül yok", 503)
    return ok(**plugin_sdk_mgr.disable_plugin(plugin_id))

@app.route("/api/plugins/template", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_plugin_template():
    if not plugin_sdk_mgr: return err("modül yok", 503)
    return ok(template=plugin_sdk_mgr.get_plugin_template())

# ── Plugin SDK — geliştirme + marketplace (v2.7.0) ────────────────────────────
@app.route("/api/plugins/upload", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_plugin_upload():
    """Plugin yükle (.py veya .zip, base64). Varsayılan: disabled (admin enable etmeli)."""
    if not plugin_sdk_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    fn = d.get("filename", "")
    content = d.get("content_b64", "")
    if not fn or not content:
        return err("filename ve content_b64 zorunlu")
    try:
        return ok(**plugin_sdk_mgr.upload_plugin(fn, content))
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/plugins/validate", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_plugin_validate():
    """Plugin kodunu syntax + güvenlik taramasından geçir (yazmadan)."""
    if not plugin_sdk_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    return ok(**plugin_sdk_mgr.validate_plugin_code(d.get("code", "")))

@app.route("/api/plugins/<plugin_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_plugin_uninstall(plugin_id):
    if not plugin_sdk_mgr: return err("modül yok", 503)
    return ok(**plugin_sdk_mgr.uninstall_plugin(plugin_id))

@app.route("/api/plugins/<plugin_id>/source", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_plugin_source_get(plugin_id):
    if not plugin_sdk_mgr: return err("modül yok", 503)
    return ok(**plugin_sdk_mgr.get_plugin_source(plugin_id))

@app.route("/api/plugins/<plugin_id>/source", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_plugin_source_save(plugin_id):
    if not plugin_sdk_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    return ok(**plugin_sdk_mgr.save_plugin_source(plugin_id, d.get("code", "")))

@app.route("/api/plugins/<plugin_id>/logs", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_plugin_logs(plugin_id):
    if not plugin_sdk_mgr: return ok(logs=[])
    limit = int(request.args.get("limit", 100))
    return ok(logs=plugin_sdk_mgr.get_plugin_logs(plugin_id, limit))

@app.route("/api/plugins/scaffold", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_plugin_scaffold():
    if not plugin_sdk_mgr: return err("modül yok", 503)
    kind = request.args.get("kind", "basic")
    return ok(**plugin_sdk_mgr.scaffold(kind))

@app.route("/api/plugins/sdk-info", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_plugin_sdk_info():
    if not plugin_sdk_mgr: return ok({})
    return ok(**plugin_sdk_mgr.get_sdk_info())

# ── VM Disk Hot-Extend ────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/disks", methods=["GET"])
@require_auth
def api_vm_hot_disks(vm_id):
    if not vm_hot_extend_mgr: return ok(disks=[])
    try:
        return ok(disks=vm_hot_extend_mgr.get_disk_info(vm_id))
    except Exception as e:
        return err(str(e), 500)

@app.route("/api/vms/<vm_id>/disks/extend", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_vm_disk_extend(vm_id):
    if not vm_hot_extend_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    try:
        return ok(**vm_hot_extend_mgr.extend_disk(
            vm_id, d.get("disk_target", "vda"), int(d.get("new_size_gb", 0))
        ))
    except Exception as e:
        return err(str(e), 500)

# ── Bulk VM Operations ────────────────────────────────────────────────────────
@app.route("/api/vms/bulk/start", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_bulk_start():
    if not bulk_vm_ops_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    return ok(**bulk_vm_ops_mgr.bulk_start(d.get("vm_ids", [])))

@app.route("/api/vms/bulk/stop", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_bulk_stop():
    if not bulk_vm_ops_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    return ok(**bulk_vm_ops_mgr.bulk_stop(d.get("vm_ids", []), bool(d.get("force", False))))

@app.route("/api/vms/bulk/snapshot", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_bulk_ops_snapshot():
    if not bulk_vm_ops_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    return ok(**bulk_vm_ops_mgr.bulk_snapshot(d.get("vm_ids", []), d.get("snap_name", "bulk-snap")))

@app.route("/api/vms/bulk/tag", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_bulk_tag():
    if not bulk_vm_ops_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    action = d.get("action", "add")
    fn = bulk_vm_ops_mgr.bulk_add_tag if action == "add" else bulk_vm_ops_mgr.bulk_remove_tag
    return ok(**fn(d.get("vm_ids", []), d.get("tag", "")))

@app.route("/api/vms/bulk/set-vcpus", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_bulk_vcpus():
    if not bulk_vm_ops_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    return ok(**bulk_vm_ops_mgr.bulk_set_vcpus(d.get("vm_ids", []), int(d.get("vcpus", 1))))

@app.route("/api/vms/bulk/set-memory", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_bulk_memory():
    if not bulk_vm_ops_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    return ok(**bulk_vm_ops_mgr.bulk_set_memory(d.get("vm_ids", []), int(d.get("memory_mb", 1024))))

@app.route("/api/vms/bulk/delete", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_bulk_delete():
    if not bulk_vm_ops_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    return ok(**bulk_vm_ops_mgr.bulk_delete(
        d.get("vm_ids", []), bool(d.get("delete_disk", False)),
        d.get("confirm_token", "")
    ))

@app.route("/api/vms/bulk/status/<job_id>", methods=["GET"])
@require_auth
def api_bulk_status(job_id):
    if not bulk_vm_ops_mgr: return ok(status="unknown")
    return ok(**bulk_vm_ops_mgr.get_bulk_status(job_id))

# ── Network Mode / IP Fix ─────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/network-mode", methods=["GET"])
@require_auth
def api_vm_network_mode(vm_id):
    """Detect NAT vs Bridge mode + static IP guidance."""
    if not net_mode_mgr: return ok(mode="UNKNOWN")
    return ok(**net_mode_mgr.detect_vm_network_mode(vm_id))

@app.route("/api/vms/<vm_id>/network-info", methods=["GET"])
@require_auth
def api_vm_network_info(vm_id):
    """Full network context: mode, gateway, DHCP range, static IP guidance."""
    if not net_mode_mgr: return ok(mode="UNKNOWN")
    return ok(**net_mode_mgr.get_network_info(vm_id))

@app.route("/api/vms/<vm_id>/network-info/validate-ip", methods=["POST"])
@require_auth
def api_vm_validate_ip(vm_id):
    """Check if a static IP assignment will work for this VM."""
    if not net_mode_mgr: return ok(valid=True)
    d = request.get_json() or {}
    return ok(**net_mode_mgr.validate_static_ip(vm_id, d.get("ip", "")))

@app.route("/api/vms/<vm_id>/network-info/suggest-fix", methods=["GET"])
@require_auth
def api_vm_ip_fix(vm_id):
    """Human-readable IP setup recommendation for this VM."""
    if not net_mode_mgr: return ok(steps=[])
    return ok(**net_mode_mgr.suggest_ip_fix(vm_id))

@app.route("/api/networks/routable", methods=["GET"])
@require_auth
def api_routable_networks():
    """List networks where VMs can get real upstream IPs."""
    if not net_mode_mgr: return ok(networks=[])
    return ok(networks=net_mode_mgr.list_routable_networks())

@app.route("/api/networks/bridge-status", methods=["GET"])
@require_auth
def api_bridge_status():
    """Check if oxbr0 bridge is configured."""
    if not net_mode_mgr: return ok(configured=False)
    return ok(**net_mode_mgr.get_bridge_setup_status())

# ── Green Mode / Power Optimization (v2.7.0) ─────────────────────────────────
@app.route("/api/green-mode/config", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_green_config():
    if not green_mode_mgr: return ok({"enabled": False, "available": False})
    return ok(**green_mode_mgr.get_config())

@app.route("/api/green-mode/config", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_green_config_set():
    if not green_mode_mgr: return err("modül yok", 503)
    return ok(**green_mode_mgr.set_config(request.get_json() or {}))

@app.route("/api/green-mode/score", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_green_score():
    if not green_mode_mgr: return ok({"score": 0})
    return ok(**green_mode_mgr.get_green_score())

@app.route("/api/green-mode/savings", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_green_savings():
    if not green_mode_mgr: return ok({"kwh_saved": 0, "cost_saved": 0})
    return ok(**green_mode_mgr.analyze_savings_potential())

@app.route("/api/green-mode/forecast", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_green_forecast():
    if not green_mode_mgr: return ok(forecast=[])
    hours = int(request.args.get("hours", 24))
    return ok(forecast=green_mode_mgr.predict_load_window(hours))

@app.route("/api/green-mode/recommendations", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_green_recommendations():
    if not green_mode_mgr: return ok(recommendations=[])
    return ok(**green_mode_mgr.recommend_consolidation())

@app.route("/api/green-mode/enter", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_green_enter():
    """Tüketim azaltma penceresine gir — VM'leri konsolide et, idle node'ları askıya al."""
    if not green_mode_mgr: return err("modül yok", 503)
    d = request.get_json(silent=True) or {}
    dry_run = bool(d.get("dry_run", True))
    return ok(**green_mode_mgr.enter_green_window(dry_run=dry_run))

@app.route("/api/green-mode/nodes", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_green_nodes():
    if not green_mode_mgr: return ok(nodes=[])
    return ok(nodes=green_mode_mgr.list_node_states())

@app.route("/api/green-mode/nodes/<node>/wake", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_green_wake(node):
    if not green_mode_mgr: return err("modül yok", 503)
    d = request.get_json(silent=True) or {}
    return ok(**green_mode_mgr.wake_node(node, method=d.get("method", "wol")))

@app.route("/api/green-mode/nodes/<node>/suspend", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_green_suspend(node):
    if not green_mode_mgr: return err("modül yok", 503)
    d = request.get_json(silent=True) or {}
    return ok(**green_mode_mgr.suspend_node(node, method=d.get("method", "s3")))

@app.route("/api/green-mode/history", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_green_history():
    if not green_mode_mgr: return ok(history=[])
    days = int(request.args.get("days", 7))
    return ok(history=green_mode_mgr.get_history(days))

# ═══════════════════════════════════════════════════════════════════════════════
# v2.7.0 — Multi-Region, Marketplace, Cloud Burst, Bare-Metal, OAuth2 SSO
# ═══════════════════════════════════════════════════════════════════════════════

# ── Multi-Region ────────────────────────────────────────────────────────────
@app.route("/api/regions", methods=["GET"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_regions_list():
    if not multi_region_mgr: return ok(regions=[])
    return ok(regions=multi_region_mgr.list_regions())

@app.route("/api/regions", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_regions_add():
    if not multi_region_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    try:
        return ok(**multi_region_mgr.add_region(
            d.get("name",""), d.get("endpoint",""),
            float(d.get("latitude", 0)), float(d.get("longitude", 0)),
            d.get("timezone","UTC"), float(d.get("weight", 1.0))
        )), 201
    except Exception as e: return err(str(e), 500)

@app.route("/api/regions/<name>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_regions_remove(name):
    if not multi_region_mgr: return err("modül yok", 503)
    return ok(**multi_region_mgr.remove_region(name))

@app.route("/api/regions/place", methods=["POST"])
@require_auth
def api_regions_place_vm():
    if not multi_region_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    return ok(**multi_region_mgr.place_vm(
        d.get("vm_spec", {}), d.get("prefer_region"), d.get("user_location")
    ))

@app.route("/api/regions/replication", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_regions_replication_status():
    if not multi_region_mgr: return ok(replications=[])
    return ok(replications=multi_region_mgr.get_replication_status())

@app.route("/api/regions/<vm_id>/failover", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_regions_failover(vm_id):
    if not multi_region_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    return ok(**multi_region_mgr.failover_to_region(vm_id, d.get("target_region","")))

@app.route("/api/regions/topology", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_regions_topology():
    if not multi_region_mgr: return ok(nodes=[], edges=[])
    return ok(**multi_region_mgr.get_topology())

# ── App Marketplace ─────────────────────────────────────────────────────────
@app.route("/api/marketplace/apps", methods=["GET"])
@require_auth
def api_marketplace_list():
    if not marketplace_mgr: return ok(apps=[])
    return ok(apps=marketplace_mgr.list_apps(request.args.get("category")))

@app.route("/api/marketplace/search", methods=["GET"])
@require_auth
def api_marketplace_search():
    if not marketplace_mgr: return ok(apps=[])
    return ok(apps=marketplace_mgr.search_apps(request.args.get("q","")))

@app.route("/api/marketplace/apps/<app_id>", methods=["GET"])
@require_auth
def api_marketplace_get(app_id):
    if not marketplace_mgr: return err("modül yok", 503)
    return ok(**marketplace_mgr.get_app(app_id))

@app.route("/api/marketplace/install", methods=["POST"])
@require_auth
@require_role("admin", "administrator", "operator")
def api_marketplace_install():
    if not marketplace_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    try:
        return ok(**marketplace_mgr.install_app(d.get("app_id",""), d.get("target_dir")))
    except Exception as e: return err(str(e), 500)

@app.route("/api/marketplace/uninstall", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_marketplace_uninstall():
    if not marketplace_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    return ok(**marketplace_mgr.uninstall_app(d.get("app_id","")))

@app.route("/api/marketplace/refresh", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_marketplace_refresh():
    if not marketplace_mgr: return err("modül yok", 503)
    return ok(**marketplace_mgr.refresh_index())

@app.route("/api/marketplace/installed", methods=["GET"])
@require_auth
def api_marketplace_installed():
    if not marketplace_mgr: return ok(installed=[])
    return ok(installed=marketplace_mgr.get_installed())

@app.route("/api/marketplace/categories", methods=["GET"])
@require_auth
def api_marketplace_categories():
    if not marketplace_mgr: return ok(categories=[])
    return ok(categories=marketplace_mgr.get_categories())

# ── Cloud Burst ─────────────────────────────────────────────────────────────
@app.route("/api/cloud-burst/config", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_burst_config():
    if not cloud_burst_mgr: return ok({"enabled": False})
    return ok(**cloud_burst_mgr.get_config())

@app.route("/api/cloud-burst/config", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_burst_config_set():
    if not cloud_burst_mgr: return err("modül yok", 503)
    return ok(**cloud_burst_mgr.set_config(request.get_json() or {}))

@app.route("/api/cloud-burst/nodes", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_burst_nodes():
    if not cloud_burst_mgr: return ok(nodes=[])
    return ok(nodes=cloud_burst_mgr.get_burst_nodes())

@app.route("/api/cloud-burst/check", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_burst_check():
    if not cloud_burst_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    return ok(**cloud_burst_mgr.check_should_burst(float(d.get("local_load_pct", 0))))

@app.route("/api/cloud-burst/provision", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_burst_provision():
    if not cloud_burst_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    try:
        return ok(**cloud_burst_mgr.provision_burst_node(d.get("provider","aws"), d.get("instance_type")))
    except Exception as e: return err(str(e), 500)

@app.route("/api/cloud-burst/nodes/<node_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_burst_retire(node_id):
    if not cloud_burst_mgr: return err("modül yok", 503)
    return ok(**cloud_burst_mgr.retire_burst_node(node_id))

@app.route("/api/cloud-burst/costs", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_burst_costs():
    if not cloud_burst_mgr: return ok({"total_usd": 0})
    days = int(request.args.get("days", 30))
    return ok(**cloud_burst_mgr.get_burst_costs(days))

@app.route("/api/cloud-burst/audit", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_burst_audit():
    if not cloud_burst_mgr: return ok(audit=[])
    limit = int(request.args.get("limit", 100))
    return ok(audit=cloud_burst_mgr.get_audit_log(limit))

# ── Bare-Metal Provisioning ─────────────────────────────────────────────────
@app.route("/api/bare-metal/status", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_baremetal_status():
    if not bare_metal_mgr: return ok({"pxe_ready": False})
    return ok(**bare_metal_mgr.get_pxe_status())

@app.route("/api/bare-metal/setup", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_baremetal_setup():
    if not bare_metal_mgr: return err("modül yok", 503)
    return ok(**bare_metal_mgr.setup_pxe_server())

@app.route("/api/bare-metal/profiles", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_baremetal_profiles_list():
    if not bare_metal_mgr: return ok(profiles=[])
    return ok(profiles=bare_metal_mgr.list_profiles())

@app.route("/api/bare-metal/profiles", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_baremetal_profile_create():
    if not bare_metal_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    try:
        return ok(**bare_metal_mgr.create_profile(
            d.get("name",""), d.get("hostname",""), d.get("disk_layout","auto"),
            d.get("network",{}), d.get("ssh_keys",[]), d.get("post_script","")
        )), 201
    except Exception as e: return err(str(e), 500)

@app.route("/api/bare-metal/profiles/<name>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_baremetal_profile_delete(name):
    if not bare_metal_mgr: return err("modül yok", 503)
    return ok(**bare_metal_mgr.delete_profile(name))

@app.route("/api/bare-metal/macs", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_baremetal_macs_list():
    if not bare_metal_mgr: return ok(registrations=[])
    return ok(registrations=bare_metal_mgr.list_registrations())

@app.route("/api/bare-metal/macs", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_baremetal_mac_register():
    if not bare_metal_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    try:
        return ok(**bare_metal_mgr.register_mac(d.get("mac",""), d.get("profile",""), d.get("hostname","")))
    except Exception as e: return err(str(e), 500)

@app.route("/api/bare-metal/macs/<path:mac>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_baremetal_mac_remove(mac):
    if not bare_metal_mgr: return err("modül yok", 503)
    return ok(**bare_metal_mgr.unregister_mac(mac))

@app.route("/api/bare-metal/build-iso", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_baremetal_build_iso():
    if not bare_metal_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    try:
        return ok(**bare_metal_mgr.build_install_iso(d.get("profile",""), d.get("output_path","/var/lib/oxware/isos/oxware-autoinstall.iso")))
    except Exception as e: return err(str(e), 500)

# ── OAuth 2.0 SSO ───────────────────────────────────────────────────────────
@app.route("/api/auth/oauth2/providers", methods=["GET"])
@require_auth
@require_role("admin", "administrator")
def api_oauth2_providers():
    if not oauth2_sso_mgr: return ok(providers={})
    return ok(providers=oauth2_sso_mgr.get_providers())

@app.route("/api/auth/oauth2/providers/<name>", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
def api_oauth2_configure(name):
    if not oauth2_sso_mgr: return err("modül yok", 503)
    d = request.get_json() or {}
    try:
        return ok(**oauth2_sso_mgr.configure_provider(
            name, d.get("client_id",""), d.get("client_secret",""),
            d.get("tenant_id"), d.get("scopes"), d.get("role_map", {})
        ))
    except Exception as e: return err(str(e), 500)

@app.route("/api/auth/oauth2/providers/<name>", methods=["DELETE"])
@require_auth
@require_role("admin", "administrator")
def api_oauth2_remove(name):
    if not oauth2_sso_mgr: return err("modül yok", 503)
    return ok(**oauth2_sso_mgr.remove_provider(name))

@app.route("/api/auth/oauth2/<provider>/start", methods=["GET"])
def api_oauth2_start(provider):
    """Public — initiates OAuth flow. Returns auth_url to redirect to."""
    if not oauth2_sso_mgr: return err("OAuth2 modülü yok", 503)
    redirect_uri = request.args.get("redirect", request.host_url + "api/auth/oauth2/" + provider + "/callback")
    try:
        return ok(**oauth2_sso_mgr.start_auth_flow(provider, redirect_uri))
    except Exception as e: return err(str(e), 400)

@app.route("/api/auth/oauth2/<provider>/callback", methods=["GET"])
def api_oauth2_callback(provider):
    """Public — handles IdP redirect, exchanges code for token, returns OXware JWT."""
    if not oauth2_sso_mgr: return err("OAuth2 modülü yok", 503)
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    if not code or not state:
        return err("code ve state zorunlu", 400)
    try:
        result = oauth2_sso_mgr.handle_callback(provider, code, state, request.host_url)
        # Map email -> OXware user, issue JWT
        email = result.get("email", "")
        role = result.get("role", "vm-user")
        if not email:
            return err("E-posta alınamadı", 400)
        # Create/update user
        username = email.split("@")[0]
        try:
            if not user_manager.get_user(username):
                user_manager.create_user(username=username, password=None,
                    role=role, display_name=result.get("name", username), oauth2=True)
        except Exception: pass
        from flask_jwt_extended import create_access_token
        token = create_access_token(identity=username)
        ev.info(f"OAuth2 girişi başarılı: {username} ({provider} -> {role})", category="auth")
        # OXW-2026-SEC-009: Token never travels in URL (query nor fragment).
        # Render a tiny HTML bridge that stashes the token in sessionStorage
        # via inline JSON-injection, then replaces the URL and navigates to /.
        # This prevents leakage through browser history, server logs, and
        # the Referer header on the next navigation.
        # Token + username land in a single <script type="application/json">
        # block; the inline script reads from textContent (no HTML interpolation).
        payload = json.dumps({"token": token, "user": username})
        bridge = (
            "<!doctype html><meta charset=\"utf-8\"><title>OXware — Login</title>"
            "<style>body{background:#0d1117;color:#c9d1d9;font-family:system-ui;"
            "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}</style>"
            "<div>Oturum açılıyor…</div>"
            "<script id=\"oxware-oauth-payload\" type=\"application/json\">"
            f"{html_escape(payload)}"
            "</script>"
            "<script>(function(){try{"
            "var raw=document.getElementById('oxware-oauth-payload').textContent;"
            "var p=JSON.parse(raw);"
            "sessionStorage.setItem('oxware_token',p.token);"
            "sessionStorage.setItem('oxware_user',p.user);"
            "history.replaceState(null,'','/');"
            "location.replace('/');"
            "}catch(e){location.replace('/login?oauth_error=1')}})();</script>"
        )
        from flask import Response as _Response
        resp = _Response(bridge, mimetype="text/html")
        # Defense-in-depth: keep the bridge page itself out of the cache.
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Referrer-Policy"] = "no-referrer"
        # SEC-014 — set HttpOnly cookie alongside the sessionStorage bridge.
        # The cookie alone authenticates future requests; sessionStorage is the
        # legacy-compat read path for the existing panel code.
        return _attach_session_cookies(resp, token)
    except Exception as e:
        ev.warn(f"OAuth2 callback hatası: {provider} / {e}", category="auth")
        return err(str(e), 400)

# ── Plugin startup — modül yüklendiğinde çalışır (python app.py + gunicorn) ───
if plugin_sdk_mgr:
    try:
        _pl_loaded = plugin_sdk_mgr.load_all_plugins(app)
        log.info("Plugin SDK: %d plugin yüklendi", len(_pl_loaded))
    except Exception as _pse:
        log.warning("Plugin startup yükleme hatası: %s", _pse)

if __name__ == "__main__":
    log.info("OXware Hypervisor v2.7.0 başlatılıyor")
    if ssh_watchdog:
        ssh_watchdog.start()
        log.info("SSH watchdog başlatıldı.")
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
