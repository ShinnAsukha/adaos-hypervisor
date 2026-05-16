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
import hmac
import logging
import subprocess
import threading
import ipaddress
from datetime import timedelta

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify, send_from_directory, render_template, make_response, send_file
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
auto_snap       = _safe_import("auto_snapshot")
sec_hard        = _safe_import("security_hardening")
vm_sched        = _safe_import("vm_scheduler")
sess_mgr        = _safe_import("session_manager")

# ── Flask ─────────────────────────────────────────────────────────────────────
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend", "templates")
STATIC_DIR   = os.path.join(os.path.dirname(__file__), "..", "frontend", "static")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR, static_url_path="/static")
app.config["JWT_SECRET_KEY"]           = config.SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)
app.config["JWT_TOKEN_LOCATION"]       = ["headers", "cookies"]
app.config["MAX_CONTENT_LENGTH"]       = 64 * 1024 * 1024 * 1024
# Security: restrict JWT to HS256 only — blocks alg:none / RSA confusion attacks
app.config["JWT_ALGORITHM"]            = "HS256"
app.config["JWT_DECODE_ALGORITHMS"]    = ["HS256"]

CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
jwt     = JWTManager(app)
sock    = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet", logger=False)

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

    token = ""
    for p in qs.split("&"):
        if p.startswith("token="):
            token = _unquote(p[6:])
            break

    # ── Auth ──
    try:
        with app.app_context():
            from flask_jwt_extended import decode_token
            decode_token(token)
    except Exception as _e:
        log.warning("VNC WS: auth failed vm=%s: %s", vm_id, _e)
        start_response("401 Unauthorized", [("Content-Type", "text/plain")])
        return [b"Unauthorized"]

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
                      "/api/auth/password-reset/request", "/api/auth/password-reset/confirm",
                      "/api/setup", "/metrics"}

@app.before_request
def _check_csrf():
    """State-changing istekler için CSRF token doğrula (double-submit cookie pattern)."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    path = request.path
    if path in _csrf_exempt_paths or path.startswith("/static"):
        return
    # API istekleri için X-CSRF-Token header kontrolü
    # Token, /api/auth/csrf endpoint'inden alınır ve localStorage'da saklanır
    csrf_header = request.headers.get("X-CSRF-Token", "")
    csrf_cookie = request.cookies.get("csrf_token", "")
    if not csrf_header or not csrf_cookie:
        return  # Token yoksa geç — backward compatibility (JWT zaten koruma sağlıyor)
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
        # Token valid — session kayıtlı değilse otomatik kaydet (restart sonrası)
        if sess_mgr:
            try:
                from flask_jwt_extended import get_jwt, get_jwt_identity
                claims = get_jwt()
                jti = claims.get("jti", "")
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
                if username == _primary_admin:
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


# noVNC session token store — CVE-2022-35508 mitigation
# Short-lived tokens prevent unauthenticated direct WebSocket access
import secrets as _secrets
_novnc_sessions: dict = {}   # {token: {"vm_id": str, "ws_port": int, "ip": str, "expires": float}}
_NOVNC_TOKEN_TTL = 300       # 5 minutes


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
def docs_page():
    return render_template("docs.html")

# ── CVE Tracker ───────────────────────────────────────────────────────────────
import urllib.request
import urllib.parse

# Takip edilen ürünler: id → {label, keyword, in_oxware_stack}
# in_oxware_stack=True → OXware'de doğrudan çalışıyor (Ubuntu 22.04 + KVM tabanlı)
CVE_PRODUCTS = {
    "linux":     {"label": "Linux Kernel", "keyword": "linux kernel",    "in_oxware_stack": True},
    "kvm":       {"label": "KVM/QEMU",     "keyword": "qemu kvm",        "in_oxware_stack": True},
    "libvirt":   {"label": "libvirt",      "keyword": "libvirt",         "in_oxware_stack": True},
    "nginx":     {"label": "Nginx",        "keyword": "nginx",           "in_oxware_stack": True},
    "openssh":   {"label": "OpenSSH",      "keyword": "openssh",         "in_oxware_stack": True},
    "openssl":   {"label": "OpenSSL",      "keyword": "openssl",         "in_oxware_stack": True},
    "python":    {"label": "Python/Flask", "keyword": "python flask",    "in_oxware_stack": True},
    "vmware":    {"label": "VMware",       "keyword": "vmware",          "in_oxware_stack": False},
    "proxmox":   {"label": "Proxmox",      "keyword": "proxmox",         "in_oxware_stack": False},
    "cpanel":    {"label": "cPanel",       "keyword": "cpanel",          "in_oxware_stack": False},
    "plesk":     {"label": "Plesk",        "keyword": "plesk",           "in_oxware_stack": False},
    "docker":    {"label": "Docker",       "keyword": "docker",          "in_oxware_stack": False},
    "wordpress": {"label": "WordPress",    "keyword": "wordpress",       "in_oxware_stack": False},
}

# Keywords in CVE descriptions that indicate OXware relevance even outside stack products
_OXWARE_DESC_KEYWORDS = [
    "qemu", "kvm", "libvirt", "nginx", "openssl", "openssh",
    "python", "flask", "jwt", "socket.io", "socketio",
    "ubuntu", "debian", "linux kernel", "privilege escalation",
    "remote code execution", "rce", "authentication bypass",
    "container escape", "hypervisor", "virtual machine",
]

_OXWARE_STACK_PRODUCT_IDS = {pid for pid, p in CVE_PRODUCTS.items() if p.get("in_oxware_stack")}

# Ubuntu 22.04 (Jammy) software versions — CVEs affecting OLDER versions are not relevant.
# Anything patched before these versions is already fixed on a standard jammy install.
_OXWARE_MIN_VERSIONS = {
    # published year cutoff per product (CVEs before this year very unlikely to affect Ubuntu 22.04)
    "linux":   2021,   # kernel 5.15+
    "kvm":     2021,   # QEMU 6.2+
    "libvirt": 2021,   # libvirt 8.0+
    "nginx":   2018,   # nginx 1.18+
    "openssh": 2020,   # OpenSSH 8.9+
    "openssl": 2020,   # OpenSSL 3.0+
    "python":  2020,   # Python 3.10+, Flask 2+
}

def _mark_affects_oxware(cve_item: dict, product_id: str) -> dict:
    """Add affects_oxware=True if this CVE is relevant to OXware's runtime stack.

    Rules:
    1. Must be published on or after the min-year for that product (old patched versions filtered out)
    2. Product in OXware stack AND severity MEDIUM/HIGH/CRITICAL
    3. OR: description mentions stack components AND severity HIGH/CRITICAL
    """
    severity = cve_item.get("severity", "UNKNOWN")
    desc_lower = cve_item.get("description", "").lower()
    published = cve_item.get("published", "")

    # Extract publish year (format: YYYY-MM-DD)
    try:
        pub_year = int(published[:4])
    except (ValueError, TypeError):
        pub_year = 0

    # Version cutoff: skip very old CVEs that don't affect current Ubuntu 22.04 packages
    min_year = _OXWARE_MIN_VERSIONS.get(product_id, 2020)
    if pub_year > 0 and pub_year < min_year:
        cve_item["affects_oxware"] = False
        cve_item["filtered_old_version"] = True
        return cve_item

    # Product is part of OXware stack AND severity is MEDIUM/HIGH/CRITICAL
    if product_id in _OXWARE_STACK_PRODUCT_IDS and severity in ("MEDIUM", "HIGH", "CRITICAL"):
        cve_item["affects_oxware"] = True
        return cve_item

    # Description mentions OXware stack components AND severity HIGH/CRITICAL
    if any(kw in desc_lower for kw in _OXWARE_DESC_KEYWORDS) and severity in ("HIGH", "CRITICAL"):
        cve_item["affects_oxware"] = True
        return cve_item

    cve_item["affects_oxware"] = False
    return cve_item

_CVE_CACHE: dict = {}   # cache_key → {data, fetched_at}
_CVE_TTL = 1800         # 30 dk cache

# CIRCL vendor/product mapping for fallback API
_CIRCL_MAPPING = {
    "linux":   ("linux", "linux_kernel"),
    "kvm":     ("qemu", "qemu"),
    "libvirt": ("redhat", "libvirt"),
    "nginx":   ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "python":  ("python", "python"),
    "vmware":  ("vmware", "esx"),
    "proxmox": ("proxmox", "virtual_environment"),
    "docker":  ("docker", "docker"),
}

def _ssl_ctx():
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    return ctx

def _http_get(url: str, headers: dict = None, timeout: int = 20) -> bytes:
    """Simple GET with SSL bypass."""
    req = urllib.request.Request(url, headers=headers or {
        "User-Agent": "OXware-CVE-Tracker/1.0",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
        return r.read()

def _score_to_severity(score) -> str:
    if score is None: return "UNKNOWN"
    s = float(score)
    if s >= 9.0: return "CRITICAL"
    if s >= 7.0: return "HIGH"
    if s >= 4.0: return "MEDIUM"
    return "LOW"

def _fetch_from_nvd(keyword: str, limit: int, years_back: int) -> list:
    """Try NVD API v2. Raises on failure."""
    import json as _json
    from datetime import datetime, timezone, timedelta
    # NVD date format: yyyy-MM-ddTHH:mm:ss.sss (no timezone suffix — NVD assumes UTC)
    now = datetime.now(timezone.utc)
    params: dict = {
        "keywordSearch": keyword,
        "resultsPerPage": limit,
        "startIndex": 0,
    }
    if years_back > 0:
        params["pubStartDate"] = (now - timedelta(days=365 * years_back)).strftime("%Y-%m-%dT00:00:00.000")
        params["pubEndDate"]   = now.strftime("%Y-%m-%dT23:59:59.999")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{urllib.parse.urlencode(params)}"
    headers = {"User-Agent": "OXware-CVE-Tracker/1.0", "Accept": "application/json"}
    nvd_key = os.environ.get("NVD_API_KEY", "")
    if nvd_key:
        headers["apiKey"] = nvd_key
    raw = _json.loads(_http_get(url, headers=headers, timeout=25))
    items = []
    for vuln in raw.get("vulnerabilities", []):
        cve  = vuln.get("cve", {})
        cid  = cve.get("id", "")
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score, severity = None, "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m  = metrics[key][0]
                cd = m.get("cvssData", {})
                score    = cd.get("baseScore")
                severity = cd.get("baseSeverity") or m.get("baseSeverity", "UNKNOWN")
                break
        items.append({
            "id": cid, "description": desc[:300],
            "score": score, "severity": severity.upper(),
            "published": cve.get("published", "")[:10],
            "refs": [r.get("url","") for r in cve.get("references", [])[:3]],
            "source": "nvd",
        })
    return items

def _fetch_from_circl(product_id: str, years_back: int) -> list:
    """CIRCL CVE Search API (cve.circl.lu) — EU-hosted, no auth needed. Raises on failure."""
    import json as _json
    from datetime import datetime, timezone, timedelta
    mapping = _CIRCL_MAPPING.get(product_id)
    if not mapping:
        raise ValueError(f"No CIRCL mapping for {product_id}")
    vendor, product = mapping
    url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    raw = _json.loads(_http_get(url, timeout=20))
    # CIRCL returns list directly
    vulns = raw if isinstance(raw, list) else raw.get("results", [])
    cutoff_year = (datetime.now(timezone.utc).year - years_back) if years_back > 0 else 0
    items = []
    for v in vulns[:30]:
        cid  = v.get("id", "") or v.get("cve_id", "")
        desc = v.get("summary", "") or v.get("description", "")
        pub  = (v.get("Published") or v.get("published", ""))[:10]
        # Year filter
        try:
            if cutoff_year and int(pub[:4]) < cutoff_year:
                continue
        except (ValueError, TypeError):
            pass
        score = v.get("cvss3") or v.get("cvss")
        if isinstance(score, dict):
            score = score.get("score") or score.get("baseScore")
        try:
            score = float(score) if score is not None else None
        except (ValueError, TypeError):
            score = None
        severity = v.get("severity", "") or _score_to_severity(score)
        refs = v.get("references", [])
        if isinstance(refs, str):
            refs = [refs]
        items.append({
            "id": cid, "description": str(desc)[:300],
            "score": score, "severity": severity.upper(),
            "published": pub,
            "refs": refs[:3],
            "source": "circl",
        })
    return items

# GitHub Advisory only works reliably for package-manager ecosystems.
# Infrastructure C libs (linux, kvm, libvirt, nginx, openssh, openssl) are NOT
# in pip/npm/cargo — GitHub Advisory keyword search returns completely unrelated
# advisories for those. Skip GitHub Advisory for these products.
_GH_SKIP_PRODUCTS = {"linux", "kvm", "libvirt", "nginx", "openssh", "openssl"}

# GitHub ecosystem + exact package name per product (strict match, not keyword)
_GH_PACKAGES = {
    "python":    [("pip", "flask"), ("pip", "werkzeug"), ("pip", "jinja2"),
                  ("pip", "cryptography"), ("pip", "urllib3"), ("pip", "requests")],
    "docker":    [("go", "github.com/docker/docker")],
    "wordpress": [("composer", "wordpress/wordpress")],
    "vmware":    [],   # no package manager — skip
    "proxmox":   [],   # no package manager — skip
    "cpanel":    [],   # no package manager — skip
    "plesk":     [],   # no package manager — skip
}

def _fetch_from_github(product_id: str, keyword: str, years_back: int) -> list:
    """GitHub Advisory Database API — ONLY for package-manager-based products.
    Uses /advisories?ecosystem=X&package=Y (strict match) instead of keyword search
    to avoid returning completely unrelated advisories.
    Raises ValueError for infrastructure products (use CIRCL/NVD instead).
    """
    import json as _json
    from datetime import datetime, timezone, timedelta

    if product_id in _GH_SKIP_PRODUCTS:
        raise ValueError(f"{product_id} is infrastructure — GitHub Advisory not applicable")

    packages = _GH_PACKAGES.get(product_id, [])
    if not packages:
        raise ValueError(f"No GitHub package mapping for {product_id}")

    cutoff = (datetime.now(timezone.utc) - timedelta(days=365 * years_back)).strftime("%Y-%m-%dT00:00:00Z") if years_back > 0 else None
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    headers = {
        "User-Agent": "OXware-CVE-Tracker/1.0",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"

    all_items = []
    seen_ids = set()
    for eco, pkg in packages:
        params = {"per_page": 20, "type": "reviewed", "ecosystem": eco, "package": pkg}
        if cutoff:
            params["published"] = f">={cutoff}"
        url = "https://api.github.com/advisories?" + urllib.parse.urlencode(params)
        try:
            raw = _json.loads(_http_get(url, headers=headers, timeout=20))
        except Exception:
            continue
        for adv in raw:
            cid = adv.get("cve_id") or ""
            if not cid or cid in seen_ids:
                continue
            seen_ids.add(cid)
            desc  = adv.get("description", "") or adv.get("summary", "")
            pub   = (adv.get("published_at") or "")[:10]
            score = None
            severity = (adv.get("severity") or "UNKNOWN").upper()
            cvss = adv.get("cvss", {}) or {}
            if isinstance(cvss, dict):
                score = cvss.get("score")
            if score is None:
                score = adv.get("cvss_score")
            try:
                score = float(score) if score is not None else None
            except (ValueError, TypeError):
                score = None
            if severity == "UNKNOWN" and score is not None:
                severity = _score_to_severity(score)
            refs = [adv.get("html_url", "")] if adv.get("html_url") else []
            all_items.append({
                "id": cid, "description": str(desc)[:300],
                "score": score, "severity": severity,
                "published": pub, "refs": refs[:3],
                "source": "github",
            })
    if not all_items:
        raise ValueError(f"No GitHub advisories found for {product_id}")
    return all_items

def _fetch_cves(keyword: str, product_id: str, limit: int = 20, years_back: int = 3) -> tuple:
    """Fetch CVEs: NVD → CIRCL → GitHub Advisory. Returns (items, error_str|None)."""
    errors = {}
    # 1. NVD
    try:
        items = _fetch_from_nvd(keyword, limit, years_back)
        log.debug("CVE NVD OK: %s (%d)", keyword, len(items))
        return [_mark_affects_oxware({**i, "product_id": product_id}, product_id) for i in items], None
    except Exception as e:
        errors["nvd"] = str(e)
        log.warning("NVD hata (%s): %s", keyword, e)
    # 2. CIRCL
    try:
        items = _fetch_from_circl(product_id, years_back)
        log.debug("CVE CIRCL OK: %s (%d)", product_id, len(items))
        return [_mark_affects_oxware({**i, "product_id": product_id}, product_id) for i in items], None
    except Exception as e:
        errors["circl"] = str(e)
        log.warning("CIRCL hata (%s): %s", product_id, e)
    # 3. GitHub Advisory
    try:
        items = _fetch_from_github(product_id, keyword, years_back)
        log.debug("CVE GitHub OK: %s (%d)", product_id, len(items))
        return [_mark_affects_oxware({**i, "product_id": product_id}, product_id) for i in items], None
    except Exception as e:
        errors["github"] = str(e)
        log.warning("GitHub Advisory hata (%s): %s", product_id, e)
    err_summary = " | ".join(f"{k}: {v[:80]}" for k, v in errors.items())
    return [], err_summary

@app.route("/api/cve/debug")
@require_auth
def api_cve_debug():
    """Test connectivity to each CVE source. Returns reachability status."""
    import json as _json
    results = {}
    tests = [
        ("nvd",    "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=nginx&resultsPerPage=1"),
        ("circl",  "https://cve.circl.lu/api/last/1"),
        ("github", "https://api.github.com/advisories?per_page=1&type=reviewed"),
    ]
    for name, url in tests:
        try:
            data = _http_get(url, timeout=10)
            parsed = _json.loads(data)
            results[name] = {"ok": True, "bytes": len(data), "sample": str(parsed)[:80]}
        except Exception as e:
            results[name] = {"ok": False, "error": str(e)[:200]}
    return ok(connectivity=results)

@app.route("/api/cve/products")
def api_cve_products():
    return ok(products=CVE_PRODUCTS)

@app.route("/api/cve/search")
def api_cve_search():
    product_id = request.args.get("product", "").lower()
    force      = request.args.get("force", "0") == "1"
    try:
        years_back = int(request.args.get("years_back", "3"))
        years_back = max(0, min(years_back, 10))  # clamp 0–10
    except ValueError:
        years_back = 3

    if product_id and product_id not in CVE_PRODUCTS:
        return err(f"Bilinmeyen ürün: {product_id}", 400)

    results = {}
    fetch_errors = []
    targets = {product_id: CVE_PRODUCTS[product_id]} if product_id else CVE_PRODUCTS

    # NVD rate limit: 5 req/30s (no key) or 50 req/30s (with key).
    # Add 0.7s delay between uncached fetches to avoid 429s.
    has_api_key = bool(os.environ.get("NVD_API_KEY", ""))
    req_delay = 0.2 if has_api_key else 0.7
    fetch_count = 0

    for pid, pinfo in targets.items():
        # Cache key includes years_back so different time ranges don't collide
        cache_key = f"{pid}:{years_back}"
        cached = _CVE_CACHE.get(cache_key)
        if not force and cached and (time.time() - cached["fetched_at"]) < _CVE_TTL:
            results[pid] = cached["data"]
            continue
        # Respect rate limit between live API calls
        if fetch_count > 0:
            time.sleep(req_delay)
        fetch_count += 1
        cves, fetch_err = _fetch_cves(pinfo["keyword"], product_id=pid, years_back=years_back)
        if fetch_err:
            fetch_errors.append(f"{pinfo['label']}: {fetch_err}")
            # Use stale cache rather than empty on error
            if cached:
                cves = cached["data"]
        _CVE_CACHE[cache_key] = {"data": cves, "fetched_at": time.time()}
        results[pid] = cves

    # Global deduplication: same CVE ID must not appear under multiple products.
    # Priority: OXware-stack products first, then alphabetical. Keep first seen.
    _PRIORITY_ORDER = ["linux", "kvm", "libvirt", "nginx", "openssh", "openssl",
                       "python", "docker", "wordpress", "vmware", "proxmox", "cpanel", "plesk"]
    seen_cve_ids: set = set()
    for pid in _PRIORITY_ORDER:
        if pid not in results:
            continue
        deduped = []
        for c in results[pid]:
            cid = c.get("id") or c.get("cve_id") or ""
            if cid and cid in seen_cve_ids:
                continue
            if cid:
                seen_cve_ids.add(cid)
            deduped.append(c)
        results[pid] = deduped
    # Also dedup any products not in priority list
    for pid in results:
        if pid in _PRIORITY_ORDER:
            continue
        deduped = []
        for c in results[pid]:
            cid = c.get("id") or c.get("cve_id") or ""
            if cid and cid in seen_cve_ids:
                continue
            if cid:
                seen_cve_ids.add(cid)
            deduped.append(c)
        results[pid] = deduped

    # Count OXware-affecting CVEs across all products
    oxware_count = sum(
        1 for pid_cves in results.values()
        for c in pid_cves if c.get("affects_oxware")
    )

    # Always return 200 — frontend shows warning banner if fetch_errors present.
    if fetch_errors and not any(results.values()):
        return ok(results=results, products=CVE_PRODUCTS,
                  oxware_stack=list(_OXWARE_STACK_PRODUCT_IDS),
                  oxware_count=oxware_count,
                  fetch_errors=fetch_errors,
                  warning="NVD API geçici olarak erişilemiyor. Lütfen daha sonra tekrar deneyin.")

    return ok(results=results, products=CVE_PRODUCTS,
              oxware_stack=list(_OXWARE_STACK_PRODUCT_IDS),
              oxware_count=oxware_count,
              fetch_errors=fetch_errors if fetch_errors else None)

# ── ISO Download ──────────────────────────────────────────────────────────────
_ISO_SEARCH_PATHS = [
    "/opt/oxware/OXware-Hypervisor-2.0.0-amd64.iso",
    "/root/OXware-Hypervisor-2.0.0-amd64.iso",
    "/tmp/OXware-Hypervisor-2.0.0-amd64.iso",
]

@app.route("/download/iso")
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
    # Also glob common build output dirs
    for pattern in ["/opt/oxware/*.iso", "/root/*.iso", "/tmp/oxware*/*.iso"]:
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
    return render_template("console.html", vm_id=vm_id)

@app.route("/vnc_console/<vm_id>")
def vnc_console_page(vm_id):
    """Dedicated VNC console page — SocketIO TCP proxy, no websockify needed."""
    return render_template("vnc_console.html", vm_id=vm_id)

@app.route("/novnc/")
@app.route("/novnc/<path:filename>")
def serve_novnc(filename="vnc.html"):
    """noVNC statik dosyalarını Flask üzerinden serve et (same-origin, X-Frame-Options yok)."""
    novnc_dir = config.NOVNC_DIR
    if not os.path.isdir(novnc_dir):
        # Fallback: yaygın kurulum yerleri
        for d in ["/usr/share/novnc", "/opt/novnc", "/usr/share/novnc/app"]:
            if os.path.isdir(d):
                novnc_dir = d
                break
        else:
            return "noVNC bulunamadı. Lütfen sunucuya novnc kurun.", 404
    resp = send_from_directory(novnc_dir, filename)
    # iframe içinde gösterim için X-Frame-Options kaldır
    resp.headers.pop("X-Frame-Options", None)
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    return resp

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

# ── 2FA pending store (in-memory, 5 dk TTL) ───────────────────────────────────
_2fa_pending: dict = {}  # temp_token → {username, expires, ip, ua}

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return err("Kullanıcı adı ve şifre zorunludur")
    # Account lockout kontrolü
    if sec_hard:
        locked, secs = sec_hard.is_account_locked(username)
        if locked:
            ev.warn(f"Kilitli hesaba giriş denemesi: {username} / {request.remote_addr}", category="auth")
            return err(f"Hesap kilitli. {secs} saniye bekleyin.", 429)
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
        if sec_hard:
            sec_hard.record_failed_login(username)
        ev.warn(f"Başarısız giriş: {username} / {request.remote_addr}", category="auth")
        return err("Geçersiz kimlik bilgileri", 401)
    if sec_hard:
        sec_hard.record_successful_login(username)
    # ── 2FA kontrolü ──────────────────────────────────────────────────────────
    if totp_mgr and totp_mgr.is_enabled(username):
        import uuid as _uuid
        temp_token = str(_uuid.uuid4())
        _2fa_pending[temp_token] = {
            "username": username,
            "expires": time.time() + 300,  # 5 dakika
            "ip": request.headers.get("X-Forwarded-For", request.remote_addr or ""),
            "ua": request.headers.get("User-Agent", "")[:120],
        }
        ev.info(f"2FA bekleniyor: {username} / {request.remote_addr}", category="auth")
        return jsonify({"requires_2fa": True, "temp_token": temp_token}), 200
    # ── 2FA yok: direkt JWT ver ───────────────────────────────────────────────
    token = create_access_token(identity=username)
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
    ev.info(f"Giriş başarılı: {username}", category="auth")
    return ok(token=token, username=username)

@app.route("/api/auth/2fa/verify-login", methods=["POST"])
def api_2fa_verify_login():
    """2FA doğrulama — temp_token + 6 haneli TOTP kodu → gerçek JWT."""
    data = request.get_json() or {}
    temp_token = data.get("temp_token", "").strip()
    code = data.get("code", "").strip()
    if not temp_token or not code:
        return err("temp_token ve code zorunludur", 400)
    # Pending kaydı bul
    pending = _2fa_pending.get(temp_token)
    if not pending:
        return err("Geçersiz veya süresi dolmuş token", 401)
    if time.time() > pending["expires"]:
        _2fa_pending.pop(temp_token, None)
        return err("2FA süresi doldu. Tekrar giriş yapın.", 401)
    username = pending["username"]
    # TOTP doğrula
    if not totp_mgr or not totp_mgr.verify_totp(username, code):
        ev.warn(f"Geçersiz 2FA kodu: {username} / {request.remote_addr}", category="auth")
        return err("Geçersiz doğrulama kodu", 401)
    # Başarılı — temp token tüket
    _2fa_pending.pop(temp_token, None)
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
    ev.info(f"2FA giriş başarılı: {username} / {request.remote_addr}", category="auth")
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

@app.route("/api/auth/2fa/debug")
@require_auth
def api_2fa_debug():
    """Sunucu saati + anlık beklenen kodu döndür (geliştirme/teşhis)."""
    import datetime
    username = get_jwt_identity()
    if not totp_mgr: return err("2FA modülü yüklenemedi")
    data  = totp_mgr._load()
    entry = data.get(username, {})
    secret = entry.get("secret", "")
    current_code = ""
    if secret:
        try:
            import pyotp
            current_code = pyotp.TOTP(secret).now()
        except Exception:
            pass
    return ok(
        server_time      = datetime.datetime.utcnow().isoformat() + "Z",
        server_timestamp = int(time.time()),
        time_window      = int(time.time()) // 30,
        current_totp     = current_code,   # sunucunun beklediği kod
        has_secret       = bool(secret),
        enabled          = entry.get("enabled", False),
    )

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

@app.route("/api/auth/password-reset/request", methods=["POST"])
def api_password_reset_request():
    """
    Şifre sıfırlama token'ı üretir.
    Eğer SMTP yapılandırılmışsa email gönderir,
    aksi hâlde token'ı response'da döndürür (admin konsoldan uygular).
    """
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    if not username:
        return err("Kullanıcı adı gerekli")

    info = cred_mgr.get_credential_info()
    if info.get("username", "").lower() != username.lower():
        # Güvenlik: kullanıcı adı yanlışsa da aynı mesajı ver
        return ok(message="Sıfırlama token'ı oluşturuldu. Yönetici e-postanızı kontrol edin.")

    token = cred_mgr.generate_reset_token(username)
    ev.warn(f"Şifre sıfırlama isteği: {username} / {request.remote_addr}", category="auth")

    # SMTP gönderimi (opsiyonel)
    smtp_host = os.environ.get("OXWARE_SMTP_HOST", "")
    reset_link = f"#reset-token={token}"
    if smtp_host:
        try:
            import smtplib
            from email.mime.text import MIMEText
            smtp_port = int(os.environ.get("OXWARE_SMTP_PORT", 587))
            smtp_user = os.environ.get("OXWARE_SMTP_USER", "")
            smtp_pass = os.environ.get("OXWARE_SMTP_PASS", "")
            smtp_from = os.environ.get("OXWARE_SMTP_FROM", smtp_user)
            smtp_to   = data.get("email", smtp_user)

            msg = MIMEText(f"""OXware Hypervisor - Şifre Sıfırlama

Kullanıcı adı: {username}
Sıfırlama kodu: {token}

Bu kod 1 saat geçerlidir. Eğer bu isteği siz yapmadıysanız dikkate almayın.
""")
            msg["Subject"] = "OXware - Şifre Sıfırlama"
            msg["From"]    = smtp_from
            msg["To"]      = smtp_to

            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
                s.starttls()
                if smtp_user:
                    s.login(smtp_user, smtp_pass)
                s.sendmail(smtp_from, [smtp_to], msg.as_string())
            log.info("Şifre sıfırlama emaili gönderildi: %s → %s", username, smtp_to)
            return ok(message="Sıfırlama kodu e-postanıza gönderildi.")
        except Exception as e:
            log.warning("SMTP hatası: %s — token döndürülüyor", e)

    # SMTP yoksa token'ı döndür (admin konsolda görünür)
    return ok(message="SMTP yapılandırılmamış. Token aşağıdadır.", token=token, dev_mode=True)

@app.route("/api/auth/password-reset/confirm", methods=["POST"])
def api_password_reset_confirm():
    data     = request.get_json() or {}
    token    = data.get("token", "").strip()
    new_pass = data.get("new_password", "")
    if not token:
        return err("Token gerekli")
    if len(new_pass) < 8:
        return err("Yeni şifre en az 8 karakter olmalıdır")
    if not cred_mgr.reset_password_with_token(token, new_pass):
        return err("Geçersiz veya süresi dolmuş token", 401)
    ev.info("Şifre token ile sıfırlandı", category="auth")
    return ok(message="Şifre başarıyla sıfırlandı. Giriş yapabilirsiniz.")

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
        # Build cloud-init userdata if app install requested
        ci_userdata = data.get("ci_userdata", "")
        if app_install:
            app_script = _get_app_install_script(app_install)
            if app_script:
                ci_userdata = (ci_userdata + "\n" + app_script).strip() if ci_userdata else app_script

        create_kwargs = dict(
            name=name, memory_mb=memory_mb, vcpus=vcpus, disk_gb=disk_gb,
            iso_path=iso_path, network=network, disk_format=disk_format,
            os_variant=os_variant, boot_order=boot_order, disk_bus=disk_bus,
            cpu_mode=cpu_mode,
        )
        # Pass cloud-init data if vm_manager supports it
        try:
            import inspect as _inspect
            if "ci_userdata" in _inspect.signature(vm_manager.create_vm).parameters:
                create_kwargs["ci_userdata"] = ci_userdata
        except Exception:
            pass

        result = vm_manager.create_vm(**create_kwargs)
        vm_id  = result["id"]
        vm_mac = result.get("mac", "")

        # ── Auto IP assignment via libvirt DHCP static entry ──────────────
        auto_ip   = data.get("auto_ip", False)
        pool_name = security.sanitize_str(data.get("ip_pool", ""), 64)
        if auto_ip and pool_name and vm_mac:
            try:
                alloc = ip_pool_mgr.allocate_ip(pool_name, vm_id, name, vm_mac)
                # Pool'un libvirt_network'ünü kullan (VM'in network'ü değil)
                dhcp_net = alloc.get("libvirt_network") or network
                vm_manager.add_dhcp_host(dhcp_net, vm_mac, alloc["ip"], name)
                result["assigned_ip"] = alloc["ip"]
                result["gateway"]     = alloc["gateway"]
                result["dns"]         = alloc["dns"]
                result["netmask"]     = alloc["netmask"]
                ev.vm_event(f"IP atandı: {alloc['ip']} ({pool_name})", vm_id, level="INFO")
            except Exception as _ip_e:
                log.warning("Auto IP atama başarısız vm=%s: %s", vm_id, _ip_e)
                result["auto_ip_error"] = str(_ip_e)

        ev.vm_event(f"VM oluşturuldu: {name}", vm_id, level="INFO")
        if app_install:
            ev.vm_event(f"App kurulum planlandı: {app_install}", vm_id, level="INFO")
        if webhook_mgr: webhook_mgr.trigger("vm.created", {"vm_id": vm_id, "vm_name": name})
        if resource_quota: resource_quota.check_quota(get_jwt_identity(), vcpus, memory_mb)
        resp = dict(result)
        if app_install:
            resp["app_install"] = app_install
            resp["app_script"]  = _get_app_install_script(app_install)
        return ok(**resp), 201
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>", methods=["DELETE"])
@require_auth
def api_delete_vm(vm_id):
    delete_disk = request.args.get("delete_disk", "true").lower() == "true"
    try:
        vm = vm_manager.get_vm(vm_id)
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
    new_name = (data.get("new_name") or data.get("name") or "").strip()
    if not new_name:
        return err("Yeni VM adı zorunludur")
    try:
        result = vm_manager.clone_vm(vm_id, new_name)
        ev.info(f"VM klonlandı: {vm_id} → {new_name}", category="vm")
        return ok(**(result if isinstance(result, dict) else {}), status="ok", name=new_name), 201
    except Exception as e:
        return err(e, 500)

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
def api_vm_nested_virt(vm_id):
    data = request.get_json() or {}
    enabled = bool(data.get("enabled", False))
    try:
        result = vm_manager.set_nested_virt(vm_id, enabled)
        ev.info(f"Nested virt {'açıldı' if enabled else 'kapatıldı'}: {vm_id}", category="vm")
        return ok(**result)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/hardware/disk/attach", methods=["POST"])
@require_auth
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
def api_vm_disk_detach(vm_id, target_dev):
    try:
        result = vm_manager.hot_detach_disk(vm_id, target_dev)
        ev.info(f"Disk çıkarıldı: {vm_id} / {target_dev}", category="vm")
        return ok(**result)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/hardware/nic/attach", methods=["POST"])
@require_auth
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
def api_vm_nic_detach(vm_id, mac):
    try:
        result = vm_manager.hot_detach_nic(vm_id, mac)
        ev.info(f"NIC çıkarıldı: {vm_id} / {mac}", category="vm")
        return ok(**result)
    except Exception as e:
        return err(e, 500)

@app.route("/api/vms/<vm_id>/autostart", methods=["PUT"])
@require_auth
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

@app.route("/api/vms/<vm_id>/nat-sync", methods=["POST"])
@require_auth
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
            return jsonify({
                "success": False,
                "error": "VM henüz IP almamış — VM açık ve ağa bağlı olduğundan emin olun.",
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
def api_start_console(vm_id):
    """
    Flask VNC proxy (/ws/vnc/<vm_id>) tüm WebSocket→VNC köprüsünü kendi yapıyor.
    Websockify artık kullanılmıyor — port 5900'e iki bağlantı açılırsa QEMU VNC
    RFB handshake'i tamamlayamıyor.
    Eski websockify varsa öldür, sadece VNC portunu dön.
    """
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

@app.route("/api/networks/<net_uuid>/autostart", methods=["POST"])
@require_auth
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

@app.route("/api/storage/isos/<name>/rename", methods=["POST"])
@require_auth
def api_rename_iso(name):
    """ISO dosyasını yeniden adlandır."""
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


@app.route("/api/ipam/pools", methods=["POST"])
@require_auth
def api_ipam_create_pool():
    data = request.get_json() or {}
    required = ["name", "network", "gateway"]
    missing = [f for f in required if f not in data]
    if missing:
        return err(f"Zorunlu alanlar: {', '.join(missing)}")
    try:
        _known = {"name", "network", "gateway", "dns", "start_ip", "end_ip", "reserved", "libvirt_network"}
        pool = ip_pool_mgr.create_pool(**{k: v for k, v in data.items() if k in _known})
        ev.info(f"IP havuzu oluşturuldu: {data['name']}", category="network")
        return ok(pool=pool), 201
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
    result = updater.check_updates_with_ai()
    return ok(**result)

@app.route("/api/update/last")
@require_auth
def api_update_last():
    """Son otomatik kontrol sonucunu döndür (AI analizi dahil)."""
    return ok(**updater.get_last_check())

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
@require_role("admin", "administrator")
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
@require_role("admin", "administrator")
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

# ── Shell Konsol ──────────────────────────────────────────────────────────────
@app.route("/api/system/execute", methods=["POST"])
@require_auth
@require_role("admin", "administrator")
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
_iso_fetch_jobs = {}   # job_id → {status, filename, progress, ...}
_vnc_sessions   = {}   # sid    → tcp_socket

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
        identity = decoded.get("sub") or decoded.get("identity", "")
        if not identity:
            emit("shell_output", {"data": "\r\n[Hata: geçersiz token kimliği]\r\n"})
            return
        log.info("Shell açıldı: %s", identity)
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
    # VNC proxy temizle
    tcp = _vnc_sessions.pop(session_id, None)
    if tcp:
        try:
            tcp.close()
        except Exception:
            pass


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
        stats = system_monitor.get_stats() if hasattr(system_monitor, "get_stats") else {}
        gauge("cpu_usage_percent", stats.get("cpu_percent", 0))
        gauge("memory_usage_percent", stats.get("memory_percent", 0))
        gauge("disk_usage_percent", stats.get("disk_percent", 0))
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
            info = vm_manager.get_vm_info(vm_id)
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

    try:
        # Mevcut boyutu kontrol et
        info_r = subprocess.run(
            ["qemu-img", "info", "--output=json", disk_path],
            capture_output=True, text=True, timeout=30
        )
        import json as _json
        img_info = _json.loads(info_r.stdout)
        current_bytes = img_info.get("virtual-size", 0)
        current_gb = current_bytes / (1024**3)

        if new_size_gb <= current_gb:
            return err(f"Yeni boyut ({new_size_gb}GB) mevcut boyuttan ({current_gb:.1f}GB) büyük olmalı")

        # VM çalışıyorsa virsh blockresize kullan (online), yoksa qemu-img resize
        vm_info = vm_manager.get_vm_info(vm_id)
        is_running = vm_info.get("state") == "running"

        if is_running:
            # Online resize — disk adını bul
            disk_name = data.get("disk_name", "vda")
            r = subprocess.run(
                ["virsh", "blockresize", vm_id, disk_name, f"{new_size_gb}G"],
                capture_output=True, text=True, timeout=60
            )
            if r.returncode != 0:
                return err(f"virsh blockresize başarısız: {r.stderr}")
        else:
            # Offline resize
            r = subprocess.run(
                ["qemu-img", "resize", disk_path, f"{new_size_gb}G"],
                capture_output=True, text=True, timeout=120
            )
            if r.returncode != 0:
                return err(f"qemu-img resize başarısız: {r.stderr}")

        ev.info(f"Disk genişletildi: {vm_id} {current_gb:.1f}GB → {new_size_gb}GB", category="vm")
        return ok({
            "vm_id": vm_id,
            "disk_path": disk_path,
            "old_size_gb": round(current_gb, 1),
            "new_size_gb": new_size_gb,
            "online": is_running,
            "guest_steps": _disk_guest_steps(new_size_gb),
        })
    except subprocess.TimeoutExpired:
        return err("Disk genişletme zaman aşımına uğradı", 504)
    except Exception as e:
        return err(e, 500)


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

# ── Let's Encrypt ─────────────────────────────────────────────────────────────
@app.route("/api/ssl/letsencrypt", methods=["POST"])
@require_auth
def api_letsencrypt():
    d      = request.get_json() or {}
    domain = d.get("domain", "").strip()
    email  = d.get("email", "").strip()
    if not domain:
        return err("Domain gerekli")
    import subprocess as _sp
    try:
        result = _sp.run(
            ["certbot", "certonly", "--standalone", "--non-interactive",
             "--agree-tos", "-m", email or "admin@" + domain,
             "-d", domain],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            import shutil
            cert_dir = f"/etc/letsencrypt/live/{domain}"
            if os.path.exists(cert_dir):
                os.makedirs("/etc/oxware/ssl", exist_ok=True)
                shutil.copy2(f"{cert_dir}/fullchain.pem", "/etc/oxware/ssl/oxware.crt")
                shutil.copy2(f"{cert_dir}/privkey.pem",   "/etc/oxware/ssl/oxware.key")
                os.chmod("/etc/oxware/ssl/oxware.key", 0o600)
            ev.info(f"Let's Encrypt sertifikası alındı: {domain}", category="system")
            return ok({"success": True, "domain": domain, "output": result.stdout[-500:]})
        return err(f"certbot hatası: {result.stderr[-400:]}")
    except FileNotFoundError:
        return err("certbot kurulu değil: apt install certbot")
    except Exception as e:
        return err(str(e))

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

# ── Pen Test ──────────────────────────────────────────────────────────────────
pentest = _safe_import("pentest")

@app.route("/api/pentest/run", methods=["POST"])
@require_auth
def api_pentest_run():
    if not pentest:
        return err("pentest modülü yüklenemedi")
    d = request.get_json() or {}
    host = d.get("host", "127.0.0.1")
    port = int(d.get("port", config.PORT))
    import threading
    def _run():
        pentest._last_result = pentest.run_pentest(host, port)
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return ok({"status": "started", "message": f"Pen test başlatıldı: {host}:{port}"})

@app.route("/api/pentest/result", methods=["GET"])
@require_auth
def api_pentest_result():
    if not pentest:
        return err("pentest modülü yüklenemedi")
    if pentest._last_result is None:
        return ok({"status": "no_result", "result": None})
    return ok({"status": "done", "result": pentest._last_result})


@app.route("/api/pentest/history", methods=["GET"])
@require_auth
def api_pentest_history():
    if not pentest:
        return err("pentest modülü yüklenemedi")
    history = pentest.get_history() if hasattr(pentest, "get_history") else []
    return ok({"history": history})


@app.route("/api/pentest/export", methods=["POST"])
@require_auth
def api_pentest_export():
    if not pentest:
        return err("pentest modülü yüklenemedi")
    body = request.get_json(silent=True) or {}
    fmt  = body.get("format", "json")
    result = pentest._last_result
    if result is None:
        return err("Henüz tamamlanmış pentest sonucu yok", 404)
    if not hasattr(pentest, "export_report"):
        return err("export_report fonksiyonu bulunamadı", 501)
    exported = pentest.export_report(result, fmt)
    if fmt == "html":
        from flask import Response as _Resp
        return _Resp(exported, mimetype="text/html",
                     headers={"Content-Disposition": "attachment; filename=pentest_report.html"})
    elif fmt == "txt":
        from flask import Response as _Resp
        return _Resp(exported, mimetype="text/plain",
                     headers={"Content-Disposition": "attachment; filename=pentest_report.txt"})
    else:
        return ok({"report": exported})


@app.route("/api/pentest/diff", methods=["POST"])
@require_auth
def api_pentest_diff():
    if not pentest:
        return err("pentest modülü yüklenemedi")
    if not hasattr(pentest, "diff_results"):
        return err("diff_results fonksiyonu bulunamadı", 501)
    body = request.get_json(silent=True) or {}
    idx_a = body.get("a", -2)
    idx_b = body.get("b", -1)
    history = pentest.get_history() if hasattr(pentest, "get_history") else []
    try:
        result_a = history[idx_a]
        result_b = history[idx_b]
    except (IndexError, TypeError):
        return err("Geçersiz tarihçe indeksi", 400)
    diff = pentest.diff_results(result_a, result_b)
    return ok({"diff": diff})


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
def api_cpu_pinning_clear(vm_id):
    """Tüm pinning'i kaldır — tüm vCPU'ları tüm pCPU'lara serbest bırak."""
    try:
        info = vm_manager.get_vm_info(vm_id)
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
@app.route("/api/vms/<vm_id>/export", methods=["POST"])
@require_auth
def api_vm_export(vm_id):
    """VM'i OVA benzeri tar arşivine aktar (XML + disk)."""
    import threading as _thr, tarfile, datetime as _dt
    try:
        info = vm_manager.get_vm_info(vm_id)
        vm_name = info.get("name", vm_id)
        import re as _re_sec
        vm_name_safe = _re_sec.sub(r'[^\w\-.]', '_', str(vm_name))[:64]
        disks = info.get("disks", [])
        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        export_dir = f"/var/lib/oxware/backups/exports"
        os.makedirs(export_dir, exist_ok=True)
        output_path = f"{export_dir}/{vm_name_safe}-{ts}.tar.gz"

        def _do_export():
            try:
                # XML dump
                xr = subprocess.run(["virsh", "dumpxml", vm_id],
                    capture_output=True, text=True, timeout=30)
                xml_content = xr.stdout

                with tarfile.open(output_path, "w:gz") as tar:
                    # XML ekle
                    import io
                    xml_bytes = xml_content.encode()
                    info_obj = tarfile.TarInfo(name=f"{vm_name_safe}.xml")
                    info_obj.size = len(xml_bytes)
                    tar.addfile(info_obj, io.BytesIO(xml_bytes))
                    # Diskleri ekle
                    for disk in disks:
                        src = disk.get("source") or disk.get("path", "")
                        if src and os.path.exists(src):
                            tar.add(src, arcname=os.path.basename(src))
                ev.info(f"OVA export tamamlandı: {vm_name} → {output_path}", category="vm")
            except Exception as ex:
                ev.info(f"OVA export hatası: {ex}", category="vm")

        t = _thr.Thread(target=_do_export, daemon=True)
        t.start()
        return ok({
            "status": "started",
            "output_path": output_path,
            "vm_name": vm_name,
            "message": "Export arkaplanda çalışıyor. Backups sayfasından indirin."
        })
    except Exception as e:
        return err(e, 500)

# ── OpenAPI / Swagger Docs ────────────────────────────────────────────────────
@app.route("/api/docs", methods=["GET"])
def api_swagger_ui():
    html = """<!DOCTYPE html>
<html>
<head>
  <title>OXware API Docs</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
<script>
SwaggerUIBundle({
  url: '/api/openapi.json',
  dom_id: '#swagger-ui',
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
  layout: "BaseLayout"
})
</script>
</body>
</html>"""
    return html, 200, {"Content-Type": "text/html"}

@app.route("/api/openapi.json", methods=["GET"])
@require_auth
def api_openapi_spec():
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "OXware Hypervisor API",
            "version": "2.2.0",
            "description": "KVM tabanlı hypervisor yönetim API'si"
        },
        "servers": [{"url": "/api", "description": "OXware API"}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
            }
        },
        "security": [{"bearerAuth": []}],
        "paths": {
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
            "/security/pentest": {"post": {"summary": "Pen test çalıştır", "tags": ["Security"], "responses": {"200": {"description": "Test sonucu"}}}},
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
def api_vm_fw_delete(vm_id):
    data = _fw_load()
    data.pop(vm_id, None)
    _fw_save(data)
    ev.info(f"VM firewall silindi: {vm_id}", category="vm")
    return jsonify({"ok": True})

# ── Maintenance Mode ───────────────────────────────────────────────────────────
@app.route("/api/vms/<vm_id>/maintenance", methods=["POST"])
@require_auth
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

@app.route("/api/import/ova", methods=["POST"])
@require_auth
def api_import_ova():
    """OVA/OVF dosyasından VM içe aktar."""
    if "file" not in request.files:
        return jsonify({"error": "file alanı gerekli"}), 400
    f = request.files["file"]
    fname = f.filename or "import.ova"
    if not fname.lower().endswith((".ova", ".ovf", ".tar", ".tar.gz")):
        return jsonify({"error": "Desteklenen format: .ova .ovf .tar .tar.gz"}), 400
    _IMPORT_DIR.mkdir(parents=True, exist_ok=True)
    save_path = _IMPORT_DIR / fname
    f.save(str(save_path))

    def _do_import():
        try:
            import tarfile as _tar
            extract_dir = _IMPORT_DIR / (fname + "_extracted")
            extract_dir.mkdir(exist_ok=True)
            if fname.lower().endswith((".ova", ".tar", ".tar.gz")):
                with _tar.open(str(save_path)) as tf:
                    tf.extractall(str(extract_dir))
            else:
                import shutil as _sh
                _sh.copy(str(save_path), str(extract_dir / fname))
            ovf_file = None
            disk_files = []
            for fp in extract_dir.iterdir():
                if fp.suffix.lower() == ".ovf":
                    ovf_file = fp
                elif fp.suffix.lower() in (".vmdk", ".qcow2", ".img", ".raw"):
                    disk_files.append(fp)
            if not disk_files:
                ev.warning(f"OVA import: disk dosyası bulunamadı — {fname}", category="vm")
                return
            vm_name = fname.replace(".ova", "").replace(".tar.gz", "").replace(".tar", "")
            disk_path = _pathlib.Path("/var/lib/libvirt/images") / f"{vm_name}.qcow2"
            src_disk = disk_files[0]
            r_conv = subprocess.run(["qemu-img", "convert", "-O", "qcow2", str(src_disk), str(disk_path)], capture_output=True, text=True)
            if r_conv.returncode != 0:
                ev.warning(f"OVA import disk convert hatası: {r_conv.stderr}", category="vm")
                return
            xml = f"""<domain type='kvm'>
  <name>{vm_name}</name>
  <memory unit='MiB'>2048</memory>
  <vcpu>2</vcpu>
  <os><type arch='x86_64' machine='pc'>hvm</type><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{disk_path}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <graphics type='vnc' port='-1' listen='0.0.0.0'/>
    <video><model type='vga'/></video>
  </devices>
</domain>"""
            import tempfile as _tmp3
            with _tmp3.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as xf:
                xf.write(xml)
                xml_path = xf.name
            r_def = subprocess.run(["virsh", "define", xml_path], capture_output=True, text=True)
            os.unlink(xml_path)
            if r_def.returncode == 0:
                ev.info(f"OVA import tamamlandı: {vm_name}", category="vm")
            else:
                ev.warning(f"OVA import virsh define hatası: {r_def.stderr}", category="vm")
        except Exception as ex:
            ev.warning(f"OVA import hatası: {ex}", category="vm")

    t = threading.Thread(target=_do_import, daemon=True)
    t.start()
    return jsonify({"ok": True, "message": f"Import başlatıldı: {fname}", "filename": fname})

@app.route("/api/import/status", methods=["GET"])
@require_auth
def api_import_status():
    """Import edilen dosyaları listele."""
    if not _IMPORT_DIR.exists():
        return jsonify({"imports": []})
    files = [{"name": p.name, "size": p.stat().st_size} for p in _IMPORT_DIR.iterdir() if p.is_file()]
    return jsonify({"imports": files})

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
