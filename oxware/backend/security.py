"""
AdaOS Güvenlik Katmanı
──────────────────────
1.  Rate limiting      — brute-force önleme (login + genel API)
2.  Security headers   — HSTS, CSP, X-Frame-Options, vb.
3.  Input sanitization — VM adı, dosya yolları, UUID doğrulama
4.  Path traversal     — dosya yolu saldırılarını önle
5.  Request logging    — güvenlik denetim kaydı
"""

import re
import os
import time
import threading
import ipaddress
import hashlib
import logging
from functools import wraps
from flask import request, jsonify, g

log = logging.getLogger("adaos.security")

# ── 1. Rate Limiter ───────────────────────────────────────────────────────────

class RateLimiter:
    def __init__(self):
        self._lock    = threading.Lock()
        self._buckets: dict[str, dict] = {}

    def _key(self, ip: str, endpoint: str) -> str:
        return f"{ip}:{endpoint}"

    def check(
        self,
        ip: str,
        endpoint: str,
        max_calls: int = 30,
        window_secs: int = 60,
    ) -> tuple[bool, int]:
        """
        Döndürür: (allowed: bool, retry_after: int)
        """
        key = self._key(ip, endpoint)
        now = time.time()

        with self._lock:
            bucket = self._buckets.get(key, {"calls": [], "blocked_until": 0})

            if bucket["blocked_until"] > now:
                return False, int(bucket["blocked_until"] - now)

            # Pencere dışındaki çağrıları temizle
            bucket["calls"] = [t for t in bucket["calls"] if now - t < window_secs]

            if len(bucket["calls"]) >= max_calls:
                block_until = now + window_secs
                bucket["blocked_until"] = block_until
                self._buckets[key] = bucket
                log.warning("Rate limit aşıldı: %s / %s", ip, endpoint)
                return False, window_secs

            bucket["calls"].append(now)
            self._buckets.setdefault(key, bucket)
            self._buckets[key] = bucket
            return True, 0

    def cleanup(self):
        """Eski kayıtları temizle (periyodik çağrılmalı)."""
        now = time.time()
        with self._lock:
            expired = [k for k, v in self._buckets.items()
                       if v["blocked_until"] < now and not v["calls"]]
            for k in expired:
                del self._buckets[k]


_limiter = RateLimiter()

# Endpoint bazlı limitler
RATE_LIMITS = {
    "/api/auth/login":    (5,   60),   # 5 deneme / dakika (brute-force)
    "/api/setup/init":    (3,  300),   # 3 deneme / 5 dakika
    "/api/provision":     (10,  60),   # 10 kurulum / dakika
    "/api/storage/isos":  (5,  300),   # 5 upload / 5 dakika
    "default":            (120, 60),   # Genel API: 120 istek / dakika
}


def rate_limit_middleware(app):
    """Flask before_request hook olarak ekle."""
    @app.before_request
    def check_rate_limit():
        if not request.path.startswith("/api/"):
            return

        ip = _get_real_ip()
        path = request.path

        max_calls, window = RATE_LIMITS.get(path, RATE_LIMITS["default"])
        allowed, retry_after = _limiter.check(ip, path, max_calls, window)

        if not allowed:
            log.warning("Rate limit: %s → %s (retry: %ds)", ip, path, retry_after)
            resp = jsonify({
                "error": "Çok fazla istek. Lütfen bekleyin.",
                "retry_after": retry_after,
            })
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry_after)
            return resp


# ── 2. Security Headers ───────────────────────────────────────────────────────

def security_headers_middleware(app):
    @app.after_request
    def add_headers(response):
        # /console/ ve /novnc/ sayfaları iframe embed gerektiriyor — frame kısıtlaması uygulanmaz
        path = request.path
        is_console_path = path.startswith("/console/") or path.startswith("/novnc/")

        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]           = "SAMEORIGIN" if is_console_path else "DENY"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "geolocation=(), camera=(), microphone=()"
        if not is_console_path:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"]        = "no-cache"

        # HSTS (yalnızca HTTPS'de)
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = \
                "max-age=31536000; includeSubDomains; preload"

        # CSP — console/novnc için frame-ancestors 'self', diğerleri için 'none'
        frame_ancestors = "'self'" if is_console_path else "'none'"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' wss: ws:; "
            f"frame-ancestors {frame_ancestors};"
        )
        return response


# ── 3. Input Sanitization ─────────────────────────────────────────────────────

# VM adı: sadece alfanümerik, tire, alt çizgi (3-64 karakter)
_VM_NAME_RE   = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
# UUID: standart format
_UUID_RE      = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
# Dosya adı: yol traversal karakterleri yok
_SAFE_FNAME_RE = re.compile(r"^[a-zA-Z0-9_\-. ]{1,255}$")
# IP adresi
_IP_RE        = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def validate_vm_name(name: str) -> str:
    if not name or not isinstance(name, str):
        raise ValueError("VM adı boş olamaz")
    name = name.strip()
    if not _VM_NAME_RE.match(name):
        raise ValueError(
            "VM adı yalnızca harf, rakam, tire ve alt çizgi içerebilir (1-64 karakter)"
        )
    # Tehlikeli kalıplar
    for bad in ["../", "//", "..", "\\", ";", "|", "&", "`", "$("]:
        if bad in name:
            raise ValueError(f"VM adında geçersiz karakter: {bad!r}")
    return name


def validate_uuid(value: str, field: str = "id") -> str:
    if not value or not isinstance(value, str):
        raise ValueError(f"{field} boş olamaz")
    if not _UUID_RE.match(value.strip()):
        raise ValueError(f"Geçersiz UUID formatı: {field}")
    return value.strip().lower()


def validate_filename(name: str) -> str:
    if not name or not isinstance(name, str):
        raise ValueError("Dosya adı boş olamaz")
    name = os.path.basename(name)  # yol bileşenlerini kaldır
    if not _SAFE_FNAME_RE.match(name):
        raise ValueError("Geçersiz dosya adı karakterleri")
    if name.startswith(".") or name.startswith("-"):
        raise ValueError("Dosya adı nokta veya tire ile başlayamaz")
    return name


def validate_path_safe(path: str, allowed_roots: list[str]) -> str:
    """Path traversal saldırısını önle."""
    path = os.path.realpath(os.path.abspath(path))
    for root in allowed_roots:
        root = os.path.realpath(os.path.abspath(root))
        if path.startswith(root + os.sep) or path == root:
            return path
    raise ValueError(f"Güvensiz dosya yolu. İzin verilen kökler: {allowed_roots}")


def validate_ip(ip: str) -> str:
    if not ip:
        raise ValueError("IP adresi boş olamaz")
    try:
        return str(ipaddress.IPv4Address(ip.strip()))
    except Exception:
        raise ValueError(f"Geçersiz IP adresi: {ip!r}")


def validate_network_cidr(cidr: str) -> str:
    try:
        return str(ipaddress.IPv4Network(cidr.strip(), strict=False))
    except Exception:
        raise ValueError(f"Geçersiz CIDR: {cidr!r}")


def validate_port(port, low: int = 1, high: int = 65535) -> int:
    try:
        p = int(port)
        if not (low <= p <= high):
            raise ValueError
        return p
    except (ValueError, TypeError):
        raise ValueError(f"Geçersiz port: {port!r} ({low}-{high} aralığında olmalı)")


def sanitize_str(value: str, max_len: int = 256) -> str:
    """Temel string temizliği."""
    if not isinstance(value, str):
        raise ValueError("Beklenen string değer")
    value = value.strip()[:max_len]
    # Null byte
    value = value.replace("\x00", "")
    return value


def validate_memory_mb(value) -> int:
    v = int(value)
    if not (64 <= v <= 1_048_576):   # 64 MB – 1 TB
        raise ValueError(f"Geçersiz bellek değeri: {v} MB (64 MB–1 TB)")
    return v


def validate_disk_gb(value) -> int:
    v = int(value)
    if not (1 <= v <= 65536):   # 1 GB – 64 TB
        raise ValueError(f"Geçersiz disk boyutu: {v} GB (1 GB–64 TB)")
    return v


def validate_vcpus(value) -> int:
    v = int(value)
    if not (1 <= v <= 512):
        raise ValueError(f"Geçersiz vCPU sayısı: {v} (1-512)")
    return v


# ── 4. Denetim kaydı ─────────────────────────────────────────────────────────

def audit_log_middleware(app):
    @app.before_request
    def before():
        g.request_start = time.time()

    @app.after_request
    def after(response):
        if not request.path.startswith("/api/"):
            return response
        duration = round((time.time() - getattr(g, "request_start", time.time())) * 1000, 1)
        ip = _get_real_ip()
        # Sadece değiştirici işlemleri kaydet
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            log.info(
                "%s %s %s %dms — %s",
                request.method, request.path, response.status_code, duration, ip,
            )
        return response


# ── 5. Error Handler — Stack trace sızdırma ───────────────────────────────────

def safe_error_handlers(app):
    @app.errorhandler(Exception)
    def handle_exception(e):
        log.error("Beklenmeyen hata: %s", e, exc_info=True)
        # İstemciye stack trace gösterme
        return jsonify({"error": "Sunucu hatası. Lütfen yöneticiye başvurun."}), 500

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Geçersiz istek"}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"error": "Kimlik doğrulama gerekli"}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"error": "Erişim reddedildi"}), 403

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Kaynak bulunamadı"}), 404
        from flask import render_template
        return render_template("index.html")

    @app.errorhandler(429)
    def too_many(e):
        return jsonify({"error": "Çok fazla istek"}), 429


# ── Yardımcı ──────────────────────────────────────────────────────────────────

def _get_real_ip() -> str:
    """Proxy arkasından gerçek IP al (güvenli)."""
    # Yalnızca localhost/trusted proxy'den gelen X-Forwarded-For'a güven
    remote = request.remote_addr or ""
    try:
        if ipaddress.ip_address(remote).is_loopback:
            xff = request.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()
    except Exception:
        pass
    return remote


def register_security(app):
    """Tüm güvenlik middleware'lerini uygulamaya kaydet."""
    rate_limit_middleware(app)
    security_headers_middleware(app)
    audit_log_middleware(app)
    safe_error_handlers(app)
    log.info("Güvenlik katmanı aktif")
