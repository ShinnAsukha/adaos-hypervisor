"""
ssl_manager.py — SSL certificate management (Let's Encrypt + custom certs)
OXware Hypervisor backend module
"""

import subprocess
import json
import logging
import os
import threading
import datetime
import ssl
import re
import shutil

log = logging.getLogger("oxware.ssl")

SSL_DIR   = "/etc/oxware"
CERT_PATH = "/etc/oxware/oxware.crt"
KEY_PATH  = "/etc/oxware/oxware.key"

_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Certificate information
# ---------------------------------------------------------------------------

def get_cert_info(cert_path=None):
    """
    Read and parse a PEM certificate using Python's ssl module.

    Returns:
        dict: subject, issuer, not_before, not_after, days_remaining,
              is_expired, domains
        None if the cert cannot be read.
    """
    path = cert_path or CERT_PATH
    if not os.path.isfile(path):
        return None

    try:
        cert_dict = ssl._ssl._test_decode_cert(path)  # undocumented but reliable
    except Exception:
        try:
            # Fallback: openssl x509
            result = subprocess.run(
                ["openssl", "x509", "-in", path, "-noout",
                 "-subject", "-issuer", "-dates"],
                capture_output=True, text=True, timeout=10
            )
            return _parse_openssl_text(result.stdout, path)
        except Exception as exc:
            log.error("get_cert_info failed: %s", exc)
            return None

    def _dn(tup_list):
        return {k: v for items in tup_list for k, v in items} if tup_list else {}

    subject = _dn(cert_dict.get("subject", ()))
    issuer  = _dn(cert_dict.get("issuer", ()))

    def _parse_dt(s):
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
            try:
                return datetime.datetime.strptime(s, fmt)
            except ValueError:
                pass
        return None

    not_before = _parse_dt(cert_dict.get("notBefore", ""))
    not_after  = _parse_dt(cert_dict.get("notAfter", ""))

    now = datetime.datetime.utcnow()
    days_remaining = int((not_after - now).days) if not_after else None
    is_expired = (days_remaining is not None and days_remaining < 0)

    # SAN domains
    domains = []
    for san_key, san_val in cert_dict.get("subjectAltName", ()):
        if san_key.lower() == "dns":
            domains.append(san_val)
    if not domains and subject.get("commonName"):
        domains = [subject["commonName"]]

    return {
        "subject":        subject,
        "issuer":         issuer,
        "not_before":     not_before.isoformat() if not_before else None,
        "not_after":      not_after.isoformat() if not_after else None,
        "days_remaining": days_remaining,
        "is_expired":     is_expired,
        "domains":        domains,
    }


def _parse_openssl_text(text, path):
    """Fallback parser for openssl x509 text output."""
    info = {}
    for line in text.splitlines():
        if line.startswith("subject="):
            info["subject"] = {"commonName": line.split("=", 1)[-1].strip()}
        elif line.startswith("issuer="):
            info["issuer"] = {"commonName": line.split("=", 1)[-1].strip()}
        elif line.startswith("notBefore="):
            info["not_before"] = line.split("=", 1)[-1].strip()
        elif line.startswith("notAfter="):
            info["not_after"] = line.split("=", 1)[-1].strip()
    try:
        not_after = datetime.datetime.strptime(
            info.get("not_after", ""), "%b %d %H:%M:%S %Y %Z")
        now = datetime.datetime.utcnow()
        days = (not_after - now).days
        info["days_remaining"] = days
        info["is_expired"] = days < 0
    except Exception:
        info["days_remaining"] = None
        info["is_expired"] = None
    info.setdefault("domains", [])
    return info


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_status():
    """
    Return the current SSL configuration status.

    Returns:
        dict: cert_path, key_path, cert_exists, key_exists,
              cert_info, ssl_enabled
    """
    cert_exists = os.path.isfile(CERT_PATH)
    key_exists  = os.path.isfile(KEY_PATH)
    cert_info   = get_cert_info() if cert_exists else None

    ssl_enabled = (
        cert_exists and key_exists
        and cert_info is not None
        and not cert_info.get("is_expired", True)
    )

    return {
        "cert_path":   CERT_PATH,
        "key_path":    KEY_PATH,
        "cert_exists": cert_exists,
        "key_exists":  key_exists,
        "cert_info":   cert_info,
        "ssl_enabled": ssl_enabled,
    }


# ---------------------------------------------------------------------------
# Let's Encrypt
# ---------------------------------------------------------------------------

def request_letsencrypt(domain, email):
    """
    Obtain a certificate from Let's Encrypt via certbot standalone.

    Returns:
        dict: success, cert_path, message
    """
    try:
        result = subprocess.run(
            [
                "certbot", "certonly", "--standalone",
                "--non-interactive", "--agree-tos",
                "-m", email, "-d", domain,
            ],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            return {"success": False, "cert_path": None,
                    "message": result.stderr.strip() or result.stdout.strip()}

        # Copy certs to SSL_DIR
        le_dir = f"/etc/letsencrypt/live/{domain}"
        os.makedirs(SSL_DIR, exist_ok=True)

        src_cert = os.path.join(le_dir, "fullchain.pem")
        src_key  = os.path.join(le_dir, "privkey.pem")

        with _lock:
            shutil.copy2(src_cert, CERT_PATH)
            shutil.copy2(src_key,  KEY_PATH)

        log.info("Let's Encrypt cert for %s installed to %s", domain, SSL_DIR)
        return {"success": True, "cert_path": CERT_PATH,
                "message": "Certificate obtained and installed successfully"}

    except FileNotFoundError:
        return {"success": False, "cert_path": None,
                "message": "certbot not found — install certbot"}
    except Exception as exc:
        log.exception("request_letsencrypt error: %s", exc)
        return {"success": False, "cert_path": None, "message": str(exc)}


def renew_cert():
    """
    Renew the certificate via ``certbot renew``.

    Returns:
        dict: success, output
    """
    try:
        result = subprocess.run(
            ["certbot", "renew", "--non-interactive"],
            capture_output=True, text=True, timeout=120
        )
        success = result.returncode == 0
        output  = (result.stdout + result.stderr).strip()
        if success:
            log.info("certbot renew succeeded")
        else:
            log.warning("certbot renew failed: %s", output)
        return {"success": success, "output": output}
    except FileNotFoundError:
        return {"success": False, "output": "certbot not found"}
    except Exception as exc:
        log.exception("renew_cert error: %s", exc)
        return {"success": False, "output": str(exc)}


# ---------------------------------------------------------------------------
# Custom certificate upload
# ---------------------------------------------------------------------------

def upload_custom_cert(cert_pem, key_pem):
    """
    Validate and install a custom PEM certificate + key.

    Args:
        cert_pem (str): PEM-encoded certificate.
        key_pem  (str): PEM-encoded private key.

    Returns:
        dict: success, message
    """
    if "BEGIN CERTIFICATE" not in cert_pem:
        return {"success": False, "message": "Invalid certificate PEM format"}
    if not re.search(r"BEGIN (RSA |EC |)PRIVATE KEY", key_pem):
        return {"success": False, "message": "Invalid private key PEM format"}

    # Validate using openssl
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".crt", delete=False) as tf:
            tf.write(cert_pem)
            tmp_cert = tf.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as tf:
            tf.write(key_pem)
            tmp_key = tf.name

        r = subprocess.run(
            ["openssl", "x509", "-in", tmp_cert, "-noout"],
            capture_output=True, timeout=10
        )
        if r.returncode != 0:
            return {"success": False,
                    "message": "Certificate validation failed: " + r.stderr.decode()}
    except Exception as exc:
        log.warning("openssl validation skipped: %s", exc)
    finally:
        for p in [tmp_cert, tmp_key]:
            try:
                os.unlink(p)
            except Exception:
                pass

    try:
        os.makedirs(SSL_DIR, exist_ok=True)
        with _lock:
            with open(CERT_PATH, "w") as f:
                f.write(cert_pem)
            with open(KEY_PATH, "w") as f:
                f.write(key_pem)
        os.chmod(KEY_PATH, 0o600)
        log.info("Custom certificate installed to %s", SSL_DIR)
        return {"success": True, "message": "Certificate installed successfully"}
    except Exception as exc:
        log.exception("upload_custom_cert write error: %s", exc)
        return {"success": False, "message": str(exc)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_expiry_days():
    """Return days remaining until certificate expiry, or None."""
    info = get_cert_info()
    if info is None:
        return None
    return info.get("days_remaining")


def check_and_alert():
    """
    Alert if the certificate is expiring soon; auto-renew if < 7 days remain.
    """
    try:
        from notifications import send_alert  # type: ignore
        _has_notifications = True
    except ImportError:
        _has_notifications = False

    days = get_expiry_days()
    if days is None:
        return

    def _alert(msg, level="warning"):
        log.warning(msg)
        if _has_notifications:
            try:
                from notifications import send_alert  # type: ignore
                send_alert(level=level, title="SSL Certificate Alert",
                           message=msg, source="ssl_manager")
            except Exception as exc:
                log.error("Notification send failed: %s", exc)

    if days < 0:
        _alert(f"SSL certificate is EXPIRED ({abs(days)} days ago)", "critical")
    elif days < 7:
        _alert(f"SSL certificate expires in {days} days — attempting auto-renew",
               "critical")
        result = renew_cert()
        if result["success"]:
            log.info("Auto-renew succeeded")
        else:
            _alert(f"Auto-renew FAILED: {result['output']}", "critical")
    elif days < 30:
        _alert(f"SSL certificate expires in {days} days", "warning")


def start_monitor(interval=86400):
    """Start a daemon thread that calls :func:`check_and_alert` daily."""
    def _worker():
        log.info("SSL monitor thread started (interval=%ds)", interval)
        while True:
            try:
                check_and_alert()
            except Exception as exc:
                log.exception("SSL monitor loop error: %s", exc)
            import time
            time.sleep(interval)

    t = threading.Thread(target=_worker, daemon=True, name="ssl-monitor")
    t.start()
    return t
