"""
webhook_manager.py — Webhook management with HMAC signing and delivery logging
OXware Hypervisor backend module
"""

import json
import hmac
import hashlib
import logging
import os
import threading
import uuid
import time

log = logging.getLogger("oxware.webhooks")

WEBHOOKS_FILE = "/var/lib/oxware/webhooks.json"
DELIVERY_LOG  = "/var/log/oxware/webhook_deliveries.jsonl"

_lock          = threading.Lock()
_delivery_lock = threading.Lock()

SUPPORTED_EVENTS = [
    "vm.created", "vm.deleted", "vm.started", "vm.stopped", "vm.error",
    "snapshot.created", "snapshot.deleted", "backup.completed", "backup.failed",
    "alert.triggered", "network.changed", "user.login", "user.failed_login",
]

# Optional requests import with urllib fallback
try:
    import requests as _req
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
    import urllib.request
    import urllib.error
    log.debug("requests not available — using urllib.request as fallback")


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _load():
    if not os.path.isfile(WEBHOOKS_FILE):
        return {}
    try:
        with open(WEBHOOKS_FILE) as f:
            return json.load(f)
    except Exception as exc:
        log.error("_load webhooks error: %s", exc)
        return {}


def _save(data):
    try:
        os.makedirs(os.path.dirname(WEBHOOKS_FILE), exist_ok=True)
        with open(WEBHOOKS_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as exc:
        log.error("_save webhooks error: %s", exc)


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def register(name, url, events, secret=""):
    """
    Register a new webhook.

    Args:
        name   (str): Human-friendly label.
        url    (str): Target URL.
        events (list[str]): List of event names to subscribe to.
        secret (str): Optional HMAC secret.

    Returns:
        dict: The created webhook record.
    """
    invalid = [e for e in events if e not in SUPPORTED_EVENTS]
    if invalid:
        log.warning("register: unknown events ignored: %s", invalid)
        events = [e for e in events if e in SUPPORTED_EVENTS]

    webhook_id = str(uuid.uuid4())
    record = {
        "id":         webhook_id,
        "name":       name,
        "url":        url,
        "events":     events,
        "secret":     secret,
        "active":     True,
        "created_at": time.time(),
    }
    with _lock:
        data = _load()
        data[webhook_id] = record
        _save(data)

    log.info("Webhook registered: %s (%s)", name, webhook_id)
    return record


def list_webhooks():
    """Return all registered webhooks."""
    with _lock:
        return list(_load().values())


def get_webhook(webhook_id):
    """Return a single webhook by ID, or None."""
    with _lock:
        return _load().get(webhook_id)


def update_webhook(webhook_id, **kwargs):
    """
    Update webhook fields (name, url, events, secret, active).

    Returns:
        dict: Updated record, or None if not found.
    """
    with _lock:
        data = _load()
        if webhook_id not in data:
            return None
        allowed = {"name", "url", "events", "secret", "active"}
        for k, v in kwargs.items():
            if k in allowed:
                data[webhook_id][k] = v
        _save(data)
        return data[webhook_id]


def delete_webhook(webhook_id):
    """Delete a webhook by ID. Returns True if deleted, False if not found."""
    with _lock:
        data = _load()
        if webhook_id not in data:
            return False
        del data[webhook_id]
        _save(data)
    log.info("Webhook deleted: %s", webhook_id)
    return True


# ---------------------------------------------------------------------------
# Triggering
# ---------------------------------------------------------------------------

def trigger(event_name, payload):
    """
    Dispatch *payload* to all active webhooks subscribed to *event_name*.

    Deliveries are performed asynchronously in daemon threads.

    Args:
        event_name (str): One of SUPPORTED_EVENTS.
        payload    (dict): Arbitrary JSON-serialisable data.
    """
    if event_name not in SUPPORTED_EVENTS:
        log.warning("trigger: unknown event '%s'", event_name)

    webhooks = list_webhooks()
    for wh in webhooks:
        if not wh.get("active", True):
            continue
        if event_name not in wh.get("events", []):
            continue
        t = threading.Thread(
            target=_send,
            args=(wh, event_name, payload),
            daemon=True,
            name=f"webhook-{wh['id'][:8]}",
        )
        t.start()


def _send(webhook, event_name, payload):
    """
    POST payload to a single webhook with HMAC-SHA256 signature.
    Logs the delivery result.
    """
    url    = webhook["url"]
    secret = webhook.get("secret", "")
    body   = json.dumps({
        "event":   event_name,
        "payload": payload,
        "ts":      time.time(),
    }).encode()

    sig = hmac.new(
        secret.encode() if secret else b"",
        body,
        hashlib.sha256,
    ).hexdigest()

    headers = {
        "Content-Type":       "application/json",
        "X-OXware-Event":     event_name,
        "X-OXware-Signature": f"sha256={sig}",
        "X-OXware-Hook-ID":   webhook["id"],
    }

    status_code = None
    success     = False
    error       = ""

    try:
        if _HAS_REQUESTS:
            resp = _req.post(url, data=body, headers=headers, timeout=10)
            status_code = resp.status_code
            success     = 200 <= status_code < 300
        else:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                status_code = resp.status
                success     = True
    except Exception as exc:
        error = str(exc)
        log.warning("Webhook delivery failed [%s] %s: %s",
                    webhook["id"], url, exc)

    _log_delivery(
        webhook_id=webhook["id"],
        event=event_name,
        url=url,
        status_code=status_code,
        success=success,
        error=error,
    )


# ---------------------------------------------------------------------------
# Delivery logging
# ---------------------------------------------------------------------------

def _log_delivery(webhook_id, event, url, status_code, success, error=""):
    """Append a JSONL delivery record to DELIVERY_LOG."""
    record = {
        "ts":          time.time(),
        "webhook_id":  webhook_id,
        "event":       event,
        "url":         url,
        "status_code": status_code,
        "success":     success,
        "error":       error,
    }
    try:
        os.makedirs(os.path.dirname(DELIVERY_LOG), exist_ok=True)
        with _delivery_lock:
            with open(DELIVERY_LOG, "a") as f:
                f.write(json.dumps(record) + "\n")
    except Exception as exc:
        log.error("_log_delivery error: %s", exc)


def get_deliveries(webhook_id, limit=50):
    """
    Return the last *limit* delivery records for a specific webhook.

    Returns:
        list[dict]
    """
    if not os.path.isfile(DELIVERY_LOG):
        return []
    records = []
    try:
        with open(DELIVERY_LOG) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get("webhook_id") == webhook_id:
                        records.append(rec)
                except json.JSONDecodeError:
                    pass
    except Exception as exc:
        log.error("get_deliveries error: %s", exc)
    return records[-limit:]


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

def test_webhook(webhook_id):
    """
    Send a test ping to the specified webhook.

    Returns:
        dict: success, status_code, error
    """
    wh = get_webhook(webhook_id)
    if wh is None:
        return {"success": False, "status_code": None,
                "error": f"Webhook '{webhook_id}' not found"}

    payload = {"message": "OXware webhook test ping", "ts": time.time()}
    # Trigger synchronously for immediate feedback
    url    = wh["url"]
    secret = wh.get("secret", "")
    body   = json.dumps({
        "event":   "test.ping",
        "payload": payload,
        "ts":      time.time(),
    }).encode()
    sig = hmac.new(
        secret.encode() if secret else b"",
        body,
        hashlib.sha256,
    ).hexdigest()
    headers = {
        "Content-Type":       "application/json",
        "X-OXware-Event":     "test.ping",
        "X-OXware-Signature": f"sha256={sig}",
        "X-OXware-Hook-ID":   webhook_id,
    }
    status_code = None
    error       = ""
    try:
        if _HAS_REQUESTS:
            resp = _req.post(url, data=body, headers=headers, timeout=10)
            status_code = resp.status_code
            success     = 200 <= status_code < 300
        else:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                status_code = resp.status
                success     = True
    except Exception as exc:
        error   = str(exc)
        success = False

    _log_delivery(webhook_id, "test.ping", url, status_code, success, error)
    return {"success": success, "status_code": status_code, "error": error}
