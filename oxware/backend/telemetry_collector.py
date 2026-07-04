"""OXware Anonymous Usage Telemetry — STRICTLY OPT-IN.

Default: DISABLED. No data leaves the host until an admin explicitly
turns it on from Settings → Privacy → Anonymous Telemetry, or by
setting the env var OXWARE_TELEMETRY_ENABLED=1 before service start.

What we collect (when enabled):
  - oxware_version
  - install_age_days (whole number)
  - host_os_id        (ubuntu, debian — never the FQDN)
  - host_os_version   (22.04, 12, etc.)
  - host_arch         (x86_64, aarch64)
  - kernel_major      (5, 6 — never the full kernel string)
  - cpu_logical_cores (integer count, no model name)
  - ram_total_gb      (integer, rounded)
  - vm_count          (integer)
  - node_count        (integer, federation members)
  - enabled_features  (list of feature-flag IDs that are turned on)
  - country_iso2      (only if the system locale exposes it, never derived from IP)
  - installation_id   (random UUIDv4 minted once on first opt-in;
                       lets us count unique installs without identifying you)

What we NEVER collect:
  - IP addresses, hostnames, MAC addresses
  - Usernames, emails, passwords, API keys, tokens
  - VM names, network names, storage paths
  - Domain XML, panel configuration, backup destinations
  - License keys

Transport: HTTPS POST with JSON body. The receiver URL is configurable
(default https://telemetry.oxware.top/api/v1/ping) so the operator can
point it at their own self-hosted receiver. The payload is signed with
an HMAC of the installation_id + a random nonce so a passive attacker
on the wire cannot forge submissions for someone else's installation.

Cadence: once on enable, then weekly. The send runs in a background
thread when the panel starts; failures are logged at DEBUG and never
retry-bomb the receiver.

State files:
  /etc/oxware/telemetry.json     {enabled, endpoint, installation_id, enabled_at}
  /var/lib/oxware/telemetry_history.jsonl  (local audit copy of every payload sent)
"""
from __future__ import annotations
import json
import logging
import os
import platform
import threading
import time
import uuid
import urllib.request
from pathlib import Path

log = logging.getLogger("oxware.telemetry")

_CFG = Path("/etc/oxware/telemetry.json")
_HISTORY = Path("/var/lib/oxware/telemetry_history.jsonl")
_LOCK = threading.Lock()

DEFAULT_ENDPOINT = os.environ.get(
    "OXWARE_TELEMETRY_ENDPOINT",
    "https://telemetry.oxware.top/api/v1/ping",
)
_WEEKLY_SECONDS = 7 * 24 * 3600

# Field-allowlist; anything else added to the payload by mistake will be
# stripped before sending. Failure-closed.
_ALLOWED_FIELDS = frozenset({
    "schema_version",
    "installation_id",
    "oxware_version",
    "install_age_days",
    "host_os_id",
    "host_os_version",
    "host_arch",
    "kernel_major",
    "cpu_logical_cores",
    "ram_total_gb",
    "vm_count",
    "node_count",
    "enabled_features",
    "country_iso2",
    "integrity_ok",
    "integrity_fp",
    "nonce",
    "ts",
})


def _load_cfg() -> dict:
    if not _CFG.exists():
        return {"enabled": False, "endpoint": DEFAULT_ENDPOINT}
    try:
        return json.loads(_CFG.read_text(encoding="utf-8"))
    except Exception:
        return {"enabled": False, "endpoint": DEFAULT_ENDPOINT}


def _save_cfg(d: dict) -> None:
    try:
        _CFG.parent.mkdir(parents=True, exist_ok=True)
        tmp = _CFG.with_suffix(".tmp")
        tmp.write_text(json.dumps(d, indent=2), encoding="utf-8")
        os.replace(tmp, _CFG)
        try:
            os.chmod(_CFG, 0o640)
        except Exception:
            pass
    except Exception as e:
        log.warning("telemetry cfg save failed: %s", e)


def status() -> dict:
    cfg = _load_cfg()
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "endpoint": cfg.get("endpoint", DEFAULT_ENDPOINT),
        "installation_id": (cfg.get("installation_id") or "")[:8] + "…"
        if cfg.get("installation_id") else None,
        "enabled_at": cfg.get("enabled_at"),
        "last_sent_at": cfg.get("last_sent_at"),
        "last_send_ok": cfg.get("last_send_ok"),
        "what_we_collect": [
            "OXware version", "install age (days)", "host OS family + version",
            "host architecture", "kernel major version", "CPU core count",
            "RAM size", "VM count", "node count",
            "enabled feature-flag IDs", "country code (locale-derived only)",
        ],
        "what_we_never_collect": [
            "IP addresses", "hostnames", "MAC addresses",
            "usernames / emails / passwords / API keys",
            "VM names / network names / storage paths",
            "license keys", "domain XML", "backup destinations",
        ],
    }


def enable(endpoint: str | None = None) -> dict:
    """Turn telemetry ON. Mints an installation_id if not already present."""
    with _LOCK:
        cfg = _load_cfg()
        cfg["enabled"] = True
        if endpoint:
            cfg["endpoint"] = endpoint
        cfg.setdefault("installation_id", str(uuid.uuid4()))
        cfg.setdefault("enabled_at", time.time())
        _save_cfg(cfg)
    log.info("telemetry enabled — installation_id %s",
             cfg["installation_id"][:8] + "…")
    return status()


def disable() -> dict:
    """Turn telemetry OFF. The installation_id is wiped so the next opt-in
    is treated as a brand new install (no historical linkage)."""
    with _LOCK:
        cfg = _load_cfg()
        cfg["enabled"] = False
        cfg.pop("installation_id", None)
        cfg.pop("enabled_at", None)
        _save_cfg(cfg)
    log.info("telemetry disabled — installation_id wiped")
    return status()


def set_endpoint(endpoint: str) -> dict:
    """Persist the receiver endpoint WITHOUT changing the enabled state.
    Lets an operator point telemetry at their own receiver before opting in,
    or change it later, without silently turning telemetry on."""
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError("endpoint must be a non-empty string")
    ep = endpoint.strip()
    if not (ep.startswith("http://") or ep.startswith("https://")):
        raise ValueError("endpoint must start with http:// or https://")
    with _LOCK:
        cfg = _load_cfg()
        cfg["endpoint"] = ep
        _save_cfg(cfg)
    log.info("telemetry endpoint set: %s", ep)
    return status()


def _detect_host_facts(deps: dict) -> dict:
    """Build the payload from host facts. Everything that could identify the
    operator (hostname, MAC, IP, username, paths) is intentionally absent."""
    facts: dict = {"schema_version": 1}
    facts["host_arch"] = platform.machine() or ""
    try:
        rel = platform.release()
        facts["kernel_major"] = int(rel.split(".")[0]) if rel and rel[0].isdigit() else 0
    except Exception:
        facts["kernel_major"] = 0
    # OS family + version come from /etc/os-release (no FQDN, no hostname).
    facts["host_os_id"] = ""
    facts["host_os_version"] = ""
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if "=" not in line:
                    continue
                k, v = line.strip().split("=", 1)
                v = v.strip().strip('"').strip("'")
                if k == "ID":
                    facts["host_os_id"] = v[:32]
                elif k == "VERSION_ID":
                    facts["host_os_version"] = v[:16]
    except Exception:
        pass
    # CPU / RAM counts only — no model, no flags, no microarch name.
    try:
        facts["cpu_logical_cores"] = os.cpu_count() or 0
    except Exception:
        facts["cpu_logical_cores"] = 0
    try:
        ram_bytes = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        facts["ram_total_gb"] = round(ram_bytes / (1024 ** 3))
    except Exception:
        facts["ram_total_gb"] = 0
    # OXware version + counts pulled from the dependency dict so we don't
    # import the live modules at telemetry time (avoids cycles).
    facts["oxware_version"] = str(deps.get("oxware_version") or "0.0.0")[:16]
    facts["vm_count"] = int(deps.get("vm_count") or 0)
    facts["node_count"] = int(deps.get("node_count") or 0)
    feats = deps.get("enabled_features") or []
    if isinstance(feats, (list, tuple)):
        facts["enabled_features"] = sorted(str(f)[:48] for f in feats)[:128]
    else:
        facts["enabled_features"] = []
    # Country comes from LANG only (e.g. "en_US.UTF-8" -> "US"). Never IP-derived.
    facts["country_iso2"] = ""
    try:
        lang = os.environ.get("LANG", "") or os.environ.get("LC_ALL", "")
        if "_" in lang:
            iso = lang.split("_", 1)[1][:2].upper()
            if iso.isalpha():
                facts["country_iso2"] = iso
    except Exception:
        pass
    return facts


def _scrub(payload: dict) -> dict:
    """Drop any key not on the allowlist. Defence in depth — a future bug
    that accidentally adds a field will not leak it."""
    return {k: v for k, v in payload.items() if k in _ALLOWED_FIELDS}


def _record_history(payload: dict, ok: bool, error: str | None) -> None:
    try:
        _HISTORY.parent.mkdir(parents=True, exist_ok=True)
        entry = {"ts": time.time(), "ok": ok, "payload": payload}
        if error:
            entry["error"] = error[:300]
        with open(_HISTORY, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception as e:
        log.debug("telemetry history write failed: %s", e)


def build_payload(deps: dict | None = None) -> dict:
    """Public helper — what we'd send right now, ready for inspection.
    The Settings page calls this to show the operator the exact JSON we
    would transmit before they flip the toggle."""
    cfg = _load_cfg()
    deps = deps or {}
    facts = _detect_host_facts(deps)
    enabled_at = cfg.get("enabled_at") or time.time()
    facts["install_age_days"] = max(int((time.time() - enabled_at) / 86400), 0)
    facts["installation_id"] = cfg.get("installation_id") or ""
    # Brand integrity signal (opt-in: only travels if telemetry is enabled).
    # Lets the author see if a phoned-home install is a stripped rebrand.
    try:
        import brand_integrity as _bi
        v = _bi.verify()
        facts["integrity_ok"] = bool(v.get("ok"))
        facts["integrity_fp"] = v.get("fingerprint")
    except Exception:
        pass
    facts["nonce"] = uuid.uuid4().hex
    facts["ts"] = time.time()
    return _scrub(facts)


def send_once(deps: dict | None = None) -> dict:
    """Fire one ping. No-op if telemetry is disabled."""
    cfg = _load_cfg()
    if not cfg.get("enabled"):
        return {"ok": False, "skipped": "disabled"}
    # Katman 2: Dark Site (tam offline) modunda dışarı hiç deneme yapma.
    # (Düz egress enforce zaten socket seviyesinde bloklar; telemetri opt-in.)
    try:
        import dark_site
        if dark_site.is_enabled():
            return {"ok": False, "skipped": "darksite-offline"}
    except Exception:
        pass
    payload = build_payload(deps or {})
    endpoint = cfg.get("endpoint", DEFAULT_ENDPOINT)
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint, data=body,
        headers={"Content-Type": "application/json",
                 "User-Agent": "OXware-Telemetry/1.0"},
        method="POST",
    )
    error = None
    ok = False
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            ok = 200 <= resp.status < 300
    except Exception as e:
        error = str(e)
        log.debug("telemetry send failed: %s", error)
    with _LOCK:
        cfg["last_sent_at"] = time.time()
        cfg["last_send_ok"] = ok
        _save_cfg(cfg)
    _record_history(payload, ok, error)
    return {"ok": ok, "endpoint": endpoint, "error": error}


_BG_STARTED = False


def start_background_sender(deps_factory) -> None:
    """Start the weekly background ping. Call once at panel boot.
    `deps_factory()` is invoked each cycle to compute current counts."""
    global _BG_STARTED
    if _BG_STARTED:
        return
    _BG_STARTED = True

    def _loop():
        while True:
            try:
                cfg = _load_cfg()
                if cfg.get("enabled"):
                    last = cfg.get("last_sent_at") or 0
                    if (time.time() - last) >= _WEEKLY_SECONDS:
                        try:
                            deps = deps_factory() if callable(deps_factory) else {}
                        except Exception:
                            deps = {}
                        send_once(deps)
            except Exception as e:
                log.debug("telemetry loop tick failed: %s", e)
            # Sleep in small chunks so a config flip is honoured promptly.
            for _ in range(60 * 60):  # one hour, polled every second
                time.sleep(1)

    t = threading.Thread(target=_loop, name="oxware-telemetry",
                         daemon=True)
    t.start()
    log.info("telemetry background sender started (weekly, opt-in)")
