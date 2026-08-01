"""
OXware SSO Manager — SAML 2.0 + OpenID Connect
────────────────────────────────────────────────
Stores IdP configuration and processes authentication flows. Crypto
verification is FAIL-CLOSED: when the required library is not installed,
SAML/OIDC callbacks refuse the assertion instead of trusting an unsigned
payload.

  - OIDC ID-token signature verification requires `python-jose` (jwt).
  - SAML AssertionConsumerService signature verification requires
    `python3-saml` (OneLogin_Saml2_Auth) or `xmlsec1` + signxml.

Development override: `OXWARE_ALLOW_UNVERIFIED_SSO=1` re-enables the legacy
stub paths and logs a WARN on every callback. Never use this in production.

Config: /var/lib/oxware/sso_config.json
"""
from __future__ import annotations
import os, json, logging, secrets, base64, time
from pathlib import Path

log = logging.getLogger("sso_manager")
_CFG = Path("/var/lib/oxware/sso_config.json")

# ── Crypto capability probes ─────────────────────────────────────────────────
try:
    from jose import jwt as _jose_jwt  # type: ignore
    _OIDC_VERIFY_AVAILABLE = True
except Exception:
    _jose_jwt = None
    _OIDC_VERIFY_AVAILABLE = False

try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore
    _SAML_VERIFY_AVAILABLE = True
except Exception:
    OneLogin_Saml2_Auth = None  # type: ignore
    _SAML_VERIFY_AVAILABLE = False


def _allow_unverified() -> bool:
    if os.environ.get("OXWARE_ALLOW_UNVERIFIED_SSO") == "1":
        log.warning("SSO unverified override active — INSECURE, do not use in production")
        return True
    return False


def crypto_status() -> dict:
    """Surface verify capability so the panel can show a clear banner."""
    return {
        "oidc_signature_verify": _OIDC_VERIFY_AVAILABLE,
        "saml_signature_verify": _SAML_VERIFY_AVAILABLE,
        "unverified_override":   bool(os.environ.get("OXWARE_ALLOW_UNVERIFIED_SSO") == "1"),
        "production_ready":      _OIDC_VERIFY_AVAILABLE and _SAML_VERIFY_AVAILABLE,
    }


def _load() -> dict:
    try:
        if _CFG.exists():
            return json.loads(_CFG.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {
        "saml": {"enabled": False, "entity_id": "", "metadata_url": "", "x509_cert": "",
                 "acs_url": "", "sso_url": "", "attr_email": "email", "attr_role": "role"},
        "oidc": {"enabled": False, "issuer": "", "client_id": "", "client_secret": "",
                 "redirect_uri": "", "scope": "openid email profile",
                 "claim_email": "email", "claim_role": "role"},
        "role_map": {"admin": "admin", "operator": "operator", "user": "vm-user"},
    }


def _save(d: dict):
    _CFG.parent.mkdir(parents=True, exist_ok=True)
    _CFG.write_text(json.dumps(d, indent=2), encoding="utf-8")
    try:
        os.chmod(_CFG, 0o600)
    except Exception:
        pass


def get_config() -> dict:
    """Return config WITHOUT secrets (for display)."""
    d = _load()
    redacted = json.loads(json.dumps(d))  # deep copy
    if redacted.get("oidc", {}).get("client_secret"):
        redacted["oidc"]["client_secret"] = "***"
    return redacted


def update_config(saml: dict = None, oidc: dict = None, role_map: dict = None) -> dict:
    d = _load()
    if saml is not None:
        d["saml"] = {**d.get("saml", {}), **saml}
    if oidc is not None:
        old_secret = d.get("oidc", {}).get("client_secret", "")
        d["oidc"] = {**d.get("oidc", {}), **oidc}
        # Don't wipe secret if frontend sent "***"
        if oidc.get("client_secret") == "***":
            d["oidc"]["client_secret"] = old_secret
    if role_map is not None:
        d["role_map"] = role_map
    _save(d)
    log.info("SSO config updated")
    return {"ok": True}


# ── SAML ──────────────────────────────────────────────────────────────────────
def saml_authn_request() -> dict:
    """Build SAML AuthnRequest URL (redirect target)."""
    cfg = _load().get("saml", {})
    if not cfg.get("enabled"):
        return {"ok": False, "error": "SAML disabled"}
    if not cfg.get("sso_url"):
        return {"ok": False, "error": "sso_url missing"}
    # Stub: real impl uses python3-saml. Here we just redirect with relay_state.
    relay = secrets.token_urlsafe(16)
    return {
        "ok": True,
        "redirect_url": cfg["sso_url"],
        "relay_state":  relay,
        "note":         "Production'da python3-saml ile imzalı request üretin.",
    }


def saml_process_acs(saml_response_b64: str, relay_state: str = "") -> dict:
    """Process SAML AssertionConsumerService callback.

    SEC: the gate used to pass when python3-saml was merely *importable*, but
    the code below never calls it — it does naive ElementTree extraction and
    returns `warning: Signature NOT verified`. Installing the library therefore
    REMOVED the fail-closed guard without adding any verification, so a forged
    assertion was accepted. Until real signature verification is implemented,
    an unverified assertion is only accepted behind the explicit dev flag.
    """
    if not _allow_unverified():
        return {"ok": False,
                "error": "SAML assertion signature verification is not implemented yet. "
                         "Refusing the assertion (fail-closed). Use OIDC, which is "
                         "verified, or set OXWARE_ALLOW_UNVERIFIED_SSO=1 for a dev "
                         "environment only.",
                "verified": False}
    try:
        decoded = base64.b64decode(saml_response_b64)
    except Exception:
        return {"ok": False, "error": "invalid base64"}
    try:
        # OXW-SEC-005: XXE prevention — defusedxml when available, fallback to stdlib
        # Python's stdlib xml.etree does NOT expand external entities by default (safe for XXE),
        # but defusedxml provides additional protection (billion laughs, etc.)
        try:
            import defusedxml.ElementTree as ET  # type: ignore
        except ImportError:
            import xml.etree.ElementTree as ET
        root = ET.fromstring(decoded)
        # Naive extraction — production must verify signature first
        ns = {"saml": "urn:oasis:names:tc:SAML:2.0:assertion"}
        nameid_el = root.find(".//saml:NameID", ns)
        attrs = {}
        for av in root.findall(".//saml:AttributeStatement/saml:Attribute", ns):
            name = av.get("Name", "")
            val_el = av.find("saml:AttributeValue", ns)
            if val_el is not None:
                attrs[name] = val_el.text
        return {
            "ok": True,
            "email": attrs.get(_load()["saml"].get("attr_email", "email")) or (nameid_el.text if nameid_el is not None else ""),
            "role":  attrs.get(_load()["saml"].get("attr_role", "role"), "vm-user"),
            "warning": "Signature NOT verified — install python3-saml for production",
        }
    except Exception as e:
        return {"ok": False, "error": f"parse: {e}"}


# ── OIDC ──────────────────────────────────────────────────────────────────────
def oidc_authorize_url(state: str = "") -> dict:
    """Build OIDC /authorize URL."""
    cfg = _load().get("oidc", {})
    if not cfg.get("enabled"):
        return {"ok": False, "error": "OIDC disabled"}
    if not all([cfg.get("issuer"), cfg.get("client_id"), cfg.get("redirect_uri")]):
        return {"ok": False, "error": "OIDC config incomplete"}
    state = state or secrets.token_urlsafe(16)
    from urllib.parse import urlencode
    url = f"{cfg['issuer'].rstrip('/')}/authorize?" + urlencode({
        "response_type": "code",
        "client_id":     cfg["client_id"],
        "redirect_uri":  cfg["redirect_uri"],
        "scope":         cfg.get("scope", "openid email profile"),
        "state":         state,
    })
    return {"ok": True, "redirect_url": url, "state": state}


def oidc_exchange_code(code: str, state: str = "") -> dict:
    """Exchange auth code for tokens."""
    cfg = _load().get("oidc", {})
    if not cfg.get("enabled"):
        return {"ok": False, "error": "OIDC disabled"}
    try:
        import urllib.request, urllib.parse, ssl
        data = urllib.parse.urlencode({
            "grant_type":    "authorization_code",
            "code":          code,
            "client_id":     cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "redirect_uri":  cfg["redirect_uri"],
        }).encode()
        req = urllib.request.Request(f"{cfg['issuer'].rstrip('/')}/token", data=data)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            tok = json.loads(resp.read().decode())
        id_tok = tok.get("id_token", "")
        if not id_tok or id_tok.count(".") != 2:
            return {"ok": False, "error": "no id_token in response"}

        # ── Fail-closed signature verification ────────────────────────────
        if _OIDC_VERIFY_AVAILABLE:
            try:
                jwks_url = cfg.get("jwks_url") or f"{cfg['issuer'].rstrip('/')}/.well-known/jwks.json"
                with urllib.request.urlopen(jwks_url, timeout=10, context=ctx) as r:
                    jwks = json.loads(r.read().decode())
                claims = _jose_jwt.decode(  # type: ignore
                    id_tok, jwks,
                    audience=cfg["client_id"],
                    issuer=cfg["issuer"].rstrip("/"),
                    options={"verify_at_hash": False},
                )
            except Exception as ve:
                return {"ok": False, "error": f"id_token verify failed: {ve}"}
            return {
                "ok": True,
                "email": claims.get(cfg.get("claim_email", "email"), ""),
                "role":  claims.get(cfg.get("claim_role", "role"), "vm-user"),
                "claims": claims,
                "verified": True,
            }
        if _allow_unverified():
            # Dev-only: decode without verifying. Caller is logged.
            payload = id_tok.split(".")[1]
            payload += "=" * (4 - len(payload) % 4)
            claims  = json.loads(base64.urlsafe_b64decode(payload))
            return {
                "ok": True,
                "email": claims.get(cfg.get("claim_email", "email"), ""),
                "role":  claims.get(cfg.get("claim_role", "role"), "vm-user"),
                "claims": claims,
                "verified": False,
                "warning": "id_token signature NOT verified (dev override)",
            }
        return {"ok": False,
                "error": "OIDC signature verification unavailable — "
                         "install python-jose or set OXWARE_ALLOW_UNVERIFIED_SSO=1 (dev only)"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def map_role(idp_role: str) -> str:
    """Map IdP role string to OXware internal role."""
    rmap = _load().get("role_map", {})
    return rmap.get(idp_role, "vm-user")


def is_sso_enabled() -> bool:
    d = _load()
    return d.get("saml", {}).get("enabled") or d.get("oidc", {}).get("enabled")
