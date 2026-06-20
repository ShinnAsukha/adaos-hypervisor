# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). This copyright notice and the
# LICENSE text must be retained in copies/forks per the MIT terms.
"""OXware brand-integrity / provenance check.

PURPOSE — tamper-evidence and forensic proof of origin, NOT unbreakable DRM.
The source is open (MIT), so any determined party can read and strip these
checks. What this gives you instead:

  1. A hidden, encrypted **provenance token** that decrypts to the original
     author identity. Whoever forks and rebrands has to find AND remove every
     copy; if they miss one, `fingerprint()` proves the code is yours.
  2. A startup **integrity check** that detects the common theft pattern —
     copyright stripped from LICENSE, repo URL swapped, the provenance canary
     deleted — and records a warning (and, in strict mode, can refuse to run).

This is deterrence + evidence. It raises the effort/visibility of a sloppy
"fork + rename + ship" without pretending to be impossible to bypass.

Modes (env OXWARE_BRAND_MODE): "warn" (default — log + banner), "strict"
(also returns block=True so the host can refuse to start), "off".
"""
from __future__ import annotations
import base64
import hashlib
import json
import logging
import os
from pathlib import Path

log = logging.getLogger("oxware.brand")

# Canonical identity. The provenance token below is the signed, encrypted
# form of this — changing these strings does not change the token.
CANON = {
    "p": "OXware Hypervisor",
    "a": "Ada Gursoy",
    "r": "https://github.com/ShinnAsukha/oxware-hypervisor",
    "y": 2026,
}

# Encrypted provenance token (Fernet). Decrypts to CANON. Do not edit.
_TOKEN = (
    "gAAAAABqNlv_94hddTqShjBaDsBIj9a7njAlfIZLvlI4DVogTS1yPPD7e2Di-kazLTzgKA7"
    "eEz5udBbBMWtIW0l6zH5dTn7XwGcMqYBeVdsu4qwjma8EYZKi5cj2addYn4Q4PpyLM3apm_"
    "xHF_DM6qd3Y8NGN2Ge-kwNntNExsaTX2XZEdTSCaW5laTU1XANOkWr-wjgrV1r0N07lpl4I"
    "m1VEqRg7R7UPZ-NpOPd7bTKiUxoUPTsUA4="
)

# Stable forensic id (sha256 of the token, first 16 hex). Keep this somewhere
# safe off-repo; it lets you prove a stranger's binary embeds your code even
# after a rebrand, as long as any token copy survives.
FINGERPRINT = hashlib.sha256(_TOKEN.encode()).hexdigest()[:16]

_PASS = b"OXware::Ada-Gursoy::provenance::v1::do-not-remove"


def _fernet():
    try:
        from cryptography.fernet import Fernet
    except Exception:
        return None
    key = base64.urlsafe_b64encode(hashlib.sha256(_PASS).digest())
    return Fernet(key)


def _decrypt(tok: str) -> dict | None:
    f = _fernet()
    if not f or not tok:
        return None
    try:
        return json.loads(f.decrypt(tok.encode()).decode())
    except Exception:
        return None


# Extra copies of the token are stashed across innocuous-looking modules
# under misleading names. A rebrander has to find and strip ALL of them; miss
# one and the mismatch (or its survival) proves origin.
_CANARY_SOURCES = [
    ("config", "_BUILD_PROVENANCE"),
    ("system_monitor", "_METRICS_SALT"),
    ("event_logger", "_LOG_SIGNATURE"),
    ("notifications", "_DELIVERY_KEY"),
]


def _canaries() -> tuple[list, list]:
    """Returns (intact, broken) canary names."""
    intact, broken = [], []
    for mod, attr in _CANARY_SOURCES:
        val = None
        try:
            m = __import__(mod)
            val = getattr(m, attr, None)
        except Exception:
            try:
                m = __import__(f"oxware.backend.{mod}", fromlist=["*"])
                val = getattr(m, attr, None)
            except Exception:
                val = None
        if val is None:
            broken.append(f"{mod}.{attr} (kaldırılmış)")
        elif val != _TOKEN:
            broken.append(f"{mod}.{attr} (değiştirilmiş)")
        else:
            intact.append(f"{mod}.{attr}")
    return intact, broken


def _license_has_author() -> bool:
    for p in ("LICENSE", "LICENSE.txt", "LICENSE.md",
              os.path.join(os.path.dirname(__file__), "..", "..", "LICENSE")):
        try:
            t = Path(p).read_text(encoding="utf-8", errors="ignore")
            if "Ada Gürsoy" in t or "Ada Gursoy" in t:
                return True
        except Exception:
            continue
    return False


def verify() -> dict:
    res = {
        "authentic": False, "rebranded": False, "attribution_removed": False,
        "tampered": False, "fingerprint": FINGERPRINT,
        "product": CANON["p"], "author": CANON["a"], "warnings": [],
    }
    marker = _decrypt(_TOKEN)
    if marker and marker.get("a") == CANON["a"]:
        res["authentic"] = True
    elif marker is None and _fernet() is None:
        # crypto not installed — cannot judge; do not raise a false alarm.
        res["warnings"].append("cryptography yok — provenance doğrulanamadı")
        res["authentic"] = True
    else:
        res["tampered"] = True
        res["warnings"].append("provenance token doğrulanamadı/değiştirilmiş")

    intact, broken = _canaries()
    res["canaries_intact"] = len(intact)
    res["canaries_total"] = len(_CANARY_SOURCES)
    if broken:
        res["warnings"].append("provenance canary'leri: " + ", ".join(broken))
    # Tampered if more canaries are broken than intact (some were stripped).
    if len(broken) > len(intact):
        res["tampered"] = True

    if not _license_has_author():
        res["attribution_removed"] = True
        res["warnings"].append("LICENSE telif sahibi (Ada Gürsoy) kaldırılmış — MIT ihlali")

    try:
        import config
        repos = getattr(config, "UPDATE_ALLOWED_REPOS", []) or []
        if repos and not any("ShinnAsukha/oxware-hypervisor" in r for r in repos):
            res["rebranded"] = True
            res["warnings"].append("repo URL değiştirilmiş")
    except Exception:
        pass

    res["ok"] = (res["authentic"] and not res["tampered"]
                 and not res["attribution_removed"])
    return res


def enforce() -> dict:
    """Run at startup. Returns the verdict; honors OXWARE_BRAND_MODE.
    Never destroys anything — at most signals block=True in strict mode."""
    mode = (os.environ.get("OXWARE_BRAND_MODE", "warn") or "warn").lower()
    if mode == "off":
        return {"mode": "off", "block": False, "ok": True, "warnings": []}
    v = verify()
    block = (mode == "strict") and not v["ok"]
    if v["warnings"]:
        log.warning("Brand integrity uyarısı [%s]: %s | fingerprint=%s",
                    mode, "; ".join(v["warnings"]), FINGERPRINT)
    if block:
        log.critical("Brand integrity STRICT: doğrulama başarısız, başlatma "
                     "engellendi. OXWARE_BRAND_MODE=warn ile uyarıya çevirin.")
    return {"mode": mode, "block": block, **v}


def fingerprint() -> str:
    return FINGERPRINT
