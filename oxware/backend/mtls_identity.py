# OXware Hypervisor — Copyright (c) 2026 Ada Gürsoy.
# Licensed under the MIT License (see LICENSE). Retain this notice in forks.
"""OXware federation mTLS identity.

Issues a private CA and per-node certificates so federation members can
authenticate each other with mutual TLS instead of a shared bearer token.
Real x509 via `cryptography` (already a dependency). Verifying a peer cert
proves it was signed by THIS cluster's CA.

State: /var/lib/oxware/mtls/  (ca.key 0600, ca.crt, nodes/<name>.{key,crt})
"""
from __future__ import annotations
import datetime
import hashlib
import logging
import os
import re
from pathlib import Path

log = logging.getLogger("oxware.mtls")
_DIR = Path("/var/lib/oxware/mtls")
_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")


def _crypto():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        return x509, hashes, serialization, rsa, NameOID
    except Exception:
        return None


def available() -> bool:
    return _crypto() is not None


def _ca_paths():
    return _DIR / "ca.key", _DIR / "ca.crt"


def ensure_ca() -> dict:
    c = _crypto()
    if not c:
        return {"ok": False, "error": "cryptography yok"}
    x509, hashes, serialization, rsa, NameOID = c
    key_p, crt_p = _ca_paths()
    if key_p.exists() and crt_p.exists():
        return {"ok": True, "created": False, "fingerprint": ca_fingerprint()}
    _DIR.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OXware Federation CA"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OXware")])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    key_p.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    os.chmod(key_p, 0o600)
    crt_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    log.info("mTLS CA oluşturuldu")
    return {"ok": True, "created": True, "fingerprint": ca_fingerprint()}


def ca_fingerprint() -> str:
    _, crt_p = _ca_paths()
    if not crt_p.exists():
        return ""
    return hashlib.sha256(crt_p.read_bytes()).hexdigest()[:32]


def issue_node_cert(node_name: str) -> dict:
    if not _NAME_RE.match(node_name or ""):
        return {"ok": False, "error": "geçersiz node adı"}
    c = _crypto()
    if not c:
        return {"ok": False, "error": "cryptography yok"}
    ca = ensure_ca()
    if not ca.get("ok"):
        return ca
    x509, hashes, serialization, rsa, NameOID = c
    key_p, crt_p = _ca_paths()
    ca_key = serialization.load_pem_private_key(key_p.read_bytes(), password=None)
    ca_crt = x509.load_pem_x509_certificate(crt_p.read_bytes())
    nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_name),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OXware")])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(subj).issuer_name(ca_crt.subject)
            .public_key(nkey.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))
    nd = _DIR / "nodes"
    nd.mkdir(parents=True, exist_ok=True)
    kp, cp = nd / f"{node_name}.key", nd / f"{node_name}.crt"
    key_pem = nkey.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    crt_pem = cert.public_bytes(serialization.Encoding.PEM)
    kp.write_bytes(key_pem); os.chmod(kp, 0o600)
    cp.write_bytes(crt_pem)
    return {"ok": True, "node": node_name,
            "cert_pem": crt_pem.decode(), "key_pem": key_pem.decode(),
            "ca_pem": crt_p.read_text(), "ca_fingerprint": ca_fingerprint()}


def list_nodes() -> list:
    nd = _DIR / "nodes"
    if not nd.is_dir():
        return []
    return sorted(p.stem for p in nd.glob("*.crt"))


def verify_peer(cert_pem: str) -> dict:
    c = _crypto()
    if not c:
        return {"ok": False, "error": "cryptography yok"}
    x509, hashes, serialization, rsa, NameOID = c
    _, crt_p = _ca_paths()
    if not crt_p.exists():
        return {"ok": False, "error": "CA yok"}
    try:
        ca_crt = x509.load_pem_x509_certificate(crt_p.read_bytes())
        peer = x509.load_pem_x509_certificate(cert_pem.encode())
        ca_crt.public_key().verify(
            peer.signature, peer.tbs_certificate_bytes,
            __import__("cryptography").hazmat.primitives.asymmetric.padding.PKCS1v15(),
            peer.signature_hash_algorithm)
        cn = peer.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        # Prefer tz-aware *_utc accessors (newer cryptography); fall back.
        nb = getattr(peer, "not_valid_before_utc", None) or peer.not_valid_before
        na = getattr(peer, "not_valid_after_utc", None) or peer.not_valid_after
        now = datetime.datetime.now(getattr(nb, "tzinfo", None))
        valid = nb <= now <= na
        return {"ok": True, "trusted": True, "cn": cn, "valid_dates": valid}
    except Exception as e:
        return {"ok": True, "trusted": False, "error": str(e)[:160]}
