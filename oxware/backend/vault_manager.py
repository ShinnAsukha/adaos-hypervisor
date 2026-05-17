"""OXware Credential Vault — Fernet-encrypted VM credentials"""
import json, os, threading, base64, logging
from pathlib import Path
from datetime import datetime

log = logging.getLogger("vault_manager")
_KEY_FILE  = "/etc/oxware/vault.key"
_DATA_FILE = "/var/lib/oxware/vault.json"
_lock = threading.Lock()
CRED_TYPES = ["root", "ssh_key", "web", "custom"]

def _get_key():
    kp = Path(_KEY_FILE)
    if kp.exists():
        return kp.read_bytes()
    key = base64.urlsafe_b64encode(os.urandom(32))
    kp.parent.mkdir(parents=True, exist_ok=True)
    kp.write_bytes(key)
    os.chmod(_KEY_FILE, 0o600)
    return key

def _encrypt(data: str) -> str:
    try:
        from cryptography.fernet import Fernet
        f = Fernet(_get_key())
        return f.encrypt(data.encode()).decode()
    except Exception:
        return base64.b64encode(data.encode()).decode()

def _decrypt(token: str) -> str:
    try:
        from cryptography.fernet import Fernet
        f = Fernet(_get_key())
        return f.decrypt(token.encode()).decode()
    except Exception:
        try: return base64.b64decode(token.encode()).decode()
        except Exception: return ""

def _load():
    try:
        p = Path(_DATA_FILE)
        if p.exists(): return json.loads(p.read_text())
    except Exception: pass
    return {}

def _save(data):
    Path(_DATA_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(_DATA_FILE).write_text(json.dumps(data, indent=2))
    os.chmod(_DATA_FILE, 0o600)

def store_credential(vm_id, cred_type, username, password, notes=""):
    if cred_type not in CRED_TYPES: raise ValueError(f"Invalid cred_type: {cred_type}")
    enc = _encrypt(password)
    entry = {"username": username, "password_enc": enc,
             "notes": str(notes)[:500], "updated_at": datetime.now().isoformat()}
    with _lock:
        d = _load()
        if str(vm_id) not in d: d[str(vm_id)] = {}
        d[str(vm_id)][cred_type] = entry; _save(d)

def get_credential(vm_id, cred_type):
    with _lock:
        e = _load().get(str(vm_id), {}).get(cred_type)
    if not e: return None
    return {"cred_type": cred_type, "username": e["username"],
            "password": _decrypt(e["password_enc"]),
            "notes": e.get("notes", ""), "updated_at": e.get("updated_at", "")}

def list_credentials(vm_id):
    with _lock:
        creds = _load().get(str(vm_id), {})
    return [{"cred_type": ct, "username": v["username"],
             "notes": v.get("notes", ""), "updated_at": v.get("updated_at", "")}
            for ct, v in creds.items()]

def delete_credential(vm_id, cred_type):
    with _lock:
        d = _load()
        if str(vm_id) in d: d[str(vm_id)].pop(cred_type, None); _save(d)

def list_all():
    with _lock: raw = _load()
    return {vm_id: [{"cred_type": ct, "username": v["username"],
                     "updated_at": v.get("updated_at", "")}
                    for ct, v in creds.items()]
            for vm_id, creds in raw.items()}
