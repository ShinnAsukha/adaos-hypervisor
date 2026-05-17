"""OXware VM Notes Manager — /var/lib/oxware/vm_notes.json"""
import json, threading
from pathlib import Path
from datetime import datetime

_NOTES_FILE = "/var/lib/oxware/vm_notes.json"
_lock = threading.Lock()

def _load():
    try:
        p = Path(_NOTES_FILE)
        if p.exists(): return json.loads(p.read_text())
    except Exception: pass
    return {}

def _save(data):
    Path(_NOTES_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(_NOTES_FILE).write_text(json.dumps(data, indent=2))

def get_note(vm_id):
    with _lock: return _load().get(str(vm_id))

def save_note(vm_id, content):
    content = str(content)[:10000]
    entry = {"content": content, "updated_at": datetime.now().isoformat()}
    with _lock:
        d = _load(); d[str(vm_id)] = entry; _save(d)
    return entry

def delete_note(vm_id):
    with _lock:
        d = _load(); d.pop(str(vm_id), None); _save(d)
