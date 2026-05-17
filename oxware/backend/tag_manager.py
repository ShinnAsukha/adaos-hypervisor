"""OXware VM Tag Manager — stores tags in /var/lib/oxware/vm_tags.json"""
import json, os, threading
from pathlib import Path

_TAGS_FILE = "/var/lib/oxware/vm_tags.json"
_lock = threading.Lock()

def _load():
    try:
        p = Path(_TAGS_FILE)
        if p.exists(): return json.loads(p.read_text())
    except Exception: pass
    return {}

def _save(data):
    Path(_TAGS_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(_TAGS_FILE).write_text(json.dumps(data, indent=2))

def _normalize(tag): return tag.strip().lower()[:20]

def get_tags(vm_id):
    with _lock: return _load().get(str(vm_id), [])

def set_tags(vm_id, tags):
    tags = list(dict.fromkeys(_normalize(t) for t in tags if t.strip()))[:10]
    with _lock:
        d = _load(); d[str(vm_id)] = tags; _save(d)
    return tags

def add_tag(vm_id, tag):
    tag = _normalize(tag)
    if not tag: return []
    with _lock:
        d = _load()
        current = d.get(str(vm_id), [])
        if tag not in current and len(current) < 10: current.append(tag)
        d[str(vm_id)] = current; _save(d)
    return d[str(vm_id)]

def remove_tag(vm_id, tag):
    tag = _normalize(tag)
    with _lock:
        d = _load()
        d[str(vm_id)] = [t for t in d.get(str(vm_id), []) if t != tag]
        _save(d)

def get_all_tags():
    with _lock: return _load()

def get_vms_by_tag(tag):
    tag = _normalize(tag)
    with _lock:
        return [vid for vid, tags in _load().items() if tag in tags]

def delete_vm_tags(vm_id):
    with _lock:
        d = _load()
        d.pop(str(vm_id), None); _save(d)

def list_all_unique_tags():
    with _lock:
        all_tags = set()
        for tags in _load().values(): all_tags.update(tags)
    return sorted(all_tags)
