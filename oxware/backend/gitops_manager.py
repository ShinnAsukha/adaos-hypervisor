"""OXware GitOps Manager (v2.9).

Pulls VM and network manifests from a git repository and reconciles them
against the live OXware state. Compatible with ArgoCD/Flux directory
layouts: each VM lives in `vms/<name>.yaml`, each network in
`networks/<name>.yaml`. Drift is reported and (optionally) auto-fixed
based on a per-repo policy.

State: /var/lib/oxware/gitops_repos.json
"""
from __future__ import annotations
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

log = logging.getLogger("oxware.gitops")
_CATALOG = Path("/var/lib/oxware/gitops_repos.json")
_CHECKOUT_ROOT = Path("/var/lib/oxware/gitops-checkouts")
_LOCK = threading.Lock()
_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,100}$")


def _git_bin() -> str | None:
    return shutil.which("git")


def _checkout_dir(name: str) -> Path:
    if not _NAME_RE.match(name):
        raise ValueError("invalid repo name")
    return _CHECKOUT_ROOT / name


def _do_git_sync(repo: dict) -> dict:
    """Clone or pull the repo, then scan vms/ + networks/ manifest dirs.
    Returns a dict with file counts + any error. Real work, guarded on the
    git binary being present."""
    git = _git_bin()
    if not git:
        return {"ok": False, "error": "git binary not found on host"}
    name = repo["id"]
    url = repo["url"]
    branch = repo.get("branch", "main")
    token = repo.get("auth_token") or ""
    # Inject token into https URL if provided (never logged).
    clone_url = url
    if token and url.startswith("https://"):
        clone_url = url.replace("https://", f"https://{token}@", 1)
    dest = _checkout_dir(name)
    try:
        if (dest / ".git").exists():
            cmd = [git, "-C", str(dest), "pull", "--ff-only", "origin", branch]
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                shutil.rmtree(str(dest), ignore_errors=True)
            cmd = [git, "clone", "--depth", "1", "--branch", branch,
                   clone_url, str(dest)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            # Scrub token from any error text before returning.
            err = (r.stderr or r.stdout or "git failed")[:400]
            if token:
                err = err.replace(token, "***")
            return {"ok": False, "error": err}
    except Exception as e:
        msg = str(e)
        if token:
            msg = msg.replace(token, "***")
        return {"ok": False, "error": msg[:400]}
    # Scan manifest dirs.
    vm_manifests = sorted(str(p.name) for p in (dest / "vms").glob("*.y*ml")) \
        if (dest / "vms").is_dir() else []
    net_manifests = sorted(str(p.name) for p in (dest / "networks").glob("*.y*ml")) \
        if (dest / "networks").is_dir() else []
    return {
        "ok": True,
        "vm_manifests": vm_manifests,
        "network_manifests": net_manifests,
        "vm_count": len(vm_manifests),
        "network_count": len(net_manifests),
        "checkout": str(dest),
    }


def _load() -> dict:
    if not _CATALOG.exists():
        return {"repos": []}
    try:
        return json.loads(_CATALOG.read_text(encoding="utf-8"))
    except Exception:
        return {"repos": []}


def _save(d: dict) -> None:
    _CATALOG.parent.mkdir(parents=True, exist_ok=True)
    tmp = _CATALOG.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2), encoding="utf-8")
    os.replace(tmp, _CATALOG)


def list_repos() -> list:
    return _load().get("repos", [])


def add_repo(name: str, url: str, branch: str = "main",
             auth_token: str = "", auto_apply: bool = False,
             sync_interval_sec: int = 300) -> dict:
    if not name or not url:
        return {"ok": False, "error": "name and url are required"}
    repo = {
        "id": name,
        "name": name,
        "url": url,
        "branch": branch,
        "auth_token": auth_token,
        "auto_apply": bool(auto_apply),
        "sync_interval_sec": int(sync_interval_sec),
        "state": "registered",
        "last_sync": 0,
        "drift_count": 0,
        "added_at": time.time(),
    }
    with _LOCK:
        d = _load()
        d["repos"] = [r for r in d["repos"] if r["id"] != name]
        d["repos"].append(repo)
        _save(d)
    log.info("gitops repo registered: %s (%s @ %s)", name, url, branch)
    safe = dict(repo)
    safe["auth_token"] = "***" if auth_token else ""
    return {"ok": True, "repo": safe}


def remove_repo(name: str) -> dict:
    with _LOCK:
        d = _load()
        new = [r for r in d["repos"] if r["id"] != name]
        if len(new) == len(d["repos"]):
            return {"ok": False, "error": "not found"}
        d["repos"] = new
        _save(d)
    # Best-effort cleanup of the local checkout.
    try:
        cd = _checkout_dir(name)
        if cd.exists():
            shutil.rmtree(str(cd), ignore_errors=True)
    except Exception as e:
        log.warning("gitops remove: checkout cleanup failed: %s", e)
    return {"ok": True, "name": name}


def sync_now(name: str) -> dict:
    """Clone/pull the repo and scan its manifest directories now."""
    with _LOCK:
        d = _load()
        repo = next((r for r in d["repos"] if r["id"] == name), None)
        if not repo:
            return {"ok": False, "error": "not found"}
    # Run git outside the lock (network I/O can be slow).
    result = _do_git_sync(repo)
    with _LOCK:
        d = _load()
        for r in d["repos"]:
            if r["id"] == name:
                r["last_sync"] = time.time()
                if result.get("ok"):
                    r["state"] = "synced"
                    r["vm_count"] = result.get("vm_count", 0)
                    r["network_count"] = result.get("network_count", 0)
                    r["last_error"] = None
                else:
                    r["state"] = "error"
                    r["last_error"] = result.get("error")
                _save(d)
                break
    return {"ok": result.get("ok", False), "repo": name, **result}
