"""
OXware VM Lifecycle Hook Manager
Executes local bash scripts at VM lifecycle events.

Hook dirs: /etc/oxware/hooks/{pre-start,post-start,pre-stop,post-stop,pre-delete,post-delete}/
All .sh files in the dir are executed in alphabetical order.
Scripts receive: VM_ID, VM_NAME, VM_STATE as environment variables.
Timeout: 30 seconds per script.
Output logged to /var/log/oxware/hooks.log
"""

import os
import re
import stat
import subprocess
import logging
from datetime import datetime

log = logging.getLogger("oxware.hooks")

HOOKS_BASE_DIR = "/etc/oxware/hooks"
HOOKS_LOG_FILE = "/var/log/oxware/hooks.log"

EVENTS = [
    "pre-start",
    "post-start",
    "pre-stop",
    "post-stop",
    "pre-delete",
    "post-delete",
]

# Allowed script names: alphanumeric, dash, underscore, must end with .sh
_NAME_RE = re.compile(r'^[a-zA-Z0-9_\-]+\.sh$')


def _validate_event(event: str):
    if event not in EVENTS:
        raise ValueError(f"Geçersiz olay: '{event}'. Geçerli olaylar: {EVENTS}")


def _validate_name(name: str):
    if not _NAME_RE.match(name):
        raise ValueError(
            f"Geçersiz script adı: '{name}'. "
            "Sadece harf, rakam, tire ve alt çizgi kullanılabilir ve .sh uzantısı zorunludur."
        )


def _hook_dir(event: str) -> str:
    return os.path.join(HOOKS_BASE_DIR, event)


def _ensure_dirs():
    """Create all hook directories if they don't exist."""
    for event in EVENTS:
        d = _hook_dir(event)
        try:
            os.makedirs(d, exist_ok=True)
        except Exception as e:
            log.warning("Hook dizini oluşturulamadı: %s — %s", d, e)


def _log_hook_output(event: str, script: str, vm_id: str, stdout: str, stderr: str,
                     returncode: int):
    """Append hook execution results to the hooks log file."""
    try:
        os.makedirs(os.path.dirname(HOOKS_LOG_FILE), exist_ok=True)
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        lines = [
            f"[{ts}] EVENT={event} SCRIPT={script} VM_ID={vm_id} RC={returncode}",
        ]
        if stdout.strip():
            for ln in stdout.strip().splitlines():
                lines.append(f"  STDOUT: {ln}")
        if stderr.strip():
            for ln in stderr.strip().splitlines():
                lines.append(f"  STDERR: {ln}")
        with open(HOOKS_LOG_FILE, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        log.warning("Hook log yazılamadı: %s", e)


def run_hooks(event: str, vm_id: str, vm_name: str, extra_env: dict = None) -> list:
    """
    Execute all .sh scripts in /etc/oxware/hooks/{event}/ in alphabetical order.
    Passes VM_ID, VM_NAME, VM_STATE as environment variables.
    Each script has a 30-second timeout.
    Results are logged to /var/log/oxware/hooks.log.

    Returns a list of dicts with per-script results.
    """
    _validate_event(event)
    _ensure_dirs()

    hook_dir = _hook_dir(event)
    results = []

    try:
        entries = sorted(
            f for f in os.listdir(hook_dir)
            if f.endswith(".sh") and os.path.isfile(os.path.join(hook_dir, f))
        )
    except Exception as e:
        log.warning("Hook dizini okunamadı %s: %s", hook_dir, e)
        return results

    if not entries:
        return results

    env = os.environ.copy()
    env["VM_ID"] = str(vm_id)
    env["VM_NAME"] = str(vm_name)
    env["VM_STATE"] = event
    if extra_env:
        env.update({str(k): str(v) for k, v in extra_env.items()})

    for script_name in entries:
        script_path = os.path.join(hook_dir, script_name)
        try:
            proc = subprocess.run(
                ["/bin/bash", script_path],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            stdout = ""
            stderr = "Hook zaman aşımına uğradı (30s)"
            rc = -1
            log.warning("Hook zaman aşımı: %s (event=%s, vm=%s)", script_path, event, vm_id)
        except Exception as e:
            stdout = ""
            stderr = str(e)
            rc = -1
            log.warning("Hook çalıştırma hatası: %s — %s", script_path, e)

        _log_hook_output(event, script_name, vm_id, stdout, stderr, rc)

        if rc != 0:
            log.warning(
                "Hook başarısız: %s (rc=%d, event=%s, vm=%s)", script_path, rc, event, vm_id
            )
        else:
            log.debug("Hook tamamlandı: %s (event=%s, vm=%s)", script_path, event, vm_id)

        results.append({
            "script": script_name,
            "returncode": rc,
            "stdout": stdout,
            "stderr": stderr,
        })

    return results


def list_hooks() -> dict:
    """
    Returns a dict mapping each event to a list of script info dicts:
      {name, path, size, executable}
    """
    _ensure_dirs()
    result = {}
    for event in EVENTS:
        hook_dir = _hook_dir(event)
        scripts = []
        try:
            for fname in sorted(os.listdir(hook_dir)):
                if not fname.endswith(".sh"):
                    continue
                fpath = os.path.join(hook_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                st = os.stat(fpath)
                executable = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                scripts.append({
                    "name": fname,
                    "path": fpath,
                    "size": st.st_size,
                    "executable": executable,
                })
        except Exception as e:
            log.warning("Hook listesi alınamadı (%s): %s", event, e)
        result[event] = scripts
    return result


def get_hook(event: str, name: str) -> str | None:
    """
    Returns the content of the named script for the given event.
    Returns None if the file does not exist.
    """
    _validate_event(event)
    _validate_name(name)
    path = os.path.join(_hook_dir(event), name)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        log.warning("Hook okunamadı %s: %s", path, e)
        return None


def save_hook(event: str, name: str, content: str) -> str:
    """
    Writes content to /etc/oxware/hooks/{event}/{name}.
    Creates the directory if needed and sets the file executable.
    Returns the absolute path of the saved script.
    """
    _validate_event(event)
    _validate_name(name)
    hook_dir = _hook_dir(event)
    os.makedirs(hook_dir, exist_ok=True)
    path = os.path.join(hook_dir, name)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    # chmod +x
    current = os.stat(path).st_mode
    os.chmod(
        path,
        current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH,
    )
    log.info("Hook kaydedildi: %s", path)
    return path


def delete_hook(event: str, name: str) -> bool:
    """
    Deletes the named script for the given event.
    Returns True if deleted, False if not found.
    """
    _validate_event(event)
    _validate_name(name)
    path = os.path.join(_hook_dir(event), name)
    if not os.path.isfile(path):
        return False
    os.remove(path)
    log.info("Hook silindi: %s", path)
    return True
