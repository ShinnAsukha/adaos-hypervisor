"""
haproxy_manager.py — HAProxy load balancer management
OXware Hypervisor backend module
"""

import subprocess
import json
import logging
import os
import threading
import socket
import re

log = logging.getLogger("oxware.haproxy")

CONFIG_PATH    = "/etc/haproxy/haproxy.cfg"
STATS_SOCKET   = "/var/run/haproxy/admin.sock"
BACKENDS_FILE  = "/var/lib/oxware/haproxy_backends.json"

_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_status():
    """
    Return HAProxy service status.

    Returns:
        dict: active, version, config_ok
    """
    active    = False
    version   = None
    config_ok = False

    try:
        r = subprocess.run(
            ["systemctl", "is-active", "haproxy"],
            capture_output=True, text=True, timeout=10
        )
        active = r.stdout.strip() == "active"
    except Exception as exc:
        log.warning("systemctl is-active haproxy failed: %s", exc)

    try:
        r = subprocess.run(
            ["haproxy", "-v"],
            capture_output=True, text=True, timeout=10
        )
        m = re.search(r"HA-?Proxy version (\S+)", r.stdout + r.stderr, re.IGNORECASE)
        if m:
            version = m.group(1)
    except Exception as exc:
        log.warning("haproxy -v failed: %s", exc)

    try:
        r = subprocess.run(
            ["haproxy", "-c", "-f", CONFIG_PATH],
            capture_output=True, text=True, timeout=10
        )
        config_ok = r.returncode == 0
    except Exception as exc:
        log.warning("haproxy config check failed: %s", exc)

    return {"active": active, "version": version, "config_ok": config_ok}


# ---------------------------------------------------------------------------
# Stats via UNIX socket
# ---------------------------------------------------------------------------

def get_stats():
    """
    Retrieve HAProxy stats via the stats socket (CSV format).

    Returns:
        list[dict]: pxname, svname, status, rate, scur (and more)
    """
    raw = _stats_cmd("show stat\n")
    if raw is None:
        return []

    lines  = [l for l in raw.splitlines() if l and not l.startswith("#")]
    header = []
    result = []

    for line in raw.splitlines():
        if line.startswith("#"):
            header = [h.strip("# \r") for h in line.split(",")]
            break

    for line in lines:
        parts = line.split(",")
        entry = {}
        for i, key in enumerate(header):
            entry[key] = parts[i] if i < len(parts) else ""
        result.append({
            "pxname": entry.get("pxname", ""),
            "svname": entry.get("svname", ""),
            "status": entry.get("status", ""),
            "rate":   entry.get("rate", ""),
            "scur":   entry.get("scur", ""),
            "_raw":   entry,
        })
    return result


def _stats_cmd(cmd):
    """Send *cmd* to the HAProxy stats socket and return the response."""
    if not os.path.exists(STATS_SOCKET):
        log.warning("HAProxy stats socket not found: %s", STATS_SOCKET)
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect(STATS_SOCKET)
            s.sendall(cmd.encode())
            chunks = []
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks).decode(errors="replace")
    except Exception as exc:
        log.error("_stats_cmd error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------

def _parse_config():
    """
    Parse HAProxy config file into frontends and backends dicts.

    Returns:
        dict: {"frontends": [...], "backends": [...], "global": str, "defaults": str}
    """
    if not os.path.isfile(CONFIG_PATH):
        return {"frontends": [], "backends": [], "global": "", "defaults": ""}

    try:
        with open(CONFIG_PATH) as f:
            content = f.read()
    except Exception as exc:
        log.error("_parse_config read error: %s", exc)
        return {"frontends": [], "backends": [], "global": "", "defaults": ""}

    frontends = []
    backends  = []
    global_lines   = []
    defaults_lines = []

    current_section = None
    current_name    = None
    current_lines   = []

    def _flush():
        nonlocal current_section, current_name, current_lines
        if current_section == "frontend" and current_name:
            frontends.append({"name": current_name, "lines": current_lines[:]})
        elif current_section == "backend" and current_name:
            servers = []
            for ln in current_lines:
                m = re.match(
                    r"\s*server\s+(\S+)\s+(\S+):(\d+)(.*)", ln)
                if m:
                    servers.append({
                        "name":   m.group(1),
                        "host":   m.group(2),
                        "port":   int(m.group(3)),
                        "params": m.group(4).strip(),
                    })
            backends.append({
                "name":    current_name,
                "lines":   current_lines[:],
                "servers": servers,
            })
        current_section = None
        current_name    = None
        current_lines   = []

    for line in content.splitlines():
        stripped = line.strip()
        m_fe = re.match(r"^frontend\s+(\S+)", stripped)
        m_be = re.match(r"^backend\s+(\S+)", stripped)
        m_gl = re.match(r"^global\b", stripped)
        m_df = re.match(r"^defaults\b", stripped)

        if m_fe or m_be or m_gl or m_df:
            _flush()
            if m_fe:
                current_section = "frontend"
                current_name    = m_fe.group(1)
            elif m_be:
                current_section = "backend"
                current_name    = m_be.group(1)
            elif m_gl:
                current_section = "global"
            elif m_df:
                current_section = "defaults"
        elif current_section in ("global", "defaults"):
            if current_section == "global":
                global_lines.append(line)
            else:
                defaults_lines.append(line)
        elif current_section in ("frontend", "backend"):
            current_lines.append(line)

    _flush()
    return {
        "frontends": frontends,
        "backends":  backends,
        "global":    "\n".join(global_lines),
        "defaults":  "\n".join(defaults_lines),
    }


def list_frontends():
    """Return parsed frontend configurations."""
    return _parse_config()["frontends"]


def list_backends():
    """Return parsed backend configurations including server lists."""
    return _parse_config()["backends"]


# ---------------------------------------------------------------------------
# Config writing
# ---------------------------------------------------------------------------

def _write_config(frontends, backends, global_section="", defaults_section=""):
    """
    Re-serialise frontends + backends into haproxy.cfg.

    *frontends* and *backends* are lists of dicts as produced by
    :func:`_parse_config`.
    """
    lines = []

    if global_section:
        lines.append("global")
        lines.append(global_section)
        lines.append("")
    if defaults_section:
        lines.append("defaults")
        lines.append(defaults_section)
        lines.append("")

    for fe in frontends:
        lines.append(f"frontend {fe['name']}")
        lines.extend(fe.get("lines", []))
        lines.append("")

    for be in backends:
        lines.append(f"backend {be['name']}")
        for ln in be.get("lines", []):
            # Skip raw server lines — regenerate from structured data
            if re.match(r"\s*server\s+", ln):
                continue
            lines.append(ln)
        for srv in be.get("servers", []):
            params = srv.get("params", "")
            lines.append(
                f"    server {srv['name']} {srv['host']}:{srv['port']} {params}".rstrip()
            )
        lines.append("")

    config_text = "\n".join(lines)
    backup_path = CONFIG_PATH + ".bak"
    try:
        if os.path.isfile(CONFIG_PATH):
            import shutil
            shutil.copy2(CONFIG_PATH, backup_path)
        with _lock:
            with open(CONFIG_PATH, "w") as f:
                f.write(config_text)
        log.info("haproxy config written to %s", CONFIG_PATH)
        return True
    except Exception as exc:
        log.exception("_write_config error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Frontend / Backend management
# ---------------------------------------------------------------------------

def create_frontend(name, bind_port, default_backend,
                    bind_ssl=False, ssl_cert=None):
    """Add a new frontend section to the config."""
    cfg = _parse_config()
    if any(fe["name"] == name for fe in cfg["frontends"]):
        return {"success": False, "message": f"Frontend '{name}' already exists"}

    bind_line = f"    bind *:{bind_port}"
    if bind_ssl and ssl_cert:
        bind_line += f" ssl crt {ssl_cert}"

    new_fe = {
        "name":  name,
        "lines": [
            bind_line,
            f"    default_backend {default_backend}",
        ],
    }
    cfg["frontends"].append(new_fe)
    ok = _write_config(cfg["frontends"], cfg["backends"],
                       cfg["global"], cfg["defaults"])
    return {"success": ok, "message": "Frontend created" if ok else "Write failed"}


def create_backend(name, algorithm="roundrobin",
                   health_check=True, check_interval=5000):
    """Add a new backend section to the config."""
    cfg = _parse_config()
    if any(be["name"] == name for be in cfg["backends"]):
        return {"success": False, "message": f"Backend '{name}' already exists"}

    lines = [f"    balance {algorithm}"]
    if health_check:
        lines.append(f"    option httpchk")
        lines.append(f"    default-server inter {check_interval}ms rise 2 fall 3")

    new_be = {"name": name, "lines": lines, "servers": []}
    cfg["backends"].append(new_be)
    ok = _write_config(cfg["frontends"], cfg["backends"],
                       cfg["global"], cfg["defaults"])
    return {"success": ok, "message": "Backend created" if ok else "Write failed"}


def add_server(backend_name, server_name, host, port,
               weight=1, backup=False):
    """Add a server to an existing backend."""
    cfg = _parse_config()
    for be in cfg["backends"]:
        if be["name"] == backend_name:
            params = f"weight {weight}"
            if backup:
                params += " backup"
            be.setdefault("servers", []).append({
                "name":   server_name,
                "host":   host,
                "port":   port,
                "params": params,
            })
            ok = _write_config(cfg["frontends"], cfg["backends"],
                               cfg["global"], cfg["defaults"])
            return {"success": ok,
                    "message": f"Server '{server_name}' added to '{backend_name}'"
                               if ok else "Write failed"}
    return {"success": False, "message": f"Backend '{backend_name}' not found"}


def remove_server(backend_name, server_name):
    """Remove a server from a backend."""
    cfg = _parse_config()
    for be in cfg["backends"]:
        if be["name"] == backend_name:
            before = len(be.get("servers", []))
            be["servers"] = [s for s in be.get("servers", [])
                             if s["name"] != server_name]
            if len(be["servers"]) == before:
                return {"success": False,
                        "message": f"Server '{server_name}' not found in '{backend_name}'"}
            ok = _write_config(cfg["frontends"], cfg["backends"],
                               cfg["global"], cfg["defaults"])
            return {"success": ok,
                    "message": "Server removed" if ok else "Write failed"}
    return {"success": False, "message": f"Backend '{backend_name}' not found"}


def delete_backend(name):
    """Remove a backend section from the config."""
    cfg = _parse_config()
    before = len(cfg["backends"])
    cfg["backends"] = [be for be in cfg["backends"] if be["name"] != name]
    if len(cfg["backends"]) == before:
        return {"success": False, "message": f"Backend '{name}' not found"}
    ok = _write_config(cfg["frontends"], cfg["backends"],
                       cfg["global"], cfg["defaults"])
    return {"success": ok, "message": "Backend deleted" if ok else "Write failed"}


def delete_frontend(name):
    """Remove a frontend section from the config."""
    cfg = _parse_config()
    before = len(cfg["frontends"])
    cfg["frontends"] = [fe for fe in cfg["frontends"] if fe["name"] != name]
    if len(cfg["frontends"]) == before:
        return {"success": False, "message": f"Frontend '{name}' not found"}
    ok = _write_config(cfg["frontends"], cfg["backends"],
                       cfg["global"], cfg["defaults"])
    return {"success": ok, "message": "Frontend deleted" if ok else "Write failed"}


# ---------------------------------------------------------------------------
# Reload
# ---------------------------------------------------------------------------

def reload():
    """Validate config and reload HAProxy. Returns dict with success and output."""
    try:
        r = subprocess.run(
            ["haproxy", "-c", "-f", CONFIG_PATH],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode != 0:
            return {"success": False,
                    "output": (r.stdout + r.stderr).strip()}

        r2 = subprocess.run(
            ["systemctl", "reload", "haproxy"],
            capture_output=True, text=True, timeout=30
        )
        success = r2.returncode == 0
        output  = (r2.stdout + r2.stderr).strip()
        if success:
            log.info("haproxy reloaded")
        else:
            log.warning("haproxy reload failed: %s", output)
        return {"success": success, "output": output}
    except FileNotFoundError:
        return {"success": False, "output": "haproxy not found"}
    except Exception as exc:
        log.exception("reload error: %s", exc)
        return {"success": False, "output": str(exc)}
