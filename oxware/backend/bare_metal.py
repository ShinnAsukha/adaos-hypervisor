"""
OXware Bare-Metal Provisioner
PXE + iPXE + cloud-init image builder for provisioning physical servers
into OXware hypervisor nodes.
PXE config: /var/lib/oxware/pxe/
TFTP root: /srv/tftp/oxware/
Auto-install profiles: /var/lib/oxware/autoinstall/
"""

import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

PXE_DIR = Path("/var/lib/oxware/pxe")
TFTP_ROOT = Path("/srv/tftp/oxware")
AUTOINSTALL_DIR = Path("/var/lib/oxware/autoinstall")
REGISTRATIONS_FILE = Path("/var/lib/oxware/pxe/registrations.json")
LOG_DIR = Path("/var/log/oxware")
AUDIT_LOG = LOG_DIR / "bare_metal.jsonl"


def _ensure_dirs():
    for d in (PXE_DIR, AUTOINSTALL_DIR, LOG_DIR):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            pass
    try:
        TFTP_ROOT.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError):
        pass


def _audit(action: str, **payload) -> None:
    _ensure_dirs()
    entry = {"ts": time.time(), "action": action, **payload}
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def _normalize_mac(mac: str) -> str:
    if not mac:
        raise ValueError("mac required")
    m = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(m) != 12:
        raise ValueError(f"invalid mac: {mac}")
    return ":".join(m[i:i + 2] for i in range(0, 12, 2))


def _load_registrations() -> dict:
    if not REGISTRATIONS_FILE.exists():
        return {}
    try:
        with open(REGISTRATIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_registrations(data: dict) -> None:
    _ensure_dirs()
    tmp = REGISTRATIONS_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, REGISTRATIONS_FILE)


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _udp_listening(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            return False
    except OSError:
        return True


def get_pxe_status() -> dict:
    return {
        "tftp_udp_69": _udp_listening(69),
        "http_80": _port_open("127.0.0.1", 80),
        "http_8080": _port_open("127.0.0.1", 8080),
        "dnsmasq_present": shutil.which("dnsmasq") is not None,
        "xorriso_present": shutil.which("xorriso") is not None,
        "tftp_root": str(TFTP_ROOT),
        "tftp_root_exists": TFTP_ROOT.exists(),
        "checked_at": time.time(),
    }


def setup_pxe_server() -> dict:
    _ensure_dirs()
    dnsmasq_conf = f"""# /etc/dnsmasq.d/oxware-pxe.conf
# OXware PXE / TFTP / proxyDHCP
port=0
interface=eth0
bind-interfaces
dhcp-range=192.168.50.100,192.168.50.200,12h
enable-tftp
tftp-root={TFTP_ROOT}
dhcp-boot=tag:!ipxe,undionly.kpxe
dhcp-boot=tag:ipxe,http://oxware/boot.ipxe
dhcp-match=set:ipxe,175
log-dhcp
log-queries
"""

    tftp_conf = """# /etc/default/tftpd-hpa
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="/srv/tftp/oxware"
TFTP_ADDRESS=":69"
TFTP_OPTIONS="--secure --create"
"""

    ipxe_default = """#!ipxe
:start
menu OXware Bare-Metal Installer
item --gap -- ---- Install Profiles ----
item default Default Ubuntu 24.04 Autoinstall
item shell   iPXE shell
choose --default default --timeout 10000 target && goto ${target}

:default
chain http://oxware/boot/default.ipxe

:shell
shell
"""

    files = {
        "/etc/dnsmasq.d/oxware-pxe.conf": dnsmasq_conf,
        "/etc/default/tftpd-hpa": tftp_conf,
        str(TFTP_ROOT / "boot.ipxe"): ipxe_default,
    }

    written = []
    for path, content in files.items():
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            written.append(path)
        except (OSError, PermissionError):
            pass

    _audit("setup_pxe", written=written)
    return {"files": files, "written": written, "ok": True}


def list_profiles() -> list:
    _ensure_dirs()
    out = []
    if not AUTOINSTALL_DIR.exists():
        return out
    for f in sorted(AUTOINSTALL_DIR.glob("*.yaml")):
        try:
            stat = f.stat()
            out.append({
                "name": f.stem,
                "path": str(f),
                "size": stat.st_size,
                "modified_at": stat.st_mtime,
            })
        except OSError:
            continue
    return out


def create_profile(name: str, hostname: str, disk_layout: str,
                   network: dict, ssh_keys: list, post_script: str) -> dict:
    if not re.match(r"^[a-zA-Z0-9_-]+$", name or ""):
        raise ValueError("profile name must be alphanumeric/_-")
    _ensure_dirs()

    keys_yaml = "\n".join(f"        - {k!r}" for k in (ssh_keys or [])) or "        []"
    net = network or {}
    dhcp = "true" if net.get("dhcp", True) else "false"
    iface = net.get("interface", "enp1s0")
    gateway = net.get("gateway", "")
    addresses = net.get("addresses", [])
    nameservers = net.get("nameservers", ["1.1.1.1", "8.8.8.8"])

    if dhcp == "true":
        net_block = f"""    network:
      version: 2
      ethernets:
        {iface}:
          dhcp4: true"""
    else:
        addrs_yaml = "\n".join(f"            - {a}" for a in addresses) or "            []"
        ns_yaml = ", ".join(f'"{n}"' for n in nameservers)
        net_block = f"""    network:
      version: 2
      ethernets:
        {iface}:
          dhcp4: false
          addresses:
{addrs_yaml}
          gateway4: {gateway}
          nameservers:
            addresses: [{ns_yaml}]"""

    disk = (disk_layout or "lvm").lower()
    if disk not in ("lvm", "direct", "zfs"):
        disk = "lvm"

    # Real per-install password hash (never a fixed placeholder). Password
    # login is disabled (allow-pw: false) — access is SSH-key only — so this
    # is a random, unknown, valid hash that effectively locks the account.
    try:
        import crypt as _crypt
        import secrets as _secrets
        _pw_hash = _crypt.crypt(_secrets.token_urlsafe(24),
                               _crypt.mksalt(_crypt.METHOD_SHA512))
    except Exception:
        # Fallback: '!' = locked account (valid /etc/shadow convention).
        _pw_hash = "!"

    post_cmd = post_script or "echo 'OXware bare-metal install complete'"

    yaml_doc = f"""#cloud-config
autoinstall:
  version: 1
  locale: en_US.UTF-8
  keyboard:
    layout: us
  identity:
    hostname: {hostname}
    username: oxware
    password: "{_pw_hash}"
  ssh:
    install-server: true
    allow-pw: false
    authorized-keys:
{keys_yaml}
  storage:
    layout:
      name: {disk}
{net_block}
  packages:
    - qemu-guest-agent
    - openssh-server
    - curl
    - python3
  late-commands:
    - curtin in-target --target=/target -- bash -c {json.dumps(post_cmd)}
  user-data:
    disable_root: true
    timezone: UTC
"""

    path = AUTOINSTALL_DIR / f"{name}.yaml"
    path.write_text(yaml_doc, encoding="utf-8")
    _audit("create_profile", name=name, hostname=hostname, disk=disk)
    return {
        "name": name,
        "path": str(path),
        "hostname": hostname,
        "disk_layout": disk,
        "ok": True,
    }


def delete_profile(name: str) -> dict:
    path = AUTOINSTALL_DIR / f"{name}.yaml"
    if not path.exists():
        raise KeyError(f"profile {name} not found")
    path.unlink()
    _audit("delete_profile", name=name)
    return {"removed": name, "ok": True}


def register_mac(mac: str, profile: str, hostname: str) -> dict:
    mac_n = _normalize_mac(mac)
    profile_path = AUTOINSTALL_DIR / f"{profile}.yaml"
    if not profile_path.exists():
        raise KeyError(f"profile {profile} not found")
    regs = _load_registrations()
    rec = {
        "mac": mac_n,
        "profile": profile,
        "hostname": hostname,
        "registered_at": time.time(),
        "status": "pending",
    }
    regs[mac_n] = rec
    _save_registrations(regs)
    _audit("register_mac", mac=mac_n, profile=profile, hostname=hostname)
    return rec


def list_registrations() -> list:
    return list(_load_registrations().values())


def unregister_mac(mac: str) -> dict:
    mac_n = _normalize_mac(mac)
    regs = _load_registrations()
    if mac_n not in regs:
        raise KeyError(f"mac {mac_n} not registered")
    del regs[mac_n]
    _save_registrations(regs)
    _audit("unregister_mac", mac=mac_n)
    return {"removed": mac_n, "ok": True}


def generate_ipxe_script(profile: str, kernel_url: str, initrd_url: str) -> str:
    profile_path = AUTOINSTALL_DIR / f"{profile}.yaml"
    if not profile_path.exists():
        raise KeyError(f"profile {profile} not found")
    autoinstall_url = f"http://oxware/autoinstall/{profile}.yaml"
    script = f"""#!ipxe
# OXware iPXE boot script for profile: {profile}
echo Booting OXware autoinstall profile: {profile}
set kernel-url {kernel_url}
set initrd-url {initrd_url}
set autoinstall-url {autoinstall_url}

kernel ${{kernel-url}} initrd=initrd ip=dhcp url=${{autoinstall-url}} autoinstall ds=nocloud-net;s=${{autoinstall-url}}
initrd ${{initrd-url}}
boot || goto fail

:fail
echo Boot failed for profile {profile}
shell
"""
    return script


def build_install_iso(profile: str, output_path: str) -> dict:
    profile_path = AUTOINSTALL_DIR / f"{profile}.yaml"
    if not profile_path.exists():
        raise KeyError(f"profile {profile} not found")
    if not shutil.which("xorriso"):
        _audit("build_iso_failed", profile=profile, reason="xorriso missing")
        return {"ok": False, "error": "xorriso not installed",
                "profile": profile, "output_path": output_path}

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "xorriso", "-as", "mkisofs",
        "-r", "-V", f"OXWARE_{profile.upper()}",
        "-o", str(out),
        "-J", "-joliet-long",
        "-b", "boot/grub/i386-pc/eltorito.img",
        "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
        str(profile_path.parent),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=600, check=False)
        ok = result.returncode == 0 and out.exists()
        _audit("build_iso", profile=profile, output=str(out), ok=ok)
        return {
            "ok": ok,
            "profile": profile,
            "output_path": str(out),
            "size": out.stat().st_size if out.exists() else 0,
            "stderr": result.stderr[-500:] if result.stderr else "",
            "returncode": result.returncode,
        }
    except (subprocess.TimeoutExpired, OSError) as e:
        _audit("build_iso_failed", profile=profile, error=str(e))
        return {"ok": False, "error": str(e), "profile": profile,
                "output_path": str(out)}


def get_install_progress(mac: str) -> dict:
    mac_n = _normalize_mac(mac)
    candidates = [
        Path("/var/log/syslog"),
        Path("/var/log/messages"),
        Path("/var/log/daemon.log"),
        Path("/var/log/dnsmasq.log"),
    ]
    matches = []
    needle = mac_n.replace(":", "")
    for log in candidates:
        if not log.exists():
            continue
        try:
            with open(log, "r", encoding="utf-8", errors="ignore") as f:
                try:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - 262144))
                    tail = f.read()
                except OSError:
                    tail = f.read()
            for line in tail.splitlines():
                low = line.lower()
                if mac_n in low or needle in low.replace(":", ""):
                    matches.append({"log": str(log), "line": line.strip()})
        except OSError:
            continue

    regs = _load_registrations()
    reg = regs.get(mac_n)
    status = "unknown"
    if reg:
        status = reg.get("status", "pending")
        if matches:
            joined = " ".join(m["line"].lower() for m in matches)
            if "tftp" in joined or "rrq" in joined:
                status = "tftp_serving"
            if "dhcpack" in joined or "dhcp_ack" in joined:
                status = "dhcp_acked"
            if "success" in joined or "installed" in joined:
                status = "installed"

    return {
        "mac": mac_n,
        "registration": reg,
        "status": status,
        "log_matches": matches[-50:],
        "match_count": len(matches),
        "checked_at": time.time(),
    }
