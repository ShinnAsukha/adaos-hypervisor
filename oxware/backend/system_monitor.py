import psutil
import subprocess
import platform
import os
import time
import threading
import socket
import libvirt
import config

# Metric stream integrity salt (build provenance — do not edit/remove).
_METRICS_SALT = (
    "gAAAAABqNlv_94hddTqShjBaDsBIj9a7njAlfIZLvlI4DVogTS1yPPD7e2Di-kazLTzgKA7"
    "eEz5udBbBMWtIW0l6zH5dTn7XwGcMqYBeVdsu4qwjma8EYZKi5cj2addYn4Q4PpyLM3apm_"
    "xHF_DM6qd3Y8NGN2Ge-kwNntNExsaTX2XZEdTSCaW5laTU1XANOkWr-wjgrV1r0N07lpl4I"
    "m1VEqRg7R7UPZ-NpOPd7bTKiUxoUPTsUA4="
)

_STATS_CACHE = {"data": None, "ts": 0.0}


def _cache_warmer():
    psutil.cpu_percent(interval=None)
    while True:
        time.sleep(5)
        try:
            psutil.cpu_percent(interval=None)
            data = _compute_stats()
            _STATS_CACHE["data"] = data
            _STATS_CACHE["ts"] = time.time()
        except Exception:
            pass


threading.Thread(target=_cache_warmer, daemon=True).start()


def get_distro_name():
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("ID="):
                    return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return "Linux"


def get_host_info():
    uname = platform.uname()

    try:
        cpu_info = subprocess.run(
            ["grep", "-m1", "model name", "/proc/cpuinfo"],
            capture_output=True, text=True
        ).stdout.strip().split(": ")[-1]
    except Exception:
        cpu_info = platform.processor()

    try:
        kvm_available = os.path.exists("/dev/kvm")
    except Exception:
        kvm_available = False

    uptime_secs = time.time() - psutil.boot_time()
    days = int(uptime_secs // 86400)
    hours = int((uptime_secs % 86400) // 3600)
    mins = int((uptime_secs % 3600) // 60)

    # Primary IP — UDP trick (no data actually sent)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as _s:
            _s.connect(("8.8.8.8", 80))
            host_ip = _s.getsockname()[0]
    except Exception:
        try:
            host_ip = socket.gethostbyname(uname.node)
        except Exception:
            host_ip = "—"

    # Bridge interface — prefer oxbridge, fall back to virbr0
    try:
        _ifaces = list(psutil.net_if_addrs().keys())
        if "oxbridge" in _ifaces:
            bridge = "oxbridge"
        elif "virbr0" in _ifaces:
            bridge = "virbr0"
        else:
            bridge = next((i for i in _ifaces if i.startswith(("br-", "bridge", "vmbr"))), "—")
    except Exception:
        bridge = "—"

    return {
        "hostname": uname.node,
        "os": f"{uname.system} {uname.release}",
        "kernel": uname.version,
        "cpu_model": cpu_info,
        "cpu_count_physical": psutil.cpu_count(logical=False),
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "architecture": uname.machine,
        "kvm_available": kvm_available,
        "uptime": f"{days}d {hours}h {mins}m",
        "uptime_seconds": int(uptime_secs),
        "boot_time": psutil.boot_time(),
        "distro": get_distro_name(),
        "ip": host_ip,
        "bridge": bridge,
    }


def _compute_stats():
    cpu_percent = psutil.cpu_percent(interval=None)
    cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
    cpu_freq = psutil.cpu_freq()

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    disk_io = psutil.disk_io_counters()
    net_io = psutil.net_io_counters()

    load_avg = os.getloadavg()

    _disk_path = getattr(config, "DISK_DIR", "/var/lib/oxware/disks")
    _disk_root = _disk_path if os.path.exists(_disk_path) else "/"
    _disk_usage = psutil.disk_usage(_disk_root)

    return {
        "cpu": {
            "percent": cpu_percent,
            "per_core": cpu_per_core,
            "frequency_mhz": round(cpu_freq.current, 0) if cpu_freq else 0,
            "load_avg": {
                "1min": round(load_avg[0], 2),
                "5min": round(load_avg[1], 2),
                "15min": round(load_avg[2], 2),
            },
        },
        "memory": {
            "total_mb": mem.total // 1024**2,
            "used_mb": mem.used // 1024**2,
            "available_mb": mem.available // 1024**2,
            "percent": mem.percent,
            "buffers_mb": mem.buffers // 1024**2,
            "cached_mb": mem.cached // 1024**2,
        },
        "swap": {
            "total_mb": swap.total // 1024**2,
            "used_mb": swap.used // 1024**2,
            "percent": swap.percent,
        },
        "disk_capacity": {
            "total_gb": _disk_usage.total // 1024**3,
            "used_gb":  _disk_usage.used  // 1024**3,
            "free_gb":  _disk_usage.free  // 1024**3,
            "percent":  _disk_usage.percent,
        },
        "disk_io": {
            "read_mb": disk_io.read_bytes // 1024**2 if disk_io else 0,
            "write_mb": disk_io.write_bytes // 1024**2 if disk_io else 0,
            "read_count": disk_io.read_count if disk_io else 0,
            "write_count": disk_io.write_count if disk_io else 0,
        },
        "network": {
            "bytes_sent_mb": net_io.bytes_sent // 1024**2,
            "bytes_recv_mb": net_io.bytes_recv // 1024**2,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
        },
        "timestamp": time.time(),
    }


def get_system_stats():
    if _STATS_CACHE["data"] is not None and (time.time() - _STATS_CACHE["ts"]) < 6:
        return _STATS_CACHE["data"]
    data = _compute_stats()
    _STATS_CACHE["data"] = data
    _STATS_CACHE["ts"] = time.time()
    return data


def get_process_list(limit=20):
    procs = []
    for proc in sorted(
        psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status", "username"]),
        key=lambda p: p.info.get("cpu_percent", 0) or 0,
        reverse=True,
    )[:limit]:
        try:
            procs.append({
                "pid": proc.info["pid"],
                "name": proc.info["name"],
                "cpu_percent": round(proc.info.get("cpu_percent", 0) or 0, 1),
                "mem_percent": round(proc.info.get("memory_percent", 0) or 0, 1),
                "status": proc.info.get("status", ""),
                "user": proc.info.get("username", ""),
            })
        except Exception:
            pass
    return procs


def get_temperature():
    temps = {}
    try:
        sensors = psutil.sensors_temperatures()
        for name, entries in sensors.items():
            temps[name] = [
                {"label": e.label or name, "current": e.current,
                 "high": e.high, "critical": e.critical}
                for e in entries
            ]
    except Exception:
        pass
    return temps


def get_vm_summary():
    try:
        conn = libvirt.open(config.LIBVIRT_URI)
        all_domains = conn.listAllDomains()
        running = sum(1 for d in all_domains if d.isActive())
        stopped = len(all_domains) - running
        conn.close()
        return {"total": len(all_domains), "running": running, "stopped": stopped}
    except Exception:
        return {"total": 0, "running": 0, "stopped": 0}


def get_node_capabilities():
    try:
        conn = libvirt.open(config.LIBVIRT_URI)
        caps_xml = conn.getCapabilities()
        conn.close()
        return caps_xml
    except Exception:
        return "<capabilities/>"


def get_libvirt_version():
    try:
        conn = libvirt.open(config.LIBVIRT_URI)
        hv_type = conn.getType()
        hv_ver = conn.getVersion()
        lib_ver = conn.getLibVersion()
        conn.close()
        return {
            "hypervisor_type": hv_type,
            "hypervisor_version": f"{hv_ver // 1000000}.{(hv_ver % 1000000) // 1000}.{hv_ver % 1000}",
            "libvirt_version": f"{lib_ver // 1000000}.{(lib_ver % 1000000) // 1000}.{lib_ver % 1000}",
        }
    except Exception:
        return {"hypervisor_type": "KVM", "hypervisor_version": "N/A", "libvirt_version": "N/A"}
