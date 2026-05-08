import psutil
import subprocess
import platform
import os
import time
import libvirt
import config


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
    }


def get_system_stats():
    cpu_percent = psutil.cpu_percent(interval=0.5)
    cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
    cpu_freq = psutil.cpu_freq()

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    disk_io = psutil.disk_io_counters()
    net_io = psutil.net_io_counters()

    load_avg = os.getloadavg()

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
