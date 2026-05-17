"""OXware Hotplug Manager — live CPU and RAM hot-plug via virsh."""
import subprocess
import re


def _run(args, timeout=15):
    return subprocess.run(
        args,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def hotplug_vcpu(vm_name, count):
    count = int(count)
    try:
        _run(["virsh", "setvcpus", vm_name, str(count), "--live", "--config"])
        return {"success": True, "message": f"vCPU count set to {count}", "new_count": count}
    except subprocess.CalledProcessError as e:
        return {"success": False, "message": e.stderr.strip() or str(e), "new_count": None}
    except Exception as e:
        return {"success": False, "message": str(e), "new_count": None}


def hotplug_memory(vm_name, ram_mb):
    ram_mb = int(ram_mb)
    ram_kb = ram_mb * 1024
    try:
        _run(["virsh", "setmem", vm_name, str(ram_kb), "--live", "--config"])
        return {"success": True, "message": f"Memory set to {ram_mb} MB", "new_ram_mb": ram_mb}
    except subprocess.CalledProcessError as e:
        return {"success": False, "message": e.stderr.strip() or str(e), "new_ram_mb": None}
    except Exception as e:
        return {"success": False, "message": str(e), "new_ram_mb": None}


def get_vcpu_info(vm_name):
    try:
        r = _run(["virsh", "vcpuinfo", vm_name])
        current = maximum = None
        for line in r.stdout.splitlines():
            if line.startswith("CPU:"):
                # Multiple "CPU:" lines — last index is current-1, count lines
                pass
        # Count CPU entries for current, use dominfo for max
        cpu_lines = [l for l in r.stdout.splitlines() if l.startswith("CPU:")]
        current = len(cpu_lines) if cpu_lines else None

        r2 = _run(["virsh", "dominfo", vm_name])
        for line in r2.stdout.splitlines():
            if line.lower().startswith("max virt. cpu"):
                m = re.search(r"\d+", line)
                if m:
                    maximum = int(m.group())
                break
        return {"current": current, "maximum": maximum}
    except Exception as e:
        return {"current": None, "maximum": None, "error": str(e)}


def get_mem_info(vm_name):
    try:
        r = _run(["virsh", "dominfo", vm_name])
        current_mb = max_mb = None
        for line in r.stdout.splitlines():
            lo = line.lower()
            if lo.startswith("used memory"):
                m = re.search(r"\d+", line)
                if m:
                    current_mb = int(m.group()) // 1024
            elif lo.startswith("max memory"):
                m = re.search(r"\d+", line)
                if m:
                    max_mb = int(m.group()) // 1024
        return {"current_mb": current_mb, "max_mb": max_mb}
    except Exception as e:
        return {"current_mb": None, "max_mb": None, "error": str(e)}
