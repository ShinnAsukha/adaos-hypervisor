"""OXware Network QoS — per-NIC bandwidth throttling via virsh domiftune."""
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


def _parse_kbps(line):
    """Extract integer value from a domiftune output line like 'inbound.average: 1024'."""
    m = re.search(r"(\d+)", line)
    return int(m.group(1)) if m else 0


def get_nic_qos(vm_name, iface):
    try:
        r = _run(["virsh", "domiftune", vm_name, iface])
        result = {
            "inbound_average": 0,
            "outbound_average": 0,
            "inbound_peak": 0,
            "outbound_peak": 0,
        }
        for line in r.stdout.splitlines():
            lo = line.lower()
            if "inbound.average" in lo:
                result["inbound_average"] = _parse_kbps(line)
            elif "inbound.peak" in lo:
                result["inbound_peak"] = _parse_kbps(line)
            elif "outbound.average" in lo:
                result["outbound_average"] = _parse_kbps(line)
            elif "outbound.peak" in lo:
                result["outbound_peak"] = _parse_kbps(line)
        return result
    except subprocess.CalledProcessError as e:
        return {"error": e.stderr.strip() or str(e)}
    except Exception as e:
        return {"error": str(e)}


def set_nic_qos(vm_name, iface, inbound_kbps=0, outbound_kbps=0):
    inbound_kbps = max(0, int(inbound_kbps))
    outbound_kbps = max(0, int(outbound_kbps))
    if inbound_kbps > 10_000_000 or outbound_kbps > 10_000_000:
        raise ValueError("Bant genişliği limiti 10 Gbps'i aşamaz")
    try:
        _run([
            "virsh", "domiftune", vm_name, iface,
            "--inbound", str(inbound_kbps),
            "--outbound", str(outbound_kbps),
            "--live", "--config",
        ])
        return {
            "success": True,
            "message": f"QoS set: inbound={inbound_kbps} Kbps, outbound={outbound_kbps} Kbps",
        }
    except subprocess.CalledProcessError as e:
        return {"success": False, "message": e.stderr.strip() or str(e)}
    except Exception as e:
        return {"success": False, "message": str(e)}


def clear_nic_qos(vm_name, iface):
    return set_nic_qos(vm_name, iface, inbound_kbps=0, outbound_kbps=0)


def list_vm_nics(vm_name):
    try:
        r = _run(["virsh", "domiflist", vm_name])
        nics = []
        lines = r.stdout.strip().splitlines()
        # Skip header (first 2 lines)
        for line in lines[2:]:
            parts = line.split()
            if parts:
                nics.append(parts[0])
        return nics
    except Exception as e:
        return []
