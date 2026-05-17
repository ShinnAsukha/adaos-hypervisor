"""OXware Storage Migration — live disk migration via virsh blockcopy."""
import subprocess
import threading
import uuid
import re
from datetime import datetime, timezone

_jobs = {}  # job_id -> job dict
_jobs_lock = threading.Lock()


def _run(args, timeout=15):
    return subprocess.run(
        args,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def list_storage_pools():
    try:
        r = _run(["virsh", "pool-list", "--all", "--details"], timeout=15)
        pools = []
        lines = r.stdout.strip().splitlines()
        # Skip header lines (first 2 lines are header/separator)
        for line in lines[2:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            name = parts[0]
            # parts: Name State Autostart Persistent Capacity Allocation Available
            # pool-list --details columns: Name, State, Autostart, Persistent, Capacity, Allocation, Available
            # Try to parse capacity and available (may have units like GiB)
            try:
                cap_str = parts[4] if len(parts) > 4 else "0"
                avail_str = parts[6] if len(parts) > 6 else "0"

                def to_gb(s):
                    s = s.upper()
                    m = re.match(r"([\d.]+)\s*(GIB|GB|MIB|MB|TIB|TB)?", s)
                    if not m:
                        return 0.0
                    val = float(m.group(1))
                    unit = m.group(2) or "GB"
                    if "MI" in unit or "MB" in unit:
                        val /= 1024
                    elif "TI" in unit or "TB" in unit:
                        val *= 1024
                    return round(val, 2)

                pools.append({
                    "name": name,
                    "path": "",
                    "type": "dir",
                    "capacity_gb": to_gb(cap_str),
                    "available_gb": to_gb(avail_str),
                })
            except Exception:
                pools.append({"name": name, "path": "", "type": "dir",
                               "capacity_gb": 0, "available_gb": 0})
        return pools
    except Exception as e:
        return [{"error": str(e)}]


def get_vm_disks(vm_name):
    try:
        r = _run(["virsh", "domblklist", vm_name, "--details"], timeout=15)
        disks = []
        lines = r.stdout.strip().splitlines()
        for line in lines[2:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            disk_type = parts[0]
            device = parts[1]
            target = parts[2]
            source = parts[3] if parts[3] != "-" else None
            if disk_type == "disk" and source:
                fmt = "qcow2"
                if source.endswith(".raw"):
                    fmt = "raw"
                disks.append({"target": target, "source_path": source, "format": fmt})
        return disks
    except Exception as e:
        return [{"error": str(e)}]


def _run_migration_job(job_id, vm_name, disk_target, dest_path, fmt):
    with _jobs_lock:
        _jobs[job_id]["status"] = "running"
    try:
        subprocess.run(
            ["virsh", "blockcopy", vm_name, disk_target,
             "--dest", dest_path, "--format", fmt, "--wait", "--verbose"],
            check=True,
            capture_output=True,
            text=True,
            timeout=3600,
        )
        with _jobs_lock:
            _jobs[job_id]["status"] = "completed"
            _jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
    except subprocess.CalledProcessError as e:
        with _jobs_lock:
            _jobs[job_id]["status"] = "failed"
            _jobs[job_id]["error"] = e.stderr.strip() or str(e)
            _jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
    except Exception as e:
        with _jobs_lock:
            _jobs[job_id]["status"] = "failed"
            _jobs[job_id]["error"] = str(e)
            _jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()


def start_migration(vm_name, disk_target, dest_path, format="qcow2"):
    import re as _re
    if not dest_path or ".." in dest_path or not dest_path.startswith("/"):
        raise ValueError("dest_path mutlak yol olmalı ve '..' içermemeli")
    if format not in ("qcow2", "raw"):
        raise ValueError("format sadece qcow2 veya raw olabilir")
    if not _re.match(r'^[a-zA-Z0-9_\-]+$', disk_target or ""):
        raise ValueError("disk_target geçersiz")
    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "status": "queued",
        "vm_name": vm_name,
        "disk_target": disk_target,
        "dest_path": dest_path,
        "format": format,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "error": None,
    }
    with _jobs_lock:
        _jobs[job_id] = job
    t = threading.Thread(
        target=_run_migration_job,
        args=(job_id, vm_name, disk_target, dest_path, format),
        daemon=True,
    )
    t.start()
    return {"job_id": job_id, "started": True}


def get_migration_status(job_id):
    with _jobs_lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def list_migrations():
    with _jobs_lock:
        return [dict(j) for j in _jobs.values()]
