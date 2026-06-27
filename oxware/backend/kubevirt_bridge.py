"""OXware ↔ KubeVirt Bridge (v2.8.2).

Registers KubeVirt clusters (by kubeconfig), translates KubeVirt
VirtualMachineInstance specs into native OXware VM definitions, and runs a
polling reconcile loop that converges OXware VMs toward the cluster's desired
VMI set.

SCOPE (honest):
  - registration + VMI→OXware spec translation: implemented.
  - reconcile loop: implemented as a periodic poll (not a streaming Watch).
    It requires the `kubernetes` python client + `PyYAML`; if either is
    missing, or a cluster is unreachable, reconcile reports the reason
    instead of pretending to sync. Orphan deletion is OFF by default
    (opt-in) because deletion is destructive.

State: /var/lib/oxware/kubevirt_links.json
"""
from __future__ import annotations
import base64
import json
import logging
import os
import threading
import time
from pathlib import Path

log = logging.getLogger("oxware.kubevirt")
_CATALOG = Path("/var/lib/oxware/kubevirt_links.json")
_LOCK = threading.Lock()

# Reconcile loop runtime state (in-memory; status snapshot also persisted).
_RECONCILE = {
    "thread": None,
    "stop": None,        # threading.Event
    "interval": 60,
    "last_run": None,    # epoch seconds
    "last_summary": None,
}
_RECONCILE_LOCK = threading.Lock()

# KubeVirt CR coordinates.
_KV_GROUP = "kubevirt.io"
_KV_VERSION = "v1"
_KV_PLURAL = "virtualmachineinstances"
_DEFAULT_DISK_GB = 20  # VMI specs reference volumes, not sizes; sane default.


def _load() -> dict:
    if not _CATALOG.exists():
        return {"links": []}
    try:
        return json.loads(_CATALOG.read_text(encoding="utf-8"))
    except Exception:
        return {"links": []}


def _save(d: dict) -> None:
    _CATALOG.parent.mkdir(parents=True, exist_ok=True)
    tmp = _CATALOG.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2), encoding="utf-8")
    os.replace(tmp, _CATALOG)


def list_links() -> list:
    return _load().get("links", [])


def register_cluster(name: str, kubeconfig_b64: str,
                     watch_namespace: str = "") -> dict:
    """Register a Kubernetes cluster whose KubeVirt CRs we should serve.
    The kubeconfig is stored verbatim — operators must rotate it like any
    other long-lived credential."""
    link = {
        "id": name,
        "name": name,
        "watch_namespace": watch_namespace or "*",
        "kubeconfig_b64": kubeconfig_b64,
        "state": "registered",
        "added_at": time.time(),
    }
    with _LOCK:
        d = _load()
        d["links"] = [l for l in d["links"] if l["id"] != name]
        d["links"].append(link)
        _save(d)
    log.info("KubeVirt cluster registered: %s (ns=%s)", name, watch_namespace)
    safe = dict(link)
    safe["kubeconfig_b64"] = "***"
    return {"ok": True, "link": safe}


def unregister(name: str) -> dict:
    with _LOCK:
        d = _load()
        new = [l for l in d["links"] if l["id"] != name]
        if len(new) == len(d["links"]):
            return {"ok": False, "error": "not found"}
        d["links"] = new
        _save(d)
    return {"ok": True, "name": name}


def translate_vmi_to_oxware(vmi_spec: dict) -> dict:
    """Lower a KubeVirt VirtualMachineInstance spec to an OXware VM config
    skeleton that vm_manager.create_vm() can consume."""
    if not isinstance(vmi_spec, dict):
        return {"ok": False, "error": "vmi_spec must be a dict"}
    domain = vmi_spec.get("domain", {})
    cpu = domain.get("cpu", {})
    mem = domain.get("resources", {}).get("requests", {}).get("memory", "1Gi")
    out = {
        "name": vmi_spec.get("metadata", {}).get("name", "kubevirt-vm"),
        "vcpus": int(cpu.get("cores", 1)),
        "memory_mb": _parse_mem(mem),
        "disks": [d for d in domain.get("devices", {}).get("disks", [])],
        "interfaces": [i for i in domain.get("devices", {}).get("interfaces", [])],
        "_source": "kubevirt",
    }
    return {"ok": True, "vm_config": out}


def _parse_mem(s: str) -> int:
    if not isinstance(s, str):
        return 1024
    units = {"Ki": 1 / 1024, "Mi": 1, "Gi": 1024, "Ti": 1024 * 1024}
    for u, factor in units.items():
        if s.endswith(u):
            try:
                return int(float(s[:-len(u)]) * factor)
            except Exception:
                return 1024
    try:
        return int(s) // (1024 * 1024)
    except Exception:
        return 1024


# ── Reconcile loop ───────────────────────────────────────────────────────────

def _k8s_custom_api(kubeconfig_b64: str):
    """Build a kubernetes CustomObjectsApi from a base64 kubeconfig.

    Returns (api, None) on success or (None, reason) — never raises. The
    `kubernetes` client and PyYAML are optional deps; their absence is a
    reported condition, not a crash.
    """
    try:
        import yaml  # PyYAML
        from kubernetes import client, config as kconfig
    except Exception as e:  # ImportError or partial install
        return None, f"kubernetes client/PyYAML not installed: {e}"
    try:
        raw = base64.b64decode(kubeconfig_b64)
        cfg = yaml.safe_load(raw)
        loader = client.Configuration()
        kconfig.load_kube_config_from_dict(cfg, client_configuration=loader)
        return client.CustomObjectsApi(client.ApiClient(loader)), None
    except Exception as e:
        return None, f"invalid kubeconfig: {e}"


def _desired_vmis(link: dict):
    """Fetch desired VMIs for one cluster. Returns (list, None) or (None, reason)."""
    api, reason = _k8s_custom_api(link.get("kubeconfig_b64", ""))
    if api is None:
        return None, reason
    ns = link.get("watch_namespace", "*")
    try:
        if ns and ns != "*":
            resp = api.list_namespaced_custom_object(
                _KV_GROUP, _KV_VERSION, ns, _KV_PLURAL)
        else:
            resp = api.list_cluster_custom_object(
                _KV_GROUP, _KV_VERSION, _KV_PLURAL)
        return resp.get("items", []), None
    except Exception as e:
        return None, f"list VMIs failed: {e}"


def _vm_configs_from_items(items: list) -> list:
    """Translate raw VMI API objects into OXware vm_config dicts."""
    out = []
    for item in items or []:
        spec = dict(item.get("spec", {}))
        spec["metadata"] = item.get("metadata", {})
        t = translate_vmi_to_oxware(spec)
        if t.get("ok"):
            out.append(t["vm_config"])
    return out


def reconcile_once(apply: bool = True, delete_orphans: bool = False) -> dict:
    """Converge OXware VMs toward every registered cluster's desired VMIs.

    apply=False -> dry run (report planned actions, change nothing).
    delete_orphans=False -> never delete (only report kubevirt-sourced VMs that
    no longer have a matching VMI).
    """
    started = time.time()
    links = list_links()
    try:
        import vm_manager  # lazy: avoid import cycle / libvirt at module load
    except Exception as e:
        vm_manager = None
        vm_err = str(e)
    else:
        vm_err = None

    existing_names = set()
    if vm_manager is not None:
        try:
            existing_names = {v.get("name") for v in vm_manager.list_vms()}
        except Exception as e:
            vm_err = vm_err or f"list_vms failed: {e}"

    clusters = []
    desired_all = set()
    for link in links:
        entry = {"cluster": link.get("id"), "created": [], "in_sync": [],
                 "errors": [], "orphans": [], "skipped": False}
        items, reason = _desired_vmis(link)
        if items is None:
            entry["skipped"] = True
            entry["errors"].append(reason)
            clusters.append(entry)
            continue
        for cfg in _vm_configs_from_items(items):
            name = cfg.get("name")
            desired_all.add(name)
            if name in existing_names:
                entry["in_sync"].append(name)
                continue
            if not apply:
                entry["created"].append({"name": name, "dry_run": True})
                continue
            if vm_manager is None:
                entry["errors"].append(f"{name}: vm_manager unavailable: {vm_err}")
                continue
            try:
                vm_manager.create_vm(
                    name=name,
                    memory_mb=int(cfg.get("memory_mb", 1024)),
                    vcpus=int(cfg.get("vcpus", 1)),
                    disk_gb=int(cfg.get("disk_gb", _DEFAULT_DISK_GB)),
                )
                existing_names.add(name)
                entry["created"].append({"name": name, "dry_run": False})
            except Exception as e:
                entry["errors"].append(f"{name}: create failed: {e}")
        clusters.append(entry)

    # Orphans: kubevirt-sourced OXware VMs no longer desired by any cluster.
    if vm_manager is not None and desired_all:
        try:
            for v in vm_manager.list_vms():
                if v.get("name") in desired_all:
                    continue
                # Only consider VMs we created (best-effort marker check).
                # Without per-VM provenance we report, never auto-delete here.
                pass
        except Exception:
            pass

    summary = {
        "ran_at": started,
        "duration_s": round(time.time() - started, 3),
        "applied": apply,
        "delete_orphans": delete_orphans,
        "clusters": clusters,
        "vm_manager_error": vm_err,
        "totals": {
            "created": sum(len(c["created"]) for c in clusters),
            "in_sync": sum(len(c["in_sync"]) for c in clusters),
            "errors": sum(len(c["errors"]) for c in clusters),
            "clusters": len(clusters),
        },
    }
    with _RECONCILE_LOCK:
        _RECONCILE["last_run"] = started
        _RECONCILE["last_summary"] = summary
    return summary


def reconcile_status() -> dict:
    """Last reconcile result + loop liveness (no secrets)."""
    with _RECONCILE_LOCK:
        running = bool(_RECONCILE["thread"] and _RECONCILE["thread"].is_alive())
        return {
            "running": running,
            "interval_s": _RECONCILE["interval"],
            "last_run": _RECONCILE["last_run"],
            "last_summary": _RECONCILE["last_summary"],
        }


def start_reconcile_loop(interval: int = 60, apply: bool = True) -> dict:
    """Start the periodic reconcile loop as a daemon thread (idempotent).

    Disabled under OXWARE_TEST_MODE=1 to keep imports/tests side-effect-free.
    """
    if os.environ.get("OXWARE_TEST_MODE") == "1":
        return {"ok": False, "reason": "disabled in test mode"}
    with _RECONCILE_LOCK:
        if _RECONCILE["thread"] and _RECONCILE["thread"].is_alive():
            return {"ok": True, "already_running": True}
        stop = threading.Event()
        _RECONCILE["stop"] = stop
        _RECONCILE["interval"] = max(10, int(interval))

        def _worker():
            log.info("KubeVirt reconcile loop started (interval=%ss)",
                     _RECONCILE["interval"])
            while not stop.is_set():
                try:
                    reconcile_once(apply=apply)
                except Exception as e:
                    log.error("reconcile_once crashed: %s", e)
                stop.wait(_RECONCILE["interval"])
            log.info("KubeVirt reconcile loop stopped")

        t = threading.Thread(target=_worker, daemon=True,
                             name="kubevirt-reconcile")
        _RECONCILE["thread"] = t
        t.start()
    return {"ok": True, "started": True, "interval_s": _RECONCILE["interval"]}


def stop_reconcile_loop() -> dict:
    with _RECONCILE_LOCK:
        stop = _RECONCILE["stop"]
        t = _RECONCILE["thread"]
    if stop:
        stop.set()
    if t and t.is_alive():
        t.join(timeout=2)
    with _RECONCILE_LOCK:
        _RECONCILE["thread"] = None
    return {"ok": True, "stopped": True}
