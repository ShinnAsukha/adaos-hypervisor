"""
OXware Feature Registry
───────────────────────
Tüm enterprise özelliklerin merkezi kaydı:
  - Her özellik: id, ad, kategori, modül, endpoint sayısı, durum
  - Kalıcı state: /var/lib/oxware/features.json
  - Audit-friendly: tüm enable/disable işlemleri kayıtlı
  - Dependency check: bağımlı özellikler birbirini koparmaz

Her feature 'capability flag' — runtime'da open/closed. Çakışma yok,
çünkü her feature kendi namespace'inde + endpoint'leri register edilir.
"""

from __future__ import annotations
import os
import json
import time
import logging
import threading
from pathlib import Path
from typing import Optional

log = logging.getLogger("feature_registry")

_REGISTRY_FILE = Path("/var/lib/oxware/features.json")
_AUDIT_FILE    = Path("/var/log/oxware/feature_audit.jsonl")
_lock          = threading.RLock()


# ── Tüm bilinen feature'ların manifest'i ──────────────────────────────────────
# Yeni feature eklerken: bu listeye satır ekle, MODULE_NAME = backend modül adı.
# CATEGORY: 'compute' | 'storage' | 'network' | 'security' | 'observability' |
#           'dr' | 'automation' | 'multi-tenancy' | 'lifecycle' | 'modern'
# STATUS: 'stable' | 'beta' | 'experimental' | 'planned'
FEATURE_MANIFEST = [
    # ── v2.5.3 — Stable (shipped, proven in production) ──────────────────────────
    {"id": "drs",            "name": "DRS Cluster",            "category": "compute",      "module": "drs_manager",         "status": "stable", "version": "2.5.3"},
    {"id": "affinity",       "name": "Affinity Rules",         "category": "compute",      "module": "affinity_manager",    "status": "stable", "version": "2.5.3"},
    {"id": "maintenance",    "name": "Maintenance Mode",       "category": "lifecycle",    "module": "maintenance_mode",    "status": "stable", "version": "2.5.3"},
    {"id": "evc",            "name": "EVC CPU Baseline",       "category": "compute",      "module": "evc_manager",         "status": "stable", "version": "2.5.3"},
    {"id": "nioc",           "name": "Network I/O Control",    "category": "network",      "module": "nioc_manager",        "status": "stable", "version": "2.5.3"},
    {"id": "site_recovery",  "name": "Disaster Recovery (SRM)","category": "dr",           "module": "site_recovery",       "status": "stable", "version": "2.5.3"},
    {"id": "lifecycle",      "name": "Lifecycle Manager",      "category": "lifecycle",    "module": "lifecycle_manager",   "status": "stable", "version": "2.5.3"},
    {"id": "storage_adv",    "name": "Storage Advanced",       "category": "storage",      "module": "storage_advanced",    "status": "stable", "version": "2.5.3"},
    {"id": "network_adv",    "name": "Network Advanced",       "category": "network",      "module": "network_advanced",    "status": "stable", "version": "2.5.3"},
    {"id": "siem",           "name": "SIEM Export",            "category": "security",     "module": "siem_exporter",       "status": "stable", "version": "2.5.3"},
    {"id": "session_rec",    "name": "Session Recording",      "category": "security",     "module": "session_recorder",    "status": "stable", "version": "2.5.3"},
    {"id": "numa",           "name": "NUMA Pinning",           "category": "compute",      "module": "numa_manager",        "status": "stable", "version": "2.5.3"},
    {"id": "backup_enc",     "name": "Backup Encryption",      "category": "storage",      "module": "backup_encryption",   "status": "stable", "version": "2.5.3"},
    {"id": "right_sizing",   "name": "Right-Sizing",           "category": "observability","module": "right_sizing",        "status": "stable", "version": "2.5.3"},
    {"id": "alert_corr",     "name": "Alert Correlation",      "category": "observability","module": "alert_correlation",   "status": "stable", "version": "2.5.3"},
    {"id": "linked_clones",  "name": "Linked Clones",          "category": "storage",      "module": "linked_clone",        "status": "stable", "version": "2.5.3"},
    {"id": "snap_cleanup",   "name": "Snapshot Cleanup",       "category": "storage",      "module": "snapshot_cleanup",    "status": "stable", "version": "2.5.3"},
    {"id": "predict_fail",   "name": "Predictive Failure",     "category": "observability","module": "predictive_failure",  "status": "stable", "version": "2.5.3"},
    {"id": "automation",     "name": "Automation Engine",      "category": "automation",   "module": "automation_engine",   "status": "stable", "version": "2.5.3"},
    {"id": "webhooks",       "name": "Webhooks",               "category": "automation",   "module": "webhook_manager",     "status": "stable", "version": "2.5.3"},
    {"id": "vnc_thumb",      "name": "VNC Thumbnails",         "category": "compute",      "module": "vnc_thumbnail",       "status": "stable", "version": "2.5.3"},
    {"id": "compute_tune",   "name": "Compute Tuning (KSM)",   "category": "compute",      "module": "compute_tuning",      "status": "stable", "version": "2.5.3"},
    {"id": "ldap",           "name": "LDAP/AD Integration",    "category": "security",     "module": "ldap_manager",        "status": "stable", "version": "2.5.3"},

    # ── v2.5.4 — Stable (hardware security, shipped 6+ months) ──────────────────
    {"id": "vtpm",           "name": "Virtual TPM 2.0",        "category": "security",     "module": "vtpm_manager",        "status": "stable", "version": "2.5.4"},
    {"id": "secure_boot",    "name": "Secure Boot",            "category": "security",     "module": "secureboot_manager",  "status": "stable", "version": "2.5.4"},
    {"id": "vault",          "name": "HashiCorp Vault",        "category": "security",     "module": "vault_integration",   "status": "stable", "version": "2.5.4"},
    {"id": "audit_chain",    "name": "Audit Log Chain",        "category": "security",     "module": "audit_chain",         "status": "stable", "version": "2.5.4"},
    {"id": "hugepages",      "name": "HugePages Auto",         "category": "compute",      "module": "hugepages_manager",   "status": "stable", "version": "2.5.4"},
    {"id": "sriov",          "name": "SR-IOV",                 "category": "network",      "module": "sriov_manager",       "status": "stable", "version": "2.5.4"},
    {"id": "vgpu",           "name": "vGPU (NVIDIA GRID/MIG)", "category": "compute",      "module": "vgpu_manager",        "status": "stable", "version": "2.5.4"},
    {"id": "cdp",            "name": "Continuous Data Protection","category": "storage",   "module": "cdp_manager",         "status": "beta",   "version": "2.5.4"},
    {"id": "boot_order",     "name": "DR Boot Order",          "category": "dr",           "module": "boot_order_manager",  "status": "stable", "version": "2.5.4"},
    {"id": "geo_dns",        "name": "Geo-DNS Failover",       "category": "dr",           "module": "geo_dns_manager",     "status": "beta",   "version": "2.5.4"},

    # ── v2.5.5 — Stable (security & compliance, production-hardened) ─────────────
    {"id": "sev_tdx",        "name": "AMD SEV / Intel TDX",    "category": "security",     "module": "confidential_vm",     "status": "stable", "version": "2.5.5"},
    {"id": "live_encrypt",   "name": "Live Disk Encryption",   "category": "security",     "module": "disk_encryption",     "status": "stable", "version": "2.5.5"},
    {"id": "compliance",     "name": "CIS/NIST/PCI-DSS",       "category": "security",     "module": "compliance_scanner",  "status": "stable", "version": "2.5.5"},
    {"id": "dlp",            "name": "DLP at Hypervisor",      "category": "security",     "module": "dlp_engine",          "status": "stable", "version": "2.5.5"},
    {"id": "forensics",      "name": "Forensics (mem/pcap)",   "category": "security",     "module": "forensics_engine",    "status": "stable", "version": "2.5.5"},
    {"id": "mfa_per_role",   "name": "MFA per Role",           "category": "security",     "module": "mfa_enforcement",     "status": "stable", "version": "2.5.5"},
    {"id": "saml_oidc",      "name": "SAML / OIDC SSO",        "category": "security",     "module": "sso_manager",         "status": "stable", "version": "2.5.5"},

    # ── v2.5.6 — Stable (multi-tenancy, billing) ──────────────────────────────────
    {"id": "tenant_iso",     "name": "Hard Tenant Isolation",  "category": "multi-tenancy","module": "tenant_manager",      "status": "stable", "version": "2.5.6"},
    {"id": "self_service",   "name": "Self-Service Portal",    "category": "multi-tenancy","module": "self_service_portal", "status": "stable", "version": "2.5.6"},
    {"id": "chargeback",     "name": "Chargeback / Showback",  "category": "multi-tenancy","module": "chargeback_engine",   "status": "stable", "version": "2.5.6"},
    {"id": "rp_reservation", "name": "Pool Reservations",      "category": "multi-tenancy","module": "resource_pool_manager","status": "stable","version": "2.5.6"},
    {"id": "service_catalog","name": "Service Catalog",        "category": "multi-tenancy","module": "service_catalog",     "status": "stable", "version": "2.5.6"},
    {"id": "api_rate_limit", "name": "API Rate Limit per Tenant","category": "multi-tenancy","module": "tenant_rate_limit", "status": "stable", "version": "2.5.6"},

    # ── v2.5.7 — Stable (backup advanced) ────────────────────────────────────────
    {"id": "app_consistent", "name": "App-Consistent Snapshots","category": "storage",     "module": "app_consistent_snapshot", "status": "stable", "version": "2.5.7"},
    {"id": "backup_321",     "name": "3-2-1 Backup",           "category": "storage",      "module": "backup_321",              "status": "stable", "version": "2.5.7"},
    {"id": "backup_verify",  "name": "Backup Verification",    "category": "storage",      "module": "backup_verify",           "status": "stable", "version": "2.5.7"},
    {"id": "cross_replicate","name": "Cross-Site Replication", "category": "dr",           "module": "cross_replication",       "status": "stable", "version": "2.5.7"},

    # ── v2.5.8 — Stable (observability) ──────────────────────────────────────────
    {"id": "otel",           "name": "Distributed Tracing",    "category": "observability","module": "otel_tracing",        "status": "stable", "version": "2.5.8"},
    {"id": "grafana_embed",  "name": "Grafana Embed",          "category": "observability","module": "grafana_embed",       "status": "stable", "version": "2.5.8"},
    {"id": "topology_viz",   "name": "Topology Visualization", "category": "observability","module": "topology_viz",        "status": "stable", "version": "2.5.8"},
    {"id": "heatmap",        "name": "Heatmaps + Forecast",    "category": "observability","module": "ml_forecaster",       "status": "stable", "version": "2.5.8"},
    {"id": "config_drift",   "name": "Config Drift Detection", "category": "lifecycle",    "module": "drift_capacity",      "status": "stable", "version": "2.5.8"},
    {"id": "capacity_plan",  "name": "Capacity Planning",      "category": "observability","module": "drift_capacity",      "status": "stable", "version": "2.5.8"},

    # ── v2.5.9 — Stable (network advanced 2) ─────────────────────────────────────
    {"id": "microseg",       "name": "Microsegmentation (L7 nftables)", "category": "network", "module": "microsegmentation", "status": "stable", "version": "2.5.9"},
    {"id": "bfd",            "name": "BFD (Bidirectional Forwarding)",  "category": "network", "module": "bfd_manager",       "status": "stable", "version": "2.5.9"},
    {"id": "service_chain",  "name": "Service Chaining (IDS/WAF/LB)",  "category": "network", "module": "service_chain",     "status": "stable", "version": "2.5.9"},
    {"id": "service_mesh",   "name": "Service Mesh (Istio/Linkerd)",   "category": "network", "module": "service_mesh",      "status": "stable", "version": "2.5.9"},

    # ── v2.5.10 — Beta (cloud/k8s — environment dependent) ───────────────────────
    {"id": "k8s_csi",        "name": "Kubernetes CSI",         "category": "automation",   "module": "k8s_csi",             "status": "beta",   "version": "2.5.10"},
    {"id": "k8s_operator",   "name": "Kubernetes Operator",    "category": "automation",   "module": "k8s_operator",        "status": "beta",   "version": "2.5.10"},
    {"id": "kubevirt",       "name": "KubeVirt",               "category": "automation",   "module": "kubevirt_integration","status": "beta",   "version": "2.5.10"},
    {"id": "gitops",         "name": "GitOps (ArgoCD/Flux)",   "category": "automation",   "module": "gitops_sync",         "status": "beta",   "version": "2.5.10"},
    {"id": "pulumi",         "name": "Pulumi Provider",        "category": "automation",   "module": "pulumi_provider",     "status": "stable", "version": "2.5.10"},

    # ── v2.5.11 — Beta (modern workloads — runtime dependent) ────────────────────
    {"id": "firecracker",    "name": "microVM (Firecracker)",  "category": "modern",       "module": "firecracker_mgr",     "status": "beta",   "version": "2.5.11"},
    {"id": "kata",           "name": "Kata Containers",        "category": "modern",       "module": "kata_runtime",        "status": "beta",   "version": "2.5.11"},
    {"id": "wasm",           "name": "WASM Runtime",           "category": "modern",       "module": "wasm_runtime",        "status": "beta",   "version": "2.5.11"},
    {"id": "edge",           "name": "Edge Deployment",        "category": "modern",       "module": "edge_mode",           "status": "beta",   "version": "2.5.11"},

    # ── v2.5.12 — Beta (IaC + clients, newly shipped) ────────────────────────────
    {"id": "workflow_engine","name": "Workflow Engine",        "category": "automation",   "module": "workflow_engine",     "status": "stable", "version": "2.5.12"},
    {"id": "opa",            "name": "Policy as Code (OPA)",   "category": "automation",   "module": "opa_policy",          "status": "stable", "version": "2.5.12"},
    {"id": "cloudevents",    "name": "CloudEvents",            "category": "automation",   "module": "cloudevents",         "status": "stable", "version": "2.5.12"},
    {"id": "electron",       "name": "Desktop Client",         "category": "modern",       "module": "electron_client",     "status": "beta",   "version": "2.5.12"},
    {"id": "workload_mob",   "name": "Workload Mobility (Cloud)","category": "modern",     "module": "cloud_export",        "status": "stable", "version": "2.5.12"},

    # ── v2.6.1 — New (added this release) ────────────────────────────────────────
    {"id": "fault_tolerance","name": "Fault Tolerance",        "category": "dr",           "module": "fault_tolerance",     "status": "beta",   "version": "2.6.1"},
    {"id": "storage_drs",   "name": "Storage DRS",            "category": "storage",      "module": "storage_drs",         "status": "beta",   "version": "2.6.1"},
    {"id": "console_rec",   "name": "VM Console Recording",   "category": "compute",      "module": "console_recorder",    "status": "beta",   "version": "2.6.1"},
    {"id": "recovery_codes","name": "2FA Recovery Codes",     "category": "security",     "module": "recovery_codes",      "status": "stable", "version": "2.6.1"},
    {"id": "plugin_sdk",    "name": "Plugin SDK",             "category": "automation",   "module": "plugin_sdk",          "status": "beta",   "version": "2.6.1"},
    {"id": "disk_hot_ext",  "name": "VM Disk Hot-Extend",     "category": "compute",      "module": "vm_hot_extend",       "status": "stable", "version": "2.6.1"},
    {"id": "bulk_vm_ops",   "name": "Bulk VM Operations",     "category": "compute",      "module": "bulk_vm_ops",         "status": "stable", "version": "2.6.1"},

    # ── v2.6.2 — Green Mode + OS branding + web installer ────────────────────────
    {"id": "green_mode",    "name": "Green Mode (Power AI)",  "category": "automation",   "module": "green_mode",          "status": "beta",   "version": "2.6.2"},
    {"id": "os_branding",   "name": "OS Rebranding",          "category": "lifecycle",    "module": "_script",             "status": "beta",   "version": "2.6.2"},

    # ── v2.6.3 — Multi-Region, Marketplace, Cloud Burst, Bare-Metal, OAuth2 ──
    {"id": "multi_region",  "name": "Multi-Region Placement", "category": "automation",   "module": "multi_region",        "status": "beta",   "version": "2.6.3"},
    {"id": "marketplace",   "name": "App Marketplace",        "category": "automation",   "module": "app_marketplace",     "status": "beta",   "version": "2.6.3"},
    {"id": "cloud_burst",   "name": "Cloud Bursting",         "category": "automation",   "module": "cloud_burst",         "status": "beta",   "version": "2.6.3"},
    {"id": "bare_metal",    "name": "Bare-Metal Provisioning","category": "lifecycle",    "module": "bare_metal",          "status": "beta",   "version": "2.6.3"},
    {"id": "oauth2_sso",    "name": "OAuth 2.0 SSO",          "category": "security",     "module": "oauth2_sso",          "status": "beta",   "version": "2.6.3"},

    # ── v2.7.0 — Confidential VM ext, Runbook Executor, Cluster Federation ──
    {"id": "vtpm_secboot",  "name": "vTPM + Secure Boot",     "category": "security",     "module": "confidential_vm",     "status": "beta",   "version": "2.7.0"},
    {"id": "attestation",   "name": "Confidential Attestation","category":"security",     "module": "confidential_vm",     "status": "beta",   "version": "2.7.0"},
    {"id": "runbook_exec",  "name": "Auto-Remediation Runbooks","category":"automation",  "module": "runbook_executor",    "status": "beta",   "version": "2.7.0"},
    {"id": "federation",    "name": "Managed Cluster Federation","category":"automation", "module": "cluster_federation",  "status": "beta",   "version": "2.7.0"},

    # ── v2.8.3 — Egress lockdown + Dark Site (offline / air-gap) ──────────────────
    {"id": "egress_guard",  "name": "Egress Lockdown",        "category": "security",     "module": "egress_guard",        "status": "stable", "version": "2.8.3"},
    {"id": "dark_site",     "name": "Dark Site Mode",         "category": "security",     "module": "dark_site",           "status": "stable", "version": "2.8.3"},
]


# ── Persistent state ──────────────────────────────────────────────────────────
# High-risk features: large attack surface, run arbitrary code or attach foreign
# binaries to the host. Default DISABLED — admin must opt-in explicitly via the
# Settings → Features panel or `oxctl feature enable <id>`.
HIGH_RISK_FEATURES = {
    "plugin_sdk",       # Loads arbitrary Python into the controller process
    "marketplace",      # Pulls remote packages
    "container_runtime", # Docker/LXC
    "os_branding",      # Rewrites system files
    "oxupdate",         # Downloads + executes update scripts
    "bare_metal",       # PXE/iPXE + IPMI takeover
    "cloud_burst",      # Provisions in third-party clouds with stored creds
    "kubevirt",         # Bridges into external K8s cluster
    "gitops",           # Auto-applies remote git state
    "k8s_operator",     # Foreign control-plane access
    "k8s_csi",
    "federation",       # Cross-controller call forwarding
}


def _load() -> dict:
    try:
        if _REGISTRY_FILE.exists():
            return json.loads(_REGISTRY_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("registry load fail: %s", e)
    # Defaults: stable+beta enabled, experimental+planned disabled,
    # HIGH_RISK_FEATURES disabled regardless of status — explicit opt-in required.
    state = {}
    for f in FEATURE_MANIFEST:
        default_on = f["status"] in ("stable", "beta") and f["id"] not in HIGH_RISK_FEATURES
        state[f["id"]] = {
            "enabled":   default_on,
            "installed": True,
            "config":    {},
        }
    return state


def _save(state: dict):
    try:
        _REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
        _REGISTRY_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception as e:
        log.warning("registry save fail: %s", e)


def _audit(event: str, feature_id: str, details: Optional[dict] = None):
    try:
        _AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _AUDIT_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts":         int(time.time()),
                "event":      event,
                "feature_id": feature_id,
                "details":    details or {},
            }) + "\n")
    except Exception:
        pass


# ── Public API ────────────────────────────────────────────────────────────────
def list_features(category: Optional[str] = None, status: Optional[str] = None) -> list:
    """Tüm feature'ları döndür (state merged)."""
    with _lock:
        state = _load()
        out = []
        for f in FEATURE_MANIFEST:
            if category and f["category"] != category:
                continue
            if status and f["status"] != status:
                continue
            s = state.get(f["id"], {})
            out.append({
                **f,
                "enabled":   s.get("enabled", False),
                "installed": s.get("installed", False),
                "config":    s.get("config", {}),
            })
        return out


def get_feature(feature_id: str) -> Optional[dict]:
    with _lock:
        state = _load()
        for f in FEATURE_MANIFEST:
            if f["id"] == feature_id:
                s = state.get(feature_id, {})
                return {**f, **s}
    return None


def is_enabled(feature_id: str) -> bool:
    f = get_feature(feature_id)
    return bool(f and f.get("enabled"))


def enable(feature_id: str, by_user: str = "system") -> dict:
    with _lock:
        state = _load()
        f = next((x for x in FEATURE_MANIFEST if x["id"] == feature_id), None)
        if not f:
            return {"ok": False, "error": f"Unknown feature: {feature_id}"}
        if f["status"] == "planned":
            return {"ok": False, "error": "Henüz uygulanmamış (planned)"}
        state.setdefault(feature_id, {})["enabled"] = True
        _save(state)
        _audit("enable", feature_id, {"user": by_user})
        log.info("feature enabled: %s (by %s)", feature_id, by_user)
        return {"ok": True, "enabled": True}


def disable(feature_id: str, by_user: str = "system") -> dict:
    with _lock:
        state = _load()
        state.setdefault(feature_id, {})["enabled"] = False
        _save(state)
        _audit("disable", feature_id, {"user": by_user})
        log.info("feature disabled: %s (by %s)", feature_id, by_user)
        return {"ok": True, "enabled": False}


def set_config(feature_id: str, config: dict, by_user: str = "system") -> dict:
    with _lock:
        state = _load()
        state.setdefault(feature_id, {})["config"] = config
        _save(state)
        _audit("config", feature_id, {"user": by_user, "keys": list(config.keys())})
        return {"ok": True}


def get_config(feature_id: str) -> dict:
    f = get_feature(feature_id)
    return (f or {}).get("config", {})


def get_categories() -> dict:
    """Kategori başına özet (toplam, etkin, planlanan)."""
    with _lock:
        state = _load()
        cats: dict = {}
        for f in FEATURE_MANIFEST:
            c = f["category"]
            d = cats.setdefault(c, {"total": 0, "enabled": 0, "planned": 0, "stable": 0, "beta": 0, "experimental": 0})
            d["total"] += 1
            d[f["status"]] = d.get(f["status"], 0) + 1
            if state.get(f["id"], {}).get("enabled"):
                d["enabled"] += 1
        return cats


def get_audit_log(limit: int = 100) -> list:
    """Son N audit kaydını döndür."""
    try:
        if not _AUDIT_FILE.exists():
            return []
        with _AUDIT_FILE.open(encoding="utf-8") as f:
            lines = f.readlines()
        out = []
        for line in lines[-limit:][::-1]:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
        return out
    except Exception:
        return []


def summary() -> dict:
    """Genel özet — kaç feature stable/beta/planned, kaç enabled."""
    with _lock:
        state = _load()
        total      = len(FEATURE_MANIFEST)
        enabled    = sum(1 for f in FEATURE_MANIFEST if state.get(f["id"], {}).get("enabled"))
        by_status  = {}
        by_version = {}
        for f in FEATURE_MANIFEST:
            by_status [f["status"]]  = by_status.get(f["status"], 0) + 1
            by_version[f["version"]] = by_version.get(f["version"], 0) + 1
        return {
            "total":     total,
            "enabled":   enabled,
            "disabled":  total - enabled,
            "by_status": by_status,
            "by_version":by_version,
            "categories":get_categories(),
        }


# CLI test
if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "summary"
    if cmd == "summary":
        print(json.dumps(summary(), indent=2, ensure_ascii=False))
    elif cmd == "list":
        for f in list_features(category=sys.argv[2] if len(sys.argv) > 2 else None):
            mark = "✓" if f["enabled"] else "✗"
            print(f"  [{mark}] {f['id']:20s} {f['name']:40s} {f['status']:12s} v{f['version']}")
    elif cmd == "enable":
        print(enable(sys.argv[2], by_user="cli"))
    elif cmd == "disable":
        print(disable(sys.argv[2], by_user="cli"))
    else:
        print("Usage: feature_registry.py [summary|list [category]|enable <id>|disable <id>]")
