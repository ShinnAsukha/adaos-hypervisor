<div align="center">

<img src="https://oxware.top/sadeceikon.png" alt="OXware" width="120" />

# OXware Hypervisor

### The open-source KVM/QEMU hypervisor with vCenter-class management.

<br>

[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e.svg?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.8.1-0091da.svg?style=for-the-badge)](https://github.com/ShinnAsukha/oxware-hypervisor/releases)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2.svg?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/c6yHhKrQs5)
[![Get OXware](https://img.shields.io/badge/⬇️_Get_OXware-Free-ff6b1a.svg?style=for-the-badge)](https://github.com/ShinnAsukha/oxware-hypervisor/releases)

<br>

![GitHub stars](https://img.shields.io/github/stars/ShinnAsukha/oxware-hypervisor?style=social)
![GitHub forks](https://img.shields.io/github/forks/ShinnAsukha/oxware-hypervisor?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/ShinnAsukha/oxware-hypervisor?style=social)

[![CI](https://img.shields.io/github/actions/workflow/status/ShinnAsukha/oxware-hypervisor/ci.yml?branch=main&label=CI&logo=github)](https://github.com/ShinnAsukha/oxware-hypervisor/actions)
[![Last commit](https://img.shields.io/github/last-commit/ShinnAsukha/oxware-hypervisor?logo=github)](https://github.com/ShinnAsukha/oxware-hypervisor/commits/main)
[![Downloads](https://img.shields.io/github/downloads/ShinnAsukha/oxware-hypervisor/total?logo=github)](https://github.com/ShinnAsukha/oxware-hypervisor/releases)
[![Contributors](https://img.shields.io/github/contributors/ShinnAsukha/oxware-hypervisor?logo=github)](https://github.com/ShinnAsukha/oxware-hypervisor/graphs/contributors)
[![Open issues](https://img.shields.io/github/issues/ShinnAsukha/oxware-hypervisor?logo=github)](https://github.com/ShinnAsukha/oxware-hypervisor/issues)
[![Closed PRs](https://img.shields.io/github/issues-pr-closed/ShinnAsukha/oxware-hypervisor?logo=github)](https://github.com/ShinnAsukha/oxware-hypervisor/pulls?q=is%3Apr+is%3Aclosed)

[![Platform](https://img.shields.io/badge/platform-Ubuntu_22.04+_|_Debian_12+-orange.svg)]()
[![Hypervisor](https://img.shields.io/badge/hypervisor-KVM%2FQEMU-red.svg)]()
[![Languages](https://img.shields.io/badge/i18n-TR_•_EN_•_ES_•_DE_•_ZH_•_FR-0091da.svg)]()
[![Confidential VMs](https://img.shields.io/badge/Confidential_VMs-SEV_•_TDX_•_vTPM-7c3aed.svg)]()
[![Audit-Ready](https://img.shields.io/badge/Compliance-SOC2_•_ISO27001_•_PCI_•_HIPAA-22c55e.svg)]()

<br>

[**🌐 Website**](https://oxware.top) ·
[**📚 Documentation**](https://oxware.top/docs/) ·
[**💰 Pricing**](https://oxware.top/pricing/) ·
[**🛒 Marketplace**](https://oxware.top/marketplace/) ·
[**🤝 Partners**](https://oxware.top/partners/) ·
[**🎓 Certification**](https://oxware.top/certification/) ·
[**🐛 Bug Bounty**](https://oxware.top/security/bug-bounty/) ·
[**📡 Status**](https://oxware.top/status/)

</div>

---

> **OXware replaces VMware vSphere — without the licence.**
> Confidential VMs (SEV/TDX) · DRS · HA · live migration · cluster federation · 6-language web UI · SOC 2 in progress · MIT licensed · **save 90%+ vs vSphere.**

---

## ⭐ Why OXware?

| | OXware | VMware vSphere | Proxmox VE |
|---|:---:|:---:|:---:|
| Open source (MIT) | ✅ | ❌ | ✅ (GPL) |
| Per-CPU socket tax | ❌ none | 💸 yes | ❌ none |
| Confidential VMs (SEV/TDX) | ✅ | ✅ | partial |
| vTPM 2.0 per VM | ✅ | ✅ | partial |
| Cluster federation API | ✅ v2 | ✅ vCenter | ❌ |
| Live migration | ✅ | ✅ | ✅ |
| Runbook auto-remediation | ✅ | partial | ❌ |
| GitOps (ArgoCD/Flux) | ✅ | ❌ | ❌ |
| Kubernetes CSI driver | ✅ | ✅ | community |
| KubeVirt bridge | 🟠 partial | ❌ | ❌ |
| Built-in compliance scanner | ✅ | partial | ❌ |
| **3-year cost (32 cores, 50 VMs)** | **~$2,250** | ~$200,000 | ~$5,000 |

---

## ✅ Is it real? — build maturity, no marketing

We hate "✅" tables that lie. Here is exactly what is production-grade, what
is usable-but-young, and what is honestly not finished yet. CI runs the real
test suite on every push (badge above is live).

| Area | Status | What that means |
|---|:---:|---|
| VM lifecycle (create/start/stop/snapshot/clone/migrate) | 🟢 Stable | Core path, covered by the test suite + daily use |
| Networking (bridges, NAT, IPAM, nftables, port-forward) | 🟢 Stable | Real libvirt + nftables, SSRF-guarded outbound |
| Storage (qcow2, LVM, NFS, snapshots, 3-2-1 backup) | 🟢 Stable | Backup verified with mount + boot check |
| Auth / RBAC / JWT (HS256-locked, CSRF, audit log) | 🟢 Stable | Algorithm allowlist enforced + tested |
| Confidential VMs (SEV/TDX), vTPM 2.0 | 🟡 Beta | Works on supported hardware; needs host firmware |
| Ceph storage backend | 🟡 Community | Functional, community-tested, not first-class yet |
| AI planner / NL commands | 🟡 Optional | With AI key = AI; **without a key it tells you so** and falls back to transparent heuristics (`source: "heuristic"`) — no fake "AI" output |
| KubeVirt bridge | 🟠 Partial | Cluster registration + VMI→OXware spec translation are real; **no live watch/reconcile loop yet** (applied out-of-band) |
| Bare-metal autoinstall | 🟢 Stable | Per-install random password hash, SSH-key-only login |
| Desktop (Electron) app | 🟠 Early | Wraps the web UI; some links still placeholder |

Legend: 🟢 stable · 🟡 beta/optional · 🟠 partial/early. If something here drifts
from reality, [open an issue](https://github.com/ShinnAsukha/oxware-hypervisor/issues) — honesty in this table is a feature.

---

## 🚀 Quick Install

```bash
curl -sSL https://oxware.top/install.sh | sudo bash
```

> Ubuntu 22.04+ / Debian 12+ • x86_64 with VT-x or AMD-V • 4 GB RAM minimum
> Installation takes ~3 minutes. Panel listens on `https://<host-ip>:8006`.

**Prefer not to pipe curl into bash?**

```bash
git clone https://github.com/ShinnAsukha/oxware-hypervisor.git /opt/oxware-src
cd /opt/oxware-src
sudo bash install.sh
```

---

## 📦 What's in the box

<table>
<tr>
<td width="50%" valign="top">

### 🖥️ VMs & lifecycle
- Create / start / stop / pause / clone / snapshot / migrate
- Disk hot-extend, SMART, qcow2 + raw
- noVNC + SPICE + xterm.js console
- Import: OVA / OVF / VMDK / VHD / VHDX / raw
- Cloud-init first-boot
- Live migration between OXware nodes
- Bulk operations w/ HMAC-bound confirm tokens

### 🌐 Networking
- libvirt bridges, NAT, isolated, routed
- IPAM with CIDR pools + DHCP static leases
- Per-VM nftables firewall, port-forward DNAT
- HAProxy + WireGuard helpers
- BGP peering (FRR), DNS manager
- Subnet calculator
- v2.7.2 SSRF guards on every outbound call

### 💾 Storage
- qcow2, LVM, NFS, Ceph (community), MinIO/S3
- Snapshots: live + scheduled + app-consistent
- 3-2-1 backup automation, mount + boot verify
- SFTP, MinIO, S3 backup targets
- Cross-site disk replication
- **Kubernetes CSI driver** (v2.7.2)

</td>
<td width="50%" valign="top">

### 🔐 Security
- RBAC: administrator / operator / viewer / vm-user
- TOTP 2FA + single-use recovery codes
- SAML 2.0 + OIDC SSO (Okta, Entra, Google, Keycloak)
- OAuth2 one-click presets (v2.7.2)
- LDAP / AD with group-to-role mapping
- API keys with scopes
- Hash-chained audit log (SHA-256)
- SSH known-hosts + first-contact approval (v2.7.2)
- **Bug bounty**: $50–$5000 per finding

### 🛡️ Confidential computing
- AMD SEV / SEV-ES / SEV-SNP
- Intel TDX
- vTPM 2.0 per VM
- UEFI Secure Boot
- Launch attestation report capture

### 🤖 AI + automation
- **OXY** — natural-language ops copilot
- Anomaly detector (z-score per metric)
- Auto-remediation runbooks (notify / shell / api_call / vm_action)
- Capacity forecasting
- Right-sizing recommendations
- **GitOps manager** (ArgoCD/Flux dirs)

### 🌍 Cloud-native (v2.7.2)
- Kubernetes **CSI driver**
- **KubeVirt** bridge
- **Firecracker** microVM runtime (<125 ms boot)
- **PWA offline mode** (read-only fallback)
- **CycloneDX SBOM** per release

</td>
</tr>
</table>

---

## 🌍 Six interface languages

Full parity, 2400+ entries per language. CI gate blocks any merge that introduces an untranslated Turkish string.

🇹🇷 Türkçe · 🇬🇧 English · 🇪🇸 Español · 🇩🇪 Deutsch · 🇨🇳 中文 · 🇫🇷 Français

---

## 🛠️ Tech stack

```
┌─────────────────────────────────────────────────────────────┐
│  Web UI (HTML/JS, no build step)        REST API + WebSocket │
│         ↕                                       ↕            │
│                    Flask 3.x backend                          │
│         ↕                                       ↕            │
│   libvirt / QEMU              nftables / iptables             │
│         ↕                                                     │
│   KVM (Linux kernel)                                          │
└─────────────────────────────────────────────────────────────┘
```

- **Backend** — Python 3.11+, Flask, Flask-SocketIO, libvirt-python
- **Frontend** — Single-page HTML + vanilla JS (no React/Vue/Webpack)
- **Reverse proxy** — nginx + Let's Encrypt
- **Process supervision** — systemd
- **Storage** — qcow2 default, plus LVM / ZFS / Ceph / NFS / MinIO / S3
- **Networking** — libvirt bridges, nftables firewall, optional Open vSwitch

---

## 📚 Resources

| Where | What |
|---|---|
| [**oxware.top**](https://oxware.top) | Marketing site + live demo + cost calculator |
| [**oxware.top/docs/**](https://oxware.top/docs/) | Full installation + admin guide |
| [**oxware.top/pricing/**](https://oxware.top/pricing/) | Pricing — Standard $35/mo · Pro $250/yr · Lifetime $2000 |
| [**oxware.top/marketplace/**](https://oxware.top/marketplace/) | Curated plugin + template registry |
| [**oxware.top/partners/**](https://oxware.top/partners/) | Reseller program — 30% recurring commission |
| [**oxware.top/certification/**](https://oxware.top/certification/) | OXware Certified Administrator ($99 exam) |
| [**oxware.top/compliance/**](https://oxware.top/compliance/) | SOC 2 / ISO 27001 / CIS / NIST / PCI / HIPAA |
| [**oxware.top/status/**](https://oxware.top/status/) | Live SaaS uptime + incident history |
| [**oxware.top/security/bug-bounty/**](https://oxware.top/security/bug-bounty/) | Bug bounty program (up to $5,000 / bug) |
| [**Discord**](https://discord.gg/c6yHhKrQs5) | Community chat — questions, plugin showcase, alpha-test announcements |
| [**SECURITY.md**](SECURITY.md) | Vulnerability disclosure policy + SEC-001..033 history |
| [**CHANGELOG.md**](CHANGELOG.md) | Per-release feature + security changelog |
| [**MODULARIZATION_PLAN.md**](MODULARIZATION_PLAN.md) | v2.8 app.py → blueprints migration plan |
| [**CONTRIBUTING.md**](CONTRIBUTING.md) | Dev setup + PR guidelines + commit format |

---

## ⚡ What's new in v2.8.1

VM boot health-check, per-VM disk I/O QoS, AI Ops Insights with role-gated tools, carbon/energy report, snapshot-chain analysis, Vault→VM secret injection, attestation dashboard, federation mTLS, SDN VXLAN overlays, built-in L4 load balancer, golden-image marketplace, OVA export, vApp boot orchestration, scheduled reports, live VM thumbnails, 14 panel themes, onboarding tour, firmware boot splash. Full i18n parity across EN/ES/DE/ZH/FR. See [`CHANGELOG.md`](CHANGELOG.md).

## ⚡ v2.8.0 — Modularization

**Modularization seed:** app.py split into 5 domain blueprints. New `/api/v2/` endpoints under `auth`, `vms`, `networks`, `storage`, `monitoring`. Legacy `/api/*` untouched. See [`MODULARIZATION_PLAN.md`](MODULARIZATION_PLAN.md).

## ⚡ What shipped in v2.7.2

**Security (SEC-029..033)** — Safe archive extraction, DNS rebinding mitigation, FTP backup deprecated, SSH known-hosts + first-contact approval, Bandit + pip-audit in CI.

**8 new feature modules** — Kubernetes CSI driver, KubeVirt bridge, GitOps manager, Firecracker microVM runtime, OAuth2 provider presets, audit-log retention policy, CycloneDX SBOM generator, PWA offline mode.

**i18n parity** — French (FR) added; 6 languages with CI gate.

See [`CHANGELOG.md`](CHANGELOG.md) for the full list.

---

## 🛡️ Security

OXware ships with `security_utils.py` carrying validated helpers for SSRF blocking (`validate_external_url`), shell argv injection guards (`validate_vm_id`, `safe_subprocess_arg`), safe archive extraction (`safe_tar_extract`, `safe_zip_extract`), and DNS rebinding mitigation (`resolve_safe_host`).

**33 SEC-tracked patches** to date (SEC-001 through SEC-033) across auth, federation, runbook executor, plugin SDK, and bulk operations. Full history in [`SECURITY.md`](SECURITY.md).

**Found a vulnerability?** Report via [GitHub Security Advisories](https://github.com/ShinnAsukha/oxware-hypervisor/security/advisories/new) or email `root@oxware.top`. Bounties up to **$5,000 / bug** — see the [Bug Bounty program](https://oxware.top/security/bug-bounty/).

---

## ⚙️ API

```bash
# Get a JWT token
curl -k -X POST https://host:8006/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpass"}'

# Use it
curl -k https://host:8006/api/vms -H "Authorization: Bearer $TOKEN"
```

Swagger UI lives at `https://<host>:8006/api/docs`. Full OpenAPI 3 spec at `/api/openapi`. **~290 endpoints** across VM management, networking, storage, RBAC, monitoring, CSI, KubeVirt, GitOps, Firecracker, runbooks, federation, OAuth2, SBOM, PWA, and the new v2.8 `/api/v2/*` blueprint routes.

A [Terraform provider](terraform-provider-oxware/) ships with `oxware_vm`, `oxware_network`, `oxware_storage_pool` resources.

---

## 🤝 Contributing

PRs welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) first:

- Run `make i18n-check` before pushing if you touched `index.html`
- Run `make security` to fire Bandit + pip-audit
- Run `make test` — the SEC-017..033 regression suite must stay green
- New features need an entry in `CHANGELOG.md`
- Don't add new routes to `app.py` — use a blueprint under `oxware/backend/blueprints/`. See [`MODULARIZATION_PLAN.md`](MODULARIZATION_PLAN.md).

By the way — a quick **⭐ star** is the cheapest way to say thanks and helps OXware appear in GitHub trending. It takes a second.

---

## 📈 Star history

[![Star History Chart](https://api.star-history.com/svg?repos=ShinnAsukha/oxware-hypervisor&type=Date)](https://star-history.com/#ShinnAsukha/oxware-hypervisor&Date)

---

## 💬 Community

- **Discord** — [discord.gg/c6yHhKrQs5](https://discord.gg/c6yHhKrQs5)
- **GitHub Discussions** — [github.com/ShinnAsukha/oxware-hypervisor/discussions](https://github.com/ShinnAsukha/oxware-hypervisor/discussions)
- **Issues** — [github.com/ShinnAsukha/oxware-hypervisor/issues](https://github.com/ShinnAsukha/oxware-hypervisor/issues)
- **Security** — [GitHub Security Advisories](https://github.com/ShinnAsukha/oxware-hypervisor/security/advisories/new) or `root@oxware.top`

---

## 📄 Licence

OXware is released under the [MIT License](LICENSE). Use it commercially, fork it, embed it, sell support around it — go ahead. Just keep the copyright notice.

A **Pro / Lifetime** plan unlocks priority issue triage, all v2.x updates, and partner perks. Source remains MIT regardless. See [pricing](https://oxware.top/pricing/) for details. Pricing is symbolic; the code is and will remain free.

---

<div align="center">

**Built with ❤️ for operators who think VMware should not charge per CPU socket.**

[⭐ Star this repo](https://github.com/ShinnAsukha/oxware-hypervisor) ·
[💬 Join Discord](https://discord.gg/c6yHhKrQs5) ·
[⬇️ Get OXware](https://github.com/ShinnAsukha/oxware-hypervisor/releases) ·
[🌐 oxware.top](https://oxware.top)

</div>
