# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x (latest) | ✅ Active support |
| 1.x | ❌ End of life |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via one of the following:

- **Email:** adalyan06@gmail.com
- **GitHub Private Advisory:** [Security Advisories](https://github.com/ShinnAsukha/oxware-hypervisor/security/advisories/new)

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected component (backend, frontend, installer, license system)
- Potential impact assessment
- Your suggested fix (optional)

### Response timeline

| Stage | Timeframe |
|-------|-----------|
| Initial acknowledgement | Within 48 hours |
| Triage & severity assessment | Within 7 days |
| Fix development | Within 30 days (critical: 7 days) |
| Public disclosure | After fix is released |

We follow **responsible disclosure** — we will coordinate with you before any public announcement.

---

## Security Architecture

OXware runs as root on a KVM hypervisor host. The attack surface includes:

| Component | Notes |
|-----------|-------|
| Web UI (HTTPS :8006) | Flask + self-signed SSL, session auth |
| libvirt socket | Unix socket, root only |
| VNC ports (5900–5999) | Per-VM, bound to host |
| noVNC WebSocket (:6080) | Proxied through OXware |
| License validation | GitHub-hosted, Fernet-encrypted |

### Default hardening

- UFW firewall enabled on install (SSH + 8006 + VNC only)
- fail2ban active on SSH and web UI
- SSL/TLS enforced on all web traffic
- Session tokens stored server-side, rotated on login
- All VM operations require authentication
- License keys stored as SHA-256 hashes locally

---

## Known Security Considerations

- **Self-signed SSL:** Browsers will show a warning. Replace with a trusted certificate for production use.
- **Root process:** OXware runs as root (required for KVM/libvirt). Restrict network access accordingly.
- **VNC ports:** VNC sessions are not encrypted by default. Use noVNC (WebSocket proxy) or a VPN.
- **Default secret key:** The installer generates a random `secret_key`. Never use the default value in production.

---

## Vulnerability Disclosure History

| CVE / ID | Severity | Component | Status |
|----------|----------|-----------|--------|
| — | — | — | No public CVEs yet |

---

## Hall of Fame

We thank the following researchers for responsible disclosures:

*(None yet — be the first!)*

---

*OXware Security Team — adalyan06@gmail.com*
