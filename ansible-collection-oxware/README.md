# Ansible Collection — `oxware.kvm`

Manage an [OXware Hypervisor](https://oxware.top) from Ansible over its REST API.
Pure-stdlib HTTP client (no external Python deps), token or username/password auth,
check-mode support, and idempotent resource modules.

## Install

```bash
ansible-galaxy collection install oxware.kvm
# or from source:
ansible-galaxy collection build && ansible-galaxy collection install oxware-kvm-*.tar.gz
```

## Authentication

All modules share the `oxware.kvm.common` argument fragment:

| Option | Description |
|--------|-------------|
| `host` | OXware base URL, e.g. `https://oxware.example.com` (required) |
| `token` | API token / bearer (or use `username`+`password`) |
| `username` / `password` | Panel credentials (module logs in for you) |
| `verify_ssl` | Verify TLS (default `true`) |
| `timeout` | Request timeout seconds (default `30`) |

Tip: generate a scoped API key in **Integrations → API Keys** and pass it as `token`.

## Modules

| Module | Manages | States |
|--------|---------|--------|
| `vm` | Virtual machines | present / absent / started / stopped / rebooted / snapshot |
| `network` | Libvirt networks | present / absent |
| `disk` | VM disks | present (attach) / absent (detach) / resized |
| `snapshot` | VM snapshots | present / absent / reverted |
| `template` | VM templates | present (capture) / absent |
| `firewall_rule` | Host nftables rules | present / absent |
| `user` | Panel users + roles | present / absent |

## Example playbook

```yaml
- hosts: localhost
  vars:
    oxware_host: https://oxware.example.com
    oxware_token: "{{ lookup('env', 'OXWARE_TOKEN') }}"
  tasks:
    - name: Web VM
      oxware.kvm.vm:
        host: "{{ oxware_host }}"
        token: "{{ oxware_token }}"
        name: web-01
        state: present
        vcpus: 2
        memory_mb: 4096
        disk_gb: 40
        os_variant: ubuntu24.04

    - name: Data disk
      oxware.kvm.disk:
        host: "{{ oxware_host }}"
        token: "{{ oxware_token }}"
        vm: web-01
        state: present
        size_gb: 100

    - name: Pre-change snapshot
      oxware.kvm.snapshot:
        host: "{{ oxware_host }}"
        token: "{{ oxware_token }}"
        vm: web-01
        name: baseline
        state: present

    - name: Allow HTTPS
      oxware.kvm.firewall_rule:
        host: "{{ oxware_host }}"
        token: "{{ oxware_token }}"
        protocol: tcp
        dst_port: "443"
        action: accept
        state: present

    - name: Deploy operator
      oxware.kvm.user:
        host: "{{ oxware_host }}"
        token: "{{ oxware_token }}"
        username: ci-deploy
        password: "{{ ci_pw }}"
        role: operator
        state: present
```

## Notes

- `disk` (state=present) is **not** idempotent — it always attaches a new disk;
  register the returned `target_dev` if you later need to detach it.
- `template` capture requires the source VM to be **stopped**.
- Modules are validated for Python syntax and match the OXware REST contract;
  run against a staging OXware before production use.

MIT — see repository root `LICENSE`.
