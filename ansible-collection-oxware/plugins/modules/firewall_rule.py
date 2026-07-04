#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Manage OXware host firewall (nftables) rules."""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: firewall_rule
short_description: Manage OXware nftables firewall rules
description:
  - Add or remove host firewall rules. Idempotent — matches an existing rule
    by protocol/src/dst/port/action within a chain before adding or deleting.
options:
  chain:
    description: nftables chain.
    type: str
    default: input
  table:
    description: nftables table.
    type: str
    default: "inet filter"
  protocol:
    description: Protocol (tcp/udp/icmp).
    type: str
  src_ip:
    description: Source IP/CIDR.
    type: str
  dst_ip:
    description: Destination IP/CIDR.
    type: str
  dst_port:
    description: Destination port.
    type: str
  action:
    description: Rule action.
    choices: [accept, drop, reject]
    default: accept
  comment:
    description: Rule comment.
    type: str
    default: ""
  state:
    description: Desired state.
    choices: [present, absent]
    default: present
extends_documentation_fragment:
  - oxware.kvm.common
author:
  - OXware (@oxware)
"""

EXAMPLES = r"""
- name: Allow SSH from the management subnet
  oxware.kvm.firewall_rule:
    host: https://oxware.example.com
    token: "{{ oxware_token }}"
    chain: input
    protocol: tcp
    src_ip: 10.0.0.0/24
    dst_port: "22"
    action: accept
    comment: mgmt-ssh
    state: present

- name: Remove that rule
  oxware.kvm.firewall_rule:
    host: https://oxware.example.com
    token: "{{ oxware_token }}"
    chain: input
    protocol: tcp
    src_ip: 10.0.0.0/24
    dst_port: "22"
    action: accept
    state: absent
"""

RETURN = r"""
rule:
  description: Matched/created rule.
  returned: on change
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.oxware.kvm.plugins.module_utils.oxware_api import (
    COMMON_ARGS, build_client
)


def _matches(rule, p):
    def eq(a, b):
        return (a or "") == (b or "")
    return (eq(rule.get("chain"), p["chain"])
            and eq(rule.get("protocol"), p.get("protocol"))
            and eq(rule.get("src_ip"), p.get("src_ip"))
            and eq(rule.get("dst_ip"), p.get("dst_ip"))
            and eq(str(rule.get("dst_port") or ""), str(p.get("dst_port") or ""))
            and eq(rule.get("action"), p["action"]))


def find_rule(client, p):
    for r in client.get("/api/firewall/rules").get("rules", []):
        if _matches(r, p):
            return r
    return None


def run():
    args = dict(COMMON_ARGS)
    args.update(
        chain    = dict(type="str", default="input"),
        table    = dict(type="str", default="inet filter"),
        protocol = dict(type="str"),
        src_ip   = dict(type="str"),
        dst_ip   = dict(type="str"),
        dst_port = dict(type="str"),
        action   = dict(type="str", default="accept", choices=["accept", "drop", "reject"]),
        comment  = dict(type="str", default=""),
        state    = dict(type="str", default="present", choices=["present", "absent"]),
    )
    module = AnsibleModule(argument_spec=args, supports_check_mode=True)
    client = build_client(module)
    p = module.params

    existing = find_rule(client, p)
    result = {"changed": False}

    if module.check_mode:
        result["changed"] = (existing is None) if p["state"] == "present" else (existing is not None)
        module.exit_json(**result)

    try:
        if p["state"] == "present":
            if not existing:
                r = client.post("/api/firewall/rules", {
                    "table": p["table"], "chain": p["chain"], "protocol": p.get("protocol"),
                    "src_ip": p.get("src_ip"), "dst_ip": p.get("dst_ip"),
                    "dst_port": p.get("dst_port"), "action": p["action"], "comment": p["comment"],
                })
                client.post("/api/firewall/save", {})
                result.update(changed=True, rule=r)
        else:  # absent
            if existing:
                handle = existing.get("handle")
                if handle is None:
                    module.fail_json(msg="matched rule has no handle; cannot delete")
                client.request("DELETE", "/api/firewall/rules/%s" % handle,
                               {"table": p["table"], "chain": p["chain"]})
                client.post("/api/firewall/save", {})
                result.update(changed=True, rule=existing)
        module.exit_json(**result)
    except Exception as e:
        module.fail_json(msg=str(e), **result)


if __name__ == "__main__":
    run()
