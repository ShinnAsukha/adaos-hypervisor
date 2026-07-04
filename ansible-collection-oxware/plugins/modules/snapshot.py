#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Manage OXware VM snapshots (create/delete/revert)."""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: snapshot
short_description: Manage OXware VM snapshots
description:
  - Create, delete, or revert snapshots of an OXware VM. Idempotent for
    create/delete (checks the existing snapshot list first).
options:
  vm:
    description: Target VM name.
    type: str
    required: true
  name:
    description: Snapshot name.
    type: str
    required: true
  state:
    description: >
      C(present) creates the snapshot if missing. C(absent) deletes it.
      C(reverted) rolls the VM back to it.
    choices: [present, absent, reverted]
    default: present
  description:
    description: Snapshot description (state=present).
    type: str
    default: ""
extends_documentation_fragment:
  - oxware.kvm.common
author:
  - OXware (@oxware)
"""

EXAMPLES = r"""
- name: Snapshot before upgrade
  oxware.kvm.snapshot:
    host: https://oxware.example.com
    token: "{{ oxware_token }}"
    vm: web-01
    name: pre-upgrade
    state: present
    description: Before applying patches

- name: Roll back
  oxware.kvm.snapshot:
    host: https://oxware.example.com
    token: "{{ oxware_token }}"
    vm: web-01
    name: pre-upgrade
    state: reverted
"""

RETURN = r"""
snapshot:
  description: Snapshot name acted upon.
  returned: always
  type: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.oxware.kvm.plugins.module_utils.oxware_api import (
    COMMON_ARGS, build_client
)


def find_vm(client, name):
    for v in client.get("/api/vms").get("vms", []):
        if v.get("name") == name:
            return v
    return None


def snapshot_exists(client, vid, snap):
    r = client.get("/api/vms/%s/snapshots" % vid)
    snaps = r.get("snapshots", r if isinstance(r, list) else [])
    for s in snaps:
        nm = s.get("name") if isinstance(s, dict) else s
        if nm == snap:
            return True
    return False


def run():
    args = dict(COMMON_ARGS)
    args.update(
        vm          = dict(type="str", required=True),
        name        = dict(type="str", required=True),
        state       = dict(type="str", default="present",
                           choices=["present", "absent", "reverted"]),
        description = dict(type="str", default=""),
    )
    module = AnsibleModule(argument_spec=args, supports_check_mode=True)
    client = build_client(module)
    p = module.params

    vm = find_vm(client, p["vm"])
    if not vm:
        module.fail_json(msg="VM not found: " + p["vm"])
    vid = vm["id"]
    snap = p["name"]
    exists = snapshot_exists(client, vid, snap)
    result = {"changed": False, "snapshot": snap}

    # Idempotency in check mode
    if module.check_mode:
        if p["state"] == "present":
            result["changed"] = not exists
        elif p["state"] == "absent":
            result["changed"] = exists
        elif p["state"] == "reverted":
            result["changed"] = True
        module.exit_json(**result)

    try:
        if p["state"] == "present":
            if not exists:
                client.post("/api/vms/%s/snapshots" % vid,
                            {"name": snap, "description": p["description"]})
                result["changed"] = True
        elif p["state"] == "absent":
            if exists:
                client.delete("/api/vms/%s/snapshots/%s" % (vid, snap))
                result["changed"] = True
        elif p["state"] == "reverted":
            if not exists:
                module.fail_json(msg="Snapshot not found: " + snap)
            client.post("/api/vms/%s/snapshots/%s/revert" % (vid, snap), {})
            result["changed"] = True
        module.exit_json(**result)
    except Exception as e:
        module.fail_json(msg=str(e), **result)


if __name__ == "__main__":
    run()
