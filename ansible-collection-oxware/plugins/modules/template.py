#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Manage OXware VM templates (create from VM / delete)."""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: template
short_description: Manage OXware VM templates
description:
  - Create a reusable template from an existing (stopped) VM, or delete a
    template. Idempotent — matches by template name.
options:
  name:
    description: Template name.
    type: str
    required: true
  state:
    description: Desired state.
    choices: [present, absent]
    default: present
  source_vm:
    description: Source VM name to capture (required for state=present).
    type: str
  description:
    description: Template description.
    type: str
    default: ""
  tags:
    description: Optional list of tags.
    type: list
    elements: str
extends_documentation_fragment:
  - oxware.kvm.common
author:
  - OXware (@oxware)
notes:
  - The source VM must be stopped for capture (OXware refuses a running VM).
"""

EXAMPLES = r"""
- name: Capture a golden template from a prepared VM
  oxware.kvm.template:
    host: https://oxware.example.com
    token: "{{ oxware_token }}"
    name: ubuntu-golden
    source_vm: build-vm
    description: Hardened Ubuntu base
    state: present

- name: Delete a template
  oxware.kvm.template:
    host: https://oxware.example.com
    token: "{{ oxware_token }}"
    name: ubuntu-golden
    state: absent
"""

RETURN = r"""
template:
  description: Template acted upon.
  returned: always
  type: dict
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


def find_template(client, name):
    for t in client.get("/api/templates").get("templates", []):
        if isinstance(t, dict) and t.get("name") == name:
            return t
    return None


def run():
    args = dict(COMMON_ARGS)
    args.update(
        name        = dict(type="str", required=True),
        state       = dict(type="str", default="present", choices=["present", "absent"]),
        source_vm   = dict(type="str"),
        description = dict(type="str", default=""),
        tags        = dict(type="list", elements="str"),
    )
    module = AnsibleModule(argument_spec=args, supports_check_mode=True)
    client = build_client(module)
    p = module.params

    existing = find_template(client, p["name"])
    result = {"changed": False, "template": existing}

    if module.check_mode:
        result["changed"] = (existing is None) if p["state"] == "present" else (existing is not None)
        module.exit_json(**result)

    try:
        if p["state"] == "present":
            if not existing:
                if not p.get("source_vm"):
                    module.fail_json(msg="source_vm required to create template " + p["name"])
                vm = find_vm(client, p["source_vm"])
                if not vm:
                    module.fail_json(msg="source VM not found: " + p["source_vm"])
                r = client.post("/api/templates", {
                    "vm_id": vm["id"], "name": p["name"],
                    "description": p["description"], "tags": p.get("tags"),
                })
                result.update(changed=True, template=r)
        else:  # absent
            if existing:
                tid = existing.get("id") or existing.get("tid")
                client.delete("/api/templates/" + str(tid))
                result.update(changed=True)
        module.exit_json(**result)
    except Exception as e:
        module.fail_json(msg=str(e), **result)


if __name__ == "__main__":
    run()
