#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Manage OXware VM disks (attach/detach/resize)."""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: disk
short_description: Manage OXware VM disks
description:
  - Attach a new disk, detach an existing one, or resize a disk on an OXware VM.
options:
  vm:
    description: Target VM name.
    type: str
    required: true
  state:
    description: >
      C(present) attaches a new disk. C(absent) detaches the disk named by
      I(target_dev). C(resized) grows the disk at I(disk_index) to I(size_gb).
    choices: [present, absent, resized]
    default: present
  size_gb:
    description: Disk size in GB (state=present) or new size (state=resized).
    type: int
  bus:
    description: Disk bus (state=present).
    type: str
    default: virtio
  format:
    description: Disk format (state=present).
    type: str
    default: qcow2
  target_dev:
    description: Target device name to detach (state=absent), e.g. vdb.
    type: str
  disk_index:
    description: Disk index to resize (state=resized).
    type: int
    default: 0
extends_documentation_fragment:
  - oxware.kvm.common
author:
  - OXware (@oxware)
notes:
  - Attach (state=present) is not idempotent — it always creates+attaches a new
    disk. Register the returned target_dev if you need to detach later.
"""

EXAMPLES = r"""
- name: Attach a 100 GB data disk
  oxware.kvm.disk:
    host: https://oxware.example.com
    token: "{{ oxware_token }}"
    vm: db-01
    state: present
    size_gb: 100

- name: Grow the primary disk to 80 GB
  oxware.kvm.disk:
    host: https://oxware.example.com
    token: "{{ oxware_token }}"
    vm: db-01
    state: resized
    disk_index: 0
    size_gb: 80

- name: Detach a data disk
  oxware.kvm.disk:
    host: https://oxware.example.com
    token: "{{ oxware_token }}"
    vm: db-01
    state: absent
    target_dev: vdb
"""

RETURN = r"""
result:
  description: API response (attached disk info / detach / resize).
  returned: on change
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


def run():
    args = dict(COMMON_ARGS)
    args.update(
        vm         = dict(type="str", required=True),
        state      = dict(type="str", default="present",
                          choices=["present", "absent", "resized"]),
        size_gb    = dict(type="int"),
        bus        = dict(type="str", default="virtio"),
        format     = dict(type="str", default="qcow2"),
        target_dev = dict(type="str"),
        disk_index = dict(type="int", default=0),
    )
    module = AnsibleModule(argument_spec=args, supports_check_mode=True)
    client = build_client(module)
    p = module.params

    vm = find_vm(client, p["vm"])
    if not vm:
        module.fail_json(msg="VM not found: " + p["vm"])
    vid = vm["id"]
    result = {"changed": False}

    if module.check_mode:
        module.exit_json(**result)

    try:
        if p["state"] == "present":
            if not p.get("size_gb"):
                module.fail_json(msg="size_gb required for state=present")
            r = client.post("/api/vms/%s/hardware/disk/attach" % vid,
                            {"size_gb": p["size_gb"], "bus": p["bus"], "format": p["format"]})
            result.update(changed=True, result=r)
        elif p["state"] == "absent":
            if not p.get("target_dev"):
                module.fail_json(msg="target_dev required for state=absent")
            r = client.delete("/api/vms/%s/hardware/disk/%s" % (vid, p["target_dev"]))
            result.update(changed=True, result=r)
        elif p["state"] == "resized":
            if not p.get("size_gb"):
                module.fail_json(msg="size_gb (new size) required for state=resized")
            r = client.post("/api/vms/%s/disk/resize" % vid,
                            {"disk_index": p["disk_index"], "new_size_gb": p["size_gb"]})
            result.update(changed=True, result=r)
        module.exit_json(**result)
    except Exception as e:
        module.fail_json(msg=str(e), **result)


if __name__ == "__main__":
    run()
