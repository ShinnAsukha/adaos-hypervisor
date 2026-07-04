#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Manage OXware users (create/delete/role)."""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: user
short_description: Manage OXware panel users
description:
  - Create or delete OXware users and keep their role in sync. Idempotent
    (checks the existing user list; updates role only when it differs).
options:
  username:
    description: Username (3-64 chars, [A-Za-z0-9_.-]).
    type: str
    required: true
  state:
    description: Desired state.
    choices: [present, absent]
    default: present
  password:
    description: Password (required when creating a new user, min 8 chars).
    type: str
  role:
    description: User role.
    choices: [administrator, admin, operator, viewer, vm-user]
    default: viewer
extends_documentation_fragment:
  - oxware.kvm.common
author:
  - OXware (@oxware)
"""

EXAMPLES = r"""
- name: Ensure an operator exists
  oxware.kvm.user:
    host: https://oxware.example.com
    token: "{{ oxware_token }}"
    username: deploy
    password: "{{ deploy_pw }}"
    role: operator
    state: present

- name: Remove a user
  oxware.kvm.user:
    host: https://oxware.example.com
    token: "{{ oxware_token }}"
    username: intern
    state: absent
"""

RETURN = r"""
user:
  description: Username acted upon.
  returned: always
  type: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.oxware.kvm.plugins.module_utils.oxware_api import (
    COMMON_ARGS, build_client
)


def find_user(client, username):
    r = client.get("/api/users")
    users = r.get("users", r if isinstance(r, list) else [])
    for u in users:
        if isinstance(u, dict) and u.get("username") == username:
            return u
        if u == username:
            return {"username": username}
    return None


def run():
    args = dict(COMMON_ARGS)
    args.update(
        username = dict(type="str", required=True),
        state    = dict(type="str", default="present", choices=["present", "absent"]),
        password = dict(type="str", no_log=True),
        role     = dict(type="str", default="viewer",
                        choices=["administrator", "admin", "operator", "viewer", "vm-user"]),
    )
    module = AnsibleModule(argument_spec=args, supports_check_mode=True)
    client = build_client(module)
    p = module.params
    username = p["username"]

    existing = find_user(client, username)
    result = {"changed": False, "user": username}

    if module.check_mode:
        if p["state"] == "present":
            result["changed"] = (existing is None) or \
                (existing.get("role") is not None and existing.get("role") != p["role"])
        else:
            result["changed"] = existing is not None
        module.exit_json(**result)

    try:
        if p["state"] == "absent":
            if existing:
                client.delete("/api/users/" + username)
                result["changed"] = True
        else:  # present
            if not existing:
                if not p.get("password"):
                    module.fail_json(msg="password required to create user " + username)
                client.post("/api/users",
                            {"username": username, "password": p["password"], "role": p["role"]})
                result["changed"] = True
            elif existing.get("role") is not None and existing.get("role") != p["role"]:
                client.put("/api/users/%s/role" % username, {"role": p["role"]})
                result["changed"] = True
        module.exit_json(**result)
    except Exception as e:
        module.fail_json(msg=str(e), **result)


if __name__ == "__main__":
    run()
