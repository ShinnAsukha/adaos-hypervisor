"""networks_bp — v2 network inventory + IP-pool helpers.

Mounted at /api/v2/networks. Read-mostly mirrors of the legacy network
routes plus two new helpers the panel was constructing client-side:
free-IP enumeration and bridge attachment count.

Endpoints:
    GET /api/v2/networks                          — list with light fields
    GET /api/v2/networks/<name>                   — detail
    GET /api/v2/networks/<name>/free-ips          — unused IPs in pool
    GET /api/v2/networks/<name>/attached-vms      — VMs using this network
    GET /api/v2/networks/host-interfaces          — host NIC inventory
"""
from __future__ import annotations
from flask import Blueprint

bp = Blueprint("v28_networks", __name__)

_require_auth = lambda fn: fn
_require_role = lambda *roles: (lambda fn: fn)
_ok = None
_err = None
_deps: dict = {}


def init_networks_bp(require_auth, require_role, ok, err, deps=None):
    global _require_auth, _require_role, _ok, _err, _deps
    _require_auth = require_auth
    _require_role = require_role
    _ok = ok
    _err = err
    _deps = deps or {}
    _register_routes()


def _safe_get(name):
    return _deps.get(name)


def _light_net(n):
    if not isinstance(n, dict):
        return {}
    return {
        "name": n.get("name"),
        "mode": n.get("mode") or n.get("forward_mode"),
        "bridge": n.get("bridge"),
        "cidr": n.get("cidr") or n.get("subnet"),
        "gateway": n.get("gateway"),
        "dhcp_start": n.get("dhcp_start"),
        "dhcp_end": n.get("dhcp_end"),
        "active": bool(n.get("active", True)),
        "autostart": bool(n.get("autostart", False)),
    }


def _register_routes():
    @bp.route("/api/v2/networks", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_networks_list():
        net_mgr = _safe_get("network_manager")
        list_fn = getattr(net_mgr, "list_networks", None) if net_mgr else None
        if not callable(list_fn):
            return _err("network_manager unavailable", 503)
        try:
            raw = list_fn() or []
            nets = [_light_net(n) for n in raw]
            return _ok(networks=nets, count=len(nets))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/networks/<name>", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_network_detail(name):
        net_mgr = _safe_get("network_manager")
        get_fn = getattr(net_mgr, "get_network", None) if net_mgr else None
        if not callable(get_fn):
            return _err("network_manager unavailable", 503)
        try:
            net = get_fn(name)
            if not net:
                return _err("network not found", 404)
            return _ok(network=_light_net(net))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/networks/<name>/free-ips", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator")
    def api_v2_network_free_ips(name):
        ipam = _safe_get("ipam") or _safe_get("network_manager")
        free_fn = getattr(ipam, "list_free_ips", None) if ipam else None
        if not callable(free_fn):
            return _err("ipam unavailable", 503)
        try:
            ips = free_fn(name) or []
            return _ok(network=name, free_ips=ips, count=len(ips))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/networks/<name>/attached-vms", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_network_attached(name):
        vm_mgr = _safe_get("vm_manager")
        list_fn = getattr(vm_mgr, "list_vms", None) if vm_mgr else None
        if not callable(list_fn):
            return _err("vm_manager unavailable", 503)
        try:
            raw = list_fn() or []
            attached = []
            for vm in raw:
                for nic in (vm.get("interfaces") or []):
                    if nic.get("network") == name:
                        attached.append({
                            "vm_id": vm.get("id") or vm.get("name"),
                            "vm_name": vm.get("name"),
                            "mac": nic.get("mac"),
                            "ip": nic.get("ip"),
                        })
                        break
            return _ok(network=name, vms=attached, count=len(attached))
        except Exception as e:
            return _err(str(e), 400)

    @bp.route("/api/v2/networks/host-interfaces", methods=["GET"])
    @_require_auth
    @_require_role("admin", "administrator", "operator", "viewer")
    def api_v2_host_ifaces():
        net_mgr = _safe_get("network_manager")
        host_fn = getattr(net_mgr, "list_host_interfaces", None) if net_mgr else None
        if not callable(host_fn):
            return _err("host iface list unavailable", 503)
        try:
            ifaces = host_fn() or []
            return _ok(interfaces=ifaces, count=len(ifaces))
        except Exception as e:
            return _err(str(e), 400)
