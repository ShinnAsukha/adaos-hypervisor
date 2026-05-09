"""
ldap_manager.py — LDAP / Active Directory integration
OXware Hypervisor backend module

Requires ldap3:  pip install ldap3
If ldap3 is not installed, all operations gracefully degrade.
"""

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    ldap3 = None

import json
import logging
import os
import threading

log = logging.getLogger("oxware.ldap")

CONFIG_FILE = "/etc/oxware/ldap_config.json"
_lock       = threading.Lock()

# Default config template
_DEFAULTS = {
    "enabled":        False,
    "server":         "",
    "port":           389,
    "use_ssl":        False,
    "base_dn":        "",
    "bind_dn":        "",
    "bind_password":  "",
    "user_filter":    "(objectClass=person)",
    "group_filter":   "(objectClass=group)",
    "admin_group":    "CN=OXware-Admins,DC=example,DC=com",
    "operator_group": "CN=OXware-Operators,DC=example,DC=com",
}


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

def get_config():
    """
    Return the current LDAP configuration (without bind_password).

    Returns:
        dict: enabled, server, port, use_ssl, base_dn, bind_dn,
              user_filter, group_filter, admin_group, operator_group, available
    """
    cfg = _DEFAULTS.copy()
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                stored = json.load(f)
            cfg.update(stored)
        except Exception as exc:
            log.error("get_config read error: %s", exc)

    # Never expose the password via this endpoint
    cfg.pop("bind_password", None)
    cfg["available"] = LDAP_AVAILABLE
    return cfg


def save_config(server, port, use_ssl, base_dn, bind_dn, bind_password,
                user_filter, group_filter, admin_group, operator_group):
    """
    Persist LDAP configuration to disk.

    Returns:
        dict: success, message
    """
    cfg = {
        "enabled":        True,
        "server":         server,
        "port":           int(port),
        "use_ssl":        bool(use_ssl),
        "base_dn":        base_dn,
        "bind_dn":        bind_dn,
        "bind_password":  bind_password,
        "user_filter":    user_filter,
        "group_filter":   group_filter,
        "admin_group":    admin_group,
        "operator_group": operator_group,
    }
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with _lock:
            with open(CONFIG_FILE, "w") as f:
                json.dump(cfg, f, indent=2)
        os.chmod(CONFIG_FILE, 0o600)
        log.info("LDAP config saved")
        return {"success": True, "message": "Configuration saved"}
    except Exception as exc:
        log.exception("save_config error: %s", exc)
        return {"success": False, "message": str(exc)}


def _full_config():
    """Return full config including bind_password (internal use only)."""
    cfg = _DEFAULTS.copy()
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                cfg.update(json.load(f))
        except Exception as exc:
            log.error("_full_config read error: %s", exc)
    return cfg


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def _connect(cfg=None):
    """
    Create and bind an ldap3 Connection.

    Returns:
        ldap3.Connection or None on failure.
    """
    if not LDAP_AVAILABLE:
        return None

    cfg = cfg or _full_config()
    try:
        tls = ldap3.Tls() if cfg.get("use_ssl") else None
        srv = Server(
            cfg["server"],
            port=int(cfg.get("port", 389)),
            use_ssl=bool(cfg.get("use_ssl")),
            tls=tls,
            get_info=ALL,
            connect_timeout=10,
        )
        conn = Connection(
            srv,
            user=cfg.get("bind_dn"),
            password=cfg.get("bind_password"),
            authentication=SIMPLE,
            auto_bind=True,
            receive_timeout=15,
        )
        return conn
    except Exception as exc:
        log.error("_connect error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Test connection
# ---------------------------------------------------------------------------

def test_connection():
    """
    Attempt to bind to the LDAP server with the stored credentials.

    Returns:
        dict: success, message, available
    """
    if not LDAP_AVAILABLE:
        return {
            "success":   False,
            "message":   "ldap3 library not installed — run: pip install ldap3",
            "available": False,
        }

    cfg = _full_config()
    if not cfg.get("server"):
        return {"success": False, "message": "LDAP server not configured",
                "available": True}

    conn = _connect(cfg)
    if conn is None:
        return {"success": False, "message": "Connection failed", "available": True}

    try:
        conn.unbind()
    except Exception:
        pass

    return {"success": True, "message": "LDAP connection successful", "available": True}


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def authenticate(username, password):
    """
    Authenticate a user against LDAP and determine their OXware role.

    Role resolution:
        admin_group   → role "admin"
        operator_group → role "operator"
        (any valid user) → role "viewer"

    Returns:
        dict: authenticated, username, role, display_name
    """
    _fail = {
        "authenticated": False,
        "username":       username,
        "role":           None,
        "display_name":   None,
    }

    if not LDAP_AVAILABLE:
        log.debug("authenticate: ldap3 not available")
        return _fail

    cfg = _full_config()
    if not cfg.get("enabled") or not cfg.get("server"):
        return _fail

    # Step 1: Bind with service account to find the user DN
    admin_conn = _connect(cfg)
    if admin_conn is None:
        return _fail

    try:
        base_dn     = cfg.get("base_dn", "")
        user_filter = cfg.get("user_filter", "(objectClass=person)")
        search_filter = f"(&{user_filter}(|(sAMAccountName={username})(uid={username})(mail={username})))"

        admin_conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["dn", "displayName", "memberOf", "cn"],
        )

        if not admin_conn.entries:
            log.info("authenticate: user '%s' not found in LDAP", username)
            return _fail

        entry      = admin_conn.entries[0]
        user_dn    = entry.entry_dn
        display    = str(entry["displayName"]) if "displayName" in entry else username
        member_of  = [str(g) for g in entry.get("memberOf", [])]

    except Exception as exc:
        log.error("authenticate search error: %s", exc)
        return _fail
    finally:
        try:
            admin_conn.unbind()
        except Exception:
            pass

    # Step 2: Bind as the user to verify password
    try:
        srv = ldap3.Server(
            cfg["server"],
            port=int(cfg.get("port", 389)),
            use_ssl=bool(cfg.get("use_ssl")),
            connect_timeout=10,
        )
        user_conn = Connection(
            srv,
            user=user_dn,
            password=password,
            authentication=SIMPLE,
            auto_bind=True,
            receive_timeout=15,
        )
        try:
            user_conn.unbind()
        except Exception:
            pass
    except Exception as exc:
        log.info("authenticate: invalid credentials for '%s': %s", username, exc)
        return _fail

    # Step 3: Determine role from group membership
    admin_group    = cfg.get("admin_group", "")
    operator_group = cfg.get("operator_group", "")

    if admin_group and any(admin_group.lower() in g.lower() for g in member_of):
        role = "admin"
    elif operator_group and any(operator_group.lower() in g.lower() for g in member_of):
        role = "operator"
    else:
        role = "viewer"

    log.info("LDAP auth success: %s → role=%s", username, role)
    return {
        "authenticated": True,
        "username":       username,
        "role":           role,
        "display_name":   display,
    }


# ---------------------------------------------------------------------------
# User listing
# ---------------------------------------------------------------------------

def get_users():
    """
    Retrieve all users from LDAP matching the configured user_filter.

    Returns:
        list[dict]: dn, username, display_name, email, groups
    """
    if not LDAP_AVAILABLE:
        log.debug("get_users: ldap3 not available")
        return []

    cfg  = _full_config()
    conn = _connect(cfg)
    if conn is None:
        return []

    users = []
    try:
        conn.search(
            search_base=cfg.get("base_dn", ""),
            search_filter=cfg.get("user_filter", "(objectClass=person)"),
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "uid", "displayName", "mail", "memberOf", "cn"],
        )
        for entry in conn.entries:
            sam = str(entry["sAMAccountName"]) if "sAMAccountName" in entry else ""
            uid = str(entry["uid"]) if "uid" in entry else ""
            users.append({
                "dn":           entry.entry_dn,
                "username":     sam or uid or str(entry["cn"]),
                "display_name": str(entry["displayName"]) if "displayName" in entry else "",
                "email":        str(entry["mail"]) if "mail" in entry else "",
                "groups":       [str(g) for g in entry.get("memberOf", [])],
            })
    except Exception as exc:
        log.error("get_users error: %s", exc)
    finally:
        try:
            conn.unbind()
        except Exception:
            pass

    return users


# ---------------------------------------------------------------------------
# User sync
# ---------------------------------------------------------------------------

def sync_users():
    """
    Synchronise LDAP users to the local user_manager.

    Returns:
        dict: success, synced_count, message
    """
    if not LDAP_AVAILABLE:
        return {"success": False, "synced_count": 0,
                "message": "ldap3 not available"}

    try:
        import user_manager  # type: ignore
    except ImportError:
        log.warning("sync_users: user_manager module not found")
        return {"success": False, "synced_count": 0,
                "message": "user_manager module not available"}

    ldap_users = get_users()
    synced = 0

    cfg            = _full_config()
    admin_group    = cfg.get("admin_group", "")
    operator_group = cfg.get("operator_group", "")

    for u in ldap_users:
        groups = u.get("groups", [])
        if admin_group and any(admin_group.lower() in g.lower() for g in groups):
            role = "admin"
        elif operator_group and any(operator_group.lower() in g.lower() for g in groups):
            role = "operator"
        else:
            role = "viewer"

        try:
            user_manager.sync_ldap_user(
                username=u["username"],
                display_name=u.get("display_name", ""),
                email=u.get("email", ""),
                role=role,
            )
            synced += 1
        except Exception as exc:
            log.warning("sync_users: failed to sync user '%s': %s",
                        u["username"], exc)

    log.info("LDAP sync complete: %d users synced", synced)
    return {"success": True, "synced_count": synced,
            "message": f"{synced} users synced from LDAP"}


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def is_enabled():
    """Return True if LDAP is configured and enabled."""
    cfg = get_config()
    return bool(cfg.get("enabled") and cfg.get("server"))
