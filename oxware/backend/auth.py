import json
import hashlib
import time
import os
from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import (
    create_access_token, verify_jwt_in_request,
    get_jwt_identity, get_jwt
)
import config

ROLES = {
    "administrator": ["*"],
    "operator": ["vm.*", "storage.read", "network.read", "system.read"],
    "viewer": ["*.read", "system.read"],
}


def _load_users():
    if not os.path.exists(config.USERS_FILE):
        # Varsayılan admin oluştur
        default_pass = hashlib.sha256(b"adaos123").hexdigest()
        users = {
            "admin": {
                "password": default_pass,
                "role": "administrator",
                "created": time.time(),
            }
        }
        _save_users(users)
        return users
    with open(config.USERS_FILE) as f:
        return json.load(f)


def _save_users(users):
    os.makedirs(os.path.dirname(config.USERS_FILE), exist_ok=True)
    with open(config.USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def verify_password(username, password):
    users = _load_users()
    user = users.get(username)
    if not user:
        return False
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return user["password"] == hashed


def get_user(username):
    users = _load_users()
    return users.get(username)


def list_users():
    users = _load_users()
    return [
        {
            "username": u,
            "role": d.get("role", "viewer"),
            "created": d.get("created"),
        }
        for u, d in users.items()
    ]


def create_user(username, password, role="operator"):
    users = _load_users()
    if username in users:
        raise ValueError(f"Kullanıcı zaten mevcut: {username}")
    users[username] = {
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "role": role,
        "created": time.time(),
    }
    _save_users(users)


def delete_user(username):
    users = _load_users()
    if username not in users:
        raise ValueError(f"Kullanıcı bulunamadı: {username}")
    if username == "admin":
        raise ValueError("Admin kullanıcısı silinemez")
    del users[username]
    _save_users(users)


def change_password(username, new_password):
    users = _load_users()
    if username not in users:
        raise ValueError(f"Kullanıcı bulunamadı: {username}")
    users[username]["password"] = hashlib.sha256(new_password.encode()).hexdigest()
    _save_users(users)


def jwt_required_role(*allowed_roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
            except Exception:
                return jsonify({"error": "Kimlik doğrulama gerekli"}), 401

            identity = get_jwt_identity()
            user = get_user(identity)
            if not user:
                return jsonify({"error": "Kullanıcı bulunamadı"}), 401

            role = user.get("role", "viewer")
            if allowed_roles and role not in allowed_roles and role != "administrator":
                return jsonify({"error": "Yetersiz yetki"}), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except Exception:
            return jsonify({"error": "Kimlik doğrulama gerekli"}), 401
        return fn(*args, **kwargs)
    return wrapper
