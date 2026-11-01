import hashlib
import hmac
import os
import secrets
import time
from functools import wraps

from flask import g, request, session

import db

ITERATIONS = 200_000

ROLES = ("viewer", "analyst", "admin")


def role_at_least(role, minimum):
    if role not in ROLES or minimum not in ROLES:
        return False
    return ROLES.index(role) >= ROLES.index(minimum)


def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        ITERATIONS
    ).hex()

    return password_hash, salt


def verify_password(password, stored_hash, salt):
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, stored_hash)


def create_user(username, password, role="viewer"):
    if role not in ROLES:
        raise ValueError("unknown role: " + str(role))

    password_hash, salt = hash_password(password)
    conn = db.get_connection()
    conn.execute(
        "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (username, password_hash, salt, role, time.time())
    )
    conn.commit()
    conn.close()


def get_user(username):
    conn = db.get_connection()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def check_login(username, password):
    if not isinstance(username, str) or not isinstance(password, str):
        return None

    user = get_user(username)
    if user is None:
        return None
    if not verify_password(password, user["password_hash"], user["salt"]):
        return None
    return user


def create_api_key(name, role):
    if role not in ROLES:
        raise ValueError("unknown role: " + str(role))

    secret = secrets.token_urlsafe(32)
    key_id = db.insert_api_key(name, role)

    secret_hash, salt = hash_password(secret)
    db.set_api_key_hash(key_id, salt + "$" + secret_hash)

    return "hids." + str(key_id) + "." + secret, key_id


def check_api_key(token):
    if not isinstance(token, str):
        return None

    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "hids":
        return None
    try:
        key_id = int(parts[1])
    except ValueError:
        return None
    secret = parts[2]

    row = db.get_api_key(key_id)
    if row is None or "$" not in row["key_hash"]:
        return None

    salt, stored_hash = row["key_hash"].split("$", 1)
    if not verify_password(secret, stored_hash, salt):
        return None

    db.touch_api_key(key_id)
    return {"username": "key:" + row["name"], "role": row["role"], "kind": "apikey"}


def do_login(user):
    session["username"] = user["username"]
    session["role"] = user["role"]


def do_logout():
    session.clear()
    g.pop("current_user", None)


def current_user():
    if "current_user" in g:
        return g.current_user

    user = None
    if "username" in session:
        user = {"username": session["username"], "role": session["role"], "kind": "session"}
    else:
        token = request.headers.get("X-API-Key")
        if token:
            user = check_api_key(token)

    g.current_user = user
    return user


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            return {"error": "authentication required"}, 401
        return view_func(*args, **kwargs)
    return wrapper


def require_role(minimum):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            user = current_user()
            if user is None:
                return {"error": "authentication required"}, 401
            if not role_at_least(user["role"], minimum):
                return {"error": "forbidden: requires role " + minimum}, 403
            return view_func(*args, **kwargs)
        return wrapper
    return decorator
