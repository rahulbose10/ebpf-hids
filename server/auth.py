import hashlib
import hmac
import os
import secrets
from functools import wraps

from flask import g, request, session

from server import db

ITERATIONS = 200_000

ROLES = ("viewer", "analyst", "admin")

_dummy = None


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
    db.insert_user(username, password_hash, salt, role)


def get_user(username):
    return db.get_user(username)


def _burn_same_time(password):
    global _dummy
    if _dummy is None:
        _dummy = hash_password("no-such-user")
    verify_password(password, _dummy[0], _dummy[1])


def check_login(username, password):
    if not isinstance(username, str) or not isinstance(password, str):
        return None

    user = get_user(username)
    if user is None:
        _burn_same_time(password)
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
    session.clear()
    session.permanent = True
    session["username"] = user["username"]


def do_logout():
    session.clear()
    g.pop("current_user", None)


def current_user():
    if "current_user" in g:
        return g.current_user

    user = None
    if "username" in session:
        row = get_user(session["username"])
        if row is None:
            session.clear()
        else:
            user = {"username": row["username"], "role": row["role"], "kind": "session"}
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
