"""Authentication for the Veridian IT Service Agent.

Accounts live in an EXTERNAL database (Supabase / hosted Postgres) and are
reached over its REST API using only the Python standard library. Nothing here
touches the operational store (var/agent.db) - user identity is deliberately
kept out of it.

Configuration lives in app/config.py (env vars > agent_config.json > defaults).
"""

import base64
import hashlib
import hmac
import json
import os
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .config import CONFIG, configured

# ---------------------------------------------------------------------------
# Supabase REST (PostgREST) client - stdlib only
# ---------------------------------------------------------------------------


def sb_request(method, path, params=None, body=None, prefer=None, timeout=12):
    if not configured():
        raise RuntimeError("Supabase is not configured (set SUPABASE_URL and SUPABASE_KEY).")
    url = CONFIG["supabase_url"].rstrip("/") + "/rest/v1/" + path
    if params:
        url += "?" + urlencode(params)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {
        "apikey": CONFIG["supabase_key"],
        "Authorization": "Bearer " + CONFIG["supabase_key"],
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        raise RuntimeError("Supabase HTTP %s: %s" % (e.code, detail[:300]))
    except URLError as e:
        raise RuntimeError("Cannot reach Supabase: %s" % e.reason)
    return json.loads(raw) if raw else None


def _users(params=None, body=None, method="GET", prefer=None):
    return sb_request(method, CONFIG["supabase_table"], params=params, body=body, prefer=prefer)


# ---------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------

_ITERATIONS = 200_000


def hash_password(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return "pbkdf2_sha256$%d$%s$%s" % (_ITERATIONS, salt.hex(), dk.hex())


def verify_password(password, stored):
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# Signed session cookies
# ---------------------------------------------------------------------------

def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64u(text):
    text += "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text.encode("ascii"))


def _sign(raw):
    return _b64u(hmac.new(CONFIG["session_secret"].encode("utf-8"), raw.encode("ascii"), hashlib.sha256).digest())


def make_session(user):
    payload = {
        "email": user["email"],
        "name": user.get("name") or user["email"].split("@")[0],
        "role": user.get("role") or "employee",
        "exp": int(time.time()) + CONFIG.get("session_ttl", 8 * 3600),
    }
    raw = _b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return raw + "." + _sign(raw)


def read_session(cookie_value):
    if not cookie_value or "." not in cookie_value:
        return None
    raw, _, sig = cookie_value.partition(".")
    try:
        if not hmac.compare_digest(sig, _sign(raw)):
            return None
        payload = json.loads(_unb64u(raw))
    except (ValueError, json.JSONDecodeError):
        return None
    if payload.get("exp", 0) < time.time():
        return None
    return payload


def cookie_header(session_value, max_age=None):
    max_age = max_age or CONFIG.get("session_ttl", 8 * 3600)
    return "session=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d" % (session_value, max_age)


def clear_cookie_header():
    return "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"


def user_from_headers(headers):
    cookie = headers.get("Cookie", "")
    for part in cookie.split(";"):
        name, _, value = part.strip().partition("=")
        if name == "session":
            return read_session(value)
    return None


# ---------------------------------------------------------------------------
# Sign-up / sign-in
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def public_user(user):
    return {"email": user["email"], "name": user.get("name") or "", "role": user.get("role") or "employee"}


def _signup_role(email):
    email = email.lower()
    if email in CONFIG["admin_emails"]:
        return "admin"
    if email in CONFIG["it_emails"]:
        return "IT"
    if email in CONFIG["finance_emails"]:
        return "finance"
    return "employee"


def signup(email, name, password):
    email = (email or "").strip().lower()
    name = (name or "").strip()
    if not EMAIL_RE.match(email):
        return None, "Enter a valid email address."
    if not email.endswith("@" + CONFIG["allowed_domain"].lower()):
        return None, "Sign-up is restricted to @%s addresses." % CONFIG["allowed_domain"]
    if len(password or "") < 8:
        return None, "Password must be at least 8 characters."
    if _users(params={"email": "eq." + email, "select": "id"}):
        return None, "An account with that email already exists."
    role = _signup_role(email)
    row = {
        "email": email,
        "name": name or email.split("@")[0],
        "password_hash": hash_password(password),
        "role": role,
    }
    created = _users(body=row, method="POST", prefer="return=representation")
    if not created:
        return None, "Could not create the account."
    return created[0], None


def login(email, password):
    email = (email or "").strip().lower()
    if not email or not password:
        return None, "Email and password are required."
    rows = _users(params={"email": "eq." + email, "select": "*"})
    if not rows:
        return None, "No account found for that email."
    user = rows[0]
    if not verify_password(password, user.get("password_hash") or ""):
        return None, "Incorrect password."
    return user, None