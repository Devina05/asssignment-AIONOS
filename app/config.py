"""Configuration for the Veridian Corp Internal Service Agent.

Precedence (first match wins):
    1. environment variables
    2. agent_config.json in the project root or next to the package
    3. built-in defaults (empty = auth disabled until configured)

Required to enable sign-in:
    SUPABASE_URL   e.g. https://abcd1234.supabase.co
    SUPABASE_KEY   service role key (server-side) or anon key + RLS policies
Optional:
    SUPABASE_TABLE  default "app_users"
    SESSION_SECRET  HMAC key for signed cookies; set this in production
    ALLOWED_DOMAIN  default "veridian-corp.example"
    IT_EMAILS       comma-separated allowlist granted role=IT on signup
    FINANCE_EMAILS  comma-separated allowlist granted role=finance on signup
    ADMIN_EMAILS    comma-separated allowlist granted role=admin on signup
"""

import json
import os
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PKG_DIR.parent

DEFAULTS = {
    "supabase_url": "",
    "supabase_key": "",
    "supabase_table": "app_users",
    "session_secret": "dev-insecure-secret-change-me",
    "session_ttl": 8 * 3600,
    "allowed_domain": "veridian-corp.example",
    "it_emails": [],
    "finance_emails": [],
    "admin_emails": [],
}

CONFIG_CANDIDATES = (
    PROJECT_ROOT / "agent_config.json",
    PKG_DIR / "agent_config.json",
)


def _load_config():
    cfg = dict(DEFAULTS)
    for path in CONFIG_CANDIDATES:
        if path.exists():
            try:
                cfg.update({k: v for k, v in json.loads(path.read_text(encoding="utf-8")).items()})
            except (OSError, json.JSONDecodeError):
                pass
            break
    env_map = {
        "SUPABASE_URL": "supabase_url",
        "SUPABASE_KEY": "supabase_key",
        "SUPABASE_TABLE": "supabase_table",
        "SESSION_SECRET": "session_secret",
        "SESSION_TTL": "session_ttl",
        "ALLOWED_DOMAIN": "allowed_domain",
    }
    for env, key in env_map.items():
        if os.environ.get(env):
            cfg[key] = os.environ[env].strip()
    cfg["session_ttl"] = int(cfg.get("session_ttl") or 8 * 3600)
    for env, key in [("IT_EMAILS", "it_emails"), ("FINANCE_EMAILS", "finance_emails"), ("ADMIN_EMAILS", "admin_emails")]:
        if os.environ.get(env):
            cfg[key] = [e.strip().lower() for e in os.environ[env].split(",") if e.strip()]
        else:
            cfg[key] = [e.strip().lower() for e in cfg.get(key) or []]
    return cfg


CONFIG = _load_config()
SESSION_TTL = 8 * 3600


def configured():
    return bool(CONFIG["supabase_url"] and CONFIG["supabase_key"])