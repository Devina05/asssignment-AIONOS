"""SQLite storage layer (stdlib sqlite3) for the operational store.

Holds the mutable state only: EmployeeRequests (with a live status), Tickets
(agent-generated) plus the pre-existing Ticket Queue rows, conversation
messages, citations, follow-ups and the append-only audit trail. Reference
policy data (KB + Asset Policy) lives in app/data/seed_data.json, not here, so
the "no invented policy" grounding guarantee is structural.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent
VAR_DIR = PKG_DIR.parent / "var"
DB_PATH = VAR_DIR / "agent.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    employee TEXT,
    email TEXT,
    date_opened TEXT,
    text TEXT NOT NULL,
    context TEXT,
    status TEXT,
    initial_action TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY,
    origin TEXT NOT NULL,
    request_id TEXT,
    employee TEXT,
    email TEXT,
    category TEXT,
    priority TEXT,
    status TEXT,
    intent TEXT,
    confidence INTEGER,
    summary TEXT,
    answer TEXT,
    note TEXT,
    escalate_to TEXT,
    follow_up TEXT,
    risk_flags TEXT,
    conflicts TEXT,
    consistency_note TEXT,
    description TEXT,
    is_open INTEGER,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS ticket_sources (
    ticket_id TEXT NOT NULL,
    source_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    body TEXT NOT NULL,
    sources TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT, actor TEXT, step TEXT, detail TEXT,
    sources TEXT, request_id TEXT, ticket_id TEXT
);
CREATE TABLE IF NOT EXISTS followups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    question TEXT NOT NULL,
    answer TEXT DEFAULT '',
    created_at TEXT,
    answered_at TEXT
);
"""


def q(sql, args=(), fetch=False):
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(sql, args)
        rows = cur.fetchall() if fetch else None
        conn.commit()
        return [dict(r) for r in rows] if rows is not None else []
    finally:
        conn.close()


def init_db():
    VAR_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(SCHEMA)
        for col in ("context", "status"):
            try:
                conn.execute("ALTER TABLE requests ADD COLUMN %s TEXT" % col)
            except sqlite3.OperationalError:
                pass
        conn.commit()
    finally:
        conn.close()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Conversation messages - one row per employee/agent message, per request.
# ---------------------------------------------------------------------------

def add_message(request_id, sender, body, sources=None):
    q("INSERT INTO messages(request_id,sender,body,sources,created_at) VALUES(?,?,?,?,?)",
      (request_id, sender, body, json.dumps(sources or []), now()))


def messages_for(request_id):
    rows = q("SELECT * FROM messages WHERE request_id=? ORDER BY id",
             (request_id,), fetch=True)
    for r in rows:
        r["sources"] = json.loads(r["sources"] or "[]")
    return rows


# ---------------------------------------------------------------------------
# Append-only audit trail
# ---------------------------------------------------------------------------

def audit(step, detail, sources=None, request_id=None, ticket_id=None):
    q("INSERT INTO audit(ts,actor,step,detail,sources,request_id,ticket_id) VALUES(?,?,?,?,?,?,?)",
      (now(), "agent", step, detail, json.dumps(sources or []), request_id, ticket_id))


def audit_for(request_id):
    rows = q("SELECT ts,actor,step,detail,sources,request_id,ticket_id FROM audit "
             "WHERE request_id=? ORDER BY id", (request_id,), fetch=True)
    for r in rows:
        r["sources"] = json.loads(r["sources"] or "[]")
    return rows


def audit_log():
    rows = q("SELECT ts,actor,step,detail,sources,request_id,ticket_id FROM audit ORDER BY id",
             fetch=True)
    for r in rows:
        r["sources"] = json.loads(r["sources"] or "[]")
    return rows