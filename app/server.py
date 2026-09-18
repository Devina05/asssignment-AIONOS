"""HTTP server + process entry point for the Internal Service Agent.

Stdlib ThreadingHTTPServer; auth-gated JSON API over the agent engine plus the
static frontend (static/). Run with:  python -m app.main   (or: python -m app)

Role model (three scopes):
- employee -> own requests only (list, detail, continue, escalate)
- IT       -> IT scope only: IT tickets / requests in the IT service desk,
              status updates on them, their audit events, queue + knowledge base
- finance  -> Finance scope only: finance tickets (pending Finance sign-off,
              expense access, home-office allowance, finance & assets),
              status updates on them, their audit events, queue + knowledge base
- admin    -> every scope (oversee everything): both desks, all requests,
              full audit trail, all status controls, queue + knowledge base
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote

from . import agent
from . import auth
from . import db
from .config import configured
from .db import q

PKG_DIR = Path(__file__).resolve().parent
STATIC_DIR = PKG_DIR.parent / "static"


def _role(user):
    return (user.get("role") or "employee")


def _is_admin(user):
    return _role(user) == "admin"


def _is_staff(user):
    return _role(user) in ("IT", "finance", "admin")


def _staff_scope(user):
    """The department scope a staff member owns (admin = both = None)."""
    role = _role(user)
    if role == "IT":
        return "it"
    if role == "finance":
        return "finance"
    return None


def _covers_scope(user, scope):
    if _is_admin(user):
        return True
    return bool(scope) and _staff_scope(user) == scope


def _can_view_request(user, rid):
    """May this user open request `rid`? Owner always; IT/finance within their
    scope; admin everywhere."""
    role = _role(user)
    if role == "employee":
        return bool(rid) and agent.owns_request(user, rid)
    if _is_admin(user):
        return True
    return bool(rid) and agent.request_scope(rid) == _staff_scope(user)


def _can_view_ticket(user, tid):
    role = _role(user)
    if _is_admin(user):
        return True
    if role == "employee":
        return False
    return bool(tid) and agent.ticket_scope_by_id(tid) == _staff_scope(user)


def _scoped_audit(user):
    rows = db.audit_log()
    scope = _staff_scope(user)
    if scope and not _is_admin(user):
        return [r for r in rows if r.get("request_id") and agent.request_scope(r["request_id"]) == scope]
    return rows


def _annotate(user, out):
    """Attach scope + can_act so the UI can hide actions the user may not take."""
    rid = out.get("request_id")
    if rid:
        out["scope"] = agent.request_scope(rid)
        out["can_act"] = _can_view_request(user, rid)
    return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/json", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        for name, value in (headers or []):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _html(self, filename):
        return self._send(200, (STATIC_DIR / filename).read_text(encoding="utf-8"),
                          "text/html; charset=utf-8")

    def _query(self):
        parts = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
        return {k: unquote(v[0]) for k, v in parts.items()}

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/login", "/login.html"):
            return self._html("login.html")
        if path in ("/", "/index.html"):
            if not auth.user_from_headers(self.headers):
                return self._redirect("/login")
            return self._html("index.html")

        user = auth.user_from_headers(self.headers)
        if path == "/api/me":
            if not user:
                return self._send(401, {"error": "not authenticated"})
            return self._send(200, user)
        if not user:
            return self._send(401, {"error": "not authenticated"})

        if path == "/api/kb":
            if not _is_staff(user):
                return self._send(403, {"error": "staff role required"})
            return self._send(200, agent.KB)

        if path == "/api/requests":
            data = agent.agent_results()
            scope = _staff_scope(user)
            if scope:
                data = [r for r in data if agent.request_scope(r["request_id"]) == scope]
            elif _role(user) == "employee":
                email = (user.get("email") or "").lower()
                data = [r for r in data if (r.get("email") or "").lower() == email]
            return self._send(200, data)

        if path == "/api/request-detail":
            rid = self._query().get("request_id")
            if not rid:
                return self._send(400, {"error": "request_id required"})
            if not _can_view_request(user, rid):
                return self._send(403, {"error": "not your request"})
            det = agent.request_detail(rid)
            if det is None:
                return self._send(404, {"error": "unknown request_id"})
            return self._send(200, det)

        if path in ("/api/queue", "/api/seed-tickets"):
            if not _is_staff(user):
                return self._send(403, {"error": "staff role required"})
            return self._send(200, agent.all_tickets("history"))

        if path == "/api/service-desk":
            if not _is_staff(user):
                return self._send(403, {"error": "staff role required"})
            qs = self._query()
            scope = qs.get("scope") or _staff_scope(user)
            if scope not in ("it", "finance"):
                scope = _staff_scope(user) or ""
            if scope and not _covers_scope(user, scope):
                return self._send(403, {"error": "outside your scope"})
            try:
                limit = int(qs["limit"]) if qs.get("limit") else None
            except ValueError:
                limit = None
            return self._send(200, agent.service_desk(qs.get("q"), qs.get("status") or None, limit, scope or None))

        if path == "/api/ticket-detail":
            tid = self._query().get("ticket_id")
            if not tid:
                return self._send(400, {"error": "ticket_id required"})
            if not _can_view_ticket(user, tid):
                return self._send(403, {"error": "outside your scope"})
            det = agent.ticket_detail(tid)
            if det is None:
                return self._send(404, {"error": "unknown ticket_id"})
            return self._send(200, det)

        if path == "/api/audit":
            if not _is_staff(user):
                return self._send(403, {"error": "staff role required"})
            return self._send(200, _scoped_audit(user))

        return self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid json"})
        path = self.path.split("?")[0]

        if path == "/api/signup":
            try:
                user, err = auth.signup(data.get("email"), data.get("name"), data.get("password"))
            except RuntimeError as e:
                return self._send(503, {"error": str(e)})
            if err:
                return self._send(400, {"error": err})
            cookie = auth.cookie_header(auth.make_session(user))
            return self._send(200, auth.public_user(user), headers=[("Set-Cookie", cookie)])
        if path == "/api/login":
            try:
                user, err = auth.login(data.get("email"), data.get("password"))
            except RuntimeError as e:
                return self._send(503, {"error": str(e)})
            if err:
                return self._send(401, {"error": err})
            cookie = auth.cookie_header(auth.make_session(user))
            return self._send(200, auth.public_user(user), headers=[("Set-Cookie", cookie)])
        if path == "/api/logout":
            return self._send(200, {"ok": True}, headers=[("Set-Cookie", auth.clear_cookie_header())])

        user = auth.user_from_headers(self.headers)
        if not user:
            return self._send(401, {"error": "not authenticated"})

        if path in ("/api/triage", "/api/request"):
            if data.get("request_id") and (data.get("answer") or "").strip():
                rid = data["request_id"]
                if not _can_view_request(user, rid):
                    return self._send(403, {"error": "not your request"})
                out = agent.continue_request(rid, data["answer"].strip())
                if out is None:
                    return self._send(404, {"error": "unknown request_id"})
                return self._send(200, _annotate(user, out))
            text = (data.get("text") or "").strip()
            if not text:
                return self._send(400, {"error": "text required"})
            if _is_staff(user):
                out = agent.triage(text, data.get("employee") or user.get("name"),
                                   data.get("email") or user.get("email"))
            else:
                out = agent.triage(text, user.get("name"), user.get("email"))
            return self._send(200, _annotate(user, out))

        if path == "/api/escalate":
            rid = data.get("request_id")
            if not rid:
                return self._send(400, {"error": "request_id required"})
            if not _can_view_request(user, rid):
                return self._send(403, {"error": "not your request"})
            out = agent.escalate_request(rid, data.get("note"))
            if out is None:
                return self._send(404, {"error": "unknown request_id"})
            return self._send(200, _annotate(user, out))

        if path == "/api/ticket-status":
            if not _is_staff(user):
                return self._send(403, {"error": "staff role required"})
            tid = data.get("ticket_id")
            status = (data.get("status") or "").strip()
            if not tid or not status:
                return self._send(400, {"error": "ticket_id and status required"})
            if not _can_view_ticket(user, tid):
                return self._send(403, {"error": "outside your scope"})
            try:
                updated = agent.update_ticket_status(tid, status, user.get("email"))
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            if updated is None:
                return self._send(404, {"error": "unknown ticket_id"})
            return self._send(200, updated)

        return self._send(404, {"error": "not found"})


def selftest():
    print("=" * 100)
    print("SELF-TEST - agent disposition of stored requests (from SQLite)")
    print("=" * 100)
    for r in agent.agent_results():
        t = r.get("ticket") or {}
        tstr = "%s (%s)" % (t.get("id"), t.get("status")) if t.get("id") else "NO TICKET (self-service)"
        print("%s | %-16s | %-26s | %s" % (r["request_id"], r["employee"], r["status"], tstr))
        det = agent.request_detail(r["request_id"])
        for m in det["messages"]:
            if m["sender"] == "agent":
                body = (m["body"] or "").replace("\n", " ")
                print("    -> %s%s" % (body[:160], " ..." if len(body) > 160 else ""))
                if m.get("sources"):
                    print("       sources: %s" % ", ".join(m["sources"]))
        if det.get("ticket") and det["ticket"].get("note"):
            print("       note: %s" % det["ticket"]["note"])
    print("-" * 100)
    desk = agent.service_desk()
    stats = desk["stats"]
    print("Service desk stats: %s" % "; ".join("%s=%d" % (k, stats[k]) for k in sorted(stats)))
    n_history = sum(1 for t in desk["queue"] if t["origin"] == "history")
    n_agent = sum(1 for t in desk["queue"] if t["origin"] == "agent")
    print("Queue rows: total=%d (history=%d, agent=%d)" % (len(desk["queue"]), n_history, n_agent))
    mc = q("SELECT COUNT(*) AS n FROM messages", fetch=True)[0]["n"]
    ac = q("SELECT COUNT(*) AS n FROM audit", fetch=True)[0]["n"]
    rc = q("SELECT COUNT(*) AS n FROM requests", fetch=True)[0]["n"]
    tc = q("SELECT COUNT(*) AS n FROM tickets", fetch=True)[0]["n"]
    print("=" * 100)
    print("Rows in %s -> requests: %s | tickets: %s | messages: %s | audit: %s" % (
        db.DB_PATH.name, rc, tc, mc, ac))


def main():
    agent.seed()
    if "--selftest" in sys.argv:
        selftest()
        return
    port = 8000
    if not configured():
        print("WARNING: Supabase auth is not configured. Set SUPABASE_URL and SUPABASE_KEY")
        print("         (or create agent_config.json). Sign-in will return 503 until then.")
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("Internal Service Agent running at http://localhost:%d" % port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()