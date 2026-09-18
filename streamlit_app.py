"""Streamlit frontend for the Veridian IT Service Agent.

Runs on streamlit run streamlit_app.py (Streamlit Cloud entrypoint).
Reuses the existing engine (app.agent / app.auth / app.db) in-process;
the HTTP server in app/server.py is not involved.

Auth requires SUPABASE_URL / SUPABASE_KEY (+ allowlists) configured
as env vars / Streamlit secrets before sign-in works.
"""

import streamlit as st

from app import agent, auth, db
from app.config import configured

agent.seed()

st.set_page_config(page_title="Veridian IT Service Agent", layout="wide")


def role(u):
    return (u.get("role") or "employee")


def is_staff(u):
    return role(u) in ("IT", "finance", "admin")


def scope(u):
    r = role(u)
    if r == "IT":
        return "it"
    if r == "finance":
        return "finance"
    return None


def covers(u, s):
    return role(u) == "admin" or scope(u) == s


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

if "user" not in st.session_state:
    st.session_state.user = None

if not st.session_state.user:
    st.title("Veridian Corp - Internal Service Agent")
    if not configured():
        st.warning("Sign-in is disabled: set SUPABASE_URL and SUPABASE_KEY as "
                   "Streamlit secrets / env vars, then restart the app.")
    login_tab, signup_tab = st.tabs(["Log in", "Sign up"])
    with login_tab:
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_pw")
        if st.button("Log in"):
            user, err = None, None
            try:
                user, err = auth.login(email, password)
            except RuntimeError as e:
                st.error(str(e))
            if err:
                st.error(err)
            elif user:
                st.session_state.user = auth.public_user(user)
                st.rerun()
    with signup_tab:
        s_email = st.text_input("Email", key="su_email")
        s_name = st.text_input("Name", key="su_name")
        s_password = st.text_input("Password (min 8 chars)", type="password", key="su_pw")
        if st.button("Sign up"):
            user, err = None, None
            try:
                user, err = auth.signup(s_email, s_name, s_password)
            except RuntimeError as e:
                st.error(str(e))
            if err:
                st.error(err)
            elif user:
                st.session_state.user = auth.public_user(user)
                st.rerun()
    st.stop()

user = st.session_state.user
is_staff_user = is_staff(user)
user_scope = scope(user)

with st.sidebar:
    st.write("**%s**  \n%s  \nrole: %s" % (user.get("name"), user.get("email"), role(user)))
    if st.button("Log out"):
        st.session_state.user = None
        st.rerun()

# ---------------------------------------------------------------------------
# Employee / staff shared: requests
# ---------------------------------------------------------------------------

all_requests = agent.agent_results()


def visible_requests():
    if role(user) == "employee":
        me = (user.get("email") or "").lower()
        return [r for r in all_requests if (r.get("email") or "").lower() == me]
    if user_scope:
        return [r for r in all_requests if agent.request_scope(r["request_id"]) == user_scope]
    return all_requests


def request_viewer(rid):
    det = agent.request_detail(rid)
    if not det:
        st.error("Unknown request")
        return
    c1, c2, c3 = st.columns(3)
    c1.metric("Request", det["request_id"])
    c2.metric("Status", det["status"])
    t = det.get("ticket") or {}
    c3.metric("Ticket", t.get("id") or "-")
    if t.get("status"):
        st.caption("ticket status: %s" % t["status"])
    if det.get("initial_action"):
        st.caption("initial action: %s" % det["initial_action"])
    for m in det["messages"]:
        st.chat_message("assistant" if m["sender"] == "agent" else "user").write(m["body"])
    if det["followups"]:
        open_q = [f["question"] for f in det["followups"] if not f["answer"]]
        if open_q:
            st.info("Awaiting your answer: " + open_q[0])
    if st.button("Escalate to a human", key=rid):
        agent.escalate_request(rid)
        st.rerun()
    answer = st.chat_input("Reply to the agent…", key="reply_" + rid)
    if answer and answer.strip():
        agent.continue_request(rid, answer.strip())
        st.rerun()


def new_request_tab():
    st.subheader("New request")
    text = st.text_area("Describe the issue you need help with", height=120,
                        key="triage_text")
    if st.button("Submit request"):
        if not text.strip():
            st.error("Describe your issue first.")
        else:
            out = agent.triage(text.strip(), user.get("name"), user.get("email"))
            st.session_state.selected = out["request_id"]
            st.rerun()


def my_requests_tab():
    st.subheader("Requests")
    rows = visible_requests()
    if not rows:
        st.info("No requests yet.")
        return
    ids = [r["request_id"] for r in rows]
    label = lambda i: "%s — %s (%s)" % (
        i, next(r["status"] for r in rows if r["request_id"] == i),
        (next(r["ticket"] for r in rows if r["request_id"] == i).get("id") or "no ticket"))
    sel = st.selectbox("Open a request", ids, format_func=label, key="req_select")
    request_viewer(sel)


# ---------------------------------------------------------------------------
# Staff: service desk / KB / audit
# ---------------------------------------------------------------------------

def service_desk_tab():
    st.subheader("Service desk queue")
    desk = agent.service_desk(scope=user_scope)
    st.caption(" | ".join("%s=%d" % (k, v) for k, v in desk["stats"].items()))
    queue = desk["queue"]
    if not queue:
        st.info("Queue is empty.")
        return
    sel = st.selectbox("Ticket", [t["id"] for t in queue],
                       format_func=lambda i: "%s — [%s] %s" % (
                           i, next(t["status"] for t in queue if t["id"] == i),
                           next((t["summary"] or "")[:60] for t in queue if t["id"] == i)),
                       key="tk_select")
    detail = agent.ticket_detail(sel)
    c1, c2, c3 = st.columns(3)
    c1.metric("Ticket", detail["id"])
    c2.metric("Status", detail["status"])
    c3.metric("Priority", detail["priority"] or "-")
    st.write("**%s**" % detail["summary"])
    st.write(detail.get("issue") or "")
    if detail.get("request_text"):
        st.caption("linked request: " + detail["request_text"])
    if detail.get("note"):
        st.caption("note: " + detail["note"])
    if detail.get("escalate_to"):
        st.caption("escalate to: " + str(detail["escalate_to"]))
    if detail.get("sources"):
        st.caption("sources: " + ", ".join(detail["sources"]))
    if detail["origin"] == "agent" and covers(user, agent.ticket_scope(detail)):
        statuses = agent.ALLOWED_TICKET_STATUSES
        pick = st.selectbox("Update status", statuses,
                            index=statuses.index(detail["status"])
                            if detail["status"] in statuses else 0,
                            key="status_pick_" + sel)
        if st.button("Set status", key="set_status_" + sel):
            try:
                agent.update_ticket_status(sel, pick, user.get("email"))
                st.rerun()
            except ValueError as e:
                st.error(str(e))
    else:
        st.caption("reference ticket (read-only)")


def kb_tab():
    st.subheader("Knowledge base")
    for item in agent.KB.values():
        with st.expander("%s — %s" % (item["id"], item["title"])):
            st.write(item["body"])


def audit_tab():
    st.subheader("Audit trail")
    rows = db.audit_log()
    if user_scope:
        rows = [r for r in rows
                if r.get("request_id") and agent.request_scope(r["request_id"]) == user_scope]
    if not rows:
        st.info("No audit events.")
        return
    st.dataframe(
        [{"ts": r["ts"], "step": r["step"], "detail": r["detail"],
          "request": r["request_id"] or "", "ticket": r["ticket_id"] or ""}
         for r in rows],
        use_container_width=True)


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

tabs = ["My Requests", "New Request"] + (["Service Desk", "Knowledge Base", "Audit"] if is_staff_user else [])
tab_objs = st.tabs(tabs)

with tab_objs[0]:
    my_requests_tab()
with tab_objs[1]:
    new_request_tab()

if is_staff_user:
    with tab_objs[2]:
        service_desk_tab()
    with tab_objs[3]:
        kb_tab()
    with tab_objs[4]:
        audit_tab()