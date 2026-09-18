"""Veridian Corp - Internal Service Agent (engine).

Deterministic, grounded engine: intent classification, policy handlers and the
EmployeeRequest -> decision -> (Ticket?) pipeline. It answers only from the
frozen reference data (KB-01..KB-10 + Asset Management Policy); it never
invents policy, and it makes no LLM calls (Gemini is optional per the brief).

Assignment alignment:
- Tickets are NOT created for every request (guest Wi-Fi, self-service answers
  resolve without one). Requests that need IT action, tracking, approval,
  investigation or escalation get a Ticket.
- Ticket status uses the assignment vocabulary: In Progress, Pending Security
  Review, Pending Finance, Escalated to Security, Waiting for Employee, ...
- Every employee/agent message and every audit event is persisted.

Public flow:
    triage(text, employee, email)          -> classify, decide, ticket?, audit
    continue_request(request_id, answer)   -> keep the conversation; re-decide
    escalate_request(request_id, note)     -> force an open escalated Ticket
"""

import json
import re
from pathlib import Path

from . import db
from .db import q, now, audit, init_db

PKG_DIR = Path(__file__).resolve().parent
SEED_PATH = PKG_DIR / "data" / "seed_data.json"
SEED = json.loads(SEED_PATH.read_text(encoding="utf-8"))
KB = SEED["kb"]

REQ_RE = re.compile(r"REQ-(\d+)")
TK_RE = re.compile(r"TK-(\d+)")


def next_request_id():
    rows = q("SELECT id FROM requests", fetch=True)
    maxn = 0
    for r in rows:
        m = REQ_RE.match(r["id"])
        if m:
            maxn = max(maxn, int(m.group(1)))
    return "REQ-%02d" % (maxn + 1)


def next_ticket_id():
    rows = q("SELECT id FROM tickets", fetch=True)
    maxn = 1051
    for r in rows:
        m = TK_RE.match(r["id"])
        if m:
            maxn = max(maxn, int(m.group(1)))
    return "TK-%d" % (maxn + 1)


# ---------------------------------------------------------------------------
# INTENT CLASSIFIER - weighted keyword matching over the issue text.
# ---------------------------------------------------------------------------

INTENTS = {
    "admin_access": [
        ("admin access", 6), ("administrator access", 6), ("privileged access", 6),
        ("admin rights", 6), ("finance reporting server", 6), ("admin on", 4),
    ],
    "security_incident": [
        ("phishing", 6), ("malware", 6), ("unauthorized access", 6), ("ransomware", 6),
        ("suspicious email", 4), ("hacked", 4), ("virus", 3),
    ],
    "guest_wifi": [
        ("guest wi-fi", 6), ("guest wifi", 6), ("guest network", 6),
        ("wi-fi access", 4), ("wifi access", 4), ("guest", 3), ("visitor", 3),
    ],
    "vpn": [("vpn", 6)],
    "expense": [("expense", 6)],
    "mailbox": [
        ("mailbox", 6), ("quota", 5), ("inbox full", 5), ("mailbox is full", 6),
        ("can't send", 4), ("cannot send", 4), ("email full", 5),
    ],
    "printer": [
        ("printer", 6), ("paper jam", 6), ("spooler", 6), ("printing", 4), ("print", 2),
    ],
    "password_reset": [
        ("locked out", 6), ("password", 6), ("failed attempts", 6), ("tried my password", 6),
        ("account locked", 6), ("forgot", 3), ("can't log in", 4), ("cannot log in", 4),
        ("log in", 2), ("login", 2), ("sign in", 2),
    ],
    "software": [
        ("install", 4), ("software", 5), ("browser extension", 6), ("extension", 4),
        ("catalog", 4), ("data-analysis", 5), ("application", 2), ("tool", 2),
    ],
    "laptop": [
        ("laptop", 6), ("won't turn on", 6), ("wont turn on", 6), ("completely dead", 6),
        ("screen is flickering", 6), ("flickering", 5), ("hardware failure", 6),
        ("replacement", 4), ("notebook", 3), ("dead", 3),
    ],
    "wfh": [
        ("work from home", 6), ("working from home", 6), ("wfh", 6), ("home office", 6),
        ("home office equipment", 7), ("remote", 3), ("monitor", 3), ("chair", 3), ("allowance", 3),
    ],
}

SAFETY_INTENTS = ("admin_access", "security_incident")


def classify(text):
    low = text.lower()
    scores = {}
    for intent, kws in INTENTS.items():
        total = sum(w for kw, w in kws if kw in low)
        if total:
            scores[intent] = total
    if not scores:
        return "unknown", 0
    for intent in SAFETY_INTENTS:
        if scores.get(intent, 0) >= 6:
            return intent, scores[intent]
    intent = max(scores, key=lambda k: (scores[k], k in SAFETY_INTENTS))
    if scores[intent] < 3:
        return "unknown", scores[intent]
    return intent, scores[intent]


# ---------------------------------------------------------------------------
# PARSE HELPERS
# ---------------------------------------------------------------------------

def parse_years(text):
    m = re.search(r"(\d+(?:\.\d+)?)\s*(?:years?|yrs?)", text.lower())
    return float(m.group(1)) if m else None


def parse_days_week(text):
    m = re.search(r"(\d+)\s*days?\s*(?:a|per|/)\s*week", text.lower())
    return int(m.group(1)) if m else None


def parse_attempts(text):
    m = re.search(r"(\d+)\s*(?:times|attempts)", text.lower())
    return int(m.group(1)) if m else None


def parse_gb(text):
    m = re.search(r"(\d+)\s*gb", text.lower())
    return int(m.group(1)) if m else None


def src(*ids):
    return list(ids)


def res(status, summary, answer, sources, actions, questions=None,
        escalate_to=None, priority="P3 - Standard", risk=None, conflicts=None):
    return {
        "status": status, "summary": summary, "answer": answer, "sources": sources,
        "actions": actions, "follow_up_questions": questions or [],
        "escalate_to": escalate_to, "priority": priority,
        "risk_flags": risk or [], "conflicts": conflicts or [],
    }


# ---------------------------------------------------------------------------
# POLICY HANDLERS - one per intent. Each returns a grounded resolution.
# ---------------------------------------------------------------------------

def h_password(text, ctx):
    attempts = parse_attempts(text)
    if attempts is not None and attempts >= 5:
        return res(
            "Resolved", "Account locked after 5+ failed attempts",
            "You are locked out. IT can unlock the account manually. No approval is required.",
            src("KB-01"),
            ["Manual account unlock authorised", "Employee resets password via self-service portal"],
            priority="P2 - High",
        )
    return res(
        "Resolved", "Self-service password reset",
        "Reset your password via the self-service portal at any time. If you are locked out after "
        "5 failed attempts, contact IT to unlock the account manually - no approval required.",
        src("KB-01"),
        ["Directed employee to self-service password portal"],
    )


def h_vpn(text, ctx):
    low = text.lower()
    if "contractor" in low:
        return res(
            "Routed", "Contractor VPN access requires manager approval",
            "VPN access is granted automatically only to full-time employees. Contractors require "
            "manager approval submitted via the access request form.",
            src("KB-02"),
            ["Route to reporting manager for approval via access request form"],
            escalate_to="Reporting Manager (then IT provisioning)",
        )
    if "expire" in low or "expired" in low:
        return res(
            "Resolved", "VPN credentials expired",
            "VPN credentials expire every 90 days and must be renewed by the employee. "
            "(Precedent: TK-1042 resolved.)",
            src("KB-02"),
            ["Directed employee to renew VPN credentials", "Cited precedent TK-1042"],
        )
    return res(
        "Needs Info", "VPN access request needs classification",
        "VPN access is automated for full-time employees; contractors need manager approval via the "
        "access request form.",
        src("KB-02"),
        ["Requested employee classification"],
        questions=["Are you a full-time employee or a contractor?"],
    )


def h_laptop(text, ctx):
    low = text.lower()
    years = parse_years(text)
    failure = any(k in low for k in ["dead", "won't turn on", "wont turn on", "verified hardware failure", "hardware failure"])
    conflict = "KB-03 (3-year eligibility) vs Asset Management Policy (4-year refresh + Finance sign-off)"
    cycle = "The Asset Management Policy sets a 4-year refresh cycle from date of issue; KB-03 makes laptops eligible after 3 years or on verified failure."
    if failure and years is not None and years >= 4:
        return res(
            "Resolved", "Laptop replacement approved - failure past the 4-year cycle",
            "The failure is verified and the device is past the Asset Management Policy's own 4-year "
            "refresh cycle, so KB-03 and the Asset Policy agree there is no conflict. Raise the "
            "replacement request at least 2 weeks in advance.",
            src("KB-03", "ASSET-POLICY"),
            ["Confirm device age and failure", "Raise replacement request (>=2 weeks ahead)"],
            priority="P2 - High",
        )
    if failure:
        return res(
            "Escalated", "Laptop replacement - verified failure under the 4-year cycle",
            "KB-03 alone would allow replacement on verified hardware failure, but the Asset "
            "Management Policy requires Finance sign-off (in addition to IT approval) for any "
            "replacement before its 4-year cycle, regardless of cause. The conflict is surfaced "
            "rather than silently choosing one policy: it needs IT approval plus Finance sign-off.",
            src("KB-03", "ASSET-POLICY"),
            ["Verify hardware failure", "Route to Finance for sign-off", "Then raise replacement request"],
            escalate_to="Finance & Assets (with IT approval)",
            priority="P2 - High",
            conflicts=[conflict],
        )
    if years is not None and years >= 4:
        return res(
            "Resolved", "Laptop replacement approved - past the 4-year cycle",
            "The device is past the Asset Management Policy's standard 4-year refresh cycle, so "
            "KB-03 and the Asset Policy agree it is eligible for replacement. Raise the request at "
            "least 2 weeks in advance.",
            src("KB-03", "ASSET-POLICY"),
            ["Confirm device age", "Raise replacement request (>=2 weeks ahead)"],
        )
    if years is not None and 3 <= years < 4:
        return res(
            "Escalated", "Laptop replacement - documented threshold conflict (3-4 years)",
            "KB-03 makes laptops eligible after 3 years, but the Asset Management Policy sets a "
            "4-year refresh cycle. The two thresholds disagree, so this is routed to Finance rather "
            "than guessing which policy wins.",
            src("KB-03", "ASSET-POLICY"),
            ["Route to Finance to resolve the threshold conflict"],
            escalate_to="Finance & Assets (with IT approval)",
            priority="P2 - High",
            conflicts=[conflict],
        )
    return res(
        "Needs Info", "Laptop replacement - confirm repairable fault and device age",
        "Under both thresholds (KB-03: 3 years, Asset Policy: 4 years) with no verified hardware "
        "failure, this is not yet an early-replacement case. " + cycle +
        " Confirm whether it is a repairable fault and the exact device age.",
        src("KB-03", "ASSET-POLICY"),
        ["Requested fault diagnosis and device age"],
        questions=["Is this a repairable fault, or a verified hardware failure?",
                   "Roughly how old is the laptop in years?"],
    )


def h_software(text, ctx):
    low = text.lower()
    monitoring = any(k in low for k in ["tracking", "monitor employees", "surveillance", "productivity tracking", "employee monitoring"])
    if monitoring:
        return res(
            "Escalated", "Monitoring-adjacent software - Security + privacy review required",
            "This reads as employee-monitoring / productivity-tracking software. KB-04 requires IT "
            "Security review for non-catalog software, and monitoring-adjacent tools carry a privacy "
            "risk class that needs Security plus HR/privacy review regardless of catalog status.",
            src("KB-04"),
            ["Route to IT Security", "Flag for HR/privacy review"],
            escalate_to="IT Security (+ HR/Privacy)",
            priority="P2 - High",
            risk=["Employee-monitoring tooling - privacy/HR review required"],
        )
    non_catalog = ("not in" in low and "catalog" in low) or "non-catalog" in low
    if non_catalog:
        return res(
            "Escalated", "Non-catalog software requires IT Security review",
            "Non-catalog software requires IT Security review, which takes 3-5 business days.",
            src("KB-04"),
            ["Route to IT Security for review", "Notify employee of 3-5 business day turnaround"],
            escalate_to="IT Security",
        )
    if "catalog" in low or "standard software" in low:
        return res(
            "Resolved", "Standard catalog software - self-install",
            "Standard software listed in the approved catalog can be self-installed. No IT Security "
            "review is required.",
            src("KB-04"),
            ["Directed employee to self-install from the approved catalog"],
        )
    return res(
        "Needs Info", "Software install request needs catalog status",
        "If the software is in the approved catalog you can self-install it. Non-catalog software "
        "requires IT Security review (3-5 business days). Please confirm the catalog status.",
        src("KB-04"),
        ["Requested software name and catalog status"],
        questions=["What is the exact software name, and is it in the approved catalog?"],
    )


def h_printer(text, ctx):
    tried = any(k in text.lower() for k in ["still", "already tried", "even though", "keeps", "persist"])
    if tried:
        return res(
            "Needs Info", "Printer fault - asset tag required to log ticket",
            "Restarting has not resolved the issue, so per KB-05 a ticket must be logged with the "
            "printer's asset tag.",
            src("KB-05"),
            ["Await asset tag to log the ticket"],
            questions=["What is the printer's asset tag?"],
        )
    return res(
        "Resolved", "Printer troubleshooting steps",
        "Check the printer queue and restart the print spooler. If the issue persists after restart, "
        "log a ticket with the printer's asset tag.",
        src("KB-05"),
        ["Provided queue and spooler troubleshooting steps"],
    )


def h_mailbox(text, ctx):
    low = text.lower()
    gb = parse_gb(text)
    if gb is not None and gb > 50:
        return res(
            "Rejected", "Requested quota exceeds the 50GB cap",
            "Quota increases are capped at 50GB per KB-06, so %dGB cannot be approved. Archive old "
            "mail and request up to the cap with manager approval." % gb,
            src("KB-06"), ["Declined increase beyond the 50GB cap"],
        )
    exceeded = any(k in low for k in ["increase", "exceeded", "over 25", "more than 25", "full", "can't send", "cannot send"])
    if exceeded or (gb is not None and gb > 25):
        return res(
            "Escalated", "Mailbox quota increase requires manager approval",
            "Quota increases beyond the default 25GB require manager approval and are capped at "
            "50GB. Routed to your manager for approval.",
            src("KB-06"),
            ["Route to manager for approval", "Raise quota change up to the 50GB cap"],
            escalate_to="Reporting Manager (then IT)",
        )
    return res(
        "Resolved", "Mailbox within default quota - archive guidance",
        "The default mailbox quota is 25GB. Archive old mail to stay within it. A quota increase "
        "beyond 25GB would need manager approval (capped at 50GB).",
        src("KB-06"),
        ["Advised archiving old mail"],
    )


def h_guest_wifi(text, ctx):
    return res(
        "Resolved", "Guest Wi-Fi - self-service at front desk",
        "Guest Wi-Fi credentials are valid for 24 hours and can be generated by any employee from "
        "the front-desk kiosk. No IT ticket is required.",
        src("KB-07"),
        ["Directed employee to front-desk kiosk (no ticket raised)"],
    )


def h_expense(text, ctx):
    low = text.lower()
    if any(k in low for k in ["no account", "not have", "don't have", "do not have", "new access", "need access", "need an account", "new user"]):
        return res(
            "Escalated", "New expense tool access is owned by Finance",
            "Access to the expense management tool is granted by Finance, not IT. The new-access "
            "request is routed to Finance for provisioning.",
            src("KB-08"),
            ["Route new-access request to Finance"],
            escalate_to="Finance",
        )
    if any(k in low for k in ["log in", "login", "credentials", "invalid", "can't log", "cannot log", "account"]):
        return res(
            "Resolved", "Expense login issue - IT can assist once an account exists",
            "An existing-account login/technical issue is handled by IT per KB-08. A ticket is "
            "raised for credential assistance.",
            src("KB-08"),
            ["Raise IT ticket for login/credential assistance"],
        )
    return res(
        "Needs Info", "Expense tool request - access vs login issue",
        "Access to the expense management tool is granted by Finance, not IT. IT can only assist "
        "with login/technical issues once an account already exists. Please clarify which applies.",
        src("KB-08"),
        ["Requested access vs login clarification"],
        questions=["Do you already have an expense tool account, and is this a login/technical issue?"],
    )


def h_security(text, ctx):
    low = text.lower()
    forwarded = "forward" in low or "teammates" in low
    risk = ["Potential credential-phishing exposure"]
    if forwarded:
        risk.append("Message was forwarded to other employees (policy breach of KB-09)")
    return res(
        "Escalated", "Security incident - report to security@ immediately",
        "This must be reported to security@veridian-corp.example immediately and must not be "
        "forwarded to other employees."
        + (" You indicated it was forwarded - stop forwarding it and inform Security so recipients "
           "can be handled." if forwarded else ""),
        src("KB-09"),
        ["Raise P1 security ticket", "Notify security@veridian-corp.example", "Instruct employee not to forward"],
        escalate_to="Security Team (security@veridian-corp.example)",
        priority="P1 - Critical",
        risk=risk,
    )


def h_wfh(text, ctx):
    days = parse_days_week(text)
    if days is not None and days <= 3:
        return res(
            "Rejected", "Not eligible for home office allowance",
            "Employees working remotely more than 3 days/week are eligible for the one-time home "
            "office equipment allowance. At %d days/week this does not meet the threshold." % days,
            src("KB-10"),
            ["Explained eligibility threshold"],
        )
    return res(
        "Routed", "Home office equipment - manager and Finance approval required",
        "Employees working remotely more than 3 days/week are eligible for a one-time home office "
        "equipment allowance (chair, monitor). It requires manager sign-off and Finance processing; "
        "IT only handles the equipment shipping request once approved.",
        src("KB-10"),
        ["Route to manager for sign-off", "Then Finance processing", "IT raises shipping request once approved"],
        escalate_to="Reporting Manager -> Finance (then IT shipping)",
    )


def h_admin_access(text, ctx):
    return res(
        "Needs Info", "Privileged access - documented business justification required",
        "No provided policy grants admin access to servers, so this cannot be auto-resolved. A "
        "documented business justification is required before it is routed to the resource owner "
        "(Security and your manager) for approval. (Precedent: TK-1050 was rejected for lacking "
        "business justification.)",
        src(),
        ["Do not grant access", "Request documented business justification", "Will route to Security and manager once provided"],
        questions=["What is the documented business justification for this admin access?"],
        priority="P2 - High",
        risk=["Privileged access request", "Urgency pressure (month-end) - verify via normal approval channel"],
        conflicts=["Request falls outside all provided KB/policy sources"],
    )


def h_unknown(text, ctx):
    return res(
        "Needs Info", "Request unclear - no source matched",
        "I'm not sure which IT team should handle this yet, so I'd like to "
        "narrow it down before routing it. Tell me a little more and I'll "
        "route it correctly.",
        src(),
        ["Requested clarifying detail"],
        questions=[
            "Which system, device, or service is affected?",
            "What exactly happens, and what error or message do you see?",
            "When did it start, and did anything change right before?",
        ],
        escalate_to="IT Service Desk (if still unclear)",
    )


HANDLERS = {
    "password_reset": h_password,
    "vpn": h_vpn,
    "laptop": h_laptop,
    "software": h_software,
    "printer": h_printer,
    "mailbox": h_mailbox,
    "guest_wifi": h_guest_wifi,
    "expense": h_expense,
    "security_incident": h_security,
    "wfh": h_wfh,
    "admin_access": h_admin_access,
    "unknown": h_unknown,
}

CATEGORY = {
    "password_reset": "Accounts & Access", "vpn": "Network & Access",
    "laptop": "Hardware", "software": "Software", "printer": "Hardware",
    "mailbox": "Email", "guest_wifi": "Network & Access", "expense": "Software",
    "security_incident": "Security", "wfh": "Hardware", "admin_access": "Security",
    "unknown": "Unclassified",
}

CLOSED_STATUSES = ("Resolved", "Rejected")

ALLOWED_TICKET_STATUSES = (
    "In Progress", "Pending", "Pending Security Review", "Pending Finance",
    "Pending Manager Approval", "Pending Approval", "Waiting for Employee",
    "Escalated to Security", "Escalated to Human", "Resolved", "Rejected", "Closed",
)


def check_consistency(intent, initial_action):
    low = initial_action.lower()
    aligned = {
        "password_reset": "reset" in low or "password" in low,
        "software": "security" in low,
        "security_incident": "security" in low,
        "printer": "investigat" in low or "technician" in low,
        "expense": "employee" in low or "response" in low,
    }
    if intent in aligned and aligned[intent]:
        return "Initial action aligns with policy."
    if intent == "security_incident" and ("forward" in low or "teammate" in low):
        return "Initial action conflicts with KB-09: the message must not be forwarded."
    return "Initial action does not resolve the request; agent disposition applied."


# ---------------------------------------------------------------------------
# TICKET NEEDED + ASSIGNMENT STATUS VOCABULARY
# ---------------------------------------------------------------------------

def needs_ticket(out, text=None):
    """True only when IT action / tracking / approval / investigation / escalation
    is needed. Simple self-service answers and KB-07 guest Wi-Fi do NOT get tickets."""
    if out["status"] in ("Escalated", "Routed", "Rejected"):
        return True
    if out["status"] == "Needs Info":
        return False
    summary = (out["summary"] or "").lower()
    intent = out["intent"]
    if intent == "guest_wifi":
        return False                      # KB-07: no IT ticket required
    if intent == "vpn":
        return False                      # employee renews credentials themselves
    if intent == "password_reset" and "self-service" in summary:
        return False
    if intent == "printer" and "troubleshooting" in summary:
        return False
    if intent == "mailbox" and "archive" in summary:
        return False
    if intent == "software" and "catalog" in summary:
        return False
    return True


def ticket_label(out):
    """Map a decision to the assignment's ticket-status vocabulary."""
    status = out["status"]
    intent = out["intent"]
    esc = out.get("escalate_to") or ""
    if status == "Needs Info":
        return "Waiting for Employee"
    if status == "Rejected":
        return "Rejected"
    if status == "Resolved":
        return "Resolved"
    if status == "Routed":
        if intent == "wfh":
            return "Pending Finance"
        if intent == "vpn":
            return "Pending Manager Approval"
        return "In Progress"
    if status == "Escalated":
        if intent == "security_incident":
            return "Escalated to Security"
        if "Security" in esc:
            return "Escalated to Security"
        if "Finance" in esc:
            return "Pending Finance"
        if intent == "admin_access":
            return "Pending Approval"
        return "In Progress"
    return status


def bucket(status):
    s = (status or "").lower()
    if any(k in s for k in ("resolved", "rejected", "closed")):
        return "Resolved"
    if "escalat" in s:
        return "Escalated"
    if any(k in s for k in ("pending", "approved", "waiting")):
        return "Pending"
    if "progress" in s:
        return "In Progress"
    return "Open"


# ---------------------------------------------------------------------------
# PIPELINE
# ---------------------------------------------------------------------------

def upsert_request(text, employee, email, request_id=None, date_opened=None, initial_action=None):
    rid = request_id
    if rid is None:
        rid = next_request_id()
        is_new = True
    else:
        if q("SELECT 1 FROM requests WHERE id=?", (rid,), fetch=True):
            return rid, False
        is_new = True
    q("INSERT INTO requests(id,employee,email,date_opened,text,context,status,initial_action,created_at) "
      "VALUES(?,?,?,?,?,?,?,?,?)",
      (rid, employee, email, date_opened or now(), text, text, "Open", initial_action, now()))
    return rid, is_new


def decide(text, employee=None, email=None):
    intent, confidence = classify(text)
    out = HANDLERS[intent](text, {"employee": employee, "email": email})
    out["intent"] = intent
    out["confidence"] = confidence
    return out


def extract_tag(text):
    m = re.search(r"\b([A-Z]{2,4}-\d{3,})\b", text)
    if m:
        return m.group(1)
    m = re.search(r"asset\s*tag[^A-Za-z0-9]*([A-Za-z0-9-]+)", text, re.I)
    return m.group(1) if m else None


def fu_printer(answer, context):
    tag = extract_tag(answer) or extract_tag(context)
    if tag:
        return res(
            "Resolved", "Printer ticket logged with asset tag %s" % tag,
            "Thanks - a ticket has been logged against printer asset tag %s in line with KB-05." % tag,
            src("KB-05"), ["Logged printer ticket with asset tag %s" % tag])
    return None


def fu_mailbox(answer, context):
    gb = parse_gb(answer) or parse_gb(context)
    low = (answer + " " + context).lower()
    if gb and gb > 50:
        return res(
            "Rejected", "Requested quota exceeds the 50GB cap",
            "Quota increases are capped at 50GB per KB-06, so %dGB cannot be approved. Archive old "
            "mail and request up to the cap with manager approval." % gb,
            src("KB-06"), ["Declined increase beyond the 50GB cap"])
    if gb and gb > 25:
        return res(
            "Routed", "Mailbox quota increase within cap",
            "At %dGB the increase requires manager approval and is capped at 50GB. Routed to your "
            "manager for approval." % gb,
            src("KB-06"), ["Route to manager for approval", "Raise quota change up to the 50GB cap"],
            escalate_to="Reporting Manager (then IT)")
    if gb and gb <= 25:
        return res(
            "Resolved", "Mailbox within default quota",
            "At %dGB you are within the default 25GB quota. Archive old mail if you approach the "
            "limit." % gb,
            src("KB-06"), ["Confirmed mailbox within default quota"])
    if "archive" in low or "no increase" in low:
        return res(
            "Resolved", "Mailbox archiving (no increase requested)",
            "Archive old mail to stay within the default 25GB quota; no increase requested.",
            src("KB-06"), ["Advised archiving old mail"])
    return None


def fu_expense(answer, context):
    low = answer.lower()
    if any(k in low for k in ["no account", "not have", "don't have", "do not have", "new access", "need access"]):
        return res(
            "Routed", "Expense access is owned by Finance",
            "Access to the expense tool is granted by Finance, not IT. Your request is routed to Finance.",
            src("KB-08"), ["Route new-access request to Finance"], escalate_to="Finance")
    if any(k in low for k in ["yes", "have an account", "already have", "account exists", "existing", "screenshot", "my account"]):
        return res(
            "Resolved", "Expense login issue - IT will assist",
            "An account already exists, so IT can assist with this login/technical issue per KB-08. "
            "A ticket is raised for credential assistance.",
            src("KB-08"), ["Raise IT ticket for login/credential assistance"])
    return None


def fu_admin_access(answer, context):
    low = answer.lower()
    if any(k in low for k in ["just give", "because i said", "no reason", "urgent", "asap", "don't have time", "dont have time"]) and len(answer.split()) < 8:
        return res(
            "Escalated", "Admin access - justification insufficient, no policy grants access",
            "The justification given does not describe a documented business need, and no provided "
            "policy grants admin access. Routed to Security and your manager; privileged access is "
            "not granted by the service agent. (Precedent: TK-1050 was rejected for lacking "
            "business justification.)",
            src(),
            ["Did not grant access", "Route to Security and manager"],
            escalate_to="Security Team + Reporting Manager",
            priority="P2 - High",
            risk=["Privileged access request"],
            conflicts=["Request falls outside all provided KB/policy sources"],
        )
    return res(
        "Escalated", "Admin access - justification recorded, routing for approval",
        "The business justification has been recorded. Privileged access is not granted by the "
        "service agent; this routes to Security and your manager for approval. (Precedent: TK-1050 "
        "was rejected for lacking business justification.)",
        src(),
        ["Recorded justification", "Route to Security and manager for approval"],
        escalate_to="Security Team + Reporting Manager",
        priority="P2 - High",
        risk=["Privileged access request"],
    )


def fu_unknown(answer, context):
    intent, conf = classify(context)
    if intent != "unknown" and conf >= 3:
        return HANDLERS[intent](context, {})
    return None


FOLLOWUP_HANDLERS = {
    "printer": fu_printer,
    "mailbox": fu_mailbox,
    "expense": fu_expense,
    "admin_access": fu_admin_access,
    "unknown": fu_unknown,
}


def _record_followups(rid, questions):
    """Persist open questions as conversation steps (deduped) so the chat can
    ask them one at a time in the fixed decision flow."""
    if not questions:
        return
    existing = {r["question"] for r in q(
        "SELECT question FROM followups WHERE request_id=?", (rid,), fetch=True)}
    for question in questions:
        if question not in existing:
            q("INSERT INTO followups(request_id,question,answer,created_at) VALUES(?,?,'',?)",
              (rid, question, now()))
            existing.add(question)


def _enrich(out, rid, employee, email, initial_action, ticket=None):
    out.update({
        "request_id": rid, "employee": employee, "email": email,
        "initial_action": initial_action,
        "ticket": ticket or {"id": None, "status": None},
        "source_docs": [KB[s] | {"id": s} for s in out["sources"] if s in KB],
    })
    return out


def insert_ticket(rid, out, text, employee, email, initial_action, label=None):
    consistency = check_consistency(out["intent"], initial_action) if initial_action else None
    tid = next_ticket_id()
    status = label or ticket_label(out)
    is_open = 0 if status in ("Resolved", "Rejected") else 1
    q("INSERT INTO tickets(id,origin,request_id,employee,email,category,priority,status,intent,"
      "confidence,summary,answer,note,escalate_to,follow_up,risk_flags,conflicts,consistency_note,"
      "description,is_open,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      (tid, "agent", rid, employee, email, CATEGORY.get(out["intent"]), out["priority"],
       status, out["intent"], out["confidence"], out["summary"], out["answer"], out["summary"],
       out["escalate_to"], json.dumps(out["follow_up_questions"]), json.dumps(out["risk_flags"]),
       json.dumps(out["conflicts"]), consistency, text, is_open, now()))
    for s in out["sources"]:
        q("INSERT INTO ticket_sources(ticket_id,source_id) VALUES(?,?)", (tid, s))
    audit("classify", "intent=%s confidence=%s" % (out["intent"], out["confidence"]), out["sources"], rid, tid)
    audit("resolve", "status=%s escalate_to=%s" % (out["status"], out["escalate_to"]), out["sources"], rid, tid)
    audit("ticket_created", "Ticket %s (%s)" % (tid, status), out["sources"], rid, tid)
    audit("status_changed", "-> %s" % status, out["sources"], rid, tid)
    return {"id": tid, "status": status}


def update_ticket(rid, out, label=None):
    row = q("SELECT id, status FROM tickets WHERE request_id=? AND origin='agent'", (rid,), fetch=True)
    if not row:
        return None
    tid = row[0]["id"]
    prev_status = row[0]["status"]
    status = label or ticket_label(out)
    is_open = 0 if status in ("Resolved", "Rejected") else 1
    q("UPDATE tickets SET category=?,priority=?,status=?,intent=?,confidence=?,summary=?,answer=?,"
      "escalate_to=?,follow_up=?,risk_flags=?,conflicts=?,is_open=? WHERE id=?",
      (CATEGORY.get(out["intent"]), out["priority"], status, out["intent"], out["confidence"],
       out["summary"], out["answer"], out["escalate_to"], json.dumps(out["follow_up_questions"]),
       json.dumps(out["risk_flags"]), json.dumps(out["conflicts"]), is_open, tid))
    q("DELETE FROM ticket_sources WHERE ticket_id=?", (tid,))
    for s in out["sources"]:
        q("INSERT INTO ticket_sources(ticket_id,source_id) VALUES(?,?)", (tid, s))
    if prev_status != status:
        audit("status_changed", "%s -> %s" % (prev_status, status), out["sources"], rid, tid)
    return {"id": tid, "status": status}


def _agent_answer(rid, out, ticket):
    db.add_message(rid, "agent", out["answer"], out["sources"])
    audit("agent_response", out["summary"], out["sources"], rid, ticket and ticket["id"])


def triage(text, employee=None, email=None, request_id=None, date_opened=None, initial_action=None):
    """EmployeeRequest -> classify -> decide -> (Ticket?) -> audit.

    Simple self-service requests resolve WITHOUT a ticket; requests that need IT
    action / tracking / approval / investigation / escalation get one. Every
    message and audit event is persisted for conversation memory.
    """
    rid, is_new = upsert_request(text, employee, email, request_id, date_opened, initial_action)
    if is_new:
        audit("request_created", "request %s opened" % rid, None, rid, None)
    db.add_message(rid, "employee", text)
    audit("employee_message", text, None, rid, None)

    out = decide(text, employee, email)
    label = ticket_label(out)
    q("UPDATE requests SET status=? WHERE id=?", (label, rid))
    audit("issue_classified", "intent=%s confidence=%s" % (out["intent"], out["confidence"]), out["sources"], rid, None)
    if out["sources"]:
        audit("policy_retrieved", ", ".join(out["sources"]), out["sources"], rid, None)
    if out["follow_up_questions"]:
        audit("followup_asked", " | ".join(out["follow_up_questions"]), out["sources"], rid, None)
    _record_followups(rid, out["follow_up_questions"])

    ticket = None
    if needs_ticket(out, text):
        ticket = insert_ticket(rid, out, text, employee, email, initial_action, label)
    out["status"] = label
    _agent_answer(rid, out, ticket)
    return _enrich(out, rid, employee, email, initial_action, ticket)


def continue_request(request_id, answer):
    """Continue the conversation: persist the employee message, re-decide on the
    merged context, update or create the Ticket as appropriate, record audit."""
    rows = q("SELECT * FROM requests WHERE id=?", (request_id,), fetch=True)
    if not rows:
        return None
    req = rows[0]
    existing = q("SELECT id, status FROM tickets WHERE request_id=? AND origin='agent'", (request_id,), fetch=True)
    tid = existing[0]["id"] if existing else None
    db.add_message(request_id, "employee", answer)
    audit("employee_update", answer, None, request_id, tid)

    context = ((req["context"] or req["text"] or "") + " " + answer).strip()
    q("UPDATE requests SET context=? WHERE id=?", (context, request_id))
    q("UPDATE followups SET answer=?, answered_at=? "
      "WHERE id=(SELECT id FROM followups WHERE request_id=? AND answer='' ORDER BY id LIMIT 1)",
      (answer, now(), request_id))

    prev = q("SELECT intent FROM tickets WHERE request_id=? AND origin='agent'", (request_id,), fetch=True)
    prev_intent = prev[0]["intent"] if prev else classify(context)[0]
    fn = FOLLOWUP_HANDLERS.get(prev_intent)
    out = fn(answer, context) if fn else None
    if out is None:
        out = decide(context, req["employee"], req["email"])
    if "intent" not in out:
        out["intent"] = classify(context)[0]
    out["confidence"] = out.get("confidence") or classify(context)[1]

    label = ticket_label(out)
    q("UPDATE requests SET status=? WHERE id=?", (label, request_id))
    audit("issue_classified", "intent=%s confidence=%s" % (out["intent"], out["confidence"]), out["sources"], request_id, None)
    if out["sources"]:
        audit("policy_retrieved", ", ".join(out["sources"]), out["sources"], request_id, None)
    if out["follow_up_questions"]:
        audit("followup_asked", " | ".join(out["follow_up_questions"]), out["sources"], request_id, None)

    # Fixed decision flow: record open questions and ask them one at a time.
    # Only questions still unanswered are presented next; once they are all
    # answered without a match, route to a human instead of looping.
    _record_followups(request_id, out["follow_up_questions"])
    if out["status"] == "Needs Info":
        unanswered = [r["question"] for r in q(
            "SELECT question FROM followups WHERE request_id=? AND answer='' ORDER BY id",
            (request_id,), fetch=True)]
        if not unanswered:
            return escalate_request(
                request_id,
                "The agent could not match the request after the clarifying questions; "
                "routed to the IT service desk.")
        out["follow_up_questions"] = unanswered
    else:
        q("UPDATE followups SET answer='n/a' WHERE request_id=? AND answer=''", (request_id,))
        out["follow_up_questions"] = []

    ticket = existing[0]["id"] if existing else None
    if existing:
        ticket = update_ticket(request_id, out, label)
    elif needs_ticket(out, context):
        ticket = insert_ticket(request_id, out, context, req["employee"], req["email"], req["initial_action"], label)
    out["status"] = label
    _agent_answer(request_id, out, ticket)
    return _enrich(out, request_id, req["employee"], req["email"], req["initial_action"], ticket)


def escalate_request(request_id, note=None):
    """Employee explicitly asks for a human; force an open escalated Ticket."""
    rows = q("SELECT * FROM requests WHERE id=?", (request_id,), fetch=True)
    if not rows:
        return None
    req = rows[0]
    row = q("SELECT * FROM tickets WHERE request_id=? AND origin='agent'", (request_id,), fetch=True)
    if not row:
        out = decide(req["context"] or req["text"], req["employee"], req["email"])
        label = "Escalated to Human"
        insert_ticket(request_id, out, req["text"], req["employee"], req["email"], req["initial_action"], label)
        row = q("SELECT * FROM tickets WHERE request_id=? AND origin='agent'", (request_id,), fetch=True)
    t = row[0]
    reason = (note or "").strip() or "Employee requested escalation to a human agent."
    answer = (t["answer"] or "") + " [Escalated to a human agent: %s]" % reason
    q("UPDATE tickets SET status=?, is_open=1, escalate_to=?, answer=?, note=? WHERE id=?",
      ("Escalated to Human", "Human IT Agent (Service Desk)", answer,
       "Employee escalated to a human agent: %s" % reason, t["id"]))
    q("UPDATE requests SET status='Escalated to Human' WHERE id=?", (request_id,))
    db.add_message(request_id, "agent", answer, None)
    audit("escalation", reason, None, request_id, t["id"])
    audit("status_changed", "-> Escalated to Human", None, request_id, t["id"])
    out = {
        "status": "Escalated to Human", "summary": "Escalated to a human agent",
        "answer": answer, "sources": [], "follow_up_questions": [],
        "escalate_to": "Human IT Agent (Service Desk)", "priority": t["priority"] or "P3 - Standard",
        "risk_flags": [], "conflicts": [], "intent": t["intent"] or "unknown",
        "confidence": t["confidence"] or 0,
    }
    return _enrich(out, request_id, req["employee"], req["email"], req["initial_action"],
                   {"id": t["id"], "status": "Escalated to Human"})


# ---------------------------------------------------------------------------
# READ APIs
# ---------------------------------------------------------------------------

def owns_request(user, request_id):
    rows = q("SELECT email FROM requests WHERE id=?", (request_id,), fetch=True)
    if not rows:
        return False
    return (rows[0]["email"] or "").lower() == (user.get("email") or "").lower()


def ticket_scope(ticket):
    """Department that owns a ticket. 'finance' when Finance sign-off or
    processing is required (Pending Finance, escalate to Finance / Finance &
    Assets, home-office allowance); everything else belongs to the IT desk.
    Expense/login issues that IT resolves per KB-08 stay in the IT scope."""
    hay = " ".join([
        str(ticket.get("escalate_to") or ""),
        str(ticket.get("status") or ""),
        str(ticket.get("category") or ""),
    ]).lower()
    if "finance" in hay:
        return "finance"
    return "it"


def request_scope(request_id):
    """Scope of the request: taken from its open ticket when one exists, else
    from the classification of the request text itself."""
    t = q("SELECT id, status, escalate_to, category FROM tickets "
          "WHERE request_id=? AND origin='agent' ORDER BY id", (request_id,), fetch=True)
    if t:
        return ticket_scope(t[0])
    req = q("SELECT text, status FROM requests WHERE id=?", (request_id,), fetch=True)
    if not req:
        return "it"
    if "finance" in (req[0]["status"] or "").lower():
        return "finance"
    intent, _ = classify(req[0]["text"])
    return "finance" if intent in ("expense", "wfh") else "it"


def ticket_scope_by_id(ticket_id):
    """Scope of a stored ticket (used for staff access checks)."""
    rows = q("SELECT id, status, escalate_to, category FROM tickets WHERE id=?",
             (ticket_id,), fetch=True)
    return ticket_scope(rows[0]) if rows else None


def _ticket_summary(row):
    sources = [r["source_id"] for r in q(
        "SELECT source_id FROM ticket_sources WHERE ticket_id=?", (row["id"],), fetch=True)]
    return {
        "id": row["id"], "origin": row["origin"], "request_id": row["request_id"],
        "employee": row["employee"], "email": row["email"], "category": row["category"],
        "priority": row["priority"], "status": row["status"], "summary": row["summary"],
        "issue": row["description"], "escalate_to": row["escalate_to"],
        "note": row["note"] or "", "open": bool(row["is_open"]),
        "created_at": row["created_at"], "sources": sources,
        "source_docs": [KB[s] | {"id": s} for s in sources if s in KB],
    }


def agent_results():
    """Every EmployeeRequest with its live status, ticket link and last activity."""
    rows = q("SELECT r.*, "
             "(SELECT MAX(m.created_at) FROM messages m WHERE m.request_id=r.id) AS last_msg "
             "FROM requests r ORDER BY r.id", fetch=True)
    out = []
    for row in rows:
        ticket = {"id": None, "status": None}
        t = q("SELECT id, status FROM tickets WHERE request_id=? AND origin='agent' ORDER BY id",
              (row["id"],), fetch=True)
        if t:
            ticket = {"id": t[0]["id"], "status": t[0]["status"]}
        out.append({
            "request_id": row["id"], "employee": row["employee"], "email": row["email"],
            "text": row["text"], "initial_action": row["initial_action"],
            "status": row["status"] or "Open",
            "date_opened": row["date_opened"],
            "updated_at": row["last_msg"] or row["created_at"] or "",
            "ticket": ticket,
        })
    return out


def all_tickets(origin=None):
    where, args = (" WHERE origin=?", (origin,)) if origin else ("", ())
    rows = q("SELECT * FROM tickets" + where + " ORDER BY id", args, fetch=True)
    return [_ticket_summary(r) for r in rows]


def related_tickets(text, limit=3):
    """Previous tickets (queue history + agent) that share intent keywords with
    the current request. Historical context only - never overrides policy."""
    low = text.lower()
    scored = []
    for tb in all_tickets():
        hay = (tb.get("issue") or "").lower()
        score = 0
        for kws in INTENTS.values():
            for kw, w in kws:
                if kw in low and kw in hay:
                    score += w
        if score:
            scored.append((score, tb))
    scored.sort(key=lambda p: p[0], reverse=True)
    return [tb for _, tb in scored[:limit]]


def ticket_detail(ticket_id):
    """Full detail of one ticket (for the IT service desk), incl. the linked
    employee request text and conversation."""
    rows = q("SELECT * FROM tickets WHERE id=?", (ticket_id,), fetch=True)
    if not rows:
        return None
    t = _ticket_summary(rows[0])
    if t.get("request_id"):
        req = q("SELECT text, context FROM requests WHERE id=?",
                (t["request_id"],), fetch=True)
        if req:
            t["request_text"] = req[0]["text"]
            t["messages"] = db.messages_for(t["request_id"])
    return t


def service_desk(search=None, status_filter=None, limit=None, scope=None):
    """The ticket queue for one department scope ('it' or 'finance'; None = all
    departments, admin view). Required fields ticked: Ticket ID, Employee,
    Issue Summary, Status."""
    items = all_tickets()
    if scope:
        items = [it for it in items if ticket_scope(it) == scope]
    stats = {"Open": 0, "In Progress": 0, "Pending": 0, "Escalated": 0, "Resolved": 0}
    for it in items:
        b = bucket(it["status"])
        stats[b] = stats.get(b, 0) + 1
    filtered = items
    if status_filter:
        sf = status_filter.lower()
        filtered = [it for it in filtered
                    if sf in it["status"].lower() or bucket(it["status"]).lower() == sf]
    if search:
        s = search.lower()
        filtered = [it for it in filtered
                    if s in it["id"].lower() or s in (it["employee"] or "").lower()
                    or s in (it["issue"] or "").lower() or s in (it["status"] or "").lower()]
    if limit:
        filtered = filtered[:limit]
    return {"queue": filtered, "stats": stats}


def request_detail(request_id):
    rows = q("SELECT * FROM requests WHERE id=?", (request_id,), fetch=True)
    if not rows:
        return None
    req = rows[0]
    ticket = None
    t = q("SELECT * FROM tickets WHERE request_id=? AND origin='agent' ORDER BY id", (request_id,), fetch=True)
    if t:
        ticket = _ticket_summary(t[0])
    return {
        "request_id": req["id"], "employee": req["employee"], "email": req["email"],
        "text": req["text"], "initial_action": req["initial_action"],
        "status": req["status"] or "Open", "date_opened": req["date_opened"],
        "messages": db.messages_for(request_id),
        "followups": q("SELECT * FROM followups WHERE request_id=? ORDER BY id", (request_id,), fetch=True),
        "ticket": ticket,
        "related_tickets": related_tickets(req["text"] or req["context"] or ""),
        "audit": db.audit_for(request_id),
    }


def update_ticket_status(ticket_id, status, actor_email):
    """Admin-only controlled action: persist a status change + audit event.
    Only agent-generated tickets are mutable; the reference Ticket Queue
    (origin='history') is read-only precedent."""
    rows = q("SELECT * FROM tickets WHERE id=?", (ticket_id,), fetch=True)
    if not rows:
        return None
    t = rows[0]
    if t["origin"] != "agent":
        raise ValueError("queue tickets are reference-only and cannot be changed")
    if status not in ALLOWED_TICKET_STATUSES:
        raise ValueError("ticket status must use the assignment vocabulary")
    prev = t["status"]
    if prev == status:
        return _ticket_summary(t)
    is_open = 0 if status in ("Resolved", "Rejected", "Closed") else 1
    q("UPDATE tickets SET status=?, is_open=? WHERE id=?", (status, is_open, ticket_id))
    q("UPDATE requests SET status=? WHERE id=?", (status, t["request_id"])) if t["request_id"] else None
    audit("status_changed", "%s -> %s (by %s)" % (prev, status, actor_email),
          None, t["request_id"], ticket_id)
    return _ticket_summary(q("SELECT * FROM tickets WHERE id=?", (ticket_id,), fetch=True)[0])


# ---------------------------------------------------------------------------
# SEEDING
# ---------------------------------------------------------------------------

def seed_reference():
    """Load frozen reference + seed operational rows exactly once."""
    if q("SELECT COUNT(*) AS n FROM requests", fetch=True)[0]["n"] == 0:
        for r in SEED["requests"]:
            q("INSERT INTO requests(id,employee,email,date_opened,text,initial_action,created_at) "
              "VALUES(?,?,?,?,?,?,?)",
              (r["id"], r["employee"], r["email"], r["date"], r["text"],
               r["initial_action"], now()))
    if q("SELECT COUNT(*) AS n FROM tickets WHERE origin='history'", fetch=True)[0]["n"] == 0:
        for t in SEED["tickets"]:
            meta = SEED["ticket_notes"].get(t["id"], {"note": "", "sources": []})
            q("INSERT INTO tickets(id,origin,employee,status,summary,note,description,is_open,created_at) "
              "VALUES(?,?,?,?,?,?,?,?,?)",
              (t["id"], "history", t["employee"], t["status"], t["issue"],
               meta["note"], t["issue"], 1 if t["open"] else 0, now()))
            for s in meta["sources"]:
                q("INSERT INTO ticket_sources(ticket_id,source_id) VALUES(?,?)", (t["id"], s))


def seed():
    """Idempotent: init schema, seed queues, then triage any request that has no
    conversation yet. Requests resolved without a ticket still record messages,
    so re-runs never duplicate work."""
    init_db()
    seed_reference()
    started = {r["request_id"] for r in q(
        "SELECT DISTINCT request_id FROM tickets WHERE origin='agent'", fetch=True)}
    started |= {r["request_id"] for r in q("SELECT DISTINCT request_id FROM messages", fetch=True)}
    for r in SEED["requests"]:
        if r["id"] not in started:
            triage(r["text"], r["employee"], r["email"], r["id"], r["date"], r["initial_action"])