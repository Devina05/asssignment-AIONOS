# Veridian Corp — Internal Service Agent

An **internal employee-support agent for the IT function**, built for the AIONOS *Agentic AI Factory* Assignment 2.

The agent reads an employee's message, matches it to the correct internal policy, asks **one follow-up at a time** in a continuous chat, resolves simple requests, escalates risky or unclear ones, raises a structured ticket, cites the source it used, and keeps an append-only audit trail. It is **deterministic and grounded** — no LLM calls at runtime.

> **Grounding constraint:** the agent answers **only** from the assignment source data — KB-01…KB-10 and the Asset Management Policy extract. It never invents policy. When nothing matches, it says so and escalates instead of guessing.

---

## 1. Features

- **Continuous chat** — the employee asks in plain words; the agent follows the decision flow **one question at a time**, without showing internal jargon to the employee.
- **Grounded, cited answers** — every reply cites the exact KB / Asset Policy source it used.
- **Tickets only when needed** — self-service answers (guest Wi-Fi, password reset, VPN renew) resolve **without** a ticket; anything needing IT action/tracking/approval gets one (max 1 per request).
- **Status vocabulary** — In Progress, Pending, Pending Security Review, Pending Finance, Pending Manager Approval, Pending Approval, Waiting for Employee, Escalated to Security, Escalated to Human, Resolved, Rejected, Closed.
- **Full persistence** — every request, ticket, message, follow-up and audit event is saved in the database and survives restarts.
- **Role segregation** — three scopes: IT, Finance, Admin, plus plain employees (see §3).

---

## 2. Quick start

No third-party dependencies (Python 3.9+ stdlib only).

```bash
python -m app.main                  # web UI  -> http://localhost:8000  (redirects to /login)
python -m app.main --selftest       # prints the agent's disposition of all stored requests
python -m unittest discover tests   # core-flow test suite (uses a temp DB)
```

**Hosting on Streamlit Community Cloud**

A Streamlit frontend (`streamlit_app.py`) reuses the engine in-process (the HTTP server in `app/server.py` is not involved):

1. Deploy the repo from Streamlit Cloud; set **Main file path** to `streamlit_app.py`.
2. Create the `app_users` table once in your Supabase project (SQL Editor → Run):
   ```sql
   create table public.app_users (
     id uuid primary key default gen_random_uuid(),
     email text not null,
     name text default '',
     password_hash text not null,
     role text default 'employee'
   );
   ```
3. Add secrets in **Manage app → … → Settings → Secrets** (the app loads them as env vars at startup):
   ```toml
   SUPABASE_URL="https://<project-ref>.supabase.co"
   SUPABASE_KEY="sb_secret_..."        # or legacy service_role key
   # optional — restrict sign-up domain / grant staff roles:
   # ALLOWED_DOMAIN="veridian-corp.example"
   # IT_EMAILS="..."  FINANCE_EMAILS="..."  ADMIN_EMAILS="..."
   ```
4. Run locally with `streamlit run streamlit_app.py`.

> Note: on Streamlit Cloud `var/agent.db` lives on an ephemeral disk, so the agent's operational store resets on redeploys. Accounts live in Supabase and survive.

---

## 3. Roles, segregation & credentials

| Role | Typical email | Password | Scope / what they see |
|---|---|---|---|
| **Admin** | `admin@veridian-corp.example` | `Password123!` | **Everything** — both desks, every request in every scope, all status controls, full audit trail |
| **IT** | `you@veridian-corp.example` | `Password123!` | **IT Service Desk only** — IT-scope requests/tickets (`TK-1053…TK-1060`), status updates on them, IT-scoped audit, ticket queue, knowledge base |
| **Finance** | `finance@veridian-corp.example` | `Password123!` | **Finance Desk only** — Finance-scope requests/tickets (`TK-1052`, `TK-1055` Pending Finance, home-office allowance, expense access), Finance status updates, scoped audit, knowledge base |


**Segregation rules (enforced server-side):**
- IT **cannot** view or update Finance tickets; Finance **cannot** view or update IT tickets (server returns `403`).
- Admin can read/update **every** scope.
- A request/ticket's scope is derived from its route (`escalate_to`, status, category): anything needing **Finance** sign-off or processing is finance-scoped; expense *login* issues IT resolves per KB-08 stay IT-scoped.

**Creating accounts:**
- **Staff accounts** are created by signing in to the page; the role is granted automatically from the allowlists in `agent_config.json`.
- **Employees can create their own login ID** — on the first page (`login.html`) click **Sign up**, enter any `@veridian-corp.example` email and a password, and the account is created immediately. Any email **not** in the allowlists is automatically given the `employee` role; no admin approval is needed.

---

## 4. Project layout

```
app/
   main.py            entry point (python -m app.main)
   server.py          stdlib HTTP server + auth-gated JSON API + static files
   agent.py           deterministic engine: classify, policy handlers, request -> ticket pipeline
   db.py              SQLite operational store (schema, queries, audit, seeding)
   auth.py            Supabase-backed sign-up / sign-in + signed cookies
   config.py          config loading (env vars > agent_config.json > defaults)
   data/seed_data.json    frozen reference (KB + Asset Policy) + seed rows
static/
   login.html         first page: sign in / sign up
   index.html         role-aware dashboard (chat, desks, queue, audit, KB)
tests/
   test_flow.py       unittest suite (temp DB, never touches var/)
var/
   agent.db           SQLite runtime store (created at runtime, gitignored)
agent_config.json     your Supabase credentials (gitignored; copy agent_config.example.json)
.env.example          documented environment variables
```

---

## 5. Data model & persistence

Everything the agent does is **saved in the database**. Nothing important lives only in memory.

| Kind | Data | Storage |
|---|---|---|
| **Reference** (frozen) | KB-01…KB-10, Asset Management Policy | `app/data/seed_data.json` |
| **Operational** (grows) | requests, tickets, citations, messages, follow-ups, audit trail | `var/agent.db` (SQLite) |
| **Accounts** | email, PBKDF2 password hash, role | Supabase (hosted Postgres) |

Tables in `var/agent.db`:

| Table | Contents |
|---|---|
| `requests` | Every employee request (own + the 15 seeded REQ-01…REQ-15), with live `status` and conversation `context`. **Every request you submit is inserted here.** |
| `tickets` | All tickets: `origin='agent'` (TK-1052…, created/mutable) and `origin='history'` (TK-1042…TK-1051, read-only precedent). |
| `messages` | One row per employee/agent message — the conversation memory. |
| `followups` | Clarifying questions asked in the chat, with answers. |
| `ticket_sources` | Normalised KB citations per ticket. |
| `audit` | Append-only audit trail (`audit()` rows, never edited or deleted). |

**Durability is proven:** run `--selftest` twice — the second run does **not** duplicate seed rows, and a request submitted through the API survives a server restart.

**Names — three distinct things:**

| Name | What it is |
|---|---|
| **EmployeeRequest** | The raw input — employee, email, date, free-text complaint. Nothing decided yet. |
| **Ticket** | The structured output of the agent pipeline, only when action/tracking/approval/investigation is needed. At most **one** per request. |
| **Ticket Queue** | Pre-existing `TK-1042…TK-1051` from the Data Pack — **precedent only**, never acted on directly. Read-only. |

---

## 6. Architecture & process flow

```
Employee message
      |
      v
[1] Intent classifier        weighted keyword scoring over the issue text
      |                      (safety intents: admin access / security always win)
      v
[2] Policy handler           one handler per intent -> grounded decision
      |                      status: Resolved | Needs Info | Routed | Escalated | Rejected
      v
[3] Conflict detection       e.g. KB-03 (3yr) vs Asset Policy (4yr + Finance sign-off)
      |
      v
[4] Ticket factory           structured ticket: id, category, priority, status,
      |                      summary, sources, escalate_to, description
      v
[5] Audit trail              append-only: classify -> resolve -> ticket_created
      |
      v
[6] Response                 reply + citations + follow-up questions + risk flags
```

| Component | What it does |
|---|---|
| `classify()` / `INTENTS` | Deterministic intent detection with weighted keywords |
| `h_*` handlers + `HANDLERS` | Policy logic per intent, returning a structured resolution |
| `needs_ticket()` / `ticket_label()` | Decides if a request needs a Ticket and maps the decision to the assignment status vocabulary |
| `triage()` / `continue_request()` / `escalate_request()` | Persist message → resolve → (Ticket?) → audit; **one clear question per turn**, escalate to a human when questions run out |
| `_record_followups()` | Persists clarifying questions (even when no ticket exists) so the chat can ask them one at a time |
| `ticket_scope()` / `request_scope()` | Derives the IT/finance scope for role-based access |
| `service_desk()` / `request_detail()` / `update_ticket_status()` | Department queue + stats, per-request detail, status changes (scoped) |
| `auth.py` | Supabase REST client, PBKDF2 hashing, signed cookies, role assignment |
| `server.py` (`Handler`) | HTTP gateway: auth gate + role-scoped JSON API + static assets |

---

## 7. API reference

All endpoints except `/api/signup` and `/api/login` require a signed session cookie.

| Method & path | Who can call | Purpose |
|---|---|---|
| `POST /api/signup` | public | Create account; role granted from allowlists |
| `POST /api/login` / `POST /api/logout` | public / session | Sign in / out (HMAC cookie) |
| `GET /api/me` | session | Current user + role |
| `GET /api/requests` | employee: own · IT/finance: their scope · admin: all | List requests with live status + ticket link |
| `GET /api/request-detail?request_id=` | owner · staff in scope · admin | Full conversation, follow-ups, ticket, audit |
| `GET /api/kb` | staff (IT/finance/admin) | Knowledge base & policies |
| `GET /api/service-desk?scope=it\|finance` | staff, **matching scope only**; admin any | Ticket queue + summary counts |
| `GET /api/ticket-detail?ticket_id=` | staff in scope · admin | One ticket, its request text and messages |
| `POST /api/ticket-status {ticket_id, status}` | staff in scope · admin | Change ticket status (audited) — history tickets are read-only |
| `GET /api/queue` (`/api/seed-tickets`) | staff | Pre-existing `TK-1042…TK-1051` reference queue |
| `GET /api/audit` | staff (IT/finance: their scope · admin: full) | Append-only audit trail |
| `POST /api/request {text}` | any session | Start a new request (chat turn) |
| `POST /api/request {request_id, answer}` | owner · staff in scope | Continue the chat (answer the agent's question) |
| `POST /api/escalate {request_id, note?}` | owner · staff in scope | Escalate to a human agent |

Cross-scope requests are rejected with `403` — this is enforced on the server, not just hidden in the UI.

---

## 8. Inputs, sources & assumptions

**Sources used (only these):**
- Policies `KB-01` … `KB-10`
- `ASSET-POLICY` — Asset Management Policy extract (Finance & Assets, Q2 2026)
- 15 employee requests (`REQ-01`…`REQ-15`)
- Ticket queue `TK-1042`…`TK-1051` (history + active cases)

**Assumptions:**
1. The ticket queue is **precedent**: closed tickets are history; open tickets remain actionable.
2. Where a request needs data the employee didn't provide (printer asset tag, mailbox usage, error screenshot), the agent **asks rather than assumes** — one question at a time.
3. Privileged admin access is **not granted by any provided policy**, so it is escalated for documented justification + manager/Security review (consistent with the TK-1050 rejection).
4. `KB-03` (3-year) and the Asset Management Policy (4-year + Finance sign-off) genuinely **conflict**; the agent surfaces the conflict and routes to Finance instead of silently picking one.

---

## 9. Agent disposition of the 15 seeded requests

| ID | Employee | Issue | Disposition | Ticket | Source |
|---|---|---|---|---|---|
| REQ-01 | Adit Sharma | Laptop dead, 3.5 yrs | **Escalated** — policy conflict, Finance sign-off | TK-1052 `Pending Finance` | KB-03 + Asset Policy |
| REQ-02 | Vikram Chawla | Guest Wi-Fi | **Resolved** — front-desk kiosk, no ticket (KB-07) | — | KB-07 |
| REQ-03 | Karan Mehta | Locked out (6 tries) | **Resolved** — manual unlock, no approval | TK-1053 `Resolved` | KB-01 |
| REQ-04 | Ritu Bhatia | Non-catalog software | **Escalated** — Security review 3–5 days | TK-1054 `Escalated to Security` | KB-04 |
| REQ-05 | Sanjay Oberoi | VPN expired | **Resolved** — employee renews credentials, no ticket | — | KB-02 |
| REQ-06 | Meera Iyer | Printer paper jam | **Waiting for Employee** — asset tag required; ticket on reply | — | KB-05 |
| REQ-07 | Farhan Ali | Monitor, WFH 4 days | **Routed** — manager + Finance, then IT shipping | TK-1055 `Pending Finance` | KB-10 |
| REQ-08 | Ananya Reddy | Phishing (forwarded) | **Escalated P1** — must not forward | TK-1056 `Escalated to Security` | KB-09 |
| REQ-09 | Rohit Desai | Mailbox full | **Escalated** — manager approval, cap 50GB | TK-1057 `In Progress` | KB-06 |
| REQ-10 | Kavya Pillai | Finance server admin | **Waiting for Employee** — justification + review needed (TK-1050 precedent) | — | none (TK-1050) |
| REQ-11 | Nikhil Bansal | Contractor VPN | **Routed** — manager approval via access form | TK-1058 `Pending Manager Approval` | KB-02 |
| REQ-12 | Sneha Kulkarni | Expense tool login | **Resolved** — existing-account login handled by IT | TK-1059 `Resolved` | KB-08 |
| REQ-13 | Aman Gupta | Flickering, 2 yrs | **Waiting for Employee** — confirm repairable fault + device age | — | KB-03 + Asset Policy |
| REQ-14 | Tanya Chopra | Browser extension | **Escalated** — non-catalog + privacy flag | TK-1060 `Escalated to Security` | KB-04 |
| REQ-15 | Rahul Menon | "it's not working" | **Waiting for Employee** — clarify system/error/when | — | none |

---

## 10. Verification & tests

```bash
python -m app.main --selftest        # disposition of all stored requests + honest DB row counts
python -m unittest discover tests    # 22 core-flow tests
```

Test coverage includes: one-ticket-per-request, guest Wi-Fi / self-service **no-ticket** cases, security escalation, Needs-Info conversation (no ticket until it continues), **one-question-at-a-time chat that escalates to a human once questions run out**, follow-up persistence, audit + status-change persistence, history tickets read-only, and **IT vs Finance scope** derivation + desk filtering.

Role-scope behaviour was smoke-tested over HTTP: employees get `403` on desks/KB/audit; IT gets `403` on Finance tickets; Finance gets `403` on IT tickets; admin sees all 15 requests and both desks.

---


