"""Core-flow tests for the Internal Service Agent (unittest, stdlib).

Run with:  python -m unittest discover tests

Each test uses a throwaway SQLite file under a temp dir, so the real
operational store (var/agent.db) is never touched.
"""

import tempfile
import unittest
from pathlib import Path

import app.agent as agent
import app.db as db


class AgentFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.DB_PATH = Path(tempfile.gettempdir()) / "test_agent_flow.db"
        if db.DB_PATH.exists():
            db.DB_PATH.unlink()
        agent.seed()

    def test_seed_is_idempotent(self):
        before = len(db.q("SELECT id FROM requests", fetch=True))
        agent.seed()
        after = len(db.q("SELECT id FROM requests", fetch=True))
        self.assertEqual(before, after)

    def test_one_agent_ticket_per_request(self):
        counts = db.q(
            "SELECT request_id, COUNT(*) AS n FROM tickets "
            "WHERE origin='agent' GROUP BY request_id HAVING n > 1",
            fetch=True)
        self.assertEqual(counts, [], "each request must yield exactly one Ticket")

    def test_queue_is_reference_only(self):
        queue = agent.all_tickets("history")
        self.assertTrue(queue)
        self.assertTrue(all(t["origin"] == "history" for t in queue))
        self.assertTrue(all(t["id"].startswith("TK-") for t in queue))

    def test_classify_security_wins(self):
        intent, conf = agent.classify("I think I got a phishing email, please help")
        self.assertEqual(intent, "security_incident")
        self.assertGreaterEqual(conf, 6)

    def test_laptop_conflict_is_surfaced(self):
        out = agent.decide("My laptop won't turn on at all, it's completely dead, had it about 3.5 years now.")
        self.assertEqual(out["status"], "Escalated")
        self.assertIn("KB-03", out["sources"])

    def test_guest_wifi_gets_no_ticket(self):
        out = agent.triage("Can I get Wi-Fi access for a guest visiting our office tomorrow?")
        self.assertIn("REQ-", out["request_id"])
        self.assertIsNone(out["ticket"]["id"], "KB-07 explicitly requires no IT ticket")
        self.assertIn("Resolved", out["status"])
        self.assertIn("KB-07", out["sources"])

    def test_self_service_resolutions_get_no_ticket(self):
        cases = [
            "My VPN says my credentials expired, how do I renew?",
            "How do I reset my own password?",
            "My printer keeps jamming but restarting helped.",
            "Help me archive old mail to free my inbox.",
        ]
        for text in cases:
            out = agent.triage(text)
            self.assertIsNone(out["ticket"]["id"], "self-service answer must not open a ticket: %r" % text)

    def test_laptop_replacement_gets_ticket(self):
        out = agent.triage("My laptop won't turn on at all, verified hardware failure, had it 3.5 years now.")
        self.assertIsNotNone(out["ticket"]["id"])

    def test_security_incident_gets_ticket(self):
        out = agent.triage("I think I got a phishing email asking for my login.")
        self.assertEqual(out["status"], "Escalated to Security")
        self.assertIsNotNone(out["ticket"]["id"])
        self.assertEqual(out["ticket"]["status"], "Escalated to Security")

    def test_needs_info_no_ticket_until_conversation_continues(self):
        out = agent.triage("Printer on the 3rd floor shows paper jam even though there's no jam.")
        self.assertEqual(out["status"], "Waiting for Employee")
        self.assertIsNone(out["ticket"]["id"])
        cont = agent.continue_request(out["request_id"], "The asset tag is PRN-0421.")
        self.assertIn("Resolved", cont["status"])
        self.assertIsNotNone(cont["ticket"]["id"], "asset tag provided -> ticket is logged per KB-05")
        self.assertIn("PRN-0421", cont["summary"])

    def test_unknown_asks_followup(self):
        out = agent.triage("hey can you help, its not working")
        self.assertEqual(out["status"], "Waiting for Employee")
        self.assertTrue(out["follow_up_questions"])

    def test_followups_recorded_even_without_ticket(self):
        out = agent.triage("hey can you help, its not working")
        self.assertIsNone(out["ticket"]["id"])
        rows = db.q("SELECT question FROM followups WHERE request_id=?",
                    (out["request_id"],), fetch=True)
        self.assertTrue(rows, "clarifying questions must be persisted even with no ticket")

    def test_unknown_chat_one_question_at_a_time_then_escalates(self):
        out = agent.triage("hey can you help, its not working")
        rid = out["request_id"]
        self.assertEqual(out["status"], "Waiting for Employee")
        self.assertTrue(out["follow_up_questions"])
        cont1 = agent.continue_request(rid, "nope nothing specific")
        self.assertTrue(cont1["follow_up_questions"], "second question must still come next")
        cont2 = agent.continue_request(rid, "still not sure")
        self.assertTrue(cont2["follow_up_questions"], "third question must still come next")
        cont3 = agent.continue_request(rid, "really no idea")
        self.assertIn("Escalated to Human", cont3["status"])
        self.assertIsNotNone(cont3["ticket"]["id"])
        # all three clarifying questions were asked and answered ("n/a-free")
        rows = db.q("SELECT answer FROM followups WHERE request_id=?", (rid,), fetch=True)
        self.assertTrue(all(r["answer"] for r in rows),
                        "once routed to a human no question stays open")

    def test_resolved_clears_open_followups(self):
        out = agent.triage("Printer on the 3rd floor shows paper jam even though there's no jam.")
        self.assertTrue(out["follow_up_questions"])
        cont = agent.continue_request(out["request_id"], "The asset tag is PRN-0421.")
        self.assertIn("Resolved", cont["status"])
        rows = db.q("SELECT answer FROM followups WHERE request_id=?",
                    (out["request_id"],), fetch=True)
        self.assertTrue(rows)
        self.assertTrue(all(r["answer"] for r in rows),
                        "open followups must be cleared once a decision is reached")

    def test_ticket_scope_finance_vs_it(self):
        fin = agent.triage("I need new access to the expense management system, I don't have an account yet.")
        sec = agent.triage("I think I got a phishing email asking for my login.")
        itx = agent.triage("I already have an expense account but I can't log in.")
        self.assertEqual(agent.request_scope(fin["request_id"]), "finance")
        self.assertEqual(agent.ticket_scope_by_id(fin["ticket"]["id"]), "finance")
        self.assertEqual(agent.request_scope(sec["request_id"]), "it")
        self.assertEqual(agent.ticket_scope_by_id(sec["ticket"]["id"]), "it")
        self.assertEqual(agent.ticket_scope_by_id(itx["ticket"]["id"]), "it",
                         "expense login issues IT resolves per KB-08 stay in IT scope")

    def test_service_desk_scope_filter(self):
        desk = agent.service_desk(scope="finance")
        self.assertTrue(desk["queue"])
        for t in desk["queue"]:
            self.assertEqual(agent.ticket_scope(t), "finance")
        desk_it = agent.service_desk(scope="it")
        for t in desk_it["queue"]:
            self.assertEqual(agent.ticket_scope(t), "it")

    def test_conversation_messages_are_persisted(self):
        out = agent.triage("Mailbox is full and I can't send emails.")
        rid = out["request_id"]
        cont = agent.continue_request(rid, "Can I have a quota increase to 40GB?")
        msgs = db.messages_for(rid)
        senders = [m["sender"] for m in msgs]
        self.assertEqual(senders.count("employee"), 2)
        self.assertEqual(senders.count("agent"), 2)
        self.assertTrue(any("40GB" in m["body"] for m in msgs if m["sender"] == "employee"))

    def test_request_detail_includes_messages_audit_and_related(self):
        out = agent.triage("My laptop screen is flickering, it's 2 years old.")
        det = agent.request_detail(out["request_id"])
        self.assertIn("messages", det)
        self.assertIn("audit", det)
        self.assertIn("related_tickets", det)
        self.assertTrue(det["messages"], "conversation must be present in the detail view")

    def test_ticket_status_update_persists_and_audits(self):
        out = agent.triage("I've started working from home 4 days a week, how do I get a monitor?")
        tid = out["ticket"]["id"]
        agent.update_ticket_status(tid, "Pending Finance", "you@veridian-corp.example")
        row = db.q("SELECT status FROM tickets WHERE id=?", (tid,), fetch=True)[0]
        self.assertEqual(row["status"], "Pending Finance")
        steps = [a["step"] for a in db.audit_for(out["request_id"])]
        self.assertIn("status_changed", steps)

    def test_history_tickets_are_read_only(self):
        with self.assertRaises(ValueError):
            agent.update_ticket_status("TK-1042", "Resolved", "you@veridian-corp.example")

    def test_agent_results_carry_ticket(self):
        for r in agent.agent_results():
            self.assertIn("ticket", r)
            self.assertIn("id", r["ticket"])

    def test_service_desk_returns_queue_and_stats(self):
        desk = agent.service_desk()
        self.assertIn("queue", desk)
        self.assertIn("stats", desk)
        self.assertTrue(desk["queue"])
        self.assertEqual(desk["stats"]["Open"], 0)


if __name__ == "__main__":
    unittest.main()