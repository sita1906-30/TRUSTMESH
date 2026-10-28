"""
TRUSTMESH Automated Verification Suite — Phase 2
Tests all 13 Phase 2 requirements using an isolated temporary test database.
"""

import os
import sqlite3
import tempfile
import unittest

from app import app
from database import (
    check_db_health,
    get_db_connection,
    init_db,
    save_analysis_transaction,
)


class TestPhase2DatabaseAndEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a dedicated temporary directory and database file for isolated testing
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_trustmesh.db")
        
        # Configure the Flask app to use the temporary test database
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["DATABASE_PATH"] = cls.test_db_path
        
        # Initialize schema and seed data in the temporary database
        init_db(db_path=cls.test_db_path)
        cls.client = app.test_client()
        with cls.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["email"] = "dev@trustmesh.local"
            sess["role"] = "user"

    @classmethod
    def tearDownClass(cls):
        # Clean up temporary test files
        cls.temp_dir.cleanup()

    def test_01_database_initialization(self):
        """1. Database initialization creates all 7 tables, view, indexes, trigger, and seed data."""
        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()

        # Check required tables
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row["name"] for row in cur.fetchall()]
        expected_tables = [
            "USERS", "ROLES", "INCIDENTS", "RISK_ASSESSMENTS",
            "RISK_SIGNALS", "ASSESSMENT_SIGNALS", "AUDIT_LOGS"
        ]
        for tbl in expected_tables:
            self.assertIn(tbl, tables, f"Expected table '{tbl}' was not created.")

        # Check reporting view
        cur.execute("SELECT name FROM sqlite_master WHERE type='view';")
        views = [row["name"] for row in cur.fetchall()]
        self.assertIn("v_incident_summary", views)

        # Check audit trigger
        cur.execute("SELECT name FROM sqlite_master WHERE type='trigger';")
        triggers = [row["name"] for row in cur.fetchall()]
        self.assertIn("trg_audit_assessment_insert", triggers)

        # Check seed data
        cur.execute("SELECT COUNT(*) as cnt FROM RISK_SIGNALS;")
        signal_count = cur.fetchone()["cnt"]
        self.assertGreaterEqual(signal_count, 9, "RISK_SIGNALS seed catalog should contain standard signals.")

        cur.execute("SELECT COUNT(*) as cnt FROM USERS WHERE user_id = 1;")
        self.assertEqual(cur.fetchone()["cnt"], 1, "Default anonymous user (user_id=1) must exist.")

        conn.close()
        print("[PASS] Test 1: Database initialization created all required schema objects and seed data.")

    def test_02_foreign_keys_enforced(self):
        """2. Foreign keys are strictly enforced in SQLite connections."""
        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()

        # Attempt to insert an INCIDENT referencing a non-existent user_id (999999)
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                """
                INSERT INTO INCIDENTS (user_id, content_type, processing_status)
                VALUES (999999, 'message', 'COMPLETED');
                """
            )
            conn.commit()

        conn.close()
        print("[PASS] Test 2: Foreign key enforcement verified (IntegrityError raised on invalid reference).")

    def test_03_valid_analysis_saved(self):
        """3. A valid analysis is saved successfully and activates the audit trigger."""
        msg = "URGENT! Please pay now to avoid penalty."
        res = self.client.post('/analyze', json={"text": msg})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertIn("incident_id", data)
        incident_id = data["incident_id"]

        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()

        # Verify incident record
        cur.execute("SELECT * FROM INCIDENTS WHERE incident_id = ?;", (incident_id,))
        incident_row = cur.fetchone()
        self.assertIsNotNone(incident_row)
        self.assertEqual(incident_row["content_type"], "message")

        # Verify assessment record
        cur.execute("SELECT * FROM RISK_ASSESSMENTS WHERE incident_id = ?;", (incident_id,))
        assessment_row = cur.fetchone()
        self.assertIsNotNone(assessment_row)
        self.assertEqual(assessment_row["risk_score"], data["score"])
        self.assertEqual(assessment_row["risk_level"], data["level"])

        # Verify trigger automatically logged the assessment creation in AUDIT_LOGS
        cur.execute("SELECT * FROM AUDIT_LOGS WHERE event_type = 'ASSESSMENT_CREATED' ORDER BY audit_id DESC LIMIT 1;")
        audit_row = cur.fetchone()
        self.assertIsNotNone(audit_row, "Audit trigger should record an event in AUDIT_LOGS.")
        self.assertEqual(audit_row["event_status"], "SUCCESS")

        conn.close()
        print(f"[PASS] Test 3: Valid analysis successfully persisted (Incident #{incident_id}) with trigger audit.")

    def test_04_multiple_signals_relationships(self):
        """4. Analysis with multiple warning indicators saves the correct relationships in ASSESSMENT_SIGNALS."""
        msg = "URGENT! Pay the registration fee immediately to claim your prize."
        res = self.client.post('/analyze', json={"text": msg})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        incident_id = data["incident_id"]

        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()

        cur.execute(
            """
            SELECT rs.signal_name, asig.points_awarded
            FROM ASSESSMENT_SIGNALS asig
            JOIN RISK_ASSESSMENTS ra ON asig.assessment_id = ra.assessment_id
            JOIN RISK_SIGNALS rs ON asig.signal_id = rs.signal_id
            WHERE ra.incident_id = ?;
            """,
            (incident_id,)
        )
        saved_signals = {row["signal_name"]: row["points_awarded"] for row in cur.fetchall()}

        # Verify expected signals were linked
        self.assertIn("urgency", saved_signals)
        self.assertIn("payment_pressure", saved_signals)
        self.assertIn("prize_reward", saved_signals)
        self.assertEqual(saved_signals["urgency"], 20)
        self.assertEqual(saved_signals["payment_pressure"], 25)
        self.assertEqual(saved_signals["prize_reward"], 15)

        conn.close()
        print(f"[PASS] Test 4: Assessment signals linked in M:N relationship: {list(saved_signals.keys())}.")

    def test_05_transaction_rollback_on_failure(self):
        """5. Analysis and all associated records roll back completely if a database write fails."""
        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as count FROM INCIDENTS;")
        count_before = cur.fetchone()["count"]
        conn.close()

        # Attempt to insert with an invalid score (-50) which violates CHECK (risk_score >= 0)
        with self.assertRaises(sqlite3.IntegrityError):
            save_analysis_transaction(
                user_id=1,
                content_type="message",
                content_fingerprint="dummy_fp",
                score=-50,  # Violates CHECK constraint!
                level="High risk",
                engine_version="2.0.0",
                recommendation="Do not act.",
                detected_signals={"urgency": 20},
                db_path=self.test_db_path
            )

        # Verify incident was NOT committed due to transaction rollback
        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as count FROM INCIDENTS;")
        count_after = cur.fetchone()["count"]
        conn.close()

        self.assertEqual(count_before, count_after, "Failed transaction should leave INCIDENTS table untouched.")
        print("[PASS] Test 5: Transaction rollback verified (no orphaned records on check violation).")

    def test_06_history_route_order(self):
        """6. The history route returns records in descending chronological order (most recent first)."""
        res = self.client.get('/api/history')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertIn("history", data)
        history = data["history"]
        self.assertIsInstance(history, list)
        self.assertGreater(len(history), 0)

        # Verify descending order of incident_id
        incident_ids = [item["incident_id"] for item in history]
        self.assertEqual(incident_ids, sorted(incident_ids, reverse=True))
        print(f"[PASS] Test 6: History returned in correct descending order: {incident_ids[:5]}...")

    def test_07_history_does_not_expose_raw_content(self):
        """7. The history route does not expose raw submitted messages or URLs."""
        secret_sample = "TOP_SECRET_USER_PAYLOAD_998877_PRIVATE_DATA"
        res_post = self.client.post('/analyze', json={"text": f"URGENT notification: {secret_sample}"})
        self.assertEqual(res_post.status_code, 200)

        # Query history endpoint
        res_history = self.client.get('/api/history')
        self.assertEqual(res_history.status_code, 200)
        history_text = res_history.get_data(as_text=True)

        # Verify secret text is NOT present in any response field
        self.assertNotIn(secret_sample, history_text, "Raw submitted text must NEVER appear in history endpoint.")
        print("[PASS] Test 7: Privacy verified (raw submitted message string absent from history response).")

    def test_08_analytics_route_aggregates(self):
        """8. The analytics route returns correct aggregate values."""
        res = self.client.get('/api/analytics')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertIn("analytics", data)
        analytics = data["analytics"]
        self.assertIn("total_analyses", analytics)
        self.assertIn("high_risk_count", analytics)
        self.assertIn("suspicious_count", analytics)
        self.assertIn("lower_risk_count", analytics)
        self.assertIn("average_score", analytics)
        self.assertIn("top_signals", analytics)

        self.assertGreater(analytics["total_analyses"], 0)
        self.assertIsInstance(analytics["average_score"], float)
        self.assertIsInstance(analytics["top_signals"], list)
        print(f"[PASS] Test 8: Analytics aggregates computed (Total: {analytics['total_analyses']}, Avg Score: {analytics['average_score']}).")

    def test_09_empty_input_rejected(self):
        """9. Empty input or whitespace-only is rejected with 400 Bad Request."""
        res = self.client.post('/analyze', json={"text": "   \n   "})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)
        self.assertIn("empty", data["error"].lower())
        print("[PASS] Test 9: Empty input rejected properly.")

    def test_10_exceeding_max_input_rejected(self):
        """10. Inputs exceeding 5,000 characters are rejected with 400 Bad Request."""
        oversized = "A" * 5001
        res = self.client.post('/analyze', json={"text": oversized})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)
        self.assertIn("5000", data["error"])
        print("[PASS] Test 10: Input > 5,000 chars rejected properly.")

    def test_11_sql_injection_attempt_safe(self):
        """11. SQL-like input strings do not alter or damage the database schema."""
        injection_payload = "'; DROP TABLE USERS; DROP TABLE INCIDENTS; --"
        res = self.client.post('/analyze', json={"text": injection_payload})
        # Should be processed normally as plain text
        self.assertEqual(res.status_code, 200)

        # Verify tables still exist
        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='USERS';")
        self.assertIsNotNone(cur.fetchone(), "Table USERS must still exist after SQL-like input.")
        conn.close()
        print("[PASS] Test 11: SQL injection payload safely parameterized (schema intact).")

    def test_12_database_failure_returns_safe_error(self):
        """12. Database failures return safe error responses without stack traces."""
        # Point app to an invalid database location (read-only or non-creatable path)
        invalid_path = os.path.join(self.temp_dir.name, "non_existent_folder", "sub", "fake.db")
        app.config["DATABASE_PATH"] = invalid_path

        res = self.client.post('/analyze', json={"text": "Valid message with DB broken"})
        self.assertEqual(res.status_code, 500)
        data = res.get_json()
        self.assertIn("error", data)
        # Ensure stack trace / internal exception type is NOT in error string
        self.assertNotIn("Traceback", data["error"])
        self.assertNotIn("sqlite3.OperationalError", data["error"])

        # Restore valid test path
        app.config["DATABASE_PATH"] = self.test_db_path
        print("[PASS] Test 12: Database failure returned generic, safe HTTP 500 response.")

    def test_13_phase1_analysis_behavior_preserved(self):
        """13. Existing Phase 1 analysis behavior remains fully functional."""
        # Ordinary message
        res1 = self.client.post('/analyze', json={"text": "Your appointment is scheduled for tomorrow at 10 AM."})
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(res1.get_json()["score"], 0)
        self.assertEqual(res1.get_json()["level"], "Lower detected risk")

        # Suspicious payment message
        res2 = self.client.post('/analyze', json={"text": "URGENT! Pay the registration fee immediately to claim your prize."})
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.get_json()["score"], 60)
        self.assertEqual(res2.get_json()["level"], "High risk")

        # Sensitive info request
        res3 = self.client.post('/analyze', json={"text": "Send your OTP and share your password immediately."})
        self.assertEqual(res3.status_code, 200)
        self.assertEqual(res3.get_json()["score"], 50)
        self.assertEqual(res3.get_json()["level"], "Suspicious")

        # HTTP URL
        res4 = self.client.post('/analyze', json={"text": "http://example.com/login"})
        self.assertEqual(res4.status_code, 200)
        self.assertEqual(res4.get_json()["score"], 15)
        self.assertEqual(res4.get_json()["level"], "Lower detected risk")
        self.assertEqual(res4.get_json()["urls_found"], 1)

        print("[PASS] Test 13: Phase 1 scoring behavior completely preserved.")

    def test_14_health_endpoint(self):
        """14. Health endpoint returns status and connectivity."""
        res = self.client.get('/health')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["database"], "connected")
        self.assertIn(data["engine_version"], ["2.0.0", "3.0.0"])
        print("[PASS] Test 14: /health endpoint verified.")


if __name__ == '__main__':
    unittest.main()
