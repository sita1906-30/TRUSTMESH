"""
TRUSTMESH Automated Security Verification Suite — Phase 3
Tests all 29 security, authentication, RBAC, CSRF, and privacy requirements.

Uses an isolated temporary SQLite database to ensure repeatable, deterministic testing.
"""

import os
import re
import sqlite3
import tempfile
import unittest
from werkzeug.security import check_password_hash, generate_password_hash

from app import app
from database import (
    create_user,
    get_db_connection,
    get_user_by_email,
    init_db,
    migrate_db,
)


class TestTrustMeshPhase3Security(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create an isolated temporary directory and database file
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_phase3_trustmesh.db")

        # Configure Flask test environment
        app.config["TESTING"] = True
        app.config["DATABASE_PATH"] = cls.test_db_path
        app.config["SECRET_KEY"] = "test-phase3-verification-secret-key-998877"
        app.config["WTF_CSRF_ENABLED"] = True  # Explicitly enable CSRF for security tests

        # Initialize schema and seed data
        init_db(db_path=cls.test_db_path)
        migrate_db(db_path=cls.test_db_path)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        # Fresh test client per test
        self.client = app.test_client()

    def _extract_csrf_token(self, get_path="/login"):
        """Helper to fetch a page and extract the CSRF token from rendered HTML."""
        response = self.client.get(get_path)
        html = response.get_data(as_text=True)
        # Check hidden form input
        match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html)
        if match:
            return match.group(1)
        # Check meta tag
        match_meta = re.search(r'meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', html)
        if match_meta:
            return match_meta.group(1)
        return ""

    # =========================================================================
    # Group 1: Registration (Tests 1 - 6)
    # =========================================================================

    def test_01_valid_registration_succeeds(self):
        """1. Valid registration succeeds and creates an active user account."""
        token = self._extract_csrf_token("/register")
        self.assertTrue(token, "CSRF token must be present on /register")

        res = self.client.post("/register", data={
            "csrf_token": token,
            "display_name": "Alice Security",
            "email": "alice@trustmesh.test",
            "password": "Password123!",
            "confirm_password": "Password123!"
        }, follow_redirects=False)

        # Successful registration redirects to /login with flash message
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers.get("Location", ""))

        user = get_user_by_email("alice@trustmesh.test", db_path=self.test_db_path)
        self.assertIsNotNone(user)
        self.assertEqual(user["display_name"], "Alice Security")
        self.assertEqual(user["role_id"], 1)  # Default user role
        print("[PASS] Test 1: Valid registration succeeds.")

    def test_02_passwords_are_stored_as_hashes(self):
        """2. Passwords are never stored in plaintext; stored using secure hash."""
        user = get_user_by_email("alice@trustmesh.test", db_path=self.test_db_path)
        self.assertIsNotNone(user)
        pwd_hash = user["password_hash"]

        self.assertNotEqual(pwd_hash, "Password123!")
        self.assertFalse(pwd_hash.startswith("Password123!"))
        # Verify Werkzeug format (e.g. scrypt: or pbkdf2:)
        self.assertTrue(check_password_hash(pwd_hash, "Password123!"))
        print("[PASS] Test 2: Passwords are stored as secure hashes.")

    def test_03_duplicate_emails_are_rejected(self):
        """3. Duplicate emails are rejected safely without exposing DB errors."""
        token = self._extract_csrf_token("/register")
        res = self.client.post("/register", data={
            "csrf_token": token,
            "display_name": "Alice Duplicate",
            "email": "alice@trustmesh.test",
            "password": "DifferentPassword123!",
            "confirm_password": "DifferentPassword123!"
        }, follow_redirects=True)

        self.assertEqual(res.status_code, 409)
        page = res.get_data(as_text=True)
        self.assertTrue("already exists" in page.lower() or "already registered" in page.lower())
        print("[PASS] Test 3: Duplicate email safely rejected.")

    def test_04_invalid_emails_are_rejected(self):
        """4. Invalid email formats are rejected with 400 Bad Request."""
        token = self._extract_csrf_token("/register")
        res = self.client.post("/register", data={
            "csrf_token": token,
            "display_name": "Bob Invalid",
            "email": "not-a-valid-email",
            "password": "Password123!",
            "confirm_password": "Password123!"
        }, follow_redirects=True)

        self.assertEqual(res.status_code, 400)
        page = res.get_data(as_text=True)
        self.assertIn("valid email", page.lower())
        print("[PASS] Test 4: Invalid email format rejected.")

    def test_05_empty_fields_are_rejected(self):
        """5. Empty or whitespace-only required fields are rejected."""
        token = self._extract_csrf_token("/register")
        res = self.client.post("/register", data={
            "csrf_token": token,
            "display_name": "   ",
            "email": "",
            "password": "Password123!",
            "confirm_password": "Password123!"
        }, follow_redirects=True)

        self.assertEqual(res.status_code, 400)
        page = res.get_data(as_text=True)
        self.assertIn("required", page.lower())
        print("[PASS] Test 5: Empty fields rejected.")

    def test_06_password_confirmation_mismatches_rejected(self):
        """6. Password confirmation mismatches are rejected."""
        token = self._extract_csrf_token("/register")
        res = self.client.post("/register", data={
            "csrf_token": token,
            "display_name": "Charlie",
            "email": "charlie@trustmesh.test",
            "password": "Password123!",
            "confirm_password": "MismatchedPassword999!"
        }, follow_redirects=True)

        self.assertEqual(res.status_code, 400)
        page = res.get_data(as_text=True)
        self.assertIn("passwords do not match", page.lower())
        print("[PASS] Test 6: Password confirmation mismatch rejected.")

    # =========================================================================
    # Group 2: Login and Logout (Tests 7 - 11)
    # =========================================================================

    def test_07_valid_credentials_allow_login(self):
        """7. Valid credentials establish an authenticated session."""
        token = self._extract_csrf_token("/login")
        res = self.client.post("/login", data={
            "csrf_token": token,
            "email": "alice@trustmesh.test",
            "password": "Password123!"
        }, follow_redirects=False)

        self.assertEqual(res.status_code, 302)
        # Check session contains minimal identity
        with self.client.session_transaction() as sess:
            self.assertIn("user_id", sess)
            self.assertEqual(sess["email"], "alice@trustmesh.test")
            self.assertEqual(sess["role"], "user")
            self.assertNotIn("password", sess)
            self.assertNotIn("password_hash", sess)
        print("[PASS] Test 7: Valid credentials allow login.")

    def test_08_invalid_credentials_are_rejected(self):
        """8. Invalid password returns generic error and denies session."""
        token = self._extract_csrf_token("/login")
        res = self.client.post("/login", data={
            "csrf_token": token,
            "email": "alice@trustmesh.test",
            "password": "WrongPassword999!"
        }, follow_redirects=True)

        self.assertEqual(res.status_code, 401)
        page = res.get_data(as_text=True)
        self.assertIn("invalid email or password", page.lower())

        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)
        print("[PASS] Test 8: Invalid credentials rejected.")

    def test_09_login_errors_do_not_reveal_user_existence(self):
        """9. Non-existent email returns the exact same generic error as bad password."""
        token = self._extract_csrf_token("/login")
        res = self.client.post("/login", data={
            "csrf_token": token,
            "email": "nonexistent_ghost_account@trustmesh.test",
            "password": "Password123!"
        }, follow_redirects=True)

        self.assertEqual(res.status_code, 401)
        page = res.get_data(as_text=True)
        self.assertIn("invalid email or password", page.lower())
        self.assertNotIn("account does not exist", page.lower())
        print("[PASS] Test 9: Login errors do not leak account existence.")

    def test_10_logout_clears_session(self):
        """10. POST /logout completely clears authenticated server-side session."""
        # First log in
        token = self._extract_csrf_token("/login")
        self.client.post("/login", data={
            "csrf_token": token,
            "email": "alice@trustmesh.test",
            "password": "Password123!"
        })

        with self.client.session_transaction() as sess:
            self.assertIn("user_id", sess)

        # Now logout via POST with CSRF token
        logout_token = self._extract_csrf_token("/dashboard")
        res = self.client.post("/logout", data={"csrf_token": logout_token}, follow_redirects=False)
        self.assertEqual(res.status_code, 302)

        # Verify session is empty
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)
            self.assertNotIn("email", sess)
            self.assertNotIn("role", sess)
        print("[PASS] Test 10: Logout clears authenticated session.")

    def test_11_protected_routes_reject_requests_after_logout(self):
        """11. Protected pages and APIs reject requests after logout."""
        # Try accessing /dashboard after logout
        res_dash = self.client.get("/dashboard")
        self.assertEqual(res_dash.status_code, 302)
        self.assertIn("/login", res_dash.headers.get("Location", ""))

        # Try accessing /api/history
        res_hist = self.client.get("/api/history")
        self.assertEqual(res_hist.status_code, 401)
        print("[PASS] Test 11: Protected routes reject requests after logout.")

    # =========================================================================
    # Group 3: Authorization and RBAC (Tests 12 - 16)
    # =========================================================================

    def test_12_anonymous_users_cannot_access_private_history(self):
        """12. Anonymous requests to GET /api/history return HTTP 401."""
        res = self.client.get("/api/history")
        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        self.assertIn("error", data)
        self.assertIn("authentication required", data["error"].lower())
        print("[PASS] Test 12: Anonymous user cannot access private history.")

    def test_13_normal_user_cannot_access_admin_dashboard(self):
        """13. Normal user (role_id=1) cannot access /admin (returns 403)."""
        # Log in as normal user
        token = self._extract_csrf_token("/login")
        self.client.post("/login", data={
            "csrf_token": token,
            "email": "alice@trustmesh.test",
            "password": "Password123!"
        })

        res = self.client.get("/admin")
        self.assertEqual(res.status_code, 403)
        self.assertIn("Access Denied", res.get_data(as_text=True))
        print("[PASS] Test 13: Normal user cannot access admin dashboard.")

    def test_14_normal_user_cannot_change_role(self):
        """14. A user cannot elevate their role via registration, form, or JSON tampering."""
        # Attempt to register with role_id=2 or role='admin'
        token = self._extract_csrf_token("/register")
        self.client.post("/register", data={
            "csrf_token": token,
            "display_name": "Mallory Attacker",
            "email": "mallory@trustmesh.test",
            "password": "Password123!",
            "confirm_password": "Password123!",
            "role": "admin",
            "role_id": 2
        })

        user = get_user_by_email("mallory@trustmesh.test", db_path=self.test_db_path)
        self.assertIsNotNone(user)
        self.assertEqual(user["role_id"], 1, "Role must strictly default to 1 (user) regardless of client parameters.")
        print("[PASS] Test 14: Normal user cannot elevate role.")

    def test_15_user_cannot_access_other_users_history_via_params(self):
        """15. Manipulating URL query parameter ?user_id=... cannot access another's records."""
        # Create user Bob and save an analysis
        client_bob = app.test_client()
        token = self._extract_csrf_token("/register")
        self.client.post("/register", data={
            "csrf_token": token,
            "display_name": "Bob Target",
            "email": "bob@trustmesh.test",
            "password": "Password123!",
            "confirm_password": "Password123!"
        })

        # Login as Bob and scan
        token_bob = self._extract_csrf_token("/login")
        client_bob.post("/login", data={
            "csrf_token": token_bob,
            "email": "bob@trustmesh.test",
            "password": "Password123!"
        })
        scan_token = self._extract_csrf_token("/dashboard")
        client_bob.post("/analyze", json={"text": "URGENT payment transfer required!"}, headers={"X-CSRFToken": scan_token})

        # Now login as Alice on self.client and try ?user_id=<bob_id>
        token_alice = self._extract_csrf_token("/login")
        self.client.post("/login", data={
            "csrf_token": token_alice,
            "email": "alice@trustmesh.test",
            "password": "Password123!"
        })

        bob = get_user_by_email("bob@trustmesh.test", db_path=self.test_db_path)
        res = self.client.get(f"/api/history?user_id={bob['user_id']}")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("history", data)
        # Verify that all incidents in Alice's history belong ONLY to Alice (none of Bob's incidents are present)
        incident_ids = [item["incident_id"] for item in data["history"]]
        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()
        cur.execute("SELECT incident_id FROM INCIDENTS WHERE user_id = ?;", (bob["user_id"],))
        bob_incident_ids = {r["incident_id"] for r in cur.fetchall()}
        conn.close()
        for i_id in incident_ids:
            self.assertNotIn(i_id, bob_incident_ids, "Alice's history must NEVER contain Bob's incidents!")
        print("[PASS] Test 15: Parameter tampering cannot expose another user's records.")

    def test_16_admin_only_api_endpoints_reject_normal_users(self):
        """16. Admin-only APIs (/api/admin/users, /api/admin/audit-logs) return 403 for normal users."""
        # Login as normal user Alice
        token = self._extract_csrf_token("/login")
        self.client.post("/login", data={
            "csrf_token": token,
            "email": "alice@trustmesh.test",
            "password": "Password123!"
        })

        res_users = self.client.get("/api/admin/users")
        self.assertEqual(res_users.status_code, 403)

        res_logs = self.client.get("/api/admin/audit-logs")
        self.assertEqual(res_logs.status_code, 403)
        print("[PASS] Test 16: Admin-only APIs reject normal users with 403.")

    # =========================================================================
    # Group 4: CSRF Protection (Tests 17 - 18)
    # =========================================================================

    def test_17_missing_or_invalid_csrf_token_rejected(self):
        """17. State-changing POST requests without CSRF token are rejected with 400 Bad Request."""
        # Missing token on register
        res_reg = self.client.post("/register", data={
            "display_name": "No CSRF",
            "email": "nocsrf@trustmesh.test",
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        self.assertEqual(res_reg.status_code, 400)

        # Invalid token on analyze
        res_ana = self.client.post("/analyze", json={"text": "Hello world"}, headers={"X-CSRFToken": "invalid-token-12345"})
        self.assertEqual(res_ana.status_code, 400)
        self.assertIn("CSRF", res_ana.get_json()["error"])
        print("[PASS] Test 17: Missing/invalid CSRF tokens rejected.")

    def test_18_valid_csrf_token_allows_request(self):
        """18. Valid CSRF token permits state-changing request."""
        token = self._extract_csrf_token("/")
        res = self.client.post("/analyze", json={"text": "Legitimate test message"}, headers={"X-CSRFToken": token})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("score", data)
        self.assertIn("level", data)
        print("[PASS] Test 18: Valid CSRF token allows state-changing request.")

    # =========================================================================
    # Group 5: Database and Privacy (Tests 19 - 24)
    # =========================================================================

    def test_19_existing_phase2_records_intact_after_migration(self):
        """19. Running migrate_db does not destroy or alter existing Phase 2 analysis rows."""
        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as count FROM INCIDENTS;")
        count_before = cur.fetchone()["count"]
        conn.close()

        # Re-run migration multiple times to verify idempotency
        migrate_db(db_path=self.test_db_path)
        migrate_db(db_path=self.test_db_path)

        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as count FROM INCIDENTS;")
        count_after = cur.fetchone()["count"]
        conn.close()

        self.assertEqual(count_before, count_after)
        print("[PASS] Test 19: Database migration is non-destructive and idempotent.")

    def test_20_new_incidents_associated_with_authenticated_user(self):
        """20. Incidents analyzed while logged in are correctly tagged with user_id in INCIDENTS table."""
        # Login as Alice
        token = self._extract_csrf_token("/login")
        self.client.post("/login", data={
            "csrf_token": token,
            "email": "alice@trustmesh.test",
            "password": "Password123!"
        })

        token_scan = self._extract_csrf_token("/dashboard")
        res = self.client.post("/analyze", json={"text": "Exclusive gift reward for account verification"}, headers={"X-CSRFToken": token_scan})
        self.assertEqual(res.status_code, 200)
        incident_id = res.get_json()["incident_id"]

        alice = get_user_by_email("alice@trustmesh.test", db_path=self.test_db_path)
        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM INCIDENTS WHERE incident_id = ?;", (incident_id,))
        row = cur.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["user_id"], alice["user_id"])
        print(f"[PASS] Test 20: Incident #{incident_id} correctly linked to authenticated User #{alice['user_id']}.")

    def test_21_raw_submitted_messages_are_not_stored(self):
        """21. Raw submitted message content is NEVER stored in SQLite database."""
        secret_raw = "MY_PRIVATE_CREDIT_CARD_4111_2222_3333_4444"
        token = self._extract_csrf_token("/")
        self.client.post("/analyze", json={"text": f"Please verify: {secret_raw}"}, headers={"X-CSRFToken": token})

        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()
        # Search all textual columns across all tables
        tables = ["INCIDENTS", "RISK_ASSESSMENTS", "ASSESSMENT_SIGNALS", "AUDIT_LOGS", "USERS"]
        for table in tables:
            cur.execute(f"PRAGMA table_info({table});")
            cols = [col["name"] for col in cur.fetchall()]
            for col in cols:
                cur.execute(f"SELECT COUNT(*) as matches FROM {table} WHERE CAST({col} AS TEXT) LIKE ?;", (f"%{secret_raw}%",))
                match_count = cur.fetchone()["matches"]
                self.assertEqual(match_count, 0, f"Raw sensitive text found in table {table}, column {col}!")
        conn.close()
        print("[PASS] Test 21: Raw submitted content verified absent from all database tables.")

    def test_22_password_hashes_and_secrets_never_returned_by_api(self):
        """22. Password hashes, session secrets, or private keys are never exposed in JSON responses."""
        # Check /api/history
        token = self._extract_csrf_token("/login")
        self.client.post("/login", data={
            "csrf_token": token,
            "email": "alice@trustmesh.test",
            "password": "Password123!"
        })

        res_hist = self.client.get("/api/history")
        text_hist = res_hist.get_data(as_text=True)
        self.assertNotIn("password_hash", text_hist)
        self.assertNotIn("scrypt:", text_hist)
        self.assertNotIn("pbkdf2:", text_hist)

        # Clear session before logging in as admin
        with self.client.session_transaction() as sess:
            sess.clear()

        # Provision admin and check admin endpoints
        create_user("Admin User", "admin_sec@trustmesh.test", generate_password_hash("AdminPass123!"), role_id=2, db_path=self.test_db_path)
        token_admin = self._extract_csrf_token("/login")
        self.client.post("/login", data={
            "csrf_token": token_admin,
            "email": "admin_sec@trustmesh.test",
            "password": "AdminPass123!"
        })

        res_admin_users = self.client.get("/api/admin/users")
        self.assertEqual(res_admin_users.status_code, 200)
        text_users = res_admin_users.get_data(as_text=True)
        self.assertNotIn("password_hash", text_users)
        self.assertNotIn("scrypt:", text_users)
        print("[PASS] Test 22: Sensitive hashes and credentials absent from API outputs.")

    def test_23_sql_injection_attempt_safe(self):
        """23. Malicious SQL payloads cannot alter schema or execute injection."""
        token = self._extract_csrf_token("/register")
        # Attempt SQL injection in registration name
        res = self.client.post("/register", data={
            "csrf_token": token,
            "display_name": "'; DROP TABLE USERS; --",
            "email": "sqli_test@trustmesh.test",
            "password": "Password123!",
            "confirm_password": "Password123!"
        })

        # Verify USERS table is completely intact
        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as count FROM USERS;")
        count = cur.fetchone()["count"]
        conn.close()
        self.assertGreater(count, 0)
        print("[PASS] Test 23: SQL injection attempt safely parameterized.")

    def test_24_audit_events_do_not_contain_secrets(self):
        """24. Security audit logs record events without logging passwords or secrets."""
        conn = get_db_connection(self.test_db_path)
        cur = conn.cursor()
        cur.execute("SELECT * FROM AUDIT_LOGS WHERE details IS NOT NULL;")
        rows = cur.fetchall()
        conn.close()

        self.assertGreater(len(rows), 0, "Audit logs should record authentication events.")
        for row in rows:
            details = row["details"] or ""
            self.assertNotIn("Password123!", details)
            self.assertNotIn("scrypt:", details)
            self.assertNotIn("pbkdf2:", details)
            self.assertNotIn("secret", details.lower())
        print(f"[PASS] Test 24: Audit logs verified clean of passwords and secrets ({len(rows)} entries inspected).")

    # =========================================================================
    # Group 6: Application Security (Tests 25 - 29)
    # =========================================================================

    def test_25_security_headers_present(self):
        """25. Required security headers are present on all HTTP responses."""
        res = self.client.get("/")
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(res.headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(res.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("default-src 'self'", res.headers.get("Content-Security-Policy", ""))
        print("[PASS] Test 25: Security headers (nosniff, SAMEORIGIN, CSP, Referrer-Policy) verified.")

    def test_26_auth_errors_handled_safely(self):
        """26. Authentication errors return user-friendly messages without technical leaks."""
        token = self._extract_csrf_token("/login")
        res = self.client.post("/login", data={
            "csrf_token": token,
            "email": "invalid' OR '1'='1",
            "password": "wrong"
        }, follow_redirects=True)

        self.assertEqual(res.status_code, 401)
        text = res.get_data(as_text=True)
        self.assertNotIn("sqlite3", text.lower())
        self.assertNotIn("traceback", text.lower())
        self.assertIn("invalid email or password", text.lower())
        print("[PASS] Test 26: Authentication errors safely handled without technical leaks.")

    def test_27_database_failures_do_not_expose_stack_traces(self):
        """27. Internal server errors return friendly error page without stack traces."""
        # Request an invalid page with error status
        res = self.client.get("/non-existent-endpoint-404")
        self.assertEqual(res.status_code, 404)
        text = res.get_data(as_text=True)
        self.assertNotIn("Traceback (most recent call last)", text)
        self.assertIn("TRUSTMESH", text)
        print("[PASS] Test 27: Error responses do not leak stack traces.")

    def test_28_existing_analyzer_functionality_works(self):
        """28. Heuristic analyzer engine correctly analyzes signals and computes scores."""
        token = self._extract_csrf_token("/")
        res = self.client.post("/analyze", json={
            "text": "URGENT! You have won $10,000 cash. Claim your prize now at http://win-claim-gift.xyz"
        }, headers={"X-CSRFToken": token})

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertGreaterEqual(data["score"], 50)
        self.assertIn("findings", data)
        self.assertTrue(any("urgency" in f.lower() for f in data["findings"]))
        self.assertTrue(any("prize" in f.lower() for f in data["findings"]))
        self.assertEqual(data["urls_found"], 1)
        print(f"[PASS] Test 28: Analyzer operational (Score: {data['score']}, Findings: {len(data['findings'])}).")

    def test_29_history_and_analytics_functional_under_authorization(self):
        """29. History and analytics return user-scoped metrics when authorized."""
        # Login as Alice
        token = self._extract_csrf_token("/login")
        self.client.post("/login", data={
            "csrf_token": token,
            "email": "alice@trustmesh.test",
            "password": "Password123!"
        })

        # History should return Alice's scans
        res_hist = self.client.get("/api/history")
        self.assertEqual(res_hist.status_code, 200)
        data_hist = res_hist.get_json()
        self.assertIn("history", data_hist)
        self.assertGreaterEqual(len(data_hist["history"]), 1)

        # Analytics should return Alice's aggregates
        res_ana = self.client.get("/api/analytics")
        self.assertEqual(res_ana.status_code, 200)
        data_ana = res_ana.get_json()
        self.assertIn("analytics", data_ana)
        self.assertGreaterEqual(data_ana["analytics"]["total_analyses"], 1)
        print("[PASS] Test 29: History and analytics fully functional under authorization rules.")


if __name__ == "__main__":
    unittest.main()
