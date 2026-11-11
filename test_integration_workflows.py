"""
TRUSTMESH Comprehensive End-to-End Workflow Verification Suite (Phase 4, Task 6)
Simulates complete real-world User and Administrator lifecycles.
"""

import json
import os
import re
import tempfile
import unittest

from app import app
from database import (
    create_user,
    init_db,
    migrate_db,
)


class TestCompleteApplicationWorkflows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_workflows.db")

        app.config["TESTING"] = True
        app.config["DATABASE_PATH"] = cls.test_db_path
        app.config["WTF_CSRF_ENABLED"] = True
        app.config["SECRET_KEY"] = "workflow-verification-secret-key-2026"

        init_db(db_path=cls.test_db_path)
        migrate_db(db_path=cls.test_db_path)

        # Seed pre-existing admin account
        cls.admin_email = "admin_e2e@trustmesh.test"
        cls.admin_password = "AdminPassword123!"
        from werkzeug.security import generate_password_hash
        cls.admin_id = create_user(
            display_name="E2E Administrator",
            email=cls.admin_email,
            password_hash=generate_password_hash(cls.admin_password),
            role_id=2,  # Admin
            db_path=cls.test_db_path
        )

        # Seed baseline assessment record for admin analytics
        from database import save_analysis_transaction
        save_analysis_transaction(
            user_id=cls.admin_id,
            content_type="message",
            content_fingerprint="fp_seed_001",
            score=70,
            level="High risk",
            engine_version="3.0.0",
            recommendation="Initial seed alert.",
            detected_signals={"urgency": 20, "sensitive_info": 30},
            db_path=cls.test_db_path
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        self.client = app.test_client()

    def _get_csrf_token(self, path="/login"):
        res = self.client.get(path)
        html = res.get_data(as_text=True)
        m = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html)
        if m:
            return m.group(1)
        m_meta = re.search(r'meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', html)
        if m_meta:
            return m_meta.group(1)
        return ""

    # =========================================================================
    # Complete Workflow 1: User Lifecycle
    # =========================================================================
    def test_complete_user_workflow(self):
        """Simulates full user journey: register, login, scan message, scan URL, check history, export, logout."""
        # 1. Open TRUSTMESH
        res_home = self.client.get("/")
        self.assertEqual(res_home.status_code, 200)
        self.assertIn("TRUSTMESH", res_home.get_data(as_text=True))

        # 2. Register a new account
        reg_csrf = self._get_csrf_token("/register")
        user_email = "student_user@trustmesh.test"
        user_password = "StudentPass123!"
        res_reg = self.client.post("/register", data={
            "csrf_token": reg_csrf,
            "display_name": "Student Researcher",
            "email": user_email,
            "password": user_password,
            "confirm_password": user_password
        }, follow_redirects=True)
        self.assertEqual(res_reg.status_code, 200)

        # 3. Log in
        login_csrf = self._get_csrf_token("/login")
        res_login = self.client.post("/login", data={
            "csrf_token": login_csrf,
            "email": user_email,
            "password": user_password
        }, follow_redirects=True)
        self.assertEqual(res_login.status_code, 200)

        # Grab CSRF token for JSON API fetch requests from dashboard
        api_csrf = self._get_csrf_token("/dashboard")
        headers = {"X-CSRFToken": api_csrf}

        # 4. Submit a suspicious message
        res_msg = self.client.post("/analyze", json={
            "text": "URGENT: Your bank account will be suspended! Click http://192.168.1.1/verify and enter your password."
        }, headers=headers)
        self.assertEqual(res_msg.status_code, 200)
        data_msg = res_msg.get_json()
        self.assertGreaterEqual(data_msg["score"], 50)
        self.assertIn(data_msg["level"], ["Suspicious", "High risk"])
        self.assertGreaterEqual(len(data_msg["findings"]), 2)
        self.assertTrue(len(data_msg["recommendation"]) > 0)
        self.assertTrue(len(data_msg["disclaimer"]) > 0)
        asm_id_1 = data_msg["assessment_id"]

        # 5. Submit a suspicious URL
        res_url = self.client.post("/analyze", json={
            "text": "http://secure-login.bank-update.com/account"
        }, headers=headers)
        self.assertEqual(res_url.status_code, 200)
        data_url = res_url.get_json()
        self.assertGreaterEqual(data_url["score"], 15)
        self.assertEqual(data_url["urls_found"], 1)
        asm_id_2 = data_url["assessment_id"]

        # 6. View assessment history
        res_hist = self.client.get("/api/history")
        self.assertEqual(res_hist.status_code, 200)
        history = res_hist.get_json()["history"]
        self.assertEqual(len(history), 2)
        # History is in reverse chronological order
        self.assertEqual(history[0]["assessment_id"], asm_id_2)
        self.assertEqual(history[1]["assessment_id"], asm_id_1)

        # 7. Export an assessment report (local export)
        res_exp = self.client.post("/api/reports/export", json={
            "assessment_id": asm_id_1,
            "save_to_cloud": False
        }, headers=headers)
        self.assertEqual(res_exp.status_code, 200)
        exp_data = res_exp.get_json()
        report_id = exp_data["report_id"]

        # 8. Download the assessment report
        res_dl = self.client.get(f"/api/reports/{report_id}/download")
        self.assertEqual(res_dl.status_code, 200)
        report_json = json.loads(res_dl.get_data(as_text=True))
        self.assertEqual(report_json["assessment_details"]["assessment_id"], asm_id_1)
        self.assertIn("report_metadata", report_json)

        # 9. Log out
        logout_csrf = self._get_csrf_token("/dashboard")
        res_logout = self.client.post("/logout", data={"csrf_token": logout_csrf}, follow_redirects=True)
        self.assertEqual(res_logout.status_code, 200)

        # 10. Verify protected routes reject anonymous access
        res_hist_post = self.client.get("/api/history")
        self.assertEqual(res_hist_post.status_code, 401)
        print("[PASS] Complete User Lifecycle workflow verified end-to-end.")

    # =========================================================================
    # Complete Workflow 2: Administrator Lifecycle
    # =========================================================================
    def test_complete_admin_workflow(self):
        """Simulates full admin journey: login, console, analytics, trends, CSV export, RBAC boundaries."""
        # 1. Log in as Administrator
        login_csrf = self._get_csrf_token("/login")
        res_login = self.client.post("/login", data={
            "csrf_token": login_csrf,
            "email": self.admin_email,
            "password": self.admin_password
        }, follow_redirects=True)
        self.assertEqual(res_login.status_code, 200)

        # 2. Open the administrative console
        res_admin = self.client.get("/admin")
        self.assertEqual(res_admin.status_code, 200)
        self.assertIn("Administration Console", res_admin.get_data(as_text=True))

        # 3. View total assessments & overview
        res_ov = self.client.get("/api/analytics/overview")
        self.assertEqual(res_ov.status_code, 200)
        ov_data = res_ov.get_json()["overview"]
        self.assertGreaterEqual(ov_data["total_assessments"], 1)

        # 4. View risk distribution
        res_dist = self.client.get("/api/analytics/risk-distribution")
        self.assertEqual(res_dist.status_code, 200)
        dist_data = res_dist.get_json()["risk_distribution"]
        self.assertEqual(len(dist_data), 3)

        # 5. View detected risk signals
        res_sig = self.client.get("/api/analytics/risk-signals")
        self.assertEqual(res_sig.status_code, 200)
        sig_data = res_sig.get_json()["risk_signals"]
        self.assertEqual(len(sig_data), 9)

        # 6. View assessment trends
        res_tr = self.client.get("/api/analytics/trends?interval=daily")
        self.assertEqual(res_tr.status_code, 200)
        tr_data = res_tr.get_json()["trends"]
        self.assertGreaterEqual(len(tr_data), 1)

        # 7. Export anonymized analytics CSV
        res_csv = self.client.get("/api/analytics/export")
        self.assertEqual(res_csv.status_code, 200)
        self.assertEqual(res_csv.mimetype, "text/csv")
        csv_text = res_csv.get_data(as_text=True)
        self.assertIn("Assessment_ID,Assessment_Date", csv_text)

        # 8. Verify privacy in exported CSV
        self.assertNotIn("student_user@trustmesh.test", csv_text)
        self.assertNotIn("admin_e2e@trustmesh.test", csv_text)
        self.assertNotIn("password", csv_text.lower())
        print("[PASS] Complete Administrator Lifecycle workflow verified end-to-end.")


if __name__ == "__main__":
    unittest.main()
