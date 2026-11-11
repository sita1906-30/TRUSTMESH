"""
TRUSTMESH Automated Verification Suite — Phase 4, Task 4: Power BI Analytics Integration
Tests database analytics views, KPI calculations, risk distributions, signal prevalence,
time trends, sanitized CSV exports, privacy guarantees, RBAC authorization, and backward compatibility.
"""

from datetime import datetime, timezone
import io
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from app import app
from database import (
    create_user,
    get_analytics_overview,
    get_anonymized_assessments_for_export,
    get_assessment_trends,
    get_database_mode,
    get_db_connection,
    get_risk_level_distribution,
    get_risk_signal_frequency,
    init_db,
    migrate_db,
    save_analysis_transaction,
)
from migrate_to_azure import parse_sql_batches, SCHEMA_AZURE_PATH
from services.analytics_service import (
    CSV_EXPORT_FIELDS,
    generate_anonymized_csv,
    get_analytics_dashboard_bundle,
    validate_anonymized_record,
)


class TestPowerBIAnalyticsIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create dedicated isolated SQLite test database
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_powerbi_analytics.db")

        app.config["TESTING"] = True
        app.config["DATABASE_PATH"] = cls.test_db_path
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "test-secret-powerbi-analytics-2026"

        init_db(db_path=cls.test_db_path)
        migrate_db(db_path=cls.test_db_path)

        # Create Standard User (User #2) and Admin User (User #3)
        cls.user_id = create_user(
            display_name="Standard User",
            email="standard_user@trustmesh.test",
            password_hash="hash_standard_123",
            role_id=1,  # User role
            db_path=cls.test_db_path
        )
        cls.admin_id = create_user(
            display_name="Admin Analyst",
            email="admin_analyst@trustmesh.test",
            password_hash="hash_admin_123",
            role_id=2,  # Admin role
            db_path=cls.test_db_path
        )

        # Seed Dummy Assessment Records across various risk levels and dates
        # Assessment 1: High risk (urgency + sensitive_info + payment_pressure)
        cls.asm1_inc, cls.asm1_id = save_analysis_transaction(
            user_id=cls.user_id,
            content_type="message",
            content_fingerprint="fp_hash_001",
            score=75,
            level="High risk",
            engine_version="3.0.0",
            recommendation="High risk detected. Do not share OTP or send payment.",
            detected_signals={"urgency": 20, "sensitive_info": 30, "payment_pressure": 25},
            db_path=cls.test_db_path
        )

        # Assessment 2: Suspicious (threats_suspension + url_insecure_http)
        cls.asm2_inc, cls.asm2_id = save_analysis_transaction(
            user_id=cls.user_id,
            content_type="url",
            content_fingerprint="fp_hash_002",
            score=45,
            level="Suspicious",
            engine_version="3.0.0",
            recommendation="Suspicious interaction. Check domain identity.",
            detected_signals={"threats_suspension": 20, "url_insecure_http": 15},
            db_path=cls.test_db_path
        )

        # Assessment 3: Lower detected risk (no signals triggered)
        cls.asm3_inc, cls.asm3_id = save_analysis_transaction(
            user_id=cls.user_id,
            content_type="message",
            content_fingerprint="fp_hash_003",
            score=10,
            level="Lower detected risk",
            engine_version="3.0.0",
            recommendation="Preliminary lower risk. Maintain standard vigilance.",
            detected_signals={},
            db_path=cls.test_db_path
        )

        # Assessment 4: High risk (prize_reward + urgency + url_ip_hostname)
        cls.asm4_inc, cls.asm4_id = save_analysis_transaction(
            user_id=cls.admin_id,
            content_type="mixed",
            content_fingerprint="fp_hash_004",
            score=85,
            level="High risk",
            engine_version="3.0.0",
            recommendation="Critical fraud indicators detected. Block sender immediately.",
            detected_signals={"prize_reward": 15, "urgency": 20, "url_ip_hostname": 20},
            db_path=cls.test_db_path
        )

        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    # =========================================================================
    # Test 1: Analytics Overview Query (v_analytics_overview)
    # =========================================================================
    def test_01_analytics_overview_query(self):
        """1. v_analytics_overview computes accurate totals, risk counts, percentages, and averages."""
        overview = get_analytics_overview(db_path=self.test_db_path)
        self.assertEqual(overview["total_assessments"], 4)
        self.assertEqual(overview["total_high_risk"], 2)
        self.assertEqual(overview["total_medium_risk"], 1)
        self.assertEqual(overview["total_low_risk"], 1)
        # Expected average: (75 + 45 + 10 + 85) / 4 = 215 / 4 = 53.75 -> 53.8 or 53.75
        self.assertAlmostEqual(overview["avg_risk_score"], 53.75, places=1)
        self.assertEqual(overview["pct_high_risk"], 50.0)
        self.assertEqual(overview["pct_medium_risk"], 25.0)
        self.assertEqual(overview["pct_low_risk"], 25.0)
        self.assertGreaterEqual(overview["total_signals_detected"], 8)
        print(f"[PASS] Test 1: Analytics overview verified (Total: {overview['total_assessments']}, Avg Score: {overview['avg_risk_score']}).")

    # =========================================================================
    # Test 2: Risk Level Distribution Query (v_risk_level_distribution)
    # =========================================================================
    def test_02_risk_distribution_query(self):
        """2. v_risk_level_distribution returns category breakdown with counts and percentages."""
        dist = get_risk_level_distribution(db_path=self.test_db_path)
        self.assertEqual(len(dist), 3)

        dist_by_name = {d["risk_level"]: d for d in dist}
        self.assertIn("High risk", dist_by_name)
        self.assertIn("Suspicious", dist_by_name)
        self.assertIn("Lower detected risk", dist_by_name)

        self.assertEqual(dist_by_name["High risk"]["assessment_count"], 2)
        self.assertEqual(dist_by_name["High risk"]["percentage"], 50.0)

        self.assertEqual(dist_by_name["Suspicious"]["assessment_count"], 1)
        self.assertEqual(dist_by_name["Suspicious"]["percentage"], 25.0)

        self.assertEqual(dist_by_name["Lower detected risk"]["assessment_count"], 1)
        self.assertEqual(dist_by_name["Lower detected risk"]["percentage"], 25.0)
        print("[PASS] Test 2: Risk level distribution verified (High: 50%, Suspicious: 25%, Low: 25%).")

    # =========================================================================
    # Test 3: Risk Signal Frequency Query (v_risk_signal_frequency)
    # =========================================================================
    def test_03_risk_signal_frequency_query(self):
        """3. v_risk_signal_frequency queries detection counts and prevalence across catalog signals."""
        signals = get_risk_signal_frequency(db_path=self.test_db_path)
        self.assertEqual(len(signals), 9)  # All 9 catalog signals

        sig_map = {s["signal_name"]: s for s in signals}
        self.assertIn("urgency", sig_map)
        # Urgency was triggered in Assessment 1 and Assessment 4 -> count = 2
        self.assertEqual(sig_map["urgency"]["detection_count"], 2)
        self.assertEqual(sig_map["urgency"]["prevalence_pct"], 50.0)

        # Sensitive info triggered in Assessment 1 -> count = 1
        self.assertEqual(sig_map["sensitive_info"]["detection_count"], 1)
        self.assertEqual(sig_map["sensitive_info"]["prevalence_pct"], 25.0)

        # Signal not triggered in any dummy test (e.g. url_punycode) -> count = 0
        self.assertEqual(sig_map["url_punycode"]["detection_count"], 0)
        self.assertEqual(sig_map["url_punycode"]["prevalence_pct"], 0.0)
        print(f"[PASS] Test 3: Signal frequency query verified (Top signal: '{signals[0]['signal_name']}' with {signals[0]['detection_count']} hits).")

    # =========================================================================
    # Test 4: Trend Queries (Daily, Weekly, Monthly)
    # =========================================================================
    def test_04_trend_queries(self):
        """4. Trend queries return aggregated volume and averages for daily, weekly, and monthly periods."""
        # Daily
        daily_trends = get_assessment_trends("daily", db_path=self.test_db_path)
        self.assertGreaterEqual(len(daily_trends), 1)
        today_trend = daily_trends[0]
        self.assertEqual(today_trend["total_assessments"], 4)
        self.assertEqual(today_trend["high_risk_count"], 2)

        # Weekly
        weekly_trends = get_assessment_trends("weekly", db_path=self.test_db_path)
        self.assertGreaterEqual(len(weekly_trends), 1)
        self.assertEqual(weekly_trends[0]["total_assessments"], 4)

        # Monthly
        monthly_trends = get_assessment_trends("monthly", db_path=self.test_db_path)
        self.assertGreaterEqual(len(monthly_trends), 1)
        self.assertEqual(monthly_trends[0]["total_assessments"], 4)
        print(f"[PASS] Test 4: Assessment trends verified across daily ({len(daily_trends)}), weekly ({len(weekly_trends)}), and monthly intervals.")

    # =========================================================================
    # Test 5: CSV Export Generation and Structure
    # =========================================================================
    def test_05_csv_export_generation_and_headers(self):
        """5. generate_anonymized_csv generates standard RFC-4180 CSV with required Power BI headers."""
        csv_text, count = generate_anonymized_csv(db_path=self.test_db_path)
        self.assertEqual(count, 4)
        self.assertTrue(len(csv_text) > 0)

        lines = csv_text.strip().split("\r\n")
        header_line = lines[0]
        headers = header_line.split(",")

        # Verify all 11 required columns are present in header
        for col in CSV_EXPORT_FIELDS:
            self.assertIn(col, headers)

        # Check data row structure
        first_row = lines[1]
        self.assertIn("High risk", first_row)
        self.assertIn("3.0.0", first_row)
        self.assertIn("fp_hash_001", first_row)
        print(f"[PASS] Test 5: Sanitized CSV export verified ({count} rows, {len(headers)} columns).")

    # =========================================================================
    # Test 6: Empty Database Handling
    # =========================================================================
    def test_06_empty_database_handling(self):
        """6. Views and export functions handle empty tables gracefully without division-by-zero errors."""
        with tempfile.TemporaryDirectory() as empty_temp:
            empty_db = os.path.join(empty_temp, "empty.db")
            init_db(db_path=empty_db)
            migrate_db(db_path=empty_db)

            # Overview
            overview = get_analytics_overview(db_path=empty_db)
            self.assertEqual(overview["total_assessments"], 0)
            self.assertEqual(overview["avg_risk_score"], 0.0)
            self.assertEqual(overview["pct_high_risk"], 0.0)

            # Distribution
            dist = get_risk_level_distribution(db_path=empty_db)
            self.assertEqual(len(dist), 3)
            for d in dist:
                self.assertEqual(d["assessment_count"], 0)
                self.assertEqual(d["percentage"], 0.0)

            # Signals
            signals = get_risk_signal_frequency(db_path=empty_db)
            self.assertEqual(len(signals), 9)
            for s in signals:
                self.assertEqual(s["detection_count"], 0)

            # Trends
            trends = get_assessment_trends("daily", db_path=empty_db)
            self.assertEqual(len(trends), 0)

            # CSV
            csv_str, count = generate_anonymized_csv(db_path=empty_db)
            self.assertEqual(count, 0)
            self.assertIn("Assessment_ID", csv_str)
        print("[PASS] Test 6: Empty database safety verified (zero values returned without crashing).")

    # =========================================================================
    # Test 7: Admin Authorization on Analytics Endpoints
    # =========================================================================
    def test_07_admin_authorization_success(self):
        """7. Authenticated administrator can access all aggregate analytics endpoints and CSV export."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.admin_id
            sess["email"] = "admin_analyst@trustmesh.test"
            sess["display_name"] = "Admin Analyst"
            sess["role"] = "admin"

        # Overview
        res = self.client.get("/api/analytics/overview")
        self.assertEqual(res.status_code, 200)
        self.assertIn("overview", res.get_json())

        # Distribution
        res = self.client.get("/api/analytics/risk-distribution")
        self.assertEqual(res.status_code, 200)
        self.assertIn("risk_distribution", res.get_json())

        # Signals
        res = self.client.get("/api/analytics/risk-signals")
        self.assertEqual(res.status_code, 200)
        self.assertIn("risk_signals", res.get_json())

        # Trends
        res = self.client.get("/api/analytics/trends?interval=daily")
        self.assertEqual(res.status_code, 200)
        self.assertIn("trends", res.get_json())

        # CSV Export
        res_export = self.client.get("/api/analytics/export")
        self.assertEqual(res_export.status_code, 200)
        self.assertEqual(res_export.mimetype, "text/csv")
        self.assertIn("Assessment_ID,Assessment_Date", res_export.get_data(as_text=True))
        print("[PASS] Test 7: Admin authorization successfully verified across all 5 analytics routes.")

    # =========================================================================
    # Test 8: Non-Admin Access Restrictions (HTTP 403 / 401)
    # =========================================================================
    def test_08_non_admin_access_restrictions(self):
        """8. Standard users receive HTTP 403 Forbidden; unauthenticated receive HTTP 401."""
        # A. Standard User (Role: user) -> 403 Forbidden
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.user_id
            sess["email"] = "standard_user@trustmesh.test"
            sess["display_name"] = "Standard User"
            sess["role"] = "user"

        for path in [
            "/api/analytics/overview",
            "/api/analytics/risk-distribution",
            "/api/analytics/risk-signals",
            "/api/analytics/trends",
            "/api/analytics/export",
        ]:
            res = self.client.get(path)
            self.assertEqual(res.status_code, 403, f"Expected 403 on {path}")
            self.assertIn("Access denied", res.get_json().get("error", ""))

        # B. Unauthenticated User (No Session) -> 401 Unauthorized
        with self.client.session_transaction() as sess:
            sess.clear()

        for path in [
            "/api/analytics/overview",
            "/api/analytics/risk-distribution",
            "/api/analytics/risk-signals",
            "/api/analytics/trends",
            "/api/analytics/export",
        ]:
            res = self.client.get(path)
            self.assertEqual(res.status_code, 401, f"Expected 401 on {path}")
        print("[PASS] Test 8: Non-admin and anonymous access strictly blocked (403/401).")

    # =========================================================================
    # Test 9: Privacy Checks on Exported CSV
    # =========================================================================
    def test_09_privacy_guarantees_on_exported_csv(self):
        """9. Exported CSV contains zero user emails, passwords, raw texts, or personal identifiers."""
        csv_text, _ = generate_anonymized_csv(db_path=self.test_db_path)

        # Verify sensitive user emails are NOT in CSV
        self.assertNotIn("standard_user@trustmesh.test", csv_text)
        self.assertNotIn("admin_analyst@trustmesh.test", csv_text)

        # Verify password hashes are NOT in CSV
        self.assertNotIn("hash_standard_123", csv_text)
        self.assertNotIn("hash_admin_123", csv_text)

        # Verify internal user IDs are NOT headers
        lines = csv_text.split("\r\n")
        header = lines[0]
        self.assertNotIn("user_id", header)
        self.assertNotIn("email", header)
        self.assertNotIn("password", header)
        self.assertNotIn("raw_message", header)

        # Test validation helper directly
        leak_rec = {
            "Assessment_ID": 10,
            "Risk_Score": 50,
            "email": "leaked_user@trustmesh.test"
        }
        safe, msg = validate_anonymized_record(leak_rec)
        self.assertFalse(safe)
        self.assertIn("Forbidden sensitive key", msg)
        print("[PASS] Test 9: Complete data privacy & anonymization verified in CSV export.")

    # =========================================================================
    # Test 10: SQLite Compatibility and SQL Views Integrity
    # =========================================================================
    def test_10_sqlite_views_integrity(self):
        """10. Direct SQL queries on all 4 views execute successfully against SQLite database."""
        conn = get_db_connection(self.test_db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='view';")
            views = [r[0] for r in cur.fetchall()]
            self.assertIn("v_analytics_overview", views)
            self.assertIn("v_risk_level_distribution", views)
            self.assertIn("v_risk_signal_frequency", views)
            self.assertIn("v_assessment_trends", views)

            # Execute SELECT on each view directly
            cur.execute("SELECT * FROM v_analytics_overview;")
            self.assertIsNotNone(cur.fetchone())

            cur.execute("SELECT * FROM v_risk_level_distribution;")
            self.assertGreaterEqual(len(cur.fetchall()), 1)

            cur.execute("SELECT * FROM v_risk_signal_frequency;")
            self.assertGreaterEqual(len(cur.fetchall()), 1)

            cur.execute("SELECT * FROM v_assessment_trends;")
            self.assertGreaterEqual(len(cur.fetchall()), 1)
        finally:
            conn.close()
        print(f"[PASS] Test 10: SQLite view integrity verified across 4 views: {views}.")

    # =========================================================================
    # Test 11: Azure SQL Compatibility (T-SQL View Syntax)
    # =========================================================================
    def test_11_azure_sql_view_batches_parsed(self):
        """11. schema_azuresql.sql parses into valid T-SQL batches containing all 4 analytics views."""
        self.assertTrue(os.path.exists(SCHEMA_AZURE_PATH), "schema_azuresql.sql must exist.")
        with open(SCHEMA_AZURE_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        batches = parse_sql_batches(content)
        self.assertGreaterEqual(len(batches), 24)

        # Check view definitions in script
        self.assertIn("CREATE OR ALTER VIEW v_analytics_overview", content)
        self.assertIn("CREATE OR ALTER VIEW v_risk_level_distribution", content)
        self.assertIn("CREATE OR ALTER VIEW v_risk_signal_frequency", content)
        self.assertIn("CREATE OR ALTER VIEW v_assessment_trends", content)
        print(f"[PASS] Test 11: Azure SQL view compatibility verified ({len(batches)} batches parsed).")

    # =========================================================================
    # Test 12: Existing Login, Analyzer, History, and Health Remain Intact
    # =========================================================================
    def test_12_phase_1_to_3_and_task2_task3_intact(self):
        """12. Existing analyzer, assessment persistence, history query, and health check remain active."""
        # Analyzer & Persistence
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.user_id
            sess["email"] = "standard_user@trustmesh.test"
            sess["display_name"] = "Standard User"
            sess["role"] = "user"

        res_analyze = self.client.post("/analyze", json={
            "text": "URGENT: Your account will be closed unless you pay immediately! Click http://192.168.1.50/pay"
        })
        self.assertEqual(res_analyze.status_code, 200)
        data = res_analyze.get_json()
        self.assertGreaterEqual(data["score"], 60)
        self.assertEqual(data["level"], "High risk")
        self.assertIn("assessment_id", data)

        # History
        res_history = self.client.get("/api/history")
        self.assertEqual(res_history.status_code, 200)
        history_list = res_history.get_json()["history"]
        self.assertGreaterEqual(len(history_list), 1)

        # Health
        res_health = self.client.get("/health")
        self.assertEqual(res_health.status_code, 200)
        h_data = res_health.get_json()
        self.assertEqual(h_data["database"], "connected")
        self.assertEqual(h_data["database_status_indicator"], "Local SQLite connected")
        print(f"[PASS] Test 12: Analyzer, history, and health integrity verified (Assessment #{data['assessment_id']}).")


if __name__ == "__main__":
    unittest.main()

