"""
TRUSTMESH Unit Test: Power BI Analytics Views & Telemetry Aggregates
Verifies SQL views, KPI computations, trend series, and admin analytics endpoints.
"""

import os
import tempfile
import unittest

from app import app
from database import (
    create_user,
    get_analytics_overview,
    get_assessment_trends,
    get_risk_level_distribution,
    get_risk_signal_frequency,
    init_db,
    migrate_db,
    save_analysis_transaction,
)


class TestAnalyticsModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_analytics_mod.db")

        app.config["TESTING"] = True
        app.config["DATABASE_PATH"] = cls.test_db_path
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "test-secret-analytics-2026"

        init_db(db_path=cls.test_db_path)
        migrate_db(db_path=cls.test_db_path)

        cls.user_id = create_user("Std", "std_an@trustmesh.test", "h1", role_id=1, db_path=cls.test_db_path)
        cls.admin_id = create_user("Adm", "adm_an@trustmesh.test", "h2", role_id=2, db_path=cls.test_db_path)

        # Assessment 1: High risk
        save_analysis_transaction(
            user_id=cls.user_id,
            content_type="message",
            content_fingerprint="fp1",
            score=80,
            level="High risk",
            engine_version="3.0.0",
            recommendation="Block sender.",
            detected_signals={"urgency": 20, "sensitive_info": 30},
            db_path=cls.test_db_path
        )
        # Assessment 2: Low risk
        save_analysis_transaction(
            user_id=cls.user_id,
            content_type="url",
            content_fingerprint="fp2",
            score=10,
            level="Lower detected risk",
            engine_version="3.0.0",
            recommendation="Safe.",
            detected_signals={},
            db_path=cls.test_db_path
        )

        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_analytics_overview_calculation(self):
        """Calculates total assessments, high risk, low risk, and average score."""
        ov = get_analytics_overview(db_path=self.test_db_path)
        self.assertEqual(ov["total_assessments"], 2)
        self.assertEqual(ov["total_high_risk"], 1)
        self.assertEqual(ov["total_low_risk"], 1)
        self.assertEqual(ov["avg_risk_score"], 45.0)

    def test_risk_distribution_categories(self):
        """Returns 3 standardized risk levels with percentages."""
        dist = get_risk_level_distribution(db_path=self.test_db_path)
        self.assertEqual(len(dist), 3)
        dist_map = {d["risk_level"]: d for d in dist}
        self.assertEqual(dist_map["High risk"]["assessment_count"], 1)
        self.assertEqual(dist_map["High risk"]["percentage"], 50.0)

    def test_risk_signal_frequency(self):
        """Calculates detection hit counts and prevalence for catalog signals."""
        signals = get_risk_signal_frequency(db_path=self.test_db_path)
        self.assertEqual(len(signals), 9)
        sig_map = {s["signal_name"]: s for s in signals}
        self.assertEqual(sig_map["urgency"]["detection_count"], 1)
        self.assertEqual(sig_map["urgency"]["prevalence_pct"], 50.0)

    def test_assessment_trends_series(self):
        """Aggregates daily, weekly, and monthly time series."""
        trends = get_assessment_trends("daily", db_path=self.test_db_path)
        self.assertGreaterEqual(len(trends), 1)
        self.assertEqual(trends[0]["total_assessments"], 2)

    def test_admin_only_endpoints(self):
        """Admin accesses /api/analytics/overview; regular user receives 403."""
        # User -> 403
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.user_id
            sess["email"] = "std_an@trustmesh.test"
            sess["display_name"] = "Std"
            sess["role"] = "user"

        res_user = self.client.get("/api/analytics/overview")
        self.assertEqual(res_user.status_code, 403)

        # Admin -> 200
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.admin_id
            sess["email"] = "adm_an@trustmesh.test"
            sess["display_name"] = "Adm"
            sess["role"] = "admin"

        res_admin = self.client.get("/api/analytics/overview")
        self.assertEqual(res_admin.status_code, 200)


if __name__ == "__main__":
    unittest.main()

