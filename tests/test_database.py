"""
TRUSTMESH Unit Test: Relational Database Integrity & Dual-Mode Configuration
Verifies 3NF schema, foreign keys, transaction rollbacks, views, and Azure SQL compatibility.
"""

import os
import sqlite3
import tempfile
import unittest

from database import (
    DatabaseMode,
    get_database_mode,
    get_database_status,
    get_db_connection,
    init_db,
    migrate_db,
    save_analysis_transaction,
)


class TestDatabaseModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_db_module.db")

        init_db(db_path=cls.test_db_path)
        migrate_db(db_path=cls.test_db_path)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_required_tables_exist(self):
        """Verifies that all 8 core tables exist in the schema."""
        conn = get_db_connection(self.test_db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {r[0] for r in cur.fetchall()}
            expected = {
                "ROLES", "USERS", "INCIDENTS", "RISK_ASSESSMENTS",
                "RISK_SIGNALS", "ASSESSMENT_SIGNALS", "AUDIT_LOGS", "EXPORTED_REPORTS"
            }
            for tbl in expected:
                self.assertIn(tbl, tables)
        finally:
            conn.close()

    def test_required_views_exist(self):
        """Verifies that all 5 reporting and analytics views exist."""
        conn = get_db_connection(self.test_db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='view';")
            views = {r[0] for r in cur.fetchall()}
            expected = {
                "v_incident_summary", "v_analytics_overview",
                "v_risk_level_distribution", "v_risk_signal_frequency", "v_assessment_trends"
            }
            for v in expected:
                self.assertIn(v, views)
        finally:
            conn.close()

    def test_foreign_key_enforcement(self):
        """Verifies that foreign key constraints reject orphaned records."""
        conn = get_db_connection(self.test_db_path)
        try:
            cur = conn.cursor()
            with self.assertRaises(sqlite3.IntegrityError):
                cur.execute(
                    "INSERT INTO INCIDENTS (user_id, content_type) VALUES (999999, 'message');"
                )
        finally:
            conn.close()

    def test_transaction_rollback_on_constraint_violation(self):
        """Ensures that invalid score constraints roll back atomic transactions."""
        conn = get_db_connection(self.test_db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM INCIDENTS;")
            before_count = cur.fetchone()[0]

            with self.assertRaises(Exception):
                save_analysis_transaction(
                    user_id=1,
                    content_type="message",
                    content_fingerprint="invalid_test_fp",
                    score=150,  # Invalid: CHECK (risk_score >= 0 AND risk_score <= 100)
                    level="High risk",
                    engine_version="3.0.0",
                    recommendation="Test",
                    detected_signals={},
                    db_path=self.test_db_path
                )

            cur.execute("SELECT COUNT(*) FROM INCIDENTS;")
            after_count = cur.fetchone()[0]
            self.assertEqual(before_count, after_count, "Orphaned incident must not be committed.")
        finally:
            conn.close()

    def test_dual_mode_switching_logic(self):
        """Verifies switching between SQLite and Azure SQL modes."""
        # Default
        if "DATABASE_MODE" in os.environ:
            del os.environ["DATABASE_MODE"]
        self.assertEqual(get_database_mode(), DatabaseMode.SQLITE)

        # Switch to azure_sql
        os.environ["DATABASE_MODE"] = "azure_sql"
        self.assertEqual(get_database_mode(), DatabaseMode.AZURE_SQL)

        # Switch back to sqlite
        os.environ["DATABASE_MODE"] = "sqlite"
        self.assertEqual(get_database_mode(), DatabaseMode.SQLITE)


if __name__ == "__main__":
    unittest.main()

