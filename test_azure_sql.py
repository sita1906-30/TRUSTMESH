"""
TRUSTMESH Automated Verification Suite — Phase 4: Azure SQL Dual-Mode
Tests database mode switching, connection status indicators, credential masking,
schema compatibility, and ensures full backward compatibility with Phases 1-3.
"""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from app import app
from database import (
    DEFAULT_DB_PATH,
    DatabaseMode,
    check_db_health,
    create_user,
    get_azure_sql_config,
    get_database_mode,
    get_database_status,
    get_db_connection,
    get_history,
    get_user_by_email,
    init_db,
    mask_credentials,
    migrate_db,
    save_analysis_transaction,
)
from migrate_to_azure import parse_sql_batches, SCHEMA_AZURE_PATH


class TestAzureSqlDualMode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create dedicated isolated SQLite test database
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_dualmode.db")

        app.config["TESTING"] = True
        app.config["DATABASE_PATH"] = cls.test_db_path
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "test-secret-dualmode-2026"

        init_db(db_path=cls.test_db_path)
        migrate_db(db_path=cls.test_db_path)
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        # Ensure default mode is sqlite
        if "DATABASE_MODE" in os.environ:
            del os.environ["DATABASE_MODE"]

    # =========================================================================
    # 1. Mode Configuration & Switching
    # =========================================================================

    def test_01_default_mode_is_sqlite(self):
        """1. System safely defaults to SQLite when DATABASE_MODE is unset."""
        mode = get_database_mode()
        self.assertEqual(mode, DatabaseMode.SQLITE)
        print("[PASS] Test 1: Default database mode verified as 'sqlite'.")

    def test_02_switching_to_azure_sql_mode(self):
        """2. System detects 'azure_sql' when configured in environment."""
        os.environ["DATABASE_MODE"] = "azure_sql"
        self.assertEqual(get_database_mode(), DatabaseMode.AZURE_SQL)

        os.environ["DATABASE_MODE"] = "cloud"
        self.assertEqual(get_database_mode(), DatabaseMode.AZURE_SQL)

        os.environ["DATABASE_MODE"] = "sqlite"
        self.assertEqual(get_database_mode(), DatabaseMode.SQLITE)
        print("[PASS] Test 2: Mode switching logic verified across aliases.")

    def test_03_status_indicator_sqlite_connected(self):
        """3. Status indicator accurately reports 'Local SQLite connected' in SQLite mode."""
        status = get_database_status(db_path=self.test_db_path)
        self.assertEqual(status["mode"], "sqlite")
        self.assertEqual(status["status"], "connected")
        self.assertEqual(status["indicator"], "Local SQLite connected")
        self.assertFalse(status["is_cloud"])
        print(f"[PASS] Test 3: Status indicator verified -> '{status['indicator']}'.")

    def test_04_health_endpoint_reports_mode_and_indicator(self):
        """4. /health endpoint reports status, mode, and indicator without breaking Phase 2."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["database"], "connected")
        self.assertEqual(data["database_mode"], "sqlite")
        self.assertEqual(data["database_status_indicator"], "Local SQLite connected")
        print("[PASS] Test 4: /health endpoint successfully reports dual-mode metadata.")

    # =========================================================================
    # 2. Azure SQL Safety & Credential Masking
    # =========================================================================

    def test_05_unconfigured_azure_sql_reports_unavailable(self):
        """5. Azure SQL mode with missing credentials reports 'Database unavailable' safely."""
        os.environ["DATABASE_MODE"] = "azure_sql"
        # Clear Azure creds
        for key in ["AZURE_SQL_SERVER", "AZURE_SQL_DATABASE", "AZURE_SQL_USERNAME", "AZURE_SQL_PASSWORD", "DATABASE_URL"]:
            if key in os.environ:
                del os.environ[key]

        status = get_database_status()
        self.assertEqual(status["mode"], "azure_sql")
        self.assertEqual(status["status"], "unavailable")
        self.assertEqual(status["indicator"], "Database unavailable")
        self.assertTrue(status["is_cloud"])
        print(f"[PASS] Test 5: Unconfigured Azure SQL safely reports '{status['indicator']}'.")

    def test_06_credential_masking_helper(self):
        """6. Credential masking utility strips secret passwords from all logs/messages."""
        raw_conn_str = "DRIVER={ODBC Driver 18};SERVER=myserver.database.windows.net;DATABASE=mydb;UID=admin;PWD=SuperSecretPassword123!;"
        masked = mask_credentials(raw_conn_str)
        self.assertNotIn("SuperSecretPassword123!", masked)
        self.assertIn("PWD=********", masked)

        url_str = "mssql+pyodbc://admin:SuperSecretPassword123!@myserver.database.windows.net/mydb"
        masked_url = mask_credentials(url_str)
        self.assertNotIn("SuperSecretPassword123!", masked_url)
        self.assertIn("admin:********@", masked_url)
        print("[PASS] Test 6: Credential masking verified (passwords removed from connection strings).")

    def test_07_mock_successful_azure_connection(self):
        """7. When Azure SQL connection test query succeeds, status reports 'Azure SQL connected'."""
        os.environ["DATABASE_MODE"] = "azure_sql"
        os.environ["AZURE_SQL_SERVER"] = "test-server.database.windows.net"
        os.environ["AZURE_SQL_DATABASE"] = "test-db"

        # Mock pyodbc connection that successfully executes SELECT 1
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = (1,)
        mock_conn.cursor.return_value = mock_cur

        with patch("database.get_azure_sql_connection", return_value=mock_conn):
            status = get_database_status()
            self.assertEqual(status["mode"], "azure_sql")
            self.assertEqual(status["status"], "connected")
            self.assertEqual(status["indicator"], "Azure SQL connected")
            self.assertTrue(status["is_cloud"])
        print("[PASS] Test 7: Mock Azure SQL connection test verified ('Azure SQL connected').")

    def test_08_azure_sql_schema_syntax_and_batches(self):
        """8. schema_azuresql.sql file exists and parses into valid T-SQL batches."""
        self.assertTrue(os.path.exists(SCHEMA_AZURE_PATH), "schema_azuresql.sql must exist.")
        with open(SCHEMA_AZURE_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        batches = parse_sql_batches(content)
        self.assertGreaterEqual(len(batches), 15, "Azure SQL schema must contain all schema batches.")
        # Verify essential tables exist in script
        self.assertIn("CREATE TABLE ROLES", content)
        self.assertIn("CREATE TABLE USERS", content)
        self.assertIn("CREATE TABLE INCIDENTS", content)
        self.assertIn("CREATE TABLE RISK_ASSESSMENTS", content)
        self.assertIn("CREATE TABLE RISK_SIGNALS", content)
        self.assertIn("CREATE TABLE ASSESSMENT_SIGNALS", content)
        self.assertIn("CREATE TABLE AUDIT_LOGS", content)
        print(f"[PASS] Test 8: Azure SQL schema script verified ({len(batches)} T-SQL batches parsed).")

    # =========================================================================
    # 3. Preservation of Phases 1, 2, and 3 Features
    # =========================================================================

    def test_09_user_registration_and_retrieval(self):
        """9. User registration and retrieval continue working seamlessly in dual-mode."""
        uid = create_user(
            display_name="Cloud Test",
            email="cloud_unit_test@trustmesh.local",
            password_hash="dummy_hash_123",
            db_path=self.test_db_path
        )
        self.assertGreater(uid, 0)

        user = get_user_by_email("cloud_unit_test@trustmesh.local", db_path=self.test_db_path)
        self.assertIsNotNone(user)
        self.assertEqual(user["display_name"], "Cloud Test")
        print(f"[PASS] Test 9: User creation and lookup verified (User #{uid}).")

    def test_10_analysis_and_transaction_persistence(self):
        """10. Analysis persistence and signal junction table function properly."""
        inc_id, asm_id = save_analysis_transaction(
            user_id=1,
            content_type="message",
            content_fingerprint="dummy_fp_hash",
            score=70,
            level="High risk",
            engine_version="3.0.0",
            recommendation="Do not act.",
            detected_signals={"urgency": 20, "sensitive_info": 30},
            db_path=self.test_db_path
        )
        self.assertGreater(inc_id, 0)
        self.assertGreater(asm_id, 0)

        history = get_history(user_id=1, limit=10, db_path=self.test_db_path)
        self.assertGreaterEqual(len(history), 1)
        self.assertEqual(history[0]["incident_id"], inc_id)
        print(f"[PASS] Test 10: Analysis transaction and history query verified (Incident #{inc_id}).")

    def test_11_live_cloud_connectivity_status(self):
        """11. Reports whether live Azure credentials are provided or marks as NOT TESTED."""
        creds = get_azure_sql_config()
        if creds["server"] and creds["database"] and creds["password"]:
            print(f"[*] Live Azure SQL credentials detected for server '{creds['server']}'. Testing...")
            from migrate_to_azure import test_azure_connection
            success, msg = test_azure_connection(creds)
            print(f"[*] Result: {msg}")
        else:
            print("[NOTICE] Actual cloud connectivity: NOT TESTED (no Azure credentials provided in environment).")


if __name__ == "__main__":
    unittest.main()

