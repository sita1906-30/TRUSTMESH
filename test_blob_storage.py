"""
TRUSTMESH Automated Verification Suite — Phase 4, Task 3: Azure Blob Storage Integration
Tests report archiving, optional cloud saving, local download fallbacks,
server-side authorization, path traversal defenses, size limits, and backward compatibility.
"""

from datetime import datetime, timezone
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from app import app
from database import (
    create_exported_report,
    create_user,
    get_database_mode,
    get_database_status,
    get_exported_report_by_id,
    get_exported_reports_by_user,
    init_db,
    migrate_db,
    save_analysis_transaction,
)
from services.blob_storage_service import (
    MAX_REPORT_SIZE_BYTES,
    check_blob_storage_health,
    download_report,
    generate_safe_blob_name,
    is_blob_storage_configured,
    upload_report,
    validate_blob_name,
)


class TestAzureBlobStorageIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create dedicated temporary test database
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_blob_storage.db")

        app.config["TESTING"] = True
        app.config["DATABASE_PATH"] = cls.test_db_path
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "test-secret-blob-storage-phase4-task3"

        init_db(db_path=cls.test_db_path)
        migrate_db(db_path=cls.test_db_path)

        # Create Test Users: Alice (User #2) and Bob (User #3)
        cls.alice_id = create_user(
            display_name="Alice Storage",
            email="alice_storage@trustmesh.test",
            password_hash="test_hash_alice",
            db_path=cls.test_db_path
        )
        cls.bob_id = create_user(
            display_name="Bob Storage",
            email="bob_storage@trustmesh.test",
            password_hash="test_hash_bob",
            db_path=cls.test_db_path
        )

        # Create Test Assessments for Alice and Bob
        cls.alice_inc_id, cls.alice_asm_id = save_analysis_transaction(
            user_id=cls.alice_id,
            content_type="message",
            content_fingerprint="alice_fp_sha256",
            score=65,
            level="High risk",
            engine_version="3.0.0",
            recommendation="Urgent verification requested. Do not send credentials.",
            detected_signals={"urgency": 20, "sensitive_info": 30, "payment_pressure": 15},
            db_path=cls.test_db_path
        )

        cls.bob_inc_id, cls.bob_asm_id = save_analysis_transaction(
            user_id=cls.bob_id,
            content_type="url",
            content_fingerprint="bob_fp_sha256",
            score=35,
            level="Suspicious",
            engine_version="3.0.0",
            recommendation="Suspicious URL detected. Verify sender.",
            detected_signals={"url_insecure_http": 15, "url_ip_hostname": 20},
            db_path=cls.test_db_path
        )

        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        # Clear environment storage variables before each test
        for key in ["AZURE_STORAGE_CONNECTION_STRING", "AZURE_STORAGE_ACCOUNT_NAME", "AZURE_STORAGE_CONTAINER_NAME"]:
            if key in os.environ:
                del os.environ[key]

    # =========================================================================
    # Test 1: Application starts without Azure Blob credentials
    # =========================================================================
    def test_01_app_starts_without_blob_credentials(self):
        """1. App safely functions when Azure Blob credentials are not provided."""
        self.assertFalse(is_blob_storage_configured())
        health = check_blob_storage_health()
        self.assertEqual(health["status"], "not_configured")
        self.assertEqual(health["indicator"], "Storage not configured (Local Fallback)")
        self.assertFalse(health["is_configured"])

        res = self.client.get("/api/storage/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("storage", data)
        self.assertEqual(data["storage"]["status"], "not_configured")
        print("[PASS] Test 1: Application and /api/storage/status verified without Azure Blob credentials.")

    # =========================================================================
    # Test 2: Local report export works
    # =========================================================================
    def test_02_local_report_export_works(self):
        """2. Exporting an assessment report generates structured JSON without cloud upload."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.alice_id
            sess["email"] = "alice_storage@trustmesh.test"
            sess["display_name"] = "Alice Storage"
            sess["role"] = "user"

        res = self.client.post("/api/reports/export", json={
            "assessment_id": self.alice_asm_id,
            "save_to_cloud": False
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["storage_status"], "LOCAL")
        self.assertIn("download_url", data)

        report_data = data["report_data"]
        self.assertIn("report_metadata", report_data)
        self.assertIn("assessment_details", report_data)
        self.assertIn("detected_risk_signals", report_data)
        self.assertIn("actionable_guidance", report_data)
        self.assertEqual(report_data["assessment_details"]["risk_score"], 65)
        self.assertEqual(report_data["assessment_details"]["risk_level"], "High risk")
        print(f"[PASS] Test 2: Local report export verified (Report #{data['report_id']}, Status: LOCAL).")

    # =========================================================================
    # Test 3: Authenticated user can export and download a report
    # =========================================================================
    def test_03_authenticated_user_can_export_report(self):
        """3. Authenticated user can trigger export and download the resulting file."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.alice_id
            sess["email"] = "alice_storage@trustmesh.test"
            sess["display_name"] = "Alice Storage"
            sess["role"] = "user"

        export_res = self.client.post("/api/reports/export", json={
            "assessment_id": self.alice_asm_id,
            "save_to_cloud": False
        })
        self.assertEqual(export_res.status_code, 200)
        report_id = export_res.get_json()["report_id"]

        # Now download the report
        download_res = self.client.get(f"/api/reports/{report_id}/download")
        self.assertEqual(download_res.status_code, 200)
        self.assertEqual(download_res.mimetype, "application/json")
        downloaded_json = json.loads(download_res.get_data(as_text=True))
        self.assertEqual(downloaded_json["assessment_details"]["assessment_id"], self.alice_asm_id)
        print(f"[PASS] Test 3: Authenticated export & download pipeline verified (Report #{report_id}).")

    # =========================================================================
    # Test 4: Unauthenticated user cannot export reports (HTTP 401)
    # =========================================================================
    def test_04_unauthenticated_user_cannot_export_reports(self):
        """4. Anonymous requests to report endpoints are rejected with HTTP 401."""
        # Clean session
        with self.client.session_transaction() as sess:
            sess.clear()

        # Try export
        res = self.client.post("/api/reports/export", json={"assessment_id": self.alice_asm_id})
        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        self.assertIn("error", data)

        # Try download
        res_dl = self.client.get("/api/reports/1/download")
        self.assertEqual(res_dl.status_code, 401)

        # Try list
        res_list = self.client.get("/api/reports")
        self.assertEqual(res_list.status_code, 401)
        print("[PASS] Test 4: Unauthenticated access rejected with HTTP 401 on all report endpoints.")

    # =========================================================================
    # Test 5: User cannot download or export another user's report (HTTP 403 Forbidden)
    # =========================================================================
    def test_05_cross_user_report_download_forbidden(self):
        """5. Server-side ownership check prevents cross-user access (HTTP 403 Forbidden)."""
        # Step A: Alice creates a report
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.alice_id
            sess["email"] = "alice_storage@trustmesh.test"
            sess["display_name"] = "Alice Storage"
            sess["role"] = "user"

        res = self.client.post("/api/reports/export", json={"assessment_id": self.alice_asm_id})
        alice_report_id = res.get_json()["report_id"]

        # Step B: Bob logs in and tries to download Alice's report
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.bob_id
            sess["email"] = "bob_storage@trustmesh.test"
            sess["display_name"] = "Bob Storage"
            sess["role"] = "user"

        dl_res = self.client.get(f"/api/reports/{alice_report_id}/download")
        self.assertEqual(dl_res.status_code, 403)
        self.assertIn("Access denied", dl_res.get_json()["error"])

        # Step C: Bob tries to export Alice's assessment directly
        export_res = self.client.post("/api/reports/export", json={"assessment_id": self.alice_asm_id})
        self.assertEqual(export_res.status_code, 403)
        self.assertIn("Access denied", export_res.get_json()["error"])
        print("[PASS] Test 5: Cross-user access prohibited with HTTP 403 Forbidden.")

    # =========================================================================
    # Test 6: Invalid blob filenames and path traversal are rejected
    # =========================================================================
    def test_06_invalid_blob_filenames_and_path_traversal_rejected(self):
        """6. validate_blob_name rejects traversal sequences, leading slashes, and special chars."""
        # Traversal attacks
        ok, msg = validate_blob_name("../reports/secret.json")
        self.assertFalse(ok)
        self.assertIn("Path traversal", msg)

        ok, msg = validate_blob_name("..\\reports\\secret.json")
        self.assertFalse(ok)
        self.assertIn("Path traversal", msg)

        # Leading slash
        ok, msg = validate_blob_name("/root/secret.json")
        self.assertFalse(ok)
        self.assertIn("Path traversal", msg)

        # Illegal characters
        ok, msg = validate_blob_name("report<test>.json")
        self.assertFalse(ok)
        self.assertIn("invalid characters", msg)

        # Empty name
        ok, msg = validate_blob_name("")
        self.assertFalse(ok)

        # Overlong name
        ok, msg = validate_blob_name("a" * 256)
        self.assertFalse(ok)
        self.assertIn("exceeds maximum length", msg)

        # Valid safe name
        safe_name = generate_safe_blob_name(user_id=2, assessment_id=1, file_ext="json")
        ok, msg = validate_blob_name(safe_name)
        self.assertTrue(ok)
        self.assertTrue(safe_name.startswith("reports/user_2/trustmesh_report_asm_1_"))
        print(f"[PASS] Test 6: Path traversal and safe naming defense verified ('{safe_name}').")

    # =========================================================================
    # Test 7: Oversized report data (>500 KB) is rejected
    # =========================================================================
    def test_07_oversized_report_data_rejected(self):
        """7. upload_report rejects payloads exceeding MAX_REPORT_SIZE_BYTES (500 KB)."""
        safe_name = generate_safe_blob_name(2, 1, "json")
        oversized = b"A" * (MAX_REPORT_SIZE_BYTES + 1024)

        ok, msg = upload_report(safe_name, oversized)
        self.assertFalse(ok)
        self.assertIn("exceeds maximum limit", msg)

        # Empty data
        ok, msg = upload_report(safe_name, b"")
        self.assertFalse(ok)
        self.assertIn("cannot be empty", msg)
        print(f"[PASS] Test 7: Memory & size protection verified (limit: {MAX_REPORT_SIZE_BYTES} bytes).")

    # =========================================================================
    # Test 8: Missing Azure configuration is handled safely (graceful fallback)
    # =========================================================================
    def test_08_missing_azure_config_graceful_fallback(self):
        """8. Requesting save_to_cloud without Azure configuration falls back cleanly."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.alice_id
            sess["email"] = "alice_storage@trustmesh.test"
            sess["display_name"] = "Alice Storage"
            sess["role"] = "user"

        res = self.client.post("/api/reports/export", json={
            "assessment_id": self.alice_asm_id,
            "save_to_cloud": True
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["storage_status"], "LOCAL")
        self.assertIn("not configured", data["message"])
        print("[PASS] Test 8: Missing cloud configuration gracefully falls back to local storage.")

    # =========================================================================
    # Test 9: Mocked blob upload succeeds when valid client is present
    # =========================================================================
    def test_09_mocked_blob_upload_success(self):
        """9. Mocked Azure Blob Storage upload succeeds and triggers private container creation."""
        mock_blob_client = MagicMock()
        mock_container_client = MagicMock()
        mock_container_client.exists.return_value = True
        mock_container_client.get_blob_client.return_value = mock_blob_client

        mock_service_client = MagicMock()
        mock_service_client.get_container_client.return_value = mock_container_client

        with patch("services.blob_storage_service.is_blob_storage_configured", return_value=True), \
             patch("services.blob_storage_service.get_blob_service_client", return_value=mock_service_client):

            safe_name = generate_safe_blob_name(self.alice_id, self.alice_asm_id, "json")
            ok, msg = upload_report(safe_name, b'{"test": "ok"}', "application/json")
            self.assertTrue(ok)
            self.assertIn("successfully saved", msg)
            mock_blob_client.upload_blob.assert_called_once()
        print("[PASS] Test 9: Mocked Azure Blob Storage upload verified.")

    # =========================================================================
    # Test 10: Mocked blob download succeeds when valid client is present
    # =========================================================================
    def test_10_mocked_blob_download_success(self):
        """10. Mocked Azure Blob Storage download retrieves stream and serves as attachment."""
        sample_payload = b'{"mock_download": "success", "score": 65}'

        mock_stream = MagicMock()
        mock_stream.readall.return_value = sample_payload

        mock_blob_client = MagicMock()
        mock_blob_client.exists.return_value = True
        mock_blob_client.download_blob.return_value = mock_stream

        mock_container_client = MagicMock()
        mock_container_client.get_blob_client.return_value = mock_blob_client

        mock_service_client = MagicMock()
        mock_service_client.get_container_client.return_value = mock_container_client

        with patch("services.blob_storage_service.is_blob_storage_configured", return_value=True), \
             patch("services.blob_storage_service.get_blob_service_client", return_value=mock_service_client):

            # Unit service test
            safe_name = "reports/user_2/trustmesh_report_asm_1_mock.json"
            data, msg = download_report(safe_name)
            self.assertEqual(data, sample_payload)
            self.assertEqual(msg, "Success")

            # Route download test with storage_status='UPLOADED'
            report_id = create_exported_report(
                user_id=self.alice_id,
                assessment_id=self.alice_asm_id,
                blob_name=safe_name,
                file_type="json",
                file_size=len(sample_payload),
                storage_status="UPLOADED",
                db_path=self.test_db_path
            )

            with self.client.session_transaction() as sess:
                sess["user_id"] = self.alice_id
                sess["email"] = "alice_storage@trustmesh.test"
                sess["display_name"] = "Alice Storage"
                sess["role"] = "user"

            dl_res = self.client.get(f"/api/reports/{report_id}/download")
            self.assertEqual(dl_res.status_code, 200)
            self.assertEqual(dl_res.data, sample_payload)
        print("[PASS] Test 10: Mocked Azure Blob Storage download & route delivery verified.")

    # =========================================================================
    # Test 11: Report metadata is correctly persisted in EXPORTED_REPORTS
    # =========================================================================
    def test_11_report_metadata_persisted_in_exported_reports(self):
        """11. Report tracking metadata is saved to EXPORTED_REPORTS and queried by user."""
        safe_name = generate_safe_blob_name(self.bob_id, self.bob_asm_id, "json")
        rep_id = create_exported_report(
            user_id=self.bob_id,
            assessment_id=self.bob_asm_id,
            blob_name=safe_name,
            file_type="json",
            file_size=2048,
            storage_status="LOCAL",
            db_path=self.test_db_path
        )
        self.assertGreater(rep_id, 0)

        record = get_exported_report_by_id(rep_id, db_path=self.test_db_path)
        self.assertIsNotNone(record)
        self.assertEqual(record["user_id"], self.bob_id)
        self.assertEqual(record["assessment_id"], self.bob_asm_id)
        self.assertEqual(record["file_size"], 2048)
        self.assertEqual(record["storage_status"], "LOCAL")

        bob_reports = get_exported_reports_by_user(self.bob_id, limit=10, db_path=self.test_db_path)
        self.assertGreaterEqual(len(bob_reports), 1)
        self.assertEqual(bob_reports[0]["report_id"], rep_id)
        print(f"[PASS] Test 11: EXPORTED_REPORTS metadata persistence verified (Report #{rep_id}).")

    # =========================================================================
    # Test 12: Existing Phase 1–3 functionality remains intact
    # =========================================================================
    def test_12_phase_1_to_3_features_intact(self):
        """12. Scam and URL risk analysis, scoring, and history persist properly."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.alice_id
            sess["email"] = "alice_storage@trustmesh.test"
            sess["display_name"] = "Alice Storage"
            sess["role"] = "user"

        res = self.client.post("/analyze", json={
            "text": "URGENT: Your bank account will be suspended! Click http://192.168.1.1/verify and enter your password."
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertGreaterEqual(data["score"], 50)
        self.assertIn("findings", data)
        self.assertIn("urls_found", data)
        self.assertIn("assessment_id", data)
        print(f"[PASS] Test 12: Core Phase 1-3 analyzer intact (Score: {data['score']}, Assessment #{data['assessment_id']}).")

    # =========================================================================
    # Test 13: Existing SQLite and Azure SQL dual-mode configuration remains intact
    # =========================================================================
    def test_13_dual_mode_db_configuration_intact(self):
        """13. Dual-mode database configuration, health checks, and indicators remain active."""
        mode = get_database_mode()
        self.assertEqual(mode, "sqlite")

        db_stat = get_database_status(db_path=self.test_db_path)
        self.assertEqual(db_stat["indicator"], "Local SQLite connected")

        # Check /health reports both DB and Storage metadata
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["database_status_indicator"], "Local SQLite connected")
        self.assertIn("storage_indicator", data)
        self.assertEqual(data["storage_indicator"], "Storage not configured (Local Fallback)")
        print("[PASS] Test 13: SQLite & Azure SQL dual-mode status and health indicators verified.")


if __name__ == "__main__":
    unittest.main()

