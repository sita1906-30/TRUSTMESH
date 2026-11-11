"""
TRUSTMESH Unit Test: Report Export, Cloud Archival & Telemetry CSV
Verifies JSON export, Blob Storage fallback, size boundaries, traversal defense, and CSV privacy.
"""

import json
import os
import tempfile
import unittest

from app import app
from database import (
    create_exported_report,
    create_user,
    init_db,
    migrate_db,
    save_analysis_transaction,
)
from services.analytics_service import generate_anonymized_csv
from services.blob_storage_service import (
    MAX_REPORT_SIZE_BYTES,
    upload_report,
    validate_blob_name,
)


class TestReportExportModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_rep_exp_mod.db")

        app.config["TESTING"] = True
        app.config["DATABASE_PATH"] = cls.test_db_path
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "test-secret-report-export-2026"

        init_db(db_path=cls.test_db_path)
        migrate_db(db_path=cls.test_db_path)

        cls.user_id = create_user("Alice Export", "alice_exp@trustmesh.test", "h1", role_id=1, db_path=cls.test_db_path)
        cls.other_id = create_user("Bob Other", "bob_exp@trustmesh.test", "h2", role_id=1, db_path=cls.test_db_path)

        cls.inc_id, cls.asm_id = save_analysis_transaction(
            user_id=cls.user_id,
            content_type="message",
            content_fingerprint="fp_alice_exp",
            score=70,
            level="High risk",
            engine_version="3.0.0",
            recommendation="Do not send OTP.",
            detected_signals={"urgency": 20},
            db_path=cls.test_db_path
        )

        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_local_report_export_and_download(self):
        """User exports and downloads their own assessment report."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.user_id
            sess["email"] = "alice_exp@trustmesh.test"
            sess["display_name"] = "Alice Export"
            sess["role"] = "user"

        res_exp = self.client.post("/api/reports/export", json={
            "assessment_id": self.asm_id,
            "save_to_cloud": False
        })
        self.assertEqual(res_exp.status_code, 200)
        report_id = res_exp.get_json()["report_id"]

        res_dl = self.client.get(f"/api/reports/{report_id}/download")
        self.assertEqual(res_dl.status_code, 200)
        self.assertEqual(res_dl.mimetype, "application/json")
        data = json.loads(res_dl.get_data(as_text=True))
        self.assertEqual(data["assessment_details"]["assessment_id"], self.asm_id)

    def test_cross_user_download_forbidden(self):
        """Bob cannot download Alice's report (HTTP 403 Forbidden)."""
        rep_id = create_exported_report(
            user_id=self.user_id,
            assessment_id=self.asm_id,
            blob_name="reports/user_2/test.json",
            file_type="json",
            file_size=1024,
            storage_status="LOCAL",
            db_path=self.test_db_path
        )

        with self.client.session_transaction() as sess:
            sess["user_id"] = self.other_id
            sess["email"] = "bob_exp@trustmesh.test"
            sess["display_name"] = "Bob Other"
            sess["role"] = "user"

        res = self.client.get(f"/api/reports/{rep_id}/download")
        self.assertEqual(res.status_code, 403)

    def test_path_traversal_in_blob_name_rejected(self):
        """Rejects traversal patterns like ../ in blob names."""
        ok, msg = validate_blob_name("../../secrets.json")
        self.assertFalse(ok)
        self.assertIn("Path traversal", msg)

    def test_oversized_payload_rejected(self):
        """Rejects report payloads exceeding 500 KB limit."""
        oversized = b"X" * (MAX_REPORT_SIZE_BYTES + 1024)
        ok, msg = upload_report("reports/user_2/test.json", oversized)
        self.assertFalse(ok)
        self.assertIn("exceeds maximum limit", msg)

    def test_anonymized_csv_export_privacy(self):
        """Verifies zero PII in CSV telemetry export."""
        csv_text, count = generate_anonymized_csv(db_path=self.test_db_path)
        self.assertGreaterEqual(count, 1)
        self.assertNotIn("alice_exp@trustmesh.test", csv_text)
        self.assertNotIn("bob_exp@trustmesh.test", csv_text)
        self.assertNotIn("h1", csv_text)
        self.assertNotIn("h2", csv_text)


if __name__ == "__main__":
    unittest.main()

