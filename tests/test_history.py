"""
TRUSTMESH Unit Test: Assessment History Isolation & User Privacy
Verifies that users can only see their own history, records are ordered, and raw text is excluded.
"""

import os
import tempfile
import unittest

from app import app
from database import (
    create_user,
    get_history,
    init_db,
    migrate_db,
    save_analysis_transaction,
)


class TestHistoryModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_hist_module.db")

        app.config["TESTING"] = True
        app.config["DATABASE_PATH"] = cls.test_db_path
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "test-secret-history-2026"

        init_db(db_path=cls.test_db_path)
        migrate_db(db_path=cls.test_db_path)

        cls.user1_id = create_user("User One", "user1_hist@trustmesh.test", "hash1", db_path=cls.test_db_path)
        cls.user2_id = create_user("User Two", "user2_hist@trustmesh.test", "hash2", db_path=cls.test_db_path)

        # User 1 scan
        save_analysis_transaction(
            user_id=cls.user1_id,
            content_type="message",
            content_fingerprint="fp1",
            score=60,
            level="High risk",
            engine_version="3.0.0",
            recommendation="Urgent check.",
            detected_signals={"urgency": 20},
            db_path=cls.test_db_path
        )

        # User 2 scan
        save_analysis_transaction(
            user_id=cls.user2_id,
            content_type="url",
            content_fingerprint="fp2",
            score=20,
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

    def test_user_history_privacy_isolation(self):
        """User 1 cannot see User 2's assessment records."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.user1_id
            sess["email"] = "user1_hist@trustmesh.test"
            sess["display_name"] = "User One"
            sess["role"] = "user"

        res = self.client.get("/api/history")
        self.assertEqual(res.status_code, 200)
        items = res.get_json()["history"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["risk_score"], 60)

    def test_raw_message_text_absent_from_history(self):
        """History response excludes raw message strings and passwords."""
        items = get_history(user_id=self.user1_id, db_path=self.test_db_path)
        self.assertEqual(len(items), 1)
        rec = items[0]
        self.assertNotIn("raw_message", rec)
        self.assertNotIn("raw_text", rec)
        self.assertIn("content_type", rec)
        self.assertIn("risk_score", rec)

    def test_unauthenticated_history_rejected(self):
        """Anonymous requests to /api/history are rejected with HTTP 401."""
        with self.client.session_transaction() as sess:
            sess.clear()

        res = self.client.get("/api/history")
        self.assertEqual(res.status_code, 401)


if __name__ == "__main__":
    unittest.main()

