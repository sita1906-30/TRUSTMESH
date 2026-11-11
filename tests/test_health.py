"""
TRUSTMESH Unit Test: Health-Check Endpoint & Diagnostic Monitoring
Verifies service availability, mode indicators, environment tags, and zero credential leakage.
"""

import json
import unittest
from unittest.mock import patch

from app import app


class TestHealthModule(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_health_check_healthy_status(self):
        """Returns HTTP 200 with status: healthy when database is reachable."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["database"], "connected")
        self.assertIn("environment", data)
        self.assertIn("database_mode", data)
        self.assertIn("database_status_indicator", data)
        self.assertIn("storage_status", data)

    def test_health_check_leaks_no_credentials(self):
        """Ensures that connection strings, passwords, and secret keys never leak via /health."""
        res = self.client.get("/health")
        payload_str = json.dumps(res.get_json()).lower()
        self.assertNotIn("password", payload_str)
        self.assertNotIn("accountkey", payload_str)
        self.assertNotIn("secret", payload_str)

    def test_health_check_unhealthy_when_database_fails(self):
        """Returns HTTP 503 with status: unhealthy when database connection fails."""
        with patch("app.check_db_health", return_value=False), \
             patch("app.get_database_status", return_value={"status": "disconnected", "mode": "sqlite", "indicator": "Database unavailable", "details": "Simulated error", "is_cloud": False}):
            res = self.client.get("/health")
            self.assertEqual(res.status_code, 503)
            data = res.get_json()
            self.assertEqual(data["status"], "unhealthy")
            self.assertEqual(data["database"], "disconnected")


if __name__ == "__main__":
    unittest.main()
