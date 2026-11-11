"""
TRUSTMESH Unit Test: Core Scam & URL Heuristic Analyzer
Verifies rule-based scoring, classification, URL parsing, and input boundaries.
"""

import unittest
from app import app, analyze_interaction


class TestAnalyzerModule(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

    def test_empty_input_rejected(self):
        """Rejects empty string or whitespace-only input with HTTP 400."""
        res = self.client.post("/analyze", json={"text": "   "})
        self.assertEqual(res.status_code, 400)
        self.assertIn("cannot be empty", res.get_json()["error"])

    def test_oversized_input_rejected(self):
        """Rejects text exceeding 5,000 characters with HTTP 400."""
        res = self.client.post("/analyze", json={"text": "A" * 5001})
        self.assertEqual(res.status_code, 400)
        self.assertIn("exceeds maximum allowed limit", res.get_json()["error"])

    def test_benign_message_scoring(self):
        """Scores benign greeting as 0 with 'Lower detected risk'."""
        result = analyze_interaction("Hi Mom, I will be home for dinner around 7pm.")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "Lower detected risk")
        self.assertEqual(len(result["findings"]), 1)
        self.assertIn("No configured warning patterns were detected", result["findings"][0])

    def test_high_risk_payment_pressure(self):
        """Detects payment urgency and classifies as High risk."""
        result = analyze_interaction("URGENT! Pay immediately or your account will be closed within 24 hours to claim your prize.")
        self.assertGreaterEqual(result["score"], 60)
        self.assertEqual(result["level"], "High risk")
        self.assertGreaterEqual(len(result["findings"]), 2)

    def test_credential_harvesting_detection(self):
        """Detects requests for passwords/OTPs and flags as Suspicious/High risk."""
        result = analyze_interaction("Please verify your account and share your one-time password OTP.")
        self.assertGreaterEqual(result["score"], 30)
        self.assertIn(result["level"], ["Suspicious", "High risk"])

    def test_insecure_http_url_detection(self):
        """Flags unencrypted HTTP URLs."""
        result = analyze_interaction("Check your order at http://tracker.com/status")
        self.assertEqual(result["urls_found"], 1)
        self.assertGreaterEqual(result["score"], 15)
        self.assertTrue(any("unencrypted HTTP" in f for f in result["findings"]))

    def test_ip_address_hostname_detection(self):
        """Flags raw IP addresses used as hostnames."""
        result = analyze_interaction("Login to your bank: http://192.168.1.1/login")
        self.assertEqual(result["urls_found"], 1)
        self.assertGreaterEqual(result["score"], 35)
        self.assertTrue(any("IP address" in f for f in result["findings"]))


if __name__ == "__main__":
    unittest.main()
