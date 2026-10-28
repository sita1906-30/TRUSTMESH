"""
TRUSTMESH Automated Verification Suite
Tests all 7 backend test scenarios specified in Section 12.
"""

import unittest
from app import app, MAX_INPUT_LENGTH


class TestTrustMeshBackend(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_00_home_page(self):
        """Verify GET / returns 200 and loads HTML template."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"TRUSTMESH", response.data)
        self.assertIn(b"YOUR DIGITAL TRUST LAYER", response.data)
        print("[PASS] Test 0 (GET /): Main page renders successfully")
    def test_01_empty_input(self):
        """Test 1: Empty input should return 400 and clear validation message."""
        # Empty string
        res1 = self.client.post('/analyze', json={"text": ""})
        self.assertEqual(res1.status_code, 400)
        data1 = res1.get_json()
        self.assertIn("error", data1)
        self.assertIn("Input cannot be empty", data1["error"])

        # Whitespace-only string
        res2 = self.client.post('/analyze', json={"text": "   \n\t   "})
        self.assertEqual(res2.status_code, 400)
        data2 = res2.get_json()
        self.assertIn("error", data2)
        print(f"[PASS] Test 1: Empty input rejected properly -> '{data1['error']}'")

    def test_02_ordinary_fictional_message(self):
        """Test 2: Ordinary fictional message - no warning patterns detected."""
        msg = "Your appointment is scheduled for tomorrow at 10 AM."
        res = self.client.post('/analyze', json={"text": msg})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        
        self.assertEqual(data["score"], 0)
        self.assertEqual(data["level"], "Lower detected risk")
        self.assertEqual(data["urls_found"], 0)
        self.assertIn("No configured warning patterns were detected. This does not prove the content is safe.", data["findings"])
        self.assertIn("disclaimer", data)
        self.assertEqual(data["disclaimer"], "This preliminary rule-based assessment cannot guarantee that content is safe or fraudulent.")
        print(f"[PASS] Test 2: Ordinary message -> score: {data['score']}, level: '{data['level']}'")

    def test_03_suspicious_payment_message(self):
        """Test 3: Suspicious payment message with urgency, fee, prize."""
        msg = "URGENT! Pay the registration fee immediately to claim your prize."
        res = self.client.post('/analyze', json={"text": msg})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Urgency (20) + Payment Pressure (25) + Prize/Reward (15) = 60
        self.assertEqual(data["score"], 60)
        self.assertEqual(data["level"], "High risk")
        
        self.assertTrue(any("urgency" in f.lower() for f in data["findings"]))
        self.assertTrue(any("payment" in f.lower() for f in data["findings"]))
        self.assertTrue(any("prize" in f.lower() for f in data["findings"]))
        print(f"[PASS] Test 3: Suspicious payment -> score: {data['score']}, level: '{data['level']}', findings: {len(data['findings'])}")

    def test_04_sensitive_information_request(self):
        """Test 4: Sensitive information request (OTP, password, urgency)."""
        msg = "Send your OTP and share your password immediately."
        res = self.client.post('/analyze', json={"text": msg})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Sensitive Info (30) + Urgency (20) = 50
        self.assertEqual(data["score"], 50)
        self.assertEqual(data["level"], "Suspicious")
        self.assertTrue(any("sensitive" in f.lower() for f in data["findings"]))
        self.assertTrue(any("urgency" in f.lower() for f in data["findings"]))
        print(f"[PASS] Test 4: Sensitive information request -> score: {data['score']}, level: '{data['level']}'")

    def test_05_http_url(self):
        """Test 5: HTTP URL should flag unencrypted HTTP without claiming definitive fraud."""
        msg = "http://example.com/login"
        res = self.client.post('/analyze', json={"text": msg})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["urls_found"], 1)
        self.assertEqual(data["score"], 15)
        self.assertEqual(data["level"], "Lower detected risk")
        self.assertTrue(any("insecure connection" in f.lower() or "http" in f.lower() for f in data["findings"]))
        print(f"[PASS] Test 5: HTTP URL -> urls_found: {data['urls_found']}, score: {data['score']}, finding: '{data['findings'][0]}'")

    def test_06_exceeding_max_characters(self):
        """Test 6: Input exceeding 5,000 characters."""
        long_text = "a" * (MAX_INPUT_LENGTH + 1)
        res = self.client.post('/analyze', json={"text": long_text})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)
        self.assertIn("5000", data["error"])
        print(f"[PASS] Test 6: Exceeding 5,000 chars rejected properly -> '{data['error']}'")

    def test_07_invalid_request_body(self):
        """Test 7: Malformed body, wrong data types, non-JSON."""
        # Non-JSON content type
        res1 = self.client.post('/analyze', data="Not JSON", content_type="text/plain")
        self.assertEqual(res1.status_code, 400)

        # Missing 'text' field
        res2 = self.client.post('/analyze', json={"wrong_key": "some text"})
        self.assertEqual(res2.status_code, 400)

        # Wrong data type for 'text' (e.g. integer or list)
        res3 = self.client.post('/analyze', json={"text": 12345})
        self.assertEqual(res3.status_code, 400)

        # None body
        res4 = self.client.post('/analyze', data="", content_type="application/json")
        self.assertEqual(res4.status_code, 400)

        print("[PASS] Test 7: Invalid request bodies handled safely without crashing")


if __name__ == '__main__':
    unittest.main()
