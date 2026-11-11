"""
TRUSTMESH Unit Test: Authentication & Session Security
Verifies user registration, password hashing, secure sessions, and login/logout.
"""

import os
import tempfile
import unittest
from werkzeug.security import check_password_hash, generate_password_hash

from app import app
from database import create_user, get_user_by_email, init_db, migrate_db


class TestAuthModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_auth.db")

        app.config["TESTING"] = True
        app.config["DATABASE_PATH"] = cls.test_db_path
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "test-secret-auth-module-2026"

        init_db(db_path=cls.test_db_path)
        migrate_db(db_path=cls.test_db_path)

        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_registration_success_and_password_hashing(self):
        """Creates user with salted password hash and verifies plaintext password is never stored."""
        res = self.client.post("/register", data={
            "display_name": "Test Student",
            "email": "student_new@trustmesh.test",
            "password": "Password123!",
            "confirm_password": "Password123!"
        }, follow_redirects=False)
        self.assertEqual(res.status_code, 302)

        # Inspect DB record
        user = get_user_by_email("student_new@trustmesh.test", db_path=self.test_db_path)
        self.assertIsNotNone(user)
        self.assertNotEqual(user["password_hash"], "Password123!")
        self.assertTrue(check_password_hash(user["password_hash"], "Password123!"))

    def test_duplicate_email_rejected(self):
        """Prevents registering multiple accounts with identical email address."""
        # First registration
        self.client.post("/register", data={
            "display_name": "Original User",
            "email": "student_dup@trustmesh.test",
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        # Second registration with same email
        res = self.client.post("/register", data={
            "display_name": "Duplicate Student",
            "email": "student_dup@trustmesh.test",
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        self.assertEqual(res.status_code, 409)
        self.assertIn("already exists", res.get_data(as_text=True).lower())

    def test_invalid_email_format_rejected(self):
        """Rejects non-RFC email formats."""
        res = self.client.post("/register", data={
            "display_name": "Bad Email",
            "email": "invalid-email-format",
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("valid email address", res.get_data(as_text=True).lower())

    def test_password_confirmation_mismatch_rejected(self):
        """Rejects registration when password confirmation does not match."""
        res = self.client.post("/register", data={
            "display_name": "Mismatch User",
            "email": "mismatch@trustmesh.test",
            "password": "Password123!",
            "confirm_password": "DifferentPassword!"
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("do not match", res.get_data(as_text=True).lower())

    def test_valid_login_and_session_establishment(self):
        """Authenticates valid credentials and establishes session."""
        create_user(
            display_name="Login User",
            email="login_user@trustmesh.test",
            password_hash=generate_password_hash("Password123!"),
            role_id=1,
            db_path=self.test_db_path
        )
        res = self.client.post("/login", data={
            "email": "login_user@trustmesh.test",
            "password": "Password123!"
        }, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        with self.client.session_transaction() as sess:
            self.assertEqual(sess["email"], "login_user@trustmesh.test")
            self.assertIn("user_id", sess)

    def test_invalid_login_rejected_with_generic_message(self):
        """Rejects invalid credentials without leaking whether email exists."""
        res = self.client.post("/login", data={
            "email": "nonexistent@trustmesh.test",
            "password": "WrongPassword!"
        }, follow_redirects=False)
        self.assertEqual(res.status_code, 401)
        self.assertIn("invalid email or password", res.get_data(as_text=True).lower())

    def test_logout_clears_session(self):
        """Logs out user and clears authenticated session."""
        create_user(
            display_name="Logout User",
            email="logout_user@trustmesh.test",
            password_hash=generate_password_hash("Password123!"),
            role_id=1,
            db_path=self.test_db_path
        )
        # Log in first
        self.client.post("/login", data={
            "email": "logout_user@trustmesh.test",
            "password": "Password123!"
        })
        # Log out
        res = self.client.post("/logout", follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        # Attempt to access protected dashboard
        res_dash = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(res_dash.status_code, 302)
        self.assertIn("/login", res_dash.headers["Location"])


if __name__ == "__main__":
    unittest.main()
