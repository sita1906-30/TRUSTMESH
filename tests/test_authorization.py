"""
TRUSTMESH Unit Test: Role-Based Access Control (RBAC) & Administrative Guardrails
Verifies that standard users are strictly forbidden from accessing admin endpoints.
"""

import os
import tempfile
import unittest

from app import app
from database import create_user, init_db, migrate_db


class TestAuthorizationModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_rbac_module.db")

        app.config["TESTING"] = True
        app.config["DATABASE_PATH"] = cls.test_db_path
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "test-secret-rbac-2026"

        init_db(db_path=cls.test_db_path)
        migrate_db(db_path=cls.test_db_path)

        cls.user_id = create_user("Standard User", "standard_rbac@trustmesh.test", "hash_std", role_id=1, db_path=cls.test_db_path)
        cls.admin_id = create_user("Admin User", "admin_rbac@trustmesh.test", "hash_adm", role_id=2, db_path=cls.test_db_path)

        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_standard_user_forbidden_from_admin_dashboard(self):
        """Standard user receives HTTP 403 when requesting /admin."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.user_id
            sess["email"] = "standard_rbac@trustmesh.test"
            sess["display_name"] = "Standard User"
            sess["role"] = "user"

        res = self.client.get("/admin")
        self.assertEqual(res.status_code, 403)

    def test_standard_user_forbidden_from_admin_apis(self):
        """Standard user receives HTTP 403 when requesting /api/admin/users and /api/admin/audit-logs."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.user_id
            sess["email"] = "standard_rbac@trustmesh.test"
            sess["display_name"] = "Standard User"
            sess["role"] = "user"

        res1 = self.client.get("/api/admin/users")
        self.assertEqual(res1.status_code, 403)

        res2 = self.client.get("/api/admin/audit-logs")
        self.assertEqual(res2.status_code, 403)

    def test_admin_user_allowed_access(self):
        """Admin user receives HTTP 200 on all administrative endpoints."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.admin_id
            sess["email"] = "admin_rbac@trustmesh.test"
            sess["display_name"] = "Admin User"
            sess["role"] = "admin"

        res_dash = self.client.get("/admin")
        self.assertEqual(res_dash.status_code, 200)

        res_users = self.client.get("/api/admin/users")
        self.assertEqual(res_users.status_code, 200)

        res_logs = self.client.get("/api/admin/audit-logs")
        self.assertEqual(res_logs.status_code, 200)


if __name__ == "__main__":
    unittest.main()

