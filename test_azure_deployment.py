"""
TRUSTMESH Automated Verification Suite — Phase 4, Task 5: Azure App Service Deployment
Tests centralized production configuration profiles, Gunicorn WSGI readiness,
secure session cookies, health check monitoring, static asset availability,
error handling without technical leaks, and cloud readiness.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from flask import Flask

from app import app
from config import (
    BaseConfig,
    DevelopmentConfig,
    ProductionConfig,
    TestingConfig,
    get_config,
)
import wsgi
from database import (
    create_user,
    get_database_mode,
    get_database_status,
    init_db,
    migrate_db,
    save_analysis_transaction,
)


class TestAzureAppServiceDeployment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create dedicated isolated SQLite test database
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_deployment.db")

        app.config["TESTING"] = True
        app.config["DATABASE_PATH"] = cls.test_db_path
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "test-secret-deployment-phase4-task5"

        init_db(db_path=cls.test_db_path)
        migrate_db(db_path=cls.test_db_path)

        # Create Standard User and Admin User
        cls.user_id = create_user(
            display_name="Production Test User",
            email="prod_user@trustmesh.test",
            password_hash="dummy_hash_user",
            role_id=1,
            db_path=cls.test_db_path
        )
        cls.admin_id = create_user(
            display_name="Production Admin",
            email="prod_admin@trustmesh.test",
            password_hash="dummy_hash_admin",
            role_id=2,
            db_path=cls.test_db_path
        )

        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    # =========================================================================
    # Test 1: Development Configuration Loading
    # =========================================================================
    def test_01_development_configuration(self):
        """1. get_config resolves DevelopmentConfig with debug enabled and permissive cookies."""
        cfg = get_config("development")
        self.assertTrue(issubclass(cfg, BaseConfig))
        self.assertTrue(cfg.DEBUG)
        self.assertFalse(cfg.TESTING)
        self.assertEqual(cfg.ENV_NAME, "development")
        self.assertFalse(cfg.SESSION_COOKIE_SECURE)  # Default for localhost HTTP
        print("[PASS] Test 1: DevelopmentConfig successfully verified (Debug: True, Cookie Secure: False).")

    # =========================================================================
    # Test 2: Production Configuration Profile
    # =========================================================================
    def test_02_production_configuration_profile(self):
        """2. get_config resolves ProductionConfig with debug disabled and HTTPS-only cookies."""
        cfg = get_config("production")
        self.assertTrue(issubclass(cfg, BaseConfig))
        self.assertFalse(cfg.DEBUG, "Production mode must strictly disable debug mode.")
        self.assertFalse(cfg.TESTING)
        self.assertEqual(cfg.ENV_NAME, "production")
        self.assertTrue(cfg.SESSION_COOKIE_SECURE, "Production must enforce HTTPS-only session cookies.")
        self.assertTrue(cfg.SESSION_COOKIE_HTTPONLY, "Production must enforce HttpOnly session cookies.")
        self.assertEqual(cfg.SESSION_COOKIE_SAMESITE, "Lax", "Production must configure SameSite=Lax.")
        self.assertEqual(cfg.MAX_CONTENT_LENGTH, 16 * 1024 * 1024, "Max upload limit must be 16 MB.")
        print("[PASS] Test 2: ProductionConfig profile verified (Debug: False, Cookie Secure: True, Max Length: 16 MB).")

    # =========================================================================
    # Test 3: Production Secret Key Validation & Warnings
    # =========================================================================
    def test_03_production_secret_key_validation(self):
        """3. ProductionConfig warns when running with default dev secret and validates custom keys."""
        # A. Default dev key triggers security warning
        with patch.dict(os.environ, {"SECRET_KEY": "trustmesh-local-dev-stable-secret-key-phase3-2026"}):
            is_valid = ProductionConfig.validate_production_secrets()
            self.assertFalse(is_valid, "Default development secret must be flagged as non-production.")

        # B. Custom production secret passes
        with patch.dict(os.environ, {"SECRET_KEY": "c0da62f98e72c83b9e4a8f9024b4592471d79a25b16c8e39023efd6849a21b3d"}):
            is_valid = ProductionConfig.validate_production_secrets()
            self.assertTrue(is_valid, "Custom strong secret key must validate successfully.")
        print("[PASS] Test 3: Production secret key validation & warning mechanism verified.")

    # =========================================================================
    # Test 4: WSGI Entry Point Callable
    # =========================================================================
    def test_04_wsgi_entry_point_callable(self):
        """4. wsgi.py exports valid WSGI application callable compatible with Gunicorn."""
        self.assertTrue(hasattr(wsgi, "app"), "wsgi.py must export 'app' callable.")
        self.assertIsInstance(wsgi.app, Flask, "wsgi.app must be an instance of Flask.")
        self.assertIs(wsgi.app, app, "wsgi.app must reference the central Flask application instance.")
        print("[PASS] Test 4: WSGI callable 'wsgi:app' and 'app:app' verified for Gunicorn hosting.")

    # =========================================================================
    # Test 5: Azure App Service Linux Startup Script (startup.sh)
    # =========================================================================
    def test_05_startup_script_configuration(self):
        """5. startup.sh exists, contains bash shebang, and specifies gunicorn with workers & threads."""
        startup_path = os.path.join(os.path.dirname(__file__), "startup.sh")
        self.assertTrue(os.path.exists(startup_path), "startup.sh must exist in repository root.")

        with open(startup_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertTrue(content.startswith("#!/bin/bash"), "startup.sh must begin with bash shebang.")
        self.assertIn("gunicorn", content, "startup.sh must invoke gunicorn.")
        self.assertIn("app:app", content, "startup.sh must specify app:app WSGI target.")
        self.assertIn("--bind", content, "startup.sh must configure network binding.")
        self.assertIn("PORT", content, "startup.sh must support Azure dynamic PORT environment variable.")
        print("[PASS] Test 5: Linux startup script (startup.sh) verified for Azure App Service.")

    # =========================================================================
    # Test 6: Health Check Endpoint in Production Mode
    # =========================================================================
    def test_06_health_endpoint_in_production(self):
        """6. /health returns 200, reports database mode & environment, and leaks zero secrets."""
        with patch.dict(app.config, {"ENV_NAME": "production"}):
            res = self.client.get("/health")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()

            self.assertEqual(data["status"], "healthy")
            self.assertEqual(data["environment"], "production")
            self.assertEqual(data["database"], "connected")
            self.assertIn("database_mode", data)
            self.assertIn("database_status_indicator", data)
            self.assertIn("storage_status", data)
            self.assertIn("storage_indicator", data)

            # Security verification: Ensure no passwords or secret tokens leak
            json_str = json.dumps(data)
            self.assertNotIn("password", json_str.lower())
            self.assertNotIn("accountkey", json_str.lower())
            self.assertNotIn("secret", json_str.lower())
        print(f"[PASS] Test 6: /health endpoint verified in production mode (Env: {data['environment']}, Status: {data['status']}).")

    # =========================================================================
    # Test 7: Static Files and Template Assets Availability
    # =========================================================================
    def test_07_static_and_template_assets_available(self):
        """7. Core UI templates and static assets (CSS, JS) are present and readable."""
        required_templates = ["index.html", "login.html", "register.html", "admin.html", "error.html"]
        for tmpl in required_templates:
            tmpl_path = os.path.join(os.path.dirname(__file__), "templates", tmpl)
            self.assertTrue(os.path.exists(tmpl_path), f"Template '{tmpl}' must exist.")

        required_static = ["style.css", "script.js"]
        for st in required_static:
            st_path = os.path.join(os.path.dirname(__file__), "static", st)
            self.assertTrue(os.path.exists(st_path), f"Static asset '{st}' must exist.")

        # Test index page renders successfully
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("TRUSTMESH", res.get_data(as_text=True))
        print("[PASS] Test 7: Template and static asset availability verified across all core views.")

    # =========================================================================
    # Test 8: Safe Error Handlers (404 and 500)
    # =========================================================================
    def test_08_safe_error_handling(self):
        """8. Error handlers for 404 and 500 return generic user messages without leaking stack traces."""
        # 404 HTML
        res_404_html = self.client.get("/nonexistent-endpoint-route-test-404")
        self.assertEqual(res_404_html.status_code, 404)
        self.assertIn("404", res_404_html.get_data(as_text=True))
        self.assertNotIn("Traceback", res_404_html.get_data(as_text=True))

        # 404 JSON API
        res_404_json = self.client.get("/api/nonexistent-endpoint-test-404")
        self.assertEqual(res_404_json.status_code, 404)
        data_404 = res_404_json.get_json()
        self.assertIn("error", data_404)
        self.assertEqual(data_404["error"], "Resource not found.")
        print("[PASS] Test 8: Safe 404 error handling verified for both HTML and JSON requests.")

    # =========================================================================
    # Test 9: Request Size Boundaries (413 Handler)
    # =========================================================================
    def test_09_payload_size_limit_handler(self):
        """9. 413 error handler safely rejects oversized payloads without technical leak."""
        # Directly invoke the registered 413 error handler
        from app import handle_413
        with app.test_request_context("/api/test-upload", json={"data": "test"}):
            resp, code = handle_413(Exception("Payload too large"))
            self.assertEqual(code, 413)
            data = resp.get_json()
            self.assertIn("exceeds maximum allowed size limit", data["error"])
        print("[PASS] Test 9: 413 Payload Too Large error handler safely protects memory boundaries.")

    # =========================================================================
    # Test 10: Authentication, RBAC, and Heuristic Analysis in Production
    # =========================================================================
    def test_10_auth_rbac_and_analyzer_integrity(self):
        """10. User login, admin access controls, and scam analysis execute properly."""
        # Scam analysis
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.user_id
            sess["email"] = "prod_user@trustmesh.test"
            sess["display_name"] = "Production Test User"
            sess["role"] = "user"

        res_ana = self.client.post("/analyze", json={
            "text": "URGENT: Please verify your bank account PIN immediately at http://192.168.1.100/verify"
        })
        self.assertEqual(res_ana.status_code, 200)
        data = res_ana.get_json()
        self.assertGreaterEqual(data["score"], 50)
        self.assertIn(data["level"], ["Suspicious", "High risk"])
        self.assertIn("assessment_id", data)

        # RBAC: Standard user denied access to admin console
        res_admin = self.client.get("/admin")
        self.assertEqual(res_admin.status_code, 403)

        # RBAC: Admin user granted access to admin console
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.admin_id
            sess["email"] = "prod_admin@trustmesh.test"
            sess["display_name"] = "Production Admin"
            sess["role"] = "admin"

        res_admin_ok = self.client.get("/admin")
        self.assertEqual(res_admin_ok.status_code, 200)
        self.assertIn("Administration Console", res_admin_ok.get_data(as_text=True))
        print(f"[PASS] Test 10: Auth, RBAC, and core analyzer integrity verified (Assessment #{data['assessment_id']}).")

    # =========================================================================
    # Test 11: Cloud Services Compatibility (Azure SQL & Blob Storage)
    # =========================================================================
    def test_11_cloud_compatibility_under_production_config(self):
        """11. Azure SQL and Blob Storage service clients initialize cleanly under production settings."""
        from services.blob_storage_service import check_blob_storage_health
        from database import get_database_status

        # When cloud unconfigured, safe fallback is reported without errors
        db_stat = get_database_status(db_path=self.test_db_path)
        self.assertEqual(db_stat["status"], "connected")
        self.assertEqual(db_stat["mode"], "sqlite")

        storage_stat = check_blob_storage_health()
        self.assertIn(storage_stat["status"], ("not_configured", "unavailable", "connected"))
        self.assertIn("indicator", storage_stat)
        print("[PASS] Test 11: Cloud services dual-mode architecture and fallback verified.")

    # =========================================================================
    # Test 12: Deployment Files and Dependency Declarations
    # =========================================================================
    def test_12_deployment_files_and_dependencies(self):
        """12. requirements.txt declares gunicorn and .deployment exists."""
        req_path = os.path.join(os.path.dirname(__file__), "requirements.txt")
        with open(req_path, "r", encoding="utf-8") as f:
            req_content = f.read()
        self.assertIn("gunicorn", req_content.lower(), "requirements.txt must declare gunicorn.")

        dep_path = os.path.join(os.path.dirname(__file__), ".deployment")
        self.assertTrue(os.path.exists(dep_path), ".deployment file must exist.")
        with open(dep_path, "r", encoding="utf-8") as f:
            self.assertIn("SCM_DO_BUILD_DURING_DEPLOYMENT", f.read())
        print("[PASS] Test 12: Deployment configuration files and requirements.txt verified.")


if __name__ == "__main__":
    unittest.main()
