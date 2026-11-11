"""
TRUSTMESH Unit Test: Production Cloud Configuration & WSGI Hosting
Verifies environment configuration profiles, Gunicorn WSGI callable, and deployment artifacts.
"""

import os
import unittest
from flask import Flask

from config import BaseConfig, DevelopmentConfig, ProductionConfig, get_config
import wsgi


class TestCloudConfigModule(unittest.TestCase):
    def test_production_config_properties(self):
        """Production config disables debug and enforces HTTPS session cookies."""
        cfg = get_config("production")
        self.assertTrue(issubclass(cfg, BaseConfig))
        self.assertFalse(cfg.DEBUG)
        self.assertTrue(cfg.SESSION_COOKIE_SECURE)
        self.assertEqual(cfg.ENV_NAME, "production")

    def test_development_config_properties(self):
        """Development config enables debug mode and allows localhost HTTP cookies."""
        cfg = get_config("development")
        self.assertTrue(issubclass(cfg, BaseConfig))
        self.assertTrue(cfg.DEBUG)
        self.assertFalse(cfg.SESSION_COOKIE_SECURE)
        self.assertEqual(cfg.ENV_NAME, "development")

    def test_wsgi_entrypoint(self):
        """wsgi.py exposes valid Flask instance 'app' for Gunicorn."""
        self.assertTrue(hasattr(wsgi, "app"))
        self.assertIsInstance(wsgi.app, Flask)

    def test_startup_script_exists_and_valid(self):
        """startup.sh exists, contains bash shebang, and specifies gunicorn command."""
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        startup_file = os.path.join(root_dir, "startup.sh")
        self.assertTrue(os.path.exists(startup_file))
        with open(startup_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue(content.startswith("#!/bin/bash"))
        self.assertIn("gunicorn", content)
        self.assertIn("app:app", content)


if __name__ == "__main__":
    unittest.main()

