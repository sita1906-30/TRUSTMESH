"""
TRUSTMESH Centralized Application Configuration (Phase 4, Task 5)

Defines environment-driven configuration profiles for:
- Development (Local Windows debugging, permissive HTTP cookies)
- Production (Azure App Service, HTTPS-enforced cookies, debug disabled, strict size limits)
- Testing (Isolated test database, CSRF disabled for unit suites)
"""

from datetime import timedelta
import logging
import os
from typing import Dict, Type

logger = logging.getLogger("trustmesh.config")


class BaseConfig:
    """Base configuration common to all environments."""
    # Secrets & Cryptographic Signing
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "trustmesh-local-dev-stable-secret-key-phase3-2026"
    )

    # Session Security & Boundaries
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"

    # Request & Upload Boundaries
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB maximum upload limit
    WTF_CSRF_TIME_LIMIT = 3600

    # Meta
    ENGINE_VERSION = "3.0.0"
    ENV_NAME = "development"

    # Database Path (for local SQLite mode)
    DATABASE_PATH = os.environ.get("DATABASE_PATH")


class DevelopmentConfig(BaseConfig):
    """Local development environment configuration."""
    DEBUG = True
    TESTING = False
    ENV_NAME = "development"
    # Localhost development does not enforce HTTPS cookies by default unless COOKIE_SECURE is set
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"


class ProductionConfig(BaseConfig):
    """Production deployment configuration for Azure App Service."""
    DEBUG = False
    TESTING = False
    ENV_NAME = "production"

    # Enforce HTTPS-only session cookies in production unless explicitly opted out
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() != "false"

    @classmethod
    def validate_production_secrets(cls) -> bool:
        """Validates that a custom production secret key is supplied."""
        secret = os.environ.get("SECRET_KEY", "")
        if not secret or "trustmesh-local-dev" in secret:
            logger.warning(
                "SECURITY WARNING: Production mode running without a customized SECRET_KEY. "
                "Ensure SECRET_KEY is set in Azure App Service Application Settings."
            )
            return False
        return True


class TestingConfig(BaseConfig):
    """Automated testing configuration."""
    DEBUG = False
    TESTING = True
    ENV_NAME = "testing"
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False


CONFIG_MAP: Dict[str, Type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "dev": DevelopmentConfig,
    "production": ProductionConfig,
    "prod": ProductionConfig,
    "testing": TestingConfig,
    "test": TestingConfig,
}


def get_config(env_name: str = None) -> Type[BaseConfig]:
    """
    Resolves the configuration class based on FLASK_ENV or provided name.
    Defaults to DevelopmentConfig for safety.
    """
    target = env_name or os.environ.get("FLASK_ENV", "development").lower().strip()
    config_cls = CONFIG_MAP.get(target, DevelopmentConfig)
    if issubclass(config_cls, ProductionConfig):
        ProductionConfig.validate_production_secrets()
    return config_cls

