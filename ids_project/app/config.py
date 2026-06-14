"""
Flask application configuration classes.

Loads settings from environment variables with sensible defaults.
Each environment (development, testing, production) has its own class.
"""

import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()


class BaseConfig:
    """Base configuration shared across all environments."""

    SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        "pool_size": int(os.environ.get("DB_POOL_SIZE", "10")),
        "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", "20")),
        "pool_timeout": int(os.environ.get("DB_POOL_TIMEOUT", "30")),
        "pool_recycle": int(os.environ.get("DB_POOL_RECYCLE", "3600")),
        "pool_pre_ping": True,
    }

    # JWT
    JWT_SECRET_KEY: str = os.environ.get("JWT_SECRET_KEY", "jwt-dev-secret-change-me")
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(
        seconds=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES", "3600"))
    )
    JWT_REFRESH_TOKEN_EXPIRES: timedelta = timedelta(
        seconds=int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRES", "604800"))
    )

    # Mail
    MAIL_SERVER: str = os.environ.get("MAIL_SERVER", "localhost")
    MAIL_PORT: int = int(os.environ.get("MAIL_PORT", "1025"))
    MAIL_USE_TLS: bool = os.environ.get("MAIL_USE_TLS", "false").lower() == "true"
    MAIL_USERNAME: str = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD: str = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER: str = os.environ.get("MAIL_DEFAULT_SENDER", "ids@example.com")

    # Logging
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")
    LOG_DIR: str = os.environ.get("LOG_DIR", "logs")
    LOG_MAX_BYTES: int = int(os.environ.get("LOG_MAX_BYTES", "10485760"))
    LOG_BACKUP_COUNT: int = int(os.environ.get("LOG_BACKUP_COUNT", "5"))

    # Packet Capture
    CAPTURE_INTERFACE: str = os.environ.get("CAPTURE_INTERFACE", "eth0")
    CAPTURE_BPF_FILTER: str = os.environ.get(
        "CAPTURE_BPF_FILTER", "not (ether broadcast or ether multicast)"
    )
    PACKET_QUEUE_SIZE: int = int(os.environ.get("PACKET_QUEUE_SIZE", "10000"))
    BATCH_INSERT_SIZE: int = int(os.environ.get("BATCH_INSERT_SIZE", "500"))
    BATCH_FLUSH_INTERVAL_MS: int = int(os.environ.get("BATCH_FLUSH_INTERVAL_MS", "500"))

    # Threat Intelligence
    ABUSEIPDB_API_KEY: str = os.environ.get("ABUSEIPDB_API_KEY", "")
    ABUSEIPDB_RATE_LIMIT: int = int(os.environ.get("ABUSEIPDB_RATE_LIMIT", "1000"))

    # Session
    PERMANENT_SESSION_LIFETIME: timedelta = timedelta(hours=8)
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"

    # WTF CSRF
    WTF_CSRF_ENABLED: bool = True


class DevelopmentConfig(BaseConfig):
    """Development environment configuration."""

    DEBUG: bool = True
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL",
        "postgresql://ids_user:ids_secure_password_change_me@localhost:5432/ids_db",
    )
    SQLALCHEMY_ECHO: bool = False
    SESSION_COOKIE_SECURE: bool = False


class TestingConfig(BaseConfig):
    """Testing environment configuration.

    Uses SQLite in-memory by default so tests run without a PostgreSQL instance.
    Set DATABASE_TEST_URL env var to override with a real DB for integration tests.
    """

    TESTING: bool = True
    DEBUG: bool = True
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_TEST_URL",
        "sqlite:///:memory:",
    )
    # Simpler engine options for SQLite (no pool needed)
    SQLALCHEMY_ENGINE_OPTIONS: dict = {"pool_pre_ping": False}
    SQLALCHEMY_ECHO: bool = False
    WTF_CSRF_ENABLED: bool = False
    SESSION_COOKIE_SECURE: bool = False
    # Skip packet capture initialisation during tests
    CAPTURE_SIMULATION: bool = True
    SKIP_CAPTURE_ENGINE: bool = True
    # Disable rate limiting in tests
    RATELIMIT_ENABLED: bool = False


class ProductionConfig(BaseConfig):
    """Production environment configuration."""

    DEBUG: bool = False
    SQLALCHEMY_DATABASE_URI: str = os.environ.get("DATABASE_URL", "")
    SQLALCHEMY_ECHO: bool = False
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_SAMESITE: str = "Strict"


config_by_name: dict[str, type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
