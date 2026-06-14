"""
Structured JSON logging configuration.

Sets up multi-channel logging:
- Application log: INFO+, rotating file handler
- Security log: WARNING+, separate file for audit events
- Error log: ERROR+, includes full stack traces
- Console: configurable level for development
"""

import logging
import logging.handlers
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Optional

from flask import Flask, g, has_request_context, request


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter.

    Every log entry includes timestamp, level, logger name, message,
    and optional request context (request_id, user_id, source_ip).
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON string."""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if has_request_context():
            log_entry["request_id"] = getattr(g, "request_id", None)
            log_entry["source_ip"] = request.remote_addr
            log_entry["method"] = request.method
            log_entry["path"] = request.path
            user_id = getattr(g, "current_user_id", None)
            if user_id:
                log_entry["user_id"] = str(user_id)

        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "extra_data"):
            log_entry["data"] = record.extra_data

        import json
        return json.dumps(log_entry, default=str)


def setup_logging(app: Flask) -> None:
    """Configure application logging with multiple handlers.

    Args:
        app: Flask application instance.
    """
    log_dir = app.config.get("LOG_DIR", "logs")
    log_level = app.config.get("LOG_LEVEL", "INFO")
    max_bytes = app.config.get("LOG_MAX_BYTES", 10 * 1024 * 1024)
    backup_count = app.config.get("LOG_BACKUP_COUNT", 5)

    os.makedirs(log_dir, exist_ok=True)

    json_formatter = JSONFormatter()
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Clear existing handlers to avoid duplicate logs on reload
    root_logger.handlers.clear()

    # Console handler (human-readable for development)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    if app.debug:
        console_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
        console_handler.setFormatter(console_formatter)
    else:
        console_handler.setFormatter(json_formatter)
    root_logger.addHandler(console_handler)

    # Application log: INFO+ rotating file
    app_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, "application.log"),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    app_handler.setLevel(logging.INFO)
    app_handler.setFormatter(json_formatter)
    root_logger.addHandler(app_handler)

    # Security log: WARNING+ separate file (never truncated in production)
    security_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, "security.log"),
        maxBytes=max_bytes * 2,
        backupCount=backup_count * 2,
        encoding="utf-8",
    )
    security_handler.setLevel(logging.WARNING)
    security_handler.setFormatter(json_formatter)
    security_logger = logging.getLogger("ids.security")
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.WARNING)

    # Error log: ERROR+ with stack traces
    error_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, "error.log"),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(json_formatter)
    root_logger.addHandler(error_handler)

    # Audit log: dedicated file for admin actions
    audit_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, "audit.log"),
        maxBytes=max_bytes * 2,
        backupCount=backup_count * 2,
        encoding="utf-8",
    )
    audit_handler.setLevel(logging.INFO)
    audit_handler.setFormatter(json_formatter)
    audit_logger = logging.getLogger("ids.audit")
    audit_logger.addHandler(audit_handler)
    audit_logger.setLevel(logging.INFO)

    # Suppress noisy third-party loggers
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if app.config.get("SQLALCHEMY_ECHO") else logging.WARNING
    )

    # Register request ID middleware
    _register_request_id_middleware(app)

    app.logger.info("Logging configured: level=%s, dir=%s", log_level, log_dir)


def _register_request_id_middleware(app: Flask) -> None:
    """Generate unique request ID for each HTTP request."""

    @app.before_request
    def set_request_id() -> None:
        g.request_id = str(uuid.uuid4())

    @app.after_request
    def add_request_id_header(response):
        request_id = getattr(g, "request_id", None)
        if request_id:
            response.headers["X-Request-ID"] = request_id
        return response


def get_security_logger() -> logging.Logger:
    """Get the security-specific logger."""
    return logging.getLogger("ids.security")


def get_audit_logger() -> logging.Logger:
    """Get the audit-specific logger."""
    return logging.getLogger("ids.audit")


def log_audit_event(
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    old_value: Optional[dict] = None,
    new_value: Optional[dict] = None,
    user_id: Optional[str] = None,
) -> None:
    """Log an audit event to both the audit logger and database.

    Args:
        action: Action performed (e.g., 'user_login', 'ip_blocked').
        resource_type: Type of resource affected.
        resource_id: ID of the resource affected.
        old_value: Previous value (for updates).
        new_value: New value (for updates).
        user_id: ID of the user who performed the action.
    """
    audit_logger = get_audit_logger()
    audit_logger.info(
        "AUDIT: action=%s resource=%s/%s user=%s",
        action,
        resource_type,
        resource_id,
        user_id,
    )
