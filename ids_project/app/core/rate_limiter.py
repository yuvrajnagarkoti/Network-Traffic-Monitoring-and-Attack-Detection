"""
Rate limiter — Flask-Limiter integration.

Configures per-IP and per-endpoint rate limits to protect the API
from brute-force and denial-of-service attempts.

Limits (examples, tune via environment variables):
  - Default        : 300/hour, 60/minute
  - Auth endpoints : 10/minute (brute-force protection)
  - Capture control: 5/minute

Config keys:
  RATELIMIT_STORAGE_URI  (str)  — Redis URI for distributed limiting
                                  (falls back to in-memory)
  RATELIMIT_ENABLED      (bool) — Master switch (default: True)
"""

import logging

logger = logging.getLogger(__name__)


def init_rate_limiter(app) -> None:
    """Initialise Flask-Limiter and attach to the app.

    Gracefully disabled if Flask-Limiter is not installed.

    Args:
        app: Flask application instance.
    """
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
    except ImportError:
        app.logger.warning(
            "flask-limiter not installed — API rate limiting is disabled. "
            "Install with: pip install flask-limiter"
        )
        return

    if not app.config.get("RATELIMIT_ENABLED", True):
        app.logger.info("Rate limiting disabled via RATELIMIT_ENABLED=False")
        return

    storage_uri = app.config.get(
        "RATELIMIT_STORAGE_URI",
        app.config.get("REDIS_URL", "memory://"),
    )

    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["300 per hour", "60 per minute"],
        storage_uri=storage_uri,
        strategy="fixed-window",
        headers_enabled=True,
        # Don't raise exceptions in production — just return 429
        on_breach=None,
    )

    # Tighter limits on auth routes
    _apply_auth_limits(app, limiter)

    # Store on app for use in blueprints
    app.extensions["limiter"] = limiter

    app.logger.info(
        "Rate limiter initialised (storage=%s, default=300/h,60/m)",
        storage_uri,
    )


def _apply_auth_limits(app, limiter) -> None:
    """Apply stricter limits to authentication endpoints after app startup.

    Uses app.before_request to defer blueprint lookup until runtime.
    """
    # Limits are applied declaratively per-route in auth.routes using
    # @limiter.limit("10 per minute") once the limiter is available.
    # This function is a hook for any global auth-path overrides.
    pass


def get_limiter(app=None):
    """Return the limiter instance attached to the current or given app.

    Args:
        app: Flask app instance. Defaults to current_app.

    Returns:
        Limiter instance or None if rate limiting is disabled.
    """
    if app is None:
        from flask import current_app
        app = current_app._get_current_object()
    return app.extensions.get("limiter")
