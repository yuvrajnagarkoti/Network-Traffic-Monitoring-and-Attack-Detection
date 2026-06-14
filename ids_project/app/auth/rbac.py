"""
Role-Based Access Control decorators.

Provides endpoint guards based on user roles (Viewer, Analyst, Admin).
Supports both session-based (Flask-Login) and JWT Bearer token auth.

Usage::

    from app.auth.rbac import require_role, UserRole

    @bp.route("/sensitive")
    @require_role(UserRole.ANALYST)
    def sensitive_view():
        ...
"""

import functools
import logging
from typing import Callable

from flask import jsonify, request

logger = logging.getLogger(__name__)


# Role hierarchy: Admin > Analyst > Viewer
_ROLE_RANKS = {
    "admin": 3,
    "analyst": 2,
    "viewer": 1,
}


def require_role(minimum_role: str):
    """Decorator that ensures the caller has at least the given role.

    Checks Bearer JWT first, then Flask-Login session.

    Args:
        minimum_role: Role string — "viewer", "analyst", or "admin".

    Returns:
        403 if role is insufficient, 401 if not authenticated.
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            user = _get_authenticated_user()
            if user is None:
                return jsonify({"error": "Authentication required"}), 401

            role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
            if _ROLE_RANKS.get(role_str, 0) < _ROLE_RANKS.get(minimum_role, 99):
                return jsonify({
                    "error": "Insufficient permissions",
                    "required": minimum_role,
                    "current": role_str,
                }), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


# Convenience decorators
require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("admin")


def _get_authenticated_user():
    """Try JWT Bearer first, then Flask-Login session."""
    # JWT
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        from app.auth.token_manager import get_current_user_from_token
        return get_current_user_from_token(request)

    # Flask-Login
    from flask_login import current_user
    if current_user and current_user.is_authenticated:
        return current_user

    return None
