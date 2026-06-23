"""
Authentication routes.

POST /api/v1/auth/login          — credential check + TOTP challenge
POST /api/v1/auth/verify-2fa     — TOTP verification + JWT issue
POST /api/v1/auth/refresh        — refresh access token
POST /api/v1/auth/logout         — revoke current session
GET  /api/v1/auth/me             — current user profile

Web pages:
  GET /auth/login                — login form
  GET /auth/logout               — logout redirect
"""

import logging
import secrets
from datetime import datetime, timedelta, timezone

from flask import (
    Blueprint, jsonify, redirect, render_template,
    request, session, url_for,
)
from flask_login import current_user, login_user, logout_user

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
auth_api_bp = Blueprint("auth_api", __name__, url_prefix="/api/v1/auth")

_MAX_ATTEMPTS = 5
_LOCKOUT_MINUTES = 15


# ---------------------------------------------------------------------------
# Web routes
# ---------------------------------------------------------------------------

@auth_bp.route("/login", methods=["GET"])
def login():
    """GET /auth/login — serve the login page."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    return render_template("login.html")


@auth_bp.route("/logout", methods=["GET"])
def logout():
    """GET /auth/logout — destroy session and redirect."""
    logout_user()
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@auth_api_bp.route("/login", methods=["POST"])
def api_login():
    """POST /api/v1/auth/login — validate credentials, return 2FA challenge."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    from app.extensions import db, bcrypt
    from app.models.user import User

    user = User.query.filter_by(username=username).first()

    if not user or not user.is_active:
        return jsonify({"error": "Invalid credentials"}), 401

    # Lockout check
    if user.is_locked:
        remaining = int((user.locked_until - datetime.now(timezone.utc)).total_seconds() / 60) + 1
        return jsonify({"error": f"Account locked. Try again in {remaining} minute(s)."}), 403

    # Password verification
    if not bcrypt.check_password_hash(user.password_hash, password):
        user.failed_login_count += 1
        if user.failed_login_count >= _MAX_ATTEMPTS:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=_LOCKOUT_MINUTES)
            logger.warning("Account %s locked after %d failed attempts", username, _MAX_ATTEMPTS)
        db.session.commit()
        return jsonify({"error": "Invalid credentials"}), 401

    # Reset failed attempts
    user.failed_login_count = 0
    user.locked_until = None
    db.session.commit()

    if user.is_2fa_enabled:
        # Store a short-lived pre-auth token in session
        pre_auth = secrets.token_hex(16)
        session["pre_auth_token"] = pre_auth
        session["pre_auth_user_id"] = str(user.id)
        return jsonify({
            "requires_2fa": True,
            "pre_auth_token": pre_auth,
        }), 200
    else:
        # No 2FA — establish Flask-Login session AND issue JWT
        login_user(user, remember=True)
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()
        from app.auth.token_manager import issue_tokens
        tokens = issue_tokens(user)
        return jsonify({"requires_2fa": False, **tokens}), 200


@auth_api_bp.route("/verify-2fa", methods=["POST"])
def verify_2fa():
    """POST /api/v1/auth/verify-2fa — validate TOTP and issue tokens."""
    data = request.get_json(silent=True) or {}
    pre_auth = data.get("pre_auth_token")
    totp_code = (data.get("totp_code") or "").strip()

    if not pre_auth or not totp_code:
        return jsonify({"error": "pre_auth_token and totp_code are required"}), 400

    if session.get("pre_auth_token") != pre_auth:
        return jsonify({"error": "Invalid or expired pre-auth token"}), 401

    user_id = session.get("pre_auth_user_id")
    if not user_id:
        return jsonify({"error": "No pending authentication"}), 401

    from app.extensions import db
    from app.models.user import User

    user = db.session.get(User, user_id)
    if not user or not user.totp_secret:
        return jsonify({"error": "2FA not configured for this account"}), 400

    try:
        import pyotp
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            return jsonify({"error": "Invalid TOTP code"}), 401
    except ImportError:
        return jsonify({"error": "pyotp not installed on server"}), 500

    # Clear pre-auth
    session.pop("pre_auth_token", None)
    session.pop("pre_auth_user_id", None)

    # Establish Flask-Login session AND update last login
    login_user(user, remember=True)
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()

    from app.auth.token_manager import issue_tokens
    tokens = issue_tokens(user)
    return jsonify(tokens), 200


@auth_api_bp.route("/refresh", methods=["POST"])
def refresh():
    """POST /api/v1/auth/refresh — exchange refresh token for new access token."""
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token", "")
    if not refresh_token:
        return jsonify({"error": "refresh_token is required"}), 400

    from app.auth.token_manager import refresh_access_token
    result = refresh_access_token(refresh_token)
    if "error" in result:
        return jsonify(result), 401
    return jsonify(result), 200


@auth_api_bp.route("/logout", methods=["POST"])
def api_logout():
    """POST /api/v1/auth/logout — revoke the refresh token."""
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token", "")
    if refresh_token:
        from app.auth.token_manager import revoke_refresh_token
        revoke_refresh_token(refresh_token)
    return jsonify({"message": "Logged out"}), 200


@auth_api_bp.route("/me", methods=["GET"])
def me():
    """GET /api/v1/auth/me — return current authenticated user profile."""
    from app.auth.token_manager import get_current_user_from_token
    user = get_current_user_from_token(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(user.to_dict()), 200
