"""
JWT token manager.

Issues and validates RS256-style JWT access tokens and opaque
refresh tokens stored in the database sessions table.

Access token: 1-hour expiry, signed with SECRET_KEY (HS256).
Refresh token: 7-day expiry, stored as a hash in the sessions table.
"""

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_ALGORITHM = "HS256"
_ACCESS_EXPIRES = timedelta(hours=1)
_REFRESH_EXPIRES = timedelta(days=7)


def _get_secret() -> str:
    from flask import current_app
    return current_app.config.get("JWT_SECRET_KEY", "change-me")


def issue_tokens(user) -> dict:
    """Create a fresh access + refresh token pair for the user.

    Args:
        user: User model instance.

    Returns:
        Dict with ``access_token``, ``refresh_token``, ``expires_in``,
        and ``user`` profile.
    """
    try:
        import jwt as pyjwt
    except ImportError:
        # Fallback: return simple signed token using hmac
        pyjwt = None

    now = datetime.now(timezone.utc)
    exp = now + _ACCESS_EXPIRES

    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role.value if hasattr(user.role, "value") else str(user.role),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    if pyjwt:
        access_token = pyjwt.encode(payload, _get_secret(), algorithm=_ALGORITHM)
    else:
        import json
        import base64
        import hmac
        import hashlib as _hs
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        sig = hmac.new(_get_secret().encode(), f"{header}.{body}".encode(), _hs.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        access_token = f"{header}.{body}.{sig_b64}"

    # Opaque refresh token
    raw_refresh = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw_refresh.encode()).hexdigest()

    # Store session
    _store_session(user.id, token_hash, now + _REFRESH_EXPIRES)

    return {
        "access_token": access_token,
        "refresh_token": raw_refresh,
        "expires_in": int(_ACCESS_EXPIRES.total_seconds()),
        "user": user.to_dict(),
    }


def refresh_access_token(raw_refresh: str) -> dict:
    """Validate a refresh token and issue a new access token."""
    token_hash = hashlib.sha256(raw_refresh.encode()).hexdigest()

    from app.extensions import db
    from app.models.user import UserSession, User

    session_rec = UserSession.query.filter_by(token_hash=token_hash, is_active=True).first()
    if not session_rec or session_rec.is_expired:
        return {"error": "Invalid or expired refresh token"}

    user = db.session.get(User, session_rec.user_id)
    if not user or not user.is_active:
        return {"error": "User account not found or disabled"}

    tokens = issue_tokens(user)
    # Revoke old session
    session_rec.is_active = False
    session_rec.revoked_at = datetime.now(timezone.utc)
    db.session.commit()
    return tokens


def revoke_refresh_token(raw_refresh: str) -> None:
    """Revoke a refresh token (logout)."""
    token_hash = hashlib.sha256(raw_refresh.encode()).hexdigest()
    try:
        from app.extensions import db
        from app.models.user import UserSession
        session_rec = UserSession.query.filter_by(token_hash=token_hash).first()
        if session_rec:
            session_rec.is_active = False
            session_rec.revoked_at = datetime.now(timezone.utc)
            db.session.commit()
    except Exception as exc:
        logger.error("Failed to revoke token: %s", exc)


def get_current_user_from_token(req) -> Optional[object]:
    """Extract and validate Bearer token from request, return User or None."""
    auth_header = req.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:]

    try:
        import jwt as pyjwt
        payload = pyjwt.decode(token, _get_secret(), algorithms=[_ALGORITHM])
        user_id = payload.get("sub")
    except Exception:
        return None

    from app.extensions import db
    from app.models.user import User
    return db.session.get(User, user_id)


def _store_session(user_id, token_hash: str, expires_at: datetime) -> None:
    """Persist a new session record."""
    try:
        from app.extensions import db
        from app.models.user import UserSession
        session_rec = UserSession(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            is_active=True,
        )
        db.session.add(session_rec)
        db.session.commit()
    except Exception as exc:
        logger.error("Failed to store session: %s", exc)
