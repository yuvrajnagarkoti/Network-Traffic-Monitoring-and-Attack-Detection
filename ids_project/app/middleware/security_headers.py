"""
Security headers middleware.

Injects security-oriented HTTP response headers on every response:
  - Content-Security-Policy  — restricts content origins
  - Strict-Transport-Security — forces HTTPS (production only)
  - X-Frame-Options          — prevents clickjacking
  - X-Content-Type-Options   — prevents MIME sniffing
  - Referrer-Policy          — limits referrer leakage
  - Permissions-Policy       — disable unneeded browser features

Register with: app.after_request(add_security_headers)
"""

from flask import Flask, Response


def add_security_headers(response: Response) -> Response:
    """Attach security headers to every HTTP response."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.socket.io https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:;"
    )
    return response


def add_hsts_header(response: Response) -> Response:
    """Add HSTS header (production-only)."""
    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubDomains; preload"
    )
    return response


def register_security_middleware(app: Flask) -> None:
    """Register all security header middleware with the app.

    Args:
        app: Flask application instance.
    """
    app.after_request(add_security_headers)
    if not app.debug:
        app.after_request(add_hsts_header)
    app.logger.info("Security headers middleware registered")
