"""
Health check API endpoint.

Provides system health status including database connectivity,
used by Docker health checks and monitoring systems.
"""

import time
from datetime import datetime, timezone

from flask import Blueprint, jsonify

from app.core.database import check_database_health

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health_check():
    """System health check endpoint.

    Returns database connectivity status, response latency,
    and system timestamp. Used by Docker HEALTHCHECK and
    external monitoring.

    Returns:
        JSON response with health status and HTTP 200 (healthy)
        or HTTP 503 (unhealthy).
    """
    start_time = time.monotonic()

    db_health = check_database_health()

    response_time_ms = (time.monotonic() - start_time) * 1000

    is_healthy = db_health.get("status") == "connected"

    response = {
        "status": "healthy" if is_healthy else "unhealthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "response_time_ms": round(response_time_ms, 2),
        "components": {
            "database": db_health,
        },
    }

    status_code = 200 if is_healthy else 503
    return jsonify(response), status_code
