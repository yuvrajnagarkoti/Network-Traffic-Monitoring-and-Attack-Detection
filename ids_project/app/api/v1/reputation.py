"""
IP reputation REST API endpoints.

Provides IP reputation lookups, bulk checks, and
admin override capabilities.
"""

import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

reputation_bp = Blueprint("reputation", __name__)

# Module-level service reference
_reputation_service = None


def init_reputation_service(app, service) -> None:
    """Wire the reputation service into the API.

    Args:
        app: Flask application instance.
        service: IPReputationService instance.
    """
    global _reputation_service
    _reputation_service = service
    logger.info("Reputation API initialized")


@reputation_bp.route("/api/v1/reputation/<ip_address>", methods=["GET"])
def get_ip_reputation(ip_address: str):
    """Return reputation data for a specific IP address.

    Checks cache first (24h TTL), then queries external sources.

    Query params:
        - force: Set to 'true' to bypass cache
    """
    if _reputation_service is None:
        return jsonify({"error": "Reputation service not initialized"}), 503

    force = request.args.get("force", "false").lower() == "true"

    try:
        result = _reputation_service.check_ip(ip_address, force_refresh=force)
        return jsonify(result), 200
    except Exception as exc:
        logger.error("Reputation check failed for %s: %s", ip_address, exc)
        return jsonify({"error": str(exc)}), 500


@reputation_bp.route("/api/v1/reputation/check-bulk", methods=["POST"])
def check_bulk_reputation():
    """Check reputation for multiple IP addresses.

    Request body:
        {"ip_addresses": ["1.2.3.4", "5.6.7.8"]}

    Maximum 100 IPs per request.
    """
    if _reputation_service is None:
        return jsonify({"error": "Reputation service not initialized"}), 503

    data = request.get_json()
    if not data or "ip_addresses" not in data:
        return jsonify({"error": "Missing 'ip_addresses' field"}), 400

    ips = data["ip_addresses"]
    if not isinstance(ips, list):
        return jsonify({"error": "'ip_addresses' must be a list"}), 400

    if len(ips) > 100:
        return jsonify({"error": "Maximum 100 IPs per request"}), 400

    try:
        results = _reputation_service.check_bulk(ips)
        return jsonify({
            "results": results,
            "count": len(results),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), 200
    except Exception as exc:
        logger.error("Bulk reputation check failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@reputation_bp.route(
    "/api/v1/reputation/<ip_address>/override", methods=["POST"]
)
def override_reputation(ip_address: str):
    """Manually override IP reputation (admin only).

    Request body:
        {"score": 0-100, "reason": "explanation"}

    TODO: Add @require_permission('MANAGE_SYSTEM_CONFIG') in Phase 9
    """
    if _reputation_service is None:
        return jsonify({"error": "Reputation service not initialized"}), 503

    data = request.get_json()
    if not data or "score" not in data or "reason" not in data:
        return jsonify({"error": "Missing 'score' and 'reason' fields"}), 400

    score = data["score"]
    if not isinstance(score, int) or not 0 <= score <= 100:
        return jsonify({"error": "Score must be integer 0-100"}), 400

    try:
        result = _reputation_service.override_reputation(
            ip_address, score, data["reason"]
        )
        return jsonify(result), 200
    except Exception as exc:
        logger.error("Override failed for %s: %s", ip_address, exc)
        return jsonify({"error": str(exc)}), 500
