"""
Attack detection REST API endpoints.

Provides attack event queries, active attack listing,
attack statistics, and status update endpoints.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

attacks_bp = Blueprint("attacks", __name__)

# Module-level orchestrator reference (set via init_detection_engine)
_orchestrator = None


def init_detection_engine(app, orchestrator) -> None:
    """Wire the detection orchestrator into the API.

    Args:
        app: Flask application instance.
        orchestrator: DetectionOrchestrator instance.
    """
    global _orchestrator
    _orchestrator = orchestrator
    logger.info("Detection engine API initialized")


@attacks_bp.route("/api/v1/attacks/active", methods=["GET"])
def get_active_attacks():
    """Return all currently active attacks.

    Active attacks are those being tracked by the state manager
    that have not yet resolved (still receiving new evidence).
    """
    if _orchestrator is None:
        return jsonify({"error": "Detection engine not initialized"}), 503

    attacks = _orchestrator.get_active_attacks()
    return jsonify({
        "active_attacks": attacks,
        "count": len(attacks),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), 200


@attacks_bp.route("/api/v1/attacks/<attack_id>", methods=["GET"])
def get_attack_detail(attack_id: str):
    """Return details for a specific attack event.

    Searches both active attacks (in-memory) and resolved
    attacks (database) by ID.

    Args:
        attack_id: UUID of the attack event.
    """
    if _orchestrator is None:
        return jsonify({"error": "Detection engine not initialized"}), 503

    # Check active attacks first
    active = _orchestrator.get_active_attacks()
    for attack in active:
        if attack.get("attack_id") == attack_id:
            attack["source"] = "active"
            return jsonify(attack), 200

    # Check database for resolved attacks
    try:
        from app.extensions import db
        from app.models.attack import AttackEvent

        event = db.session.get(AttackEvent, attack_id)
        if event:
            result = event.to_dict()
            result["source"] = "resolved"

            # Include detail tables if available
            if event.port_scan_detail:
                result["port_scan_detail"] = event.port_scan_detail.to_dict()
            if event.brute_force_detail:
                result["brute_force_detail"] = event.brute_force_detail.to_dict()
            if event.ddos_detail:
                result["ddos_detail"] = event.ddos_detail.to_dict()

            return jsonify(result), 200
    except Exception as exc:
        logger.error("Failed to query attack event: %s", exc)

    return jsonify({"error": "Attack event not found"}), 404


@attacks_bp.route("/api/v1/attacks/stats", methods=["GET"])
def get_attack_stats():
    """Return attack statistics by type and time window.

    Query params:
        - hours: Time window in hours (default: 24)

    Returns counts of attacks by type, severity, and status.
    """
    if _orchestrator is None:
        return jsonify({"error": "Detection engine not initialized"}), 503

    hours = request.args.get("hours", 24, type=int)

    result = {
        "orchestrator": _orchestrator.stats,
        "detectors": _orchestrator.get_detector_stats(),
        "active_attacks": _orchestrator.get_active_attacks(),
        "time_window_hours": hours,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Query database for historical stats
    try:
        from datetime import timedelta
        from sqlalchemy import func
        from app.extensions import db
        from app.models.attack import AttackEvent

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Count by attack type
        type_counts = (
            db.session.query(
                AttackEvent.attack_type,
                func.count(AttackEvent.id),
            )
            .filter(AttackEvent.first_seen >= cutoff)
            .group_by(AttackEvent.attack_type)
            .all()
        )
        result["attack_counts_by_type"] = {
            str(atype): count for atype, count in type_counts
        }

        # Count by status
        status_counts = (
            db.session.query(
                AttackEvent.status,
                func.count(AttackEvent.id),
            )
            .filter(AttackEvent.first_seen >= cutoff)
            .group_by(AttackEvent.status)
            .all()
        )
        result["attack_counts_by_status"] = {
            str(status): count for status, count in status_counts
        }

        # Total in window
        result["total_attacks"] = sum(
            count for _, count in type_counts
        )

    except Exception as exc:
        logger.error("Failed to query attack stats: %s", exc)
        result["db_error"] = str(exc)

    return jsonify(result), 200


@attacks_bp.route("/api/v1/attacks/<attack_id>/status", methods=["POST"])
def update_attack_status(attack_id: str):
    """Update the status of an attack event.

    Admin/analyst endpoint for marking attacks as resolved,
    false positive, etc.

    Request body:
        {"status": "resolved" | "false_positive" | "monitoring"}

    TODO: Add @require_permission('MANAGE_ALERTS') in Phase 9
    """
    data = request.get_json()
    if not data or "status" not in data:
        return jsonify({"error": "Missing 'status' field"}), 400

    new_status = data["status"]
    valid_statuses = {"active", "monitoring", "resolved", "false_positive"}
    if new_status not in valid_statuses:
        return jsonify({
            "error": f"Invalid status. Must be one of: {valid_statuses}"
        }), 400

    try:
        from app.extensions import db
        from app.models.attack import AttackEvent

        event = db.session.get(AttackEvent, attack_id)
        if not event:
            return jsonify({"error": "Attack event not found"}), 404

        old_status = event.status
        event.status = new_status
        db.session.commit()

        logger.info(
            "Attack %s status changed: %s → %s",
            attack_id, old_status, new_status,
        )

        return jsonify({
            "id": str(event.id),
            "old_status": str(old_status),
            "new_status": new_status,
            "message": "Status updated successfully",
        }), 200

    except Exception as exc:
        logger.error("Failed to update attack status: %s", exc)
        return jsonify({"error": str(exc)}), 500
