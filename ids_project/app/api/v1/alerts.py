"""
Alerts REST API endpoints.

Routes:
  GET  /api/v1/alerts                   — paginated alert list
  GET  /api/v1/alerts/<alert_id>        — single alert with comments
  PATCH /api/v1/alerts/<alert_id>/status — update status
  PATCH /api/v1/alerts/<alert_id>/assign — assign to analyst
  POST  /api/v1/alerts/<alert_id>/comment — add comment
  POST  /api/v1/alerts/bulk-acknowledge  — bulk ack by severity
  GET   /api/v1/alerts/statistics        — MTTA/MTTR metrics
  GET   /api/v1/alerts/campaigns         — active attack campaigns
"""

import logging

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/v1/alerts")

# Module-level service references (injected by init_alerts_api)
_alert_manager = None
_aggregator = None
_streamer = None


def init_alerts_api(app, alert_manager, aggregator, streamer) -> None:
    """Inject service dependencies from the app factory."""
    global _alert_manager, _aggregator, _streamer
    _alert_manager = alert_manager
    _aggregator = aggregator
    _streamer = streamer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mgr():
    """Return alert manager, raising if not initialised."""
    if _alert_manager is None:
        from flask import abort
        abort(503, "Alert manager not initialised")
    return _alert_manager


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@alerts_bp.route("", methods=["GET"])
def list_alerts():
    """GET /api/v1/alerts — paginated, filtered alert list."""
    severity = request.args.get("severity")
    status = request.args.get("status")
    attack_type = request.args.get("attack_type")
    source_ip = request.args.get("source_ip")
    assigned_to = request.args.get("assigned_to")
    hours = int(request.args.get("hours", 24))
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))

    result = _mgr().get_alerts(
        severity=severity, status=status, attack_type=attack_type,
        source_ip=source_ip, assigned_to=assigned_to,
        hours=hours, limit=limit, offset=offset,
    )
    return jsonify(result), 200


@alerts_bp.route("/<alert_id>", methods=["GET"])
def get_alert(alert_id: str):
    """GET /api/v1/alerts/<alert_id> — single alert with comments."""
    alert = _mgr().get_alert(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(alert), 200


@alerts_bp.route("/<alert_id>", methods=["PATCH"])
def patch_alert(alert_id: str):
    """PATCH /api/v1/alerts/<alert_id> — update status from body (JS alias).

    Accepts { status, user_id } in the request body and delegates to
    the standard update_status() handler so existing tests remain valid.
    """
    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    if not new_status:
        return jsonify({"error": "status field is required"}), 400

    user_id = data.get("user_id")
    result = _mgr().update_status(alert_id, new_status, user_id=user_id)

    status_code = result.pop("status_code", 200)
    if "error" in result:
        return jsonify(result), status_code

    if _streamer:
        updated = _mgr().get_alert(alert_id)
        if updated:
            _streamer.emit_alert_updated(updated)

    return jsonify(result), status_code


@alerts_bp.route("/<alert_id>/status", methods=["PATCH"])
def update_status(alert_id: str):
    """PATCH /api/v1/alerts/<alert_id>/status — lifecycle transition."""
    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    if not new_status:
        return jsonify({"error": "status field is required"}), 400

    user_id = data.get("user_id")
    result = _mgr().update_status(alert_id, new_status, user_id=user_id)

    status_code = result.pop("status_code", 200)
    if "error" in result:
        return jsonify(result), status_code

    # Broadcast updated alert
    if _streamer:
        updated = _mgr().get_alert(alert_id)
        if updated:
            _streamer.emit_alert_updated(updated)

    return jsonify(result), status_code


@alerts_bp.route("/<alert_id>/assign", methods=["PATCH"])
def assign_alert(alert_id: str):
    """PATCH /api/v1/alerts/<alert_id>/assign — assign to analyst."""
    data = request.get_json(silent=True) or {}
    analyst_id = data.get("analyst_id")
    if not analyst_id:
        return jsonify({"error": "analyst_id is required"}), 400

    result = _mgr().assign_alert(alert_id, analyst_id)
    status_code = result.pop("status_code", 200)
    return jsonify(result), status_code


@alerts_bp.route("/<alert_id>/comment", methods=["POST"])
def add_comment(alert_id: str):
    """POST /api/v1/alerts/<alert_id>/comment — add analyst comment."""
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    comment_text = data.get("comment", "").strip()

    if not comment_text:
        return jsonify({"error": "comment text is required"}), 400
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    result = _mgr().add_comment(alert_id, user_id, comment_text)
    status_code = result.pop("status_code", 201)
    return jsonify(result), status_code


@alerts_bp.route("/bulk-acknowledge", methods=["POST"])
def bulk_acknowledge():
    """POST /api/v1/alerts/bulk-acknowledge — bulk ack by severity."""
    data = request.get_json(silent=True) or {}
    severity = data.get("severity")
    user_id = data.get("user_id")

    result = _mgr().bulk_acknowledge(severity=severity, user_id=user_id)
    status_code = result.pop("status_code", 200)
    return jsonify(result), status_code


@alerts_bp.route("/statistics", methods=["GET"])
def statistics():
    """GET /api/v1/alerts/statistics — MTTA, MTTR, counts."""
    hours = int(request.args.get("hours", 24))
    result = _mgr().get_statistics(hours=hours)
    return jsonify(result), 200


@alerts_bp.route("/campaigns", methods=["GET"])
def campaigns():
    """GET /api/v1/alerts/campaigns — active attack campaigns."""
    if _aggregator is None:
        return jsonify({"campaigns": []}), 200
    active = _aggregator.get_active_campaigns()
    return jsonify({"campaigns": active, "count": len(active)}), 200
