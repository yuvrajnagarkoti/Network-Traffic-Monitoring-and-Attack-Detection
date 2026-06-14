"""
Investigation REST API.

GET  /api/v1/investigation/timeline/<attack_event_id>
GET  /api/v1/investigation/ip/<ip>
GET  /api/v1/investigation/flow
"""

import logging
from datetime import datetime

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

investigation_bp = Blueprint("investigation", __name__, url_prefix="/api/v1/investigation")

_timeline = None
_ip_investigator = None
_flow_reconstructor = None


def init_investigation_api(app, timeline, ip_investigator, flow_reconstructor) -> None:
    global _timeline, _ip_investigator, _flow_reconstructor
    _timeline = timeline
    _ip_investigator = ip_investigator
    _flow_reconstructor = flow_reconstructor


@investigation_bp.route("/timeline/<attack_event_id>", methods=["GET"])
def get_timeline(attack_event_id: str):
    """GET /api/v1/investigation/timeline/<id> — attack event timeline."""
    context_minutes = int(request.args.get("context_minutes", 5))
    result = _timeline.build(attack_event_id, context_minutes=context_minutes)
    if "error" in result:
        return jsonify(result), 404
    return jsonify(result), 200


@investigation_bp.route("/ip/<path:ip>", methods=["GET"])
def get_ip_profile(ip: str):
    """GET /api/v1/investigation/ip/<ip> — comprehensive IP profile."""
    days = int(request.args.get("days", 30))
    result = _ip_investigator.profile(ip, days=days)
    return jsonify(result), 200


@investigation_bp.route("/flow", methods=["GET"])
def reconstruct_flow():
    """GET /api/v1/investigation/flow — TCP flow reconstruction."""
    args = request.args
    src_ip = args.get("src_ip")
    dst_ip = args.get("dst_ip")
    if not src_ip or not dst_ip:
        return jsonify({"error": "src_ip and dst_ip are required"}), 400

    start_time = None
    end_time = None
    if args.get("start"):
        try:
            start_time = datetime.fromisoformat(args["start"])
        except ValueError:
            return jsonify({"error": "Invalid start datetime"}), 400
    if args.get("end"):
        try:
            end_time = datetime.fromisoformat(args["end"])
        except ValueError:
            return jsonify({"error": "Invalid end datetime"}), 400

    result = _flow_reconstructor.reconstruct(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=int(args["src_port"]) if args.get("src_port") else None,
        dst_port=int(args["dst_port"]) if args.get("dst_port") else None,
        start_time=start_time,
        end_time=end_time,
        max_packets=int(args.get("max_packets", 1000)),
    )
    return jsonify(result), 200
