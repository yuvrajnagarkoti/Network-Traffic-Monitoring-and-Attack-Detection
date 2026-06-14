"""
IP Block management REST API endpoints.

Routes:
  GET    /api/v1/blocks                  — list active blocks
  POST   /api/v1/blocks                  — manually block an IP
  DELETE /api/v1/blocks/<ip>             — unblock an IP
  GET    /api/v1/blocks/blacklist        — list blacklist entries
  POST   /api/v1/blocks/blacklist        — add to blacklist
  DELETE /api/v1/blocks/blacklist/<ip>   — remove from blacklist
  GET    /api/v1/blocks/whitelist        — list whitelist entries
  POST   /api/v1/blocks/whitelist        — add to whitelist
  DELETE /api/v1/blocks/whitelist/<ip>   — remove from whitelist
  POST   /api/v1/blocks/blacklist/import — CSV bulk import
  GET    /api/v1/blocks/blacklist/export — CSV download
  POST   /api/v1/blocks/whitelist/import — CSV bulk import
  GET    /api/v1/blocks/whitelist/export — CSV download
"""

import logging

from flask import Blueprint, Response, jsonify, request

logger = logging.getLogger(__name__)

blocks_bp = Blueprint("blocks", __name__, url_prefix="/api/v1/blocks")

_blocker = None
_list_manager = None


def init_blocks_api(app, blocker, list_manager) -> None:
    """Inject dependencies from the app factory."""
    global _blocker, _list_manager
    _blocker = blocker
    _list_manager = list_manager


# ---------------------------------------------------------------------------
# Active blocks
# ---------------------------------------------------------------------------

@blocks_bp.route("", methods=["GET"])
def list_blocks():
    """GET /api/v1/blocks — active IP blocks."""
    from app.models.block import IpBlock
    blocks = IpBlock.query.filter_by(is_active=True).order_by(IpBlock.blocked_at.desc()).limit(200).all()
    return jsonify({"blocks": [b.to_dict() for b in blocks], "count": len(blocks)}), 200


@blocks_bp.route("", methods=["POST"])
def block_ip():
    """POST /api/v1/blocks — manually block an IP."""
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip is required"}), 400

    result = _blocker.block(
        ip=ip,
        reason=data.get("reason", "Manual block"),
        duration_hours=data.get("duration_hours", 24),
        user_id=data.get("user_id"),
        block_type="manual",
    )
    status_code = 200 if result["success"] else 400
    return jsonify(result), status_code


@blocks_bp.route("/<path:ip>", methods=["DELETE"])
def unblock_ip(ip: str):
    """DELETE /api/v1/blocks/<ip> — unblock an IP."""
    data = request.get_json(silent=True) or {}
    result = _blocker.unblock(ip=ip, user_id=data.get("user_id"))
    status_code = 200 if result["success"] else 404
    return jsonify(result), status_code


# ---------------------------------------------------------------------------
# Blacklist
# ---------------------------------------------------------------------------

@blocks_bp.route("/blacklist", methods=["GET"])
def list_blacklist():
    limit = min(int(request.args.get("limit", 100)), 1000)
    offset = int(request.args.get("offset", 0))
    entries = _list_manager.list_blacklist(limit=limit, offset=offset)
    return jsonify({"entries": entries, "count": len(entries)}), 200


@blocks_bp.route("/blacklist", methods=["POST"])
def add_blacklist():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip is required"}), 400

    result = _list_manager.add_to_blacklist(
        ip=ip, reason=data.get("reason"), source="manual", user_id=data.get("user_id")
    )
    status_code = 201 if result.get("success") else 400
    return jsonify(result), status_code


@blocks_bp.route("/blacklist/<path:ip>", methods=["DELETE"])
def remove_blacklist(ip: str):
    result = _list_manager.remove_from_blacklist(ip)
    status_code = 200 if result.get("success") else 404
    return jsonify(result), status_code


@blocks_bp.route("/blacklist/import", methods=["POST"])
def import_blacklist():
    csv_text = request.data.decode("utf-8") if request.data else ""
    if not csv_text:
        return jsonify({"error": "CSV body required"}), 400
    result = _list_manager.import_csv(csv_text, "blacklist", user_id=request.args.get("user_id"))
    return jsonify(result), 200


@blocks_bp.route("/blacklist/export", methods=["GET"])
def export_blacklist():
    csv_data = _list_manager.export_csv("blacklist")
    return Response(csv_data, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=blacklist.csv"})


# ---------------------------------------------------------------------------
# Whitelist
# ---------------------------------------------------------------------------

@blocks_bp.route("/whitelist", methods=["GET"])
def list_whitelist():
    limit = min(int(request.args.get("limit", 100)), 1000)
    offset = int(request.args.get("offset", 0))
    entries = _list_manager.list_whitelist(limit=limit, offset=offset)
    return jsonify({"entries": entries, "count": len(entries)}), 200


@blocks_bp.route("/whitelist", methods=["POST"])
def add_whitelist():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip is required"}), 400

    result = _list_manager.add_to_whitelist(
        ip=ip, description=data.get("description"), user_id=data.get("user_id")
    )
    status_code = 201 if result.get("success") else 400
    return jsonify(result), status_code


@blocks_bp.route("/whitelist/<path:ip>", methods=["DELETE"])
def remove_whitelist(ip: str):
    result = _list_manager.remove_from_whitelist(ip)
    status_code = 200 if result.get("success") else 404
    return jsonify(result), status_code


@blocks_bp.route("/whitelist/import", methods=["POST"])
def import_whitelist():
    csv_text = request.data.decode("utf-8") if request.data else ""
    if not csv_text:
        return jsonify({"error": "CSV body required"}), 400
    result = _list_manager.import_csv(csv_text, "whitelist", user_id=request.args.get("user_id"))
    return jsonify(result), 200


@blocks_bp.route("/whitelist/export", methods=["GET"])
def export_whitelist():
    csv_data = _list_manager.export_csv("whitelist")
    return Response(csv_data, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=whitelist.csv"})
