"""
Packet search REST API.

GET /api/v1/search/packets    — cursor-paginated packet search
GET /api/v1/packets/search    — alias (matches app.js URL)
"""

import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

search_bp = Blueprint("search", __name__)

_search_engine = None


def init_search_api(app, search_engine) -> None:
    global _search_engine
    _search_engine = search_engine


def _do_search():
    """Shared search logic for both route aliases."""
    args = request.args

    # Parse time range
    start_time = None
    end_time = None
    if args.get("start"):
        try:
            start_time = datetime.fromisoformat(args["start"])
        except ValueError:
            return jsonify({"error": "Invalid start datetime (use ISO 8601)"}), 400

    if args.get("end"):
        try:
            end_time = datetime.fromisoformat(args["end"])
        except ValueError:
            return jsonify({"error": "Invalid end datetime (use ISO 8601)"}), 400

    cursor = args.get("cursor")
    cursor_int = int(cursor) if cursor else None

    if _search_engine is None:
        # Graceful degradation: return empty results if search engine not wired
        return jsonify({"packets": [], "next_cursor": None, "total": 0}), 200

    result = _search_engine.search(
        src_ip=args.get("src_ip"),
        dst_ip=args.get("dst_ip"),
        src_port=int(args["src_port"]) if args.get("src_port") else None,
        dst_port=int(args["dst_port"]) if args.get("dst_port") else None,
        protocol=args.get("protocol"),
        min_size=int(args["min_size"]) if args.get("min_size") else None,
        max_size=int(args["max_size"]) if args.get("max_size") else None,
        start_time=start_time,
        end_time=end_time,
        cursor=cursor_int,
        limit=min(int(args.get("limit", 50)), 200),
        order=args.get("order", "desc"),
    )
    return jsonify(result), 200


@search_bp.route("/api/v1/search/packets", methods=["GET"])
def search_packets():
    """GET /api/v1/search/packets — filtered, cursor-paginated packet log search."""
    return _do_search()


@search_bp.route("/api/v1/packets/search", methods=["GET"])
def search_packets_alias():
    """GET /api/v1/packets/search — same as /api/v1/search/packets (JS alias)."""
    return _do_search()

