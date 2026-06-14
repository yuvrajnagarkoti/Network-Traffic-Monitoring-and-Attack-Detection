"""
Threat scoring REST API endpoints.

Provides score lookup for specific attack events,
high-priority active threats listing, and score
distribution statistics.
"""

import logging
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request

from app.extensions import db

logger = logging.getLogger(__name__)

threats_bp = Blueprint("threats", __name__)

# Module-level references (set via init_threats_api)
_scorer = None
_response_engine = None


def init_threats_api(app, scorer, response_engine) -> None:
    """Wire scorer and response engine into the API.

    Args:
        app: Flask application instance.
        scorer: ThreatScorer instance.
        response_engine: ResponseEngine instance.
    """
    global _scorer, _response_engine
    _scorer = scorer
    _response_engine = response_engine
    logger.info("Threats API initialized")


@threats_bp.route("/api/v1/threats/score/<attack_event_id>", methods=["GET"])
def get_threat_score(attack_event_id: str):
    """Get detailed threat score breakdown for a specific attack event.

    Args:
        attack_event_id: UUID of the attack event.

    Returns:
        Score breakdown including all modifiers and explanation.
    """
    try:
        from app.models.threat import ThreatScore

        score = ThreatScore.query.filter_by(
            attack_event_id=attack_event_id
        ).first()

        if not score:
            return jsonify({"error": "Threat score not found"}), 404

        result = score.to_dict()

        # Include attack event info if available
        if score.attack_event:
            result["attack_event"] = {
                "id": str(score.attack_event.id),
                "attack_type": str(score.attack_event.attack_type),
                "source_ip": score.attack_event.source_ip,
                "status": str(score.attack_event.status),
            }

        return jsonify(result), 200

    except Exception as exc:
        logger.error("Failed to fetch threat score: %s", exc)
        return jsonify({"error": str(exc)}), 500


@threats_bp.route("/api/v1/threats/high-priority", methods=["GET"])
def get_high_priority_threats():
    """List all active HIGH and CRITICAL threats.

    Query params:
        limit: Max results (default 50, max 200).

    Returns:
        List of scored threats sorted by score descending.
    """
    try:
        from app.models.threat import ThreatScore, SeverityLevel
        from app.models.attack import AttackEvent

        limit = min(request.args.get("limit", 50, type=int), 200)

        threats = (
            db.session.query(ThreatScore)
            .join(AttackEvent)
            .filter(
                AttackEvent.status.in_(["active", "monitoring"]),
                ThreatScore.severity.in_([
                    SeverityLevel.HIGH,
                    SeverityLevel.CRITICAL,
                ]),
            )
            .order_by(ThreatScore.final_score.desc())
            .limit(limit)
            .all()
        )

        results = []
        for ts in threats:
            item = ts.to_dict()
            if ts.attack_event:
                item["attack_event"] = {
                    "id": str(ts.attack_event.id),
                    "attack_type": str(ts.attack_event.attack_type),
                    "source_ip": ts.attack_event.source_ip,
                    "target_ip": ts.attack_event.target_ip,
                    "status": str(ts.attack_event.status),
                    "first_seen": (
                        ts.attack_event.first_seen.isoformat()
                        if ts.attack_event.first_seen else None
                    ),
                }
            results.append(item)

        return jsonify({
            "threats": results,
            "count": len(results),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), 200

    except Exception as exc:
        logger.error("Failed to fetch high-priority threats: %s", exc)
        return jsonify({"error": str(exc)}), 500


@threats_bp.route("/api/v1/threats/statistics", methods=["GET"])
def get_threat_statistics():
    """Get threat score distribution and statistics.

    Query params:
        hours: Time window in hours (default 24, max 720).

    Returns:
        Score distribution, averages by attack type, severity counts.
    """
    try:
        from sqlalchemy import func, case
        from app.models.threat import ThreatScore, SeverityLevel
        from app.models.attack import AttackEvent

        hours = min(request.args.get("hours", 24, type=int), 720)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Severity distribution
        severity_counts = (
            db.session.query(
                ThreatScore.severity,
                func.count(ThreatScore.id),
            )
            .filter(ThreatScore.calculated_at >= cutoff)
            .group_by(ThreatScore.severity)
            .all()
        )

        severity_dist = {}
        for sev, count in severity_counts:
            key = sev.value if isinstance(sev, SeverityLevel) else str(sev)
            severity_dist[key] = count

        # Average score by attack type
        avg_by_type = (
            db.session.query(
                AttackEvent.attack_type,
                func.avg(ThreatScore.final_score).label("avg_score"),
                func.count(ThreatScore.id).label("count"),
            )
            .join(ThreatScore)
            .filter(ThreatScore.calculated_at >= cutoff)
            .group_by(AttackEvent.attack_type)
            .all()
        )

        type_stats = {}
        for atype, avg, count in avg_by_type:
            type_stats[str(atype)] = {
                "average_score": round(float(avg), 1) if avg else 0,
                "count": count,
            }

        # Overall stats
        overall = (
            db.session.query(
                func.count(ThreatScore.id),
                func.avg(ThreatScore.final_score),
                func.max(ThreatScore.final_score),
                func.min(ThreatScore.final_score),
            )
            .filter(ThreatScore.calculated_at >= cutoff)
            .first()
        )

        # Score range distribution (buckets of 25)
        buckets = {
            "low_0_24": 0,
            "medium_25_49": 0,
            "high_50_74": 0,
            "critical_75_100": 0,
        }

        bucket_counts = (
            db.session.query(
                case(
                    (ThreatScore.final_score < 25, "low_0_24"),
                    (ThreatScore.final_score < 50, "medium_25_49"),
                    (ThreatScore.final_score < 75, "high_50_74"),
                    else_="critical_75_100",
                ).label("bucket"),
                func.count(ThreatScore.id),
            )
            .filter(ThreatScore.calculated_at >= cutoff)
            .group_by("bucket")
            .all()
        )

        for bucket_name, count in bucket_counts:
            buckets[bucket_name] = count

        return jsonify({
            "time_window_hours": hours,
            "total_scores": overall[0] if overall else 0,
            "average_score": round(float(overall[1]), 1) if overall and overall[1] else 0,
            "max_score": overall[2] if overall else 0,
            "min_score": overall[3] if overall else 0,
            "severity_distribution": severity_dist,
            "score_buckets": buckets,
            "by_attack_type": type_stats,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), 200

    except Exception as exc:
        logger.error("Failed to fetch threat statistics: %s", exc)
        return jsonify({"error": str(exc)}), 500
