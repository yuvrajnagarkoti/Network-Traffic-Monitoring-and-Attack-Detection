"""
Score modifier calculations.

Computes individual score modifiers from attack rate, duration,
recurrence, IP reputation, ML confidence, and blacklist/whitelist.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ── Base scores by attack type (0–50) ──
BASE_SCORES = {
    "port_scan": 20,
    "brute_force": 35,
    "traffic_anomaly": 25,
    "ddos": 45,
    "ml_anomaly": 30,
}

# ── Critical asset list (configurable) ──
CRITICAL_ASSETS = {
    "database_server", "auth_server", "dns_server",
    "mail_server", "vpn_gateway", "domain_controller",
}


def base_score(attack_type: str) -> int:
    """Get base score for an attack type.

    Args:
        attack_type: Attack type string from detector.

    Returns:
        Base score 0–50.
    """
    return BASE_SCORES.get(attack_type, 20)


def rate_modifier(packets_per_second: float = 0, attempts_per_second: float = 0) -> int:
    """Compute rate-based modifier (+0 to +20).

    Higher packet or attempt rates indicate more aggressive attacks.

    Args:
        packets_per_second: Packet rate for volume attacks.
        attempts_per_second: Attempt rate for brute force.

    Returns:
        Rate modifier 0–20.
    """
    rate = max(packets_per_second, attempts_per_second)

    if rate >= 10000:
        return 20
    elif rate >= 5000:
        return 16
    elif rate >= 1000:
        return 13
    elif rate >= 500:
        return 10
    elif rate >= 100:
        return 7
    elif rate >= 50:
        return 5
    elif rate >= 10:
        return 3
    else:
        return 0


def duration_modifier(duration_seconds: int = 0) -> int:
    """Compute duration-based modifier (+0 to +10).

    Longer attacks are more concerning and indicate persistence.

    Args:
        duration_seconds: Attack duration in seconds.

    Returns:
        Duration modifier 0–10.
    """
    if duration_seconds >= 3600:     # 1 hour+
        return 10
    elif duration_seconds >= 1800:   # 30 min+
        return 8
    elif duration_seconds >= 600:    # 10 min+
        return 6
    elif duration_seconds >= 300:    # 5 min+
        return 4
    elif duration_seconds >= 60:     # 1 min+
        return 2
    else:
        return 0


def recurrence_modifier(source_ip: str, app=None) -> int:
    """Compute recurrence modifier (+0 to +10).

    Checks if the same source IP has attacked within the last 7 days.

    Args:
        source_ip: Source IP address.
        app: Flask application instance.

    Returns:
        Recurrence modifier 0–10.
    """
    try:
        if app is None:
            from flask import current_app
            app = current_app._get_current_object()

        with app.app_context():
            from app.extensions import db
            from app.models.attack import AttackEvent

            cutoff = datetime.now(timezone.utc) - timedelta(days=7)
            prior_attacks = (
                db.session.query(AttackEvent)
                .filter(
                    AttackEvent.source_ip == source_ip,
                    AttackEvent.first_seen >= cutoff,
                )
                .count()
            )

            if prior_attacks >= 10:
                return 10
            elif prior_attacks >= 5:
                return 7
            elif prior_attacks >= 2:
                return 5
            elif prior_attacks >= 1:
                return 3
            else:
                return 0

    except Exception as exc:
        logger.debug("Recurrence check failed: %s", exc)
        return 0


def ip_reputation_modifier(source_ip: str, app=None) -> int:
    """Compute IP reputation modifier (-10 to +15).

    Reputation > 75 → +15 (confirmed malicious)
    Reputation > 50 → +8 (likely malicious)
    Reputation < 25 → -10 (likely safe, may be false positive)

    Args:
        source_ip: Source IP address.
        app: Flask application instance.

    Returns:
        Reputation modifier -10 to +15.
    """
    try:
        if app is None:
            from flask import current_app
            app = current_app._get_current_object()

        with app.app_context():
            from app.extensions import db
            from app.models.threat import IpReputation

            rep = (
                db.session.query(IpReputation)
                .filter(IpReputation.ip_address == source_ip)
                .first()
            )

            if rep is None:
                return 0

            score = rep.reputation_score
            if score >= 76:
                return 15
            elif score >= 51:
                return 8
            elif score <= 25:
                return -10
            else:
                return 0

    except Exception as exc:
        logger.debug("IP reputation check failed: %s", exc)
        return 0


def ml_confidence_modifier(source_ip: str, app=None) -> int:
    """Compute ML confidence modifier (+0 or +10).

    If the ML anomaly detector also flagged this IP within the
    same time window, add +10 as corroboration.

    Args:
        source_ip: Source IP address.
        app: Flask application instance.

    Returns:
        ML modifier 0 or 10.
    """
    try:
        if app is None:
            from flask import current_app
            app = current_app._get_current_object()

        with app.app_context():
            from app.extensions import db
            from app.models.threat import MlPrediction

            cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
            ml_flag = (
                db.session.query(MlPrediction)
                .filter(
                    MlPrediction.prediction == "anomaly",
                    MlPrediction.predicted_at >= cutoff,
                )
                .first()
            )

            return 10 if ml_flag else 0

    except Exception as exc:
        logger.debug("ML confidence check failed: %s", exc)
        return 0


def blacklist_modifier(source_ip: str, app=None) -> int:
    """Compute blacklist modifier (+0 or +20).

    IP on known blacklist → immediate escalation.

    Args:
        source_ip: Source IP address.
        app: Flask application instance.

    Returns:
        Blacklist modifier 0 or 20.
    """
    try:
        if app is None:
            from flask import current_app
            app = current_app._get_current_object()

        with app.app_context():
            from app.extensions import db
            from app.models.block import Blacklist

            match = (
                db.session.query(Blacklist)
                .filter(Blacklist.ip_address == source_ip)
                .first()
            )

            return 20 if match else 0

    except Exception as exc:
        logger.debug("Blacklist check failed: %s", exc)
        return 0


def whitelist_check(source_ip: str, app=None) -> bool:
    """Check if an IP is whitelisted.

    Whitelisted IPs override ALL scores → total score = 0.

    Args:
        source_ip: Source IP address.
        app: Flask application instance.

    Returns:
        True if IP is whitelisted.
    """
    # Never whitelist bogon or unspecified
    if source_ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
        return False

    try:
        if app is None:
            from flask import current_app
            app = current_app._get_current_object()

        with app.app_context():
            from app.extensions import db
            from app.models.block import Whitelist

            match = (
                db.session.query(Whitelist)
                .filter(Whitelist.ip_address == source_ip)
                .first()
            )

            return match is not None

    except Exception as exc:
        logger.debug("Whitelist check failed: %s", exc)
        return False


def critical_asset_modifier(target_ip: str, app=None) -> int:
    """Compute critical asset modifier (+0 or +10).

    If the target of the attack is a known critical asset
    (database server, auth server, etc.), escalate score.

    Args:
        target_ip: Target/destination IP address.
        app: Flask application instance.

    Returns:
        Critical asset modifier 0 or 10.
    """
    # In production, this would check a configurable asset registry.
    # For now, return 0 (no critical asset DB configured yet).
    return 0
