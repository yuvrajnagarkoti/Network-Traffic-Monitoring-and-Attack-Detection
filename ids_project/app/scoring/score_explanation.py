"""
Score explanation generator.

Produces human-readable explanations of threat score
breakdowns for analyst review.
"""

from app.scoring.severity_classifier import SeverityLevel


def generate_explanation(breakdown: dict) -> str:
    """Generate a human-readable threat score explanation.

    Args:
        breakdown: Score breakdown dictionary from ThreatScorer.

    Returns:
        Multi-line explanation string.

    Example output:
        Score: 78 (CRITICAL). Base: 45 (DDoS), Rate: +13 (8,500 pps),
        IP Reputation: +15 (confirmed malicious), Recurrence: +5 (attacked 2 days ago)
    """
    final_score = breakdown.get("final_score", 0)
    severity = breakdown.get("severity", SeverityLevel.classify(final_score))
    attack_type = breakdown.get("attack_type", "unknown")

    parts = [
        f"Score: {final_score} ({severity.upper()})"
    ]

    # Base score
    base = breakdown.get("base_score", 0)
    parts.append(f"Base: {base} ({_format_attack_type(attack_type)})")

    # Rate modifier
    rate_mod = breakdown.get("rate_modifier", 0)
    if rate_mod > 0:
        rate_value = breakdown.get("rate_value", 0)
        parts.append(f"Rate: +{rate_mod} ({_format_rate(rate_value)})")

    # Duration modifier
    dur_mod = breakdown.get("duration_modifier", 0)
    if dur_mod > 0:
        dur_seconds = breakdown.get("duration_seconds", 0)
        parts.append(f"Duration: +{dur_mod} ({_format_duration(dur_seconds)})")

    # Recurrence modifier
    rec_mod = breakdown.get("recurrence_modifier", 0)
    if rec_mod > 0:
        parts.append(f"Recurrence: +{rec_mod} (repeat offender)")

    # IP reputation modifier
    rep_mod = breakdown.get("ip_reputation_modifier", 0)
    if rep_mod != 0:
        sign = "+" if rep_mod > 0 else ""
        rep_desc = _reputation_description(rep_mod)
        parts.append(f"IP Reputation: {sign}{rep_mod} ({rep_desc})")

    # ML confidence modifier
    ml_mod = breakdown.get("ml_confidence_modifier", 0)
    if ml_mod > 0:
        parts.append(f"ML Corroboration: +{ml_mod} (anomaly detected)")

    # Blacklist modifier
    bl_mod = breakdown.get("blacklist_modifier", 0)
    if bl_mod > 0:
        parts.append(f"Blacklist: +{bl_mod} (known malicious IP)")

    # Critical asset modifier
    ca_mod = breakdown.get("critical_asset_modifier", 0)
    if ca_mod > 0:
        parts.append(f"Critical Asset: +{ca_mod} (high-value target)")

    # Whitelist override
    if breakdown.get("whitelist_override", False):
        parts = [
            f"Score: 0 (WHITELISTED)",
            "All scores overridden — IP is on the whitelist",
        ]

    return ". ".join(parts)


def generate_short_explanation(breakdown: dict) -> str:
    """Generate a one-line summary explanation.

    Args:
        breakdown: Score breakdown dictionary.

    Returns:
        Short explanation string.
    """
    final_score = breakdown.get("final_score", 0)
    severity = breakdown.get("severity", SeverityLevel.classify(final_score))
    attack_type = _format_attack_type(breakdown.get("attack_type", "unknown"))

    if breakdown.get("whitelist_override", False):
        return "Whitelisted IP — no action required"

    return f"{severity.upper()} {attack_type} (score {final_score}/100)"


def _format_attack_type(attack_type: str) -> str:
    """Format attack type for display."""
    formats = {
        "port_scan": "Port Scan",
        "brute_force": "Brute Force",
        "traffic_anomaly": "Traffic Anomaly",
        "ddos": "DDoS Attack",
        "ml_anomaly": "ML-Detected Anomaly",
    }
    return formats.get(attack_type, attack_type.replace("_", " ").title())


def _format_rate(rate: float) -> str:
    """Format packet/attempt rate for display."""
    if rate >= 1000:
        return f"{rate:,.0f} pps"
    elif rate >= 1:
        return f"{rate:.1f} pps"
    else:
        return "low rate"


def _format_duration(seconds: int) -> str:
    """Format duration for display."""
    if seconds >= 3600:
        hours = seconds // 3600
        return f"{hours}h {(seconds % 3600) // 60}m"
    elif seconds >= 60:
        return f"{seconds // 60}m {seconds % 60}s"
    else:
        return f"{seconds}s"


def _reputation_description(modifier: int) -> str:
    """Describe IP reputation modifier."""
    if modifier >= 15:
        return "confirmed malicious"
    elif modifier >= 8:
        return "likely malicious"
    elif modifier <= -10:
        return "likely safe — possible false positive"
    else:
        return "unknown reputation"
