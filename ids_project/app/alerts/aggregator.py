"""
Alert campaign aggregator.

Groups consecutive alerts from the same source IP into a single
"attack campaign" to reduce analyst fatigue.  Tracks the campaign
window (30-minute inactivity resets the campaign) and counts how
many raw alerts contributed.
"""

import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Campaign window: if the same IP has no new alerts for this duration,
# its campaign is considered closed.
_CAMPAIGN_WINDOW = timedelta(minutes=30)


class CampaignAggregator:
    """Thread-safe, in-memory grouper that deduplicates alerts per source IP."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # {source_ip: {"first_seen": dt, "last_seen": dt, "count": int,
        #              "attack_types": set, "max_score": float}}
        self._campaigns: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_alert(self, alert_dict: dict) -> dict:
        """Register a scored alert and return the enriched alert with campaign data.

        Args:
            alert_dict: Alert dictionary from AlertManager / ResponseEngine.

        Returns:
            The same dict with ``campaign`` sub-key added.
        """
        source_ip = alert_dict.get("source_ip") or self._extract_source_ip(alert_dict)
        if not source_ip:
            alert_dict["campaign"] = None
            return alert_dict

        now = datetime.now(timezone.utc)

        with self._lock:
            campaign = self._campaigns.get(source_ip)

            if campaign is None or (now - campaign["last_seen"]) > _CAMPAIGN_WINDOW:
                # Start a new campaign
                campaign = {
                    "source_ip": source_ip,
                    "first_seen": now,
                    "last_seen": now,
                    "count": 1,
                    "attack_types": {alert_dict.get("attack_type", "unknown")},
                    "max_score": alert_dict.get("score", 0),
                }
                self._campaigns[source_ip] = campaign
                is_new_campaign = True
            else:
                # Update existing campaign
                campaign["last_seen"] = now
                campaign["count"] += 1
                campaign["attack_types"].add(alert_dict.get("attack_type", "unknown"))
                campaign["max_score"] = max(campaign["max_score"], alert_dict.get("score", 0))
                is_new_campaign = False

            snapshot = {
                "source_ip": source_ip,
                "first_seen": campaign["first_seen"].isoformat(),
                "last_seen": campaign["last_seen"].isoformat(),
                "count": campaign["count"],
                "attack_types": list(campaign["attack_types"]),
                "max_score": campaign["max_score"],
                "is_new_campaign": is_new_campaign,
            }

        alert_dict = dict(alert_dict)
        alert_dict["campaign"] = snapshot
        return alert_dict

    def get_active_campaigns(self) -> list[dict]:
        """Return all campaigns that are still within the activity window."""
        now = datetime.now(timezone.utc)
        active = []
        with self._lock:
            for ip, c in self._campaigns.items():
                if (now - c["last_seen"]) <= _CAMPAIGN_WINDOW:
                    active.append({
                        "source_ip": ip,
                        "first_seen": c["first_seen"].isoformat(),
                        "last_seen": c["last_seen"].isoformat(),
                        "count": c["count"],
                        "attack_types": list(c["attack_types"]),
                        "max_score": c["max_score"],
                    })
        return sorted(active, key=lambda x: x["max_score"], reverse=True)

    def purge_expired(self) -> int:
        """Remove campaigns outside the activity window. Returns count removed."""
        now = datetime.now(timezone.utc)
        to_remove = []
        with self._lock:
            for ip, c in self._campaigns.items():
                if (now - c["last_seen"]) > _CAMPAIGN_WINDOW:
                    to_remove.append(ip)
            for ip in to_remove:
                del self._campaigns[ip]
        if to_remove:
            logger.debug("Purged %d expired campaigns", len(to_remove))
        return len(to_remove)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_source_ip(self, alert_dict: dict) -> Optional[str]:
        """Try to pull source IP from nested attack_event data."""
        attack = alert_dict.get("attack_event") or {}
        return attack.get("source_ip")
