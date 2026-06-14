"""
IP reputation aggregator.

Combines scores from AbuseIPDB, local blacklist, and
external feeds into a single weighted reputation score.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from app.intelligence.abuseipdb import AbuseIPDBClient
from app.intelligence.cache_manager import ReputationCacheManager

logger = logging.getLogger(__name__)

# Weight configuration for score aggregation
WEIGHT_ABUSEIPDB = 0.40
WEIGHT_BLACKLIST = 0.40
WEIGHT_EXTERNAL = 0.20


class IPReputationService:
    """Aggregates IP reputation from multiple intelligence sources.

    Combines:
    - AbuseIPDB API (40% weight)
    - Local blacklist check (40% weight)
    - External feed data (20% weight)

    Final score: 0 (clean) to 100 (confirmed malicious).

    Risk levels:
    - 0–25: clean
    - 26–50: suspicious
    - 51–75: likely_malicious
    - 76–100: confirmed_malicious
    """

    def __init__(self, app=None) -> None:
        """Initialize reputation service.

        Args:
            app: Flask application instance.
        """
        self.app = app
        self._abuseipdb = AbuseIPDBClient()
        self._cache = ReputationCacheManager(app=app)
        self._total_lookups: int = 0

    def check_ip(
        self,
        ip_address: str,
        force_refresh: bool = False,
    ) -> dict:
        """Check IP reputation across all sources.

        Args:
            ip_address: IP address to check.
            force_refresh: Skip cache and fetch fresh data.

        Returns:
            Aggregated reputation data dictionary.
        """
        self._total_lookups += 1

        # Check cache first (unless force refresh)
        if not force_refresh:
            cached = self._cache.get(ip_address)
            if cached:
                return cached

        # Gather scores from all sources
        abuseipdb_data = self._check_abuseipdb(ip_address)
        blacklist_data = self._check_blacklist(ip_address)

        # Compute weighted aggregate score
        result = self._aggregate_scores(
            ip_address, abuseipdb_data, blacklist_data
        )

        # Cache the result
        self._cache.put(ip_address, result)

        return result

    def check_bulk(self, ip_addresses: list[str]) -> list[dict]:
        """Check multiple IPs in batch.

        Args:
            ip_addresses: List of IP addresses (max 100).

        Returns:
            List of reputation data dictionaries.
        """
        results = []
        for ip in ip_addresses[:100]:
            result = self.check_ip(ip)
            results.append(result)
        return results

    def override_reputation(
        self,
        ip_address: str,
        score: int,
        reason: str,
    ) -> dict:
        """Manually override IP reputation (admin function).

        Args:
            ip_address: IP address to override.
            score: Manual reputation score (0-100).
            reason: Reason for override.

        Returns:
            Updated reputation data.
        """
        result = {
            "ip_address": ip_address,
            "abuse_confidence_score": score,
            "total_reports": 0,
            "source": "manual_override",
            "override_reason": reason,
            "is_tor": False,
        }

        self._cache.put(ip_address, result)

        logger.info(
            "IP %s reputation overridden to %d: %s",
            ip_address, score, reason,
        )

        return {
            "ip_address": ip_address,
            "reputation_score": score,
            "risk_level": self._classify_risk(score),
            "source": "manual_override",
            "reason": reason,
        }

    def _check_abuseipdb(self, ip_address: str) -> Optional[dict]:
        """Check IP against AbuseIPDB.

        Args:
            ip_address: IP to check.

        Returns:
            AbuseIPDB response data or None.
        """
        try:
            return self._abuseipdb.check_ip(ip_address)
        except Exception as exc:
            logger.debug("AbuseIPDB check failed for %s: %s", ip_address, exc)
            return None

    def _check_blacklist(self, ip_address: str) -> Optional[dict]:
        """Check IP against local blacklist tables.

        Args:
            ip_address: IP to check.

        Returns:
            Blacklist match data or None.
        """
        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.block import Blacklist

                match = (
                    db.session.query(Blacklist)
                    .filter(
                        Blacklist.ip_address == ip_address,
                    )
                    .first()
                )

                if match:
                    return {
                        "is_blacklisted": True,
                        "blacklist_source": match.source,
                        "blacklist_reason": match.reason,
                        "score": 100,
                    }

                return {"is_blacklisted": False, "score": 0}

        except Exception as exc:
            logger.debug("Blacklist check error: %s", exc)
            return None

    def _aggregate_scores(
        self,
        ip_address: str,
        abuseipdb_data: Optional[dict],
        blacklist_data: Optional[dict],
    ) -> dict:
        """Aggregate scores from all sources into final reputation.

        Args:
            ip_address: IP address.
            abuseipdb_data: AbuseIPDB response.
            blacklist_data: Blacklist check result.

        Returns:
            Aggregated reputation dictionary.
        """
        # Extract individual scores
        abuse_score = 0
        if abuseipdb_data:
            abuse_score = abuseipdb_data.get("abuse_confidence_score", 0)

        blacklist_score = 0
        is_blacklisted = False
        if blacklist_data:
            blacklist_score = blacklist_data.get("score", 0)
            is_blacklisted = blacklist_data.get("is_blacklisted", False)

        # Weighted aggregation
        weighted_score = (
            abuse_score * WEIGHT_ABUSEIPDB
            + blacklist_score * WEIGHT_BLACKLIST
            + 0 * WEIGHT_EXTERNAL  # Future: Shodan, etc.
        )

        # If blacklisted, ensure minimum score
        if is_blacklisted:
            weighted_score = max(weighted_score, 75)

        final_score = int(min(max(weighted_score, 0), 100))
        risk_level = self._classify_risk(final_score)

        return {
            "ip_address": ip_address,
            "abuse_confidence_score": abuse_score,
            "reputation_score": final_score,
            "risk_level": risk_level,
            "is_blacklisted": is_blacklisted,
            "total_reports": (
                abuseipdb_data.get("total_reports", 0) if abuseipdb_data else 0
            ),
            "country_code": (
                abuseipdb_data.get("country_code") if abuseipdb_data else None
            ),
            "is_tor": (
                abuseipdb_data.get("is_tor", False) if abuseipdb_data else False
            ),
            "source": "aggregated",
            "score_breakdown": {
                "abuseipdb": {
                    "raw_score": abuse_score,
                    "weight": WEIGHT_ABUSEIPDB,
                    "weighted": round(abuse_score * WEIGHT_ABUSEIPDB, 2),
                },
                "blacklist": {
                    "raw_score": blacklist_score,
                    "weight": WEIGHT_BLACKLIST,
                    "weighted": round(blacklist_score * WEIGHT_BLACKLIST, 2),
                    "is_blacklisted": is_blacklisted,
                },
            },
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _classify_risk(score: int) -> str:
        """Classify risk level from score."""
        if score >= 76:
            return "confirmed_malicious"
        elif score >= 51:
            return "likely_malicious"
        elif score >= 26:
            return "suspicious"
        else:
            return "clean"

    @property
    def stats(self) -> dict:
        """Return service statistics."""
        return {
            "total_lookups": self._total_lookups,
            "abuseipdb": self._abuseipdb.stats,
            "cache": self._cache.stats,
        }
