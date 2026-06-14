"""
IP reputation cache manager.

Caches IP reputation lookups in the database with a 24-hour
TTL to minimize external API calls.
"""

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

CACHE_TTL_HOURS = 24


class ReputationCacheManager:
    """Manages IP reputation caching with 24-hour TTL.

    Cache flow:
    1. Check cache (ip_reputation table) for IP
    2. If cached and fresh (<24h) → return cached result
    3. If miss or stale → fetch from API, cache result
    """

    def __init__(self, app=None) -> None:
        """Initialize cache manager.

        Args:
            app: Flask application instance.
        """
        self.app = app
        self._lock = threading.Lock()
        self._total_hits: int = 0
        self._total_misses: int = 0

    def get(self, ip_address: str) -> Optional[dict]:
        """Look up cached reputation for an IP.

        Args:
            ip_address: IP address to look up.

        Returns:
            Cached reputation dict or None if miss/stale.
        """
        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.threat import IpReputation

                cutoff = datetime.now(timezone.utc) - timedelta(hours=CACHE_TTL_HOURS)

                cached = (
                    db.session.query(IpReputation)
                    .filter(
                        IpReputation.ip_address == ip_address,
                        IpReputation.last_checked >= cutoff,
                    )
                    .first()
                )

                if cached:
                    self._total_hits += 1
                    return {
                        "ip_address": cached.ip_address,
                        "reputation_score": cached.reputation_score,
                        "risk_level": cached.risk_level,
                        "is_malicious": cached.is_malicious,
                        "country_code": cached.country_code,
                        "sources": cached.sources,
                        "last_checked": cached.last_checked.isoformat(),
                        "cached": True,
                    }

                self._total_misses += 1
                return None

        except Exception as exc:
            logger.debug("Cache lookup error for %s: %s", ip_address, exc)
            self._total_misses += 1
            return None

    def put(self, ip_address: str, reputation_data: dict) -> None:
        """Store or update reputation data in cache.

        Args:
            ip_address: IP address.
            reputation_data: Reputation data to cache.
        """
        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.threat import IpReputation

                existing = (
                    db.session.query(IpReputation)
                    .filter(IpReputation.ip_address == ip_address)
                    .first()
                )

                abuse_score = reputation_data.get("abuse_confidence_score", 0)
                reputation_score = self._compute_reputation_score(reputation_data)
                is_malicious = reputation_score >= 51

                if existing:
                    existing.reputation_score = reputation_score
                    existing.is_malicious = is_malicious
                    existing.country_code = reputation_data.get("country_code")
                    existing.sources = {
                        "abuseipdb": {
                            "abuse_confidence": abuse_score,
                            "total_reports": reputation_data.get("total_reports", 0),
                        },
                        "source": reputation_data.get("source", "abuseipdb"),
                    }
                    existing.last_checked = datetime.now(timezone.utc)
                else:
                    record = IpReputation(
                        ip_address=ip_address,
                        reputation_score=reputation_score,
                        is_malicious=is_malicious,
                        country_code=reputation_data.get("country_code"),
                        sources={
                            "abuseipdb": {
                                "abuse_confidence": abuse_score,
                                "total_reports": reputation_data.get("total_reports", 0),
                            },
                            "source": reputation_data.get("source", "abuseipdb"),
                        },
                        last_checked=datetime.now(timezone.utc),
                    )
                    db.session.add(record)

                db.session.commit()

        except Exception as exc:
            logger.error("Cache store error for %s: %s", ip_address, exc)

    def invalidate(self, ip_address: str) -> None:
        """Invalidate cached reputation for an IP.

        Args:
            ip_address: IP address to invalidate.
        """
        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.threat import IpReputation

                db.session.query(IpReputation).filter(
                    IpReputation.ip_address == ip_address
                ).delete()
                db.session.commit()

        except Exception as exc:
            logger.debug("Cache invalidation error: %s", exc)

    def _compute_reputation_score(self, data: dict) -> int:
        """Compute a 0-100 reputation score from raw data.

        Args:
            data: Raw reputation data from API.

        Returns:
            Integer 0 (clean) to 100 (confirmed malicious).
        """
        abuse_score = data.get("abuse_confidence_score", 0)
        total_reports = data.get("total_reports", 0)
        is_tor = data.get("is_tor", False)

        # Base score from abuse confidence (0-100)
        score = abuse_score

        # Report volume modifier
        if total_reports > 100:
            score = min(score + 10, 100)
        elif total_reports > 50:
            score = min(score + 5, 100)

        # Tor modifier
        if is_tor:
            score = min(score + 10, 100)

        return int(score)

    @staticmethod
    def _classify_risk(score: int) -> str:
        """Classify risk level from reputation score."""
        if score >= 76:
            return "confirmed_malicious"
        elif score >= 51:
            return "likely_malicious"
        elif score >= 26:
            return "suspicious"
        else:
            return "clean"

    @property
    def hit_rate(self) -> float:
        """Cache hit rate percentage."""
        total = self._total_hits + self._total_misses
        return (self._total_hits / max(total, 1)) * 100

    @property
    def stats(self) -> dict:
        """Return cache statistics."""
        return {
            "total_hits": self._total_hits,
            "total_misses": self._total_misses,
            "hit_rate": round(self.hit_rate, 1),
            "ttl_hours": CACHE_TTL_HOURS,
        }
