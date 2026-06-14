"""
AbuseIPDB API adapter.

Provides IP reputation lookups via the AbuseIPDB v2 API
with rate limiting and error handling.
"""

import logging
import os
import time
import threading
from typing import Optional

import requests

logger = logging.getLogger(__name__)

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_RATE_LIMIT = 1000  # Free tier: 1000 checks/day
RATE_LIMIT_WINDOW = 86400  # 24 hours in seconds


class AbuseIPDBClient:
    """AbuseIPDB API v2 client with rate limiting.

    Provides IP reputation checks with:
    - Automatic rate limiting (1000/day free tier)
    - Response caching delegation to CacheManager
    - Error handling for network failures and API errors
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        daily_limit: int = DEFAULT_RATE_LIMIT,
    ) -> None:
        """Initialize client.

        Args:
            api_key: AbuseIPDB API key. Falls back to
                ABUSEIPDB_API_KEY environment variable.
            daily_limit: Maximum API calls per day.
        """
        self.api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        self.daily_limit = daily_limit

        self._lock = threading.Lock()
        self._call_count: int = 0
        self._window_start: float = time.time()
        self._total_calls: int = 0
        self._total_errors: int = 0

    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Optional[dict]:
        """Check an IP address against AbuseIPDB.

        Args:
            ip_address: IP address to check.
            max_age_days: Maximum report age to consider.

        Returns:
            Reputation data dict or None on error.
        """
        if not self.api_key:
            logger.debug("AbuseIPDB API key not configured")
            return None

        if not self._check_rate_limit():
            logger.warning("AbuseIPDB rate limit reached (%d/%d)", self._call_count, self.daily_limit)
            return None

        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json",
            }
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": str(max_age_days),
            }

            response = requests.get(
                ABUSEIPDB_API_URL,
                headers=headers,
                params=params,
                timeout=5,
            )

            self._total_calls += 1

            if response.status_code == 429:
                logger.warning("AbuseIPDB rate limited (HTTP 429)")
                return None

            if response.status_code != 200:
                logger.error(
                    "AbuseIPDB API error: HTTP %d for %s",
                    response.status_code,
                    ip_address,
                )
                self._total_errors += 1
                return None

            data = response.json().get("data", {})

            return {
                "ip_address": data.get("ipAddress", ip_address),
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "last_reported_at": data.get("lastReportedAt"),
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "is_tor": data.get("isTor", False),
                "source": "abuseipdb",
            }

        except requests.exceptions.Timeout:
            logger.warning("AbuseIPDB timeout for %s", ip_address)
            self._total_errors += 1
            return None

        except requests.exceptions.RequestException as exc:
            logger.error("AbuseIPDB request error: %s", exc)
            self._total_errors += 1
            return None

        except Exception as exc:
            logger.error("AbuseIPDB unexpected error: %s", exc)
            self._total_errors += 1
            return None

    def _check_rate_limit(self) -> bool:
        """Check and enforce daily rate limit.

        Returns:
            True if a call is allowed.
        """
        with self._lock:
            now = time.time()

            # Reset window if 24h elapsed
            if (now - self._window_start) > RATE_LIMIT_WINDOW:
                self._call_count = 0
                self._window_start = now

            if self._call_count >= self.daily_limit:
                return False

            self._call_count += 1
            return True

    @property
    def remaining_calls(self) -> int:
        """Number of API calls remaining today."""
        return max(0, self.daily_limit - self._call_count)

    @property
    def stats(self) -> dict:
        """Return client statistics."""
        return {
            "api_configured": bool(self.api_key),
            "total_calls": self._total_calls,
            "total_errors": self._total_errors,
            "calls_today": self._call_count,
            "remaining_today": self.remaining_calls,
            "daily_limit": self.daily_limit,
        }
