"""
External threat intelligence feed importer.

Imports IP blocklists from Emerging Threats, Spamhaus DROP,
and Feodo Tracker into the local blacklist table.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# Public blocklist feed URLs
FEED_SOURCES = {
    "emerging_threats": {
        "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "description": "Emerging Threats Compromised IPs",
        "parser": "line_per_ip",
    },
    "spamhaus_drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "description": "Spamhaus Don't Route or Peer List",
        "parser": "spamhaus",
    },
    "feodo_tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "description": "Feodo Tracker Botnet C2 IPs",
        "parser": "comment_filtered",
    },
}


class FeedImporter:
    """Imports external IP blocklists into the local database.

    Supports multiple feed formats and daily refresh scheduling.
    """

    def __init__(self, app=None) -> None:
        """Initialize feed importer.

        Args:
            app: Flask application instance.
        """
        self.app = app
        self._total_imported: int = 0
        self._last_import_time: Optional[float] = None
        self._import_errors: int = 0

    def import_all_feeds(self) -> dict:
        """Import all configured blocklist feeds.

        Returns:
            Summary of import results per feed.
        """
        results = {}

        for feed_name, feed_config in FEED_SOURCES.items():
            try:
                count = self._import_feed(feed_name, feed_config)
                results[feed_name] = {
                    "success": True,
                    "imported": count,
                    "url": feed_config["url"],
                }
            except Exception as exc:
                logger.error("Failed to import %s: %s", feed_name, exc)
                self._import_errors += 1
                results[feed_name] = {
                    "success": False,
                    "error": str(exc),
                }

        self._last_import_time = time.time()
        logger.info(
            "Feed import complete: %s",
            {k: v.get("imported", "error") for k, v in results.items()},
        )
        return results

    def _import_feed(self, feed_name: str, feed_config: dict) -> int:
        """Import a single blocklist feed.

        Args:
            feed_name: Feed identifier.
            feed_config: Feed configuration with URL and parser.

        Returns:
            Number of IPs imported.
        """
        url = feed_config["url"]
        parser = feed_config["parser"]

        logger.info("Importing feed: %s from %s", feed_name, url)

        response = requests.get(url, timeout=30)
        response.raise_for_status()

        # Parse IPs from response
        ips = self._parse_feed(response.text, parser)

        if not ips:
            logger.warning("No IPs parsed from %s", feed_name)
            return 0

        # Store in database
        count = self._store_ips(ips, feed_name, feed_config["description"])
        self._total_imported += count
        return count

    def _parse_feed(self, content: str, parser_type: str) -> list[str]:
        """Parse IP addresses from feed content.

        Args:
            content: Raw feed text.
            parser_type: Parser strategy name.

        Returns:
            List of IP address strings.
        """
        ips = []

        for line in content.strip().split("\n"):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            if parser_type == "spamhaus":
                # Format: "netblock ; SBL_ID"
                parts = line.split(";")
                if parts:
                    ip_or_cidr = parts[0].strip()
                    # Extract base IP from CIDR
                    ip = ip_or_cidr.split("/")[0]
                    if self._is_valid_ip(ip):
                        ips.append(ip)

            elif parser_type == "comment_filtered":
                # Lines with IPs, comments start with #
                ip = line.split("#")[0].strip()
                if self._is_valid_ip(ip):
                    ips.append(ip)

            else:  # line_per_ip
                ip = line.split("#")[0].strip()
                if self._is_valid_ip(ip):
                    ips.append(ip)

        return ips

    def _store_ips(
        self,
        ips: list[str],
        source: str,
        description: str,
    ) -> int:
        """Store imported IPs in the blacklist table.

        Args:
            ips: List of IP addresses.
            source: Feed source name.
            description: Feed description.

        Returns:
            Number of IPs stored.
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

                # Remove old entries from this source
                db.session.query(Blacklist).filter(
                    Blacklist.source == f"feed:{source}"
                ).delete()

                # Batch insert new entries
                now = datetime.now(timezone.utc)
                records = [
                    {
                        "ip_address": ip,
                        "reason": description,
                        "source": f"feed:{source}",
                        "is_permanent": True,
                        "added_at": now,
                    }
                    for ip in ips[:50000]  # Cap to prevent memory issues
                ]

                db.session.bulk_insert_mappings(Blacklist, records)
                db.session.commit()

                logger.info(
                    "Stored %d IPs from %s", len(records), source
                )
                return len(records)

        except Exception as exc:
            logger.error("Failed to store IPs from %s: %s", source, exc)
            return 0

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Basic IP address validation.

        Args:
            ip: String to validate.

        Returns:
            True if it looks like an IPv4 address.
        """
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    @property
    def stats(self) -> dict:
        """Return importer statistics."""
        return {
            "total_imported": self._total_imported,
            "import_errors": self._import_errors,
            "last_import": self._last_import_time,
            "configured_feeds": list(FEED_SOURCES.keys()),
        }
