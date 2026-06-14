"""
Blacklist & whitelist list manager.

Provides CRUD operations and CSV bulk import/export for the
IP blacklist and whitelist tables.
"""

import csv
import io
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class ListManager:
    """Manages blacklist and whitelist DB records with CSV support."""

    def __init__(self, app=None) -> None:
        self.app = app

    # ------------------------------------------------------------------
    # Blacklist
    # ------------------------------------------------------------------

    def add_to_blacklist(
        self,
        ip: str,
        reason: Optional[str] = None,
        source: Optional[str] = "manual",
        user_id: Optional[str] = None,
    ) -> dict:
        """Add an IP to the blacklist. Returns result dict."""
        try:
            _app = self._get_app()
            with _app.app_context():
                from app.extensions import db
                from app.models.block import Blacklist

                existing = Blacklist.query.get(ip)
                if existing:
                    return {"success": False, "message": f"{ip} already blacklisted"}

                entry = Blacklist(
                    ip_address=ip,
                    reason=reason,
                    source=source,
                    added_by=user_id,
                )
                db.session.add(entry)
                db.session.commit()
                logger.info("Added %s to blacklist (source=%s)", ip, source)
                return {"success": True, "ip": ip}
        except Exception as exc:
            logger.error("Failed to blacklist %s: %s", ip, exc)
            return {"success": False, "message": str(exc)}

    def remove_from_blacklist(self, ip: str) -> dict:
        """Remove an IP from the blacklist."""
        try:
            _app = self._get_app()
            with _app.app_context():
                from app.extensions import db
                from app.models.block import Blacklist

                entry = Blacklist.query.get(ip)
                if not entry:
                    return {"success": False, "message": f"{ip} not found in blacklist"}

                db.session.delete(entry)
                db.session.commit()
                logger.info("Removed %s from blacklist", ip)
                return {"success": True, "ip": ip}
        except Exception as exc:
            logger.error("Failed to remove %s from blacklist: %s", ip, exc)
            return {"success": False, "message": str(exc)}

    def list_blacklist(self, limit: int = 200, offset: int = 0) -> list[dict]:
        """Return paginated blacklist entries."""
        _app = self._get_app()
        with _app.app_context():
            from app.models.block import Blacklist
            entries = Blacklist.query.order_by(Blacklist.added_at.desc()).offset(offset).limit(limit).all()
            return [e.to_dict() for e in entries]

    # ------------------------------------------------------------------
    # Whitelist
    # ------------------------------------------------------------------

    def add_to_whitelist(
        self,
        ip: str,
        description: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> dict:
        """Add an IP to the whitelist. Returns result dict."""
        try:
            _app = self._get_app()
            with _app.app_context():
                from app.extensions import db
                from app.models.block import Whitelist

                existing = Whitelist.query.get(ip)
                if existing:
                    return {"success": False, "message": f"{ip} already whitelisted"}

                entry = Whitelist(
                    ip_address=ip,
                    description=description,
                    added_by=user_id,
                )
                db.session.add(entry)
                db.session.commit()
                logger.info("Added %s to whitelist", ip)
                return {"success": True, "ip": ip}
        except Exception as exc:
            logger.error("Failed to whitelist %s: %s", ip, exc)
            return {"success": False, "message": str(exc)}

    def remove_from_whitelist(self, ip: str) -> dict:
        """Remove an IP from the whitelist."""
        try:
            _app = self._get_app()
            with _app.app_context():
                from app.extensions import db
                from app.models.block import Whitelist

                entry = Whitelist.query.get(ip)
                if not entry:
                    return {"success": False, "message": f"{ip} not found in whitelist"}

                db.session.delete(entry)
                db.session.commit()
                logger.info("Removed %s from whitelist", ip)
                return {"success": True, "ip": ip}
        except Exception as exc:
            logger.error("Failed to remove %s from whitelist: %s", ip, exc)
            return {"success": False, "message": str(exc)}

    def list_whitelist(self, limit: int = 200, offset: int = 0) -> list[dict]:
        """Return paginated whitelist entries."""
        _app = self._get_app()
        with _app.app_context():
            from app.models.block import Whitelist
            entries = Whitelist.query.order_by(Whitelist.added_at.desc()).offset(offset).limit(limit).all()
            return [e.to_dict() for e in entries]

    # ------------------------------------------------------------------
    # CSV import / export
    # ------------------------------------------------------------------

    def import_csv(self, csv_text: str, list_type: str, user_id: Optional[str] = None) -> dict:
        """Bulk import IPs from CSV text.

        CSV format: ip_address[,reason][,source]

        Args:
            csv_text:  Raw CSV string (header row ignored if present).
            list_type: "blacklist" or "whitelist".
            user_id:   Requesting user UUID.

        Returns:
            {added: int, skipped: int, errors: list}
        """
        reader = csv.reader(io.StringIO(csv_text.strip()))
        added, skipped, errors = 0, 0, []

        for row in reader:
            if not row:
                continue
            ip = row[0].strip()
            if ip.lower() in ("ip_address", "ip"):
                continue  # header row

            reason = row[1].strip() if len(row) > 1 else None
            source = row[2].strip() if len(row) > 2 else "csv_import"

            if list_type == "blacklist":
                result = self.add_to_blacklist(ip, reason=reason, source=source, user_id=user_id)
            else:
                result = self.add_to_whitelist(ip, description=reason, user_id=user_id)

            if result.get("success"):
                added += 1
            elif "already" in result.get("message", ""):
                skipped += 1
            else:
                errors.append({"ip": ip, "error": result.get("message", "unknown error")})

        return {"added": added, "skipped": skipped, "errors": errors}

    def export_csv(self, list_type: str) -> str:
        """Export blacklist or whitelist as CSV string."""
        if list_type == "blacklist":
            entries = self.list_blacklist(limit=100000)
            rows = [["ip_address", "reason", "source", "added_at"]]
            rows += [[e["ip_address"], e.get("reason", ""), e.get("source", ""), e.get("added_at", "")] for e in entries]
        else:
            entries = self.list_whitelist(limit=100000)
            rows = [["ip_address", "description", "added_at"]]
            rows += [[e["ip_address"], e.get("description", ""), e.get("added_at", "")] for e in entries]

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerows(rows)
        return buf.getvalue()

    def _get_app(self):
        if self.app is not None:
            return self.app
        from flask import current_app
        return current_app._get_current_object()
