"""
IP blocker — iptables interface.

Manages host-level firewall rules to block/unblock IP addresses.
All subprocess calls use list arguments (never shell=True) to prevent
command injection.

Safety guards:
  - Never blocks loopback (127.0.0.1 / ::1)
  - Never blocks private RFC-1918 ranges
  - Never blocks whitelisted IPs
  - Checks the database before issuing the OS command

On Windows (development) the iptables calls are simulated and logged
so the rest of the code path can be tested without root access.
"""

import ipaddress
import logging
import platform
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# IPs / networks that must NEVER be blocked
_PROTECTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

_IS_LINUX = platform.system() == "Linux"


def _is_protected(ip: str) -> bool:
    """Return True if the IP falls in a protected range."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # malformed → protect by default
    return any(addr in net for net in _PROTECTED_NETWORKS)


class IPBlocker:
    """Manages iptables rules for automatic IP blocking/unblocking."""

    def __init__(self, app=None) -> None:
        self.app = app

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def block(
        self,
        ip: str,
        reason: str = "",
        duration_hours: Optional[int] = 24,
        user_id: Optional[str] = None,
        attack_event_id: Optional[str] = None,
        block_type: str = "manual",
    ) -> dict:
        """Block an IP address.

        Args:
            ip:               IP address to block.
            reason:           Human-readable reason for the block.
            duration_hours:   Hours until auto-expiry.  None = permanent.
            user_id:          UUID of the requesting user (manual blocks).
            attack_event_id:  UUID of the triggering attack event.
            block_type:       "auto" or "manual".

        Returns:
            Result dict with ``success``, ``message``, and ``block_id``.
        """
        if _is_protected(ip):
            logger.warning("Rejected block for protected IP %s", ip)
            return {"success": False, "message": f"IP {ip} is in a protected range"}

        # Whitelist check via DB
        if self._is_whitelisted(ip):
            return {"success": False, "message": f"IP {ip} is whitelisted"}

        # Check for existing active block
        existing = self._get_active_block(ip)
        if existing:
            return {
                "success": False,
                "message": f"IP {ip} is already blocked",
                "block_id": str(existing.id),
            }

        # Issue iptables command
        rule_id = self._apply_iptables_rule(ip)

        # Record in database
        block_record = self._create_block_record(
            ip=ip,
            reason=reason,
            duration_hours=duration_hours,
            user_id=user_id,
            attack_event_id=attack_event_id,
            block_type=block_type,
            rule_id=rule_id,
        )

        logger.warning(
            "IP %s blocked (type=%s, expires=%s)", ip, block_type,
            f"{duration_hours}h" if duration_hours else "permanent"
        )

        return {
            "success": True,
            "message": f"IP {ip} blocked successfully",
            "block_id": str(block_record.id) if block_record else None,
        }

    def unblock(self, ip: str, user_id: Optional[str] = None) -> dict:
        """Remove an active block for an IP.

        Returns:
            Result dict with ``success`` and ``message``.
        """
        block = self._get_active_block(ip)
        if not block:
            return {"success": False, "message": f"No active block found for {ip}"}

        # Remove iptables rule
        self._remove_iptables_rule(ip)

        # Mark DB record as inactive
        self._deactivate_block(block)

        logger.info("IP %s unblocked (by user %s)", ip, user_id)
        return {"success": True, "message": f"IP {ip} unblocked"}

    def expire_blocks(self) -> int:
        """Deactivate all blocks whose expiry time has passed.

        Returns:
            Number of blocks expired.
        """
        count = 0
        _app = self._get_app()
        with _app.app_context():
            from app.extensions import db
            from app.models.block import IpBlock

            now = datetime.now(timezone.utc)
            expired = (
                IpBlock.query
                .filter(
                    IpBlock.is_active.is_(True),
                    IpBlock.expires_at <= now,
                )
                .all()
            )

            for block in expired:
                self._remove_iptables_rule(block.ip_address)
                block.is_active = False
                count += 1

            if count:
                db.session.commit()
                logger.info("Expired %d IP blocks", count)

        return count

    # ------------------------------------------------------------------
    # iptables helpers
    # ------------------------------------------------------------------

    def _apply_iptables_rule(self, ip: str) -> Optional[str]:
        """Insert DROP rule at top of INPUT chain.  Returns a rule ID tag."""
        rule_id = f"ids-{ip.replace('.', '-').replace(':', '-')}"
        if _IS_LINUX:
            cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP",
                   "-m", "comment", "--comment", rule_id]
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=10)
                logger.info("iptables DROP rule added for %s", ip)
            except subprocess.CalledProcessError as exc:
                logger.error("iptables block failed for %s: %s", ip, exc.stderr)
                return None
        else:
            # Non-Linux (dev/test): simulate
            logger.info("[SIMULATED] iptables DROP %s", ip)
        return rule_id

    def _remove_iptables_rule(self, ip: str) -> None:
        """Remove the DROP rule for an IP from the INPUT chain."""
        if _IS_LINUX:
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=10)
                logger.info("iptables DROP rule removed for %s", ip)
            except subprocess.CalledProcessError as exc:
                logger.error("iptables unblock failed for %s: %s", ip, exc.stderr)
        else:
            logger.info("[SIMULATED] iptables REMOVE DROP %s", ip)

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    def _is_whitelisted(self, ip: str) -> bool:
        try:
            _app = self._get_app()
            with _app.app_context():
                from app.models.block import Whitelist
                return Whitelist.query.get(ip) is not None
        except Exception:
            return False

    def _get_active_block(self, ip: str):
        try:
            _app = self._get_app()
            with _app.app_context():
                from app.models.block import IpBlock
                return IpBlock.query.filter_by(ip_address=ip, is_active=True).first()
        except Exception:
            return None

    def _create_block_record(
        self, ip, reason, duration_hours, user_id, attack_event_id, block_type, rule_id
    ):
        try:
            _app = self._get_app()
            with _app.app_context():
                from app.extensions import db
                from app.models.block import IpBlock, BlockType

                expires_at = (
                    datetime.now(timezone.utc) + timedelta(hours=duration_hours)
                    if duration_hours else None
                )

                block = IpBlock(
                    ip_address=ip,
                    block_type=BlockType.AUTO if block_type == "auto" else BlockType.MANUAL,
                    reason=reason,
                    blocked_by=user_id,
                    attack_event_id=attack_event_id,
                    expires_at=expires_at,
                    is_active=True,
                    firewall_rule_id=rule_id,
                )
                db.session.add(block)
                db.session.commit()
                return block
        except Exception as exc:
            logger.error("Failed to create block record: %s", exc)
            return None

    def _deactivate_block(self, block) -> None:
        try:
            _app = self._get_app()
            with _app.app_context():
                from app.extensions import db
                from app.models.block import IpBlock
                record = db.session.get(IpBlock, block.id)
                if record:
                    record.is_active = False
                    db.session.commit()
        except Exception as exc:
            logger.error("Failed to deactivate block: %s", exc)

    def _get_app(self):
        if self.app is not None:
            return self.app
        from flask import current_app
        return current_app._get_current_object()
