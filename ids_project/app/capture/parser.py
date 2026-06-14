"""
Packet parser and feature extractor.

Transforms raw Scapy packet objects into structured dictionaries
ready for database storage, detection modules, and ML pipeline.
"""

import hashlib
import logging
import time
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

logger = logging.getLogger(__name__)

# TCP flag bitmask constants
TCP_FLAGS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
    "ECE": 0x40,
    "CWR": 0x80,
}

# Maximum payload bytes to hash for deduplication
MAX_PAYLOAD_HASH_BYTES = 64


class PacketParser:
    """Parses raw Scapy packets into structured data.

    Handles protocol identification, TCP flag parsing, feature
    extraction, and packet deduplication via rolling hash window.
    """

    def __init__(self, dedup_window_size: int = 1000) -> None:
        """Initialize parser with dedup cache.

        Args:
            dedup_window_size: Number of recent packet hashes to
                keep for duplicate detection.
        """
        self._dedup_cache: deque = deque(maxlen=dedup_window_size)
        self._dedup_lock = Lock()
        self._total_parsed: int = 0
        self._total_deduped: int = 0

    def parse(self, packet) -> Optional[dict]:
        """Parse a raw Scapy packet into a structured dictionary.

        Returns None if the packet is a duplicate or unparseable.

        Args:
            packet: Raw Scapy packet object.

        Returns:
            Parsed packet dictionary or None if duplicate/invalid.
        """
        try:
            from app.capture.protocol_identifier import identify_protocol

            # Basic validation
            if not packet.haslayer("IP") and not packet.haslayer("IPv6"):
                return None

            # Extract core fields
            parsed = self._extract_core_fields(packet)
            if parsed is None:
                return None

            # Protocol identification
            proto_info = identify_protocol(packet)
            parsed["protocol"] = proto_info["combined"]
            parsed["layer3"] = proto_info["layer3"]
            parsed["layer4"] = proto_info["layer4"]
            parsed["layer7"] = proto_info["layer7"]

            # TCP flag parsing
            if packet.haslayer("TCP"):
                parsed["flags"] = self._parse_tcp_flags(packet["TCP"])
                parsed["flags_raw"] = int(packet["TCP"].flags)
                parsed["window_size"] = packet["TCP"].window
                parsed["seq_num"] = packet["TCP"].seq
                parsed["ack_num"] = packet["TCP"].ack
            else:
                parsed["flags"] = None
                parsed["flags_raw"] = 0
                parsed["window_size"] = None
                parsed["seq_num"] = None
                parsed["ack_num"] = None

            # Payload hash for dedup
            payload_hash = self._compute_payload_hash(packet, parsed)
            parsed["payload_hash"] = payload_hash

            # Dedup check
            if self._is_duplicate(payload_hash):
                self._total_deduped += 1
                return None

            # Flow ID for flow tracker
            parsed["flow_id"] = self._compute_flow_id(parsed)

            # Timestamp
            parsed["captured_at"] = datetime.now(timezone.utc)
            parsed["timestamp_unix"] = time.time()

            self._total_parsed += 1
            return parsed

        except Exception as exc:
            logger.warning("Failed to parse packet: %s", exc)
            return None

    def _extract_core_fields(self, packet) -> Optional[dict]:
        """Extract IP addresses, ports, and size from packet.

        Args:
            packet: Scapy packet with IP/IPv6 layer.

        Returns:
            Dictionary with core network fields.
        """
        try:
            result = {}

            if packet.haslayer("IP"):
                ip_layer = packet["IP"]
                result["src_ip"] = ip_layer.src
                result["dst_ip"] = ip_layer.dst
                result["ttl"] = ip_layer.ttl
                result["ip_version"] = 4
            elif packet.haslayer("IPv6"):
                ipv6_layer = packet["IPv6"]
                result["src_ip"] = ipv6_layer.src
                result["dst_ip"] = ipv6_layer.dst
                result["ttl"] = ipv6_layer.hlim
                result["ip_version"] = 6
            else:
                return None

            # Ports
            if packet.haslayer("TCP"):
                result["src_port"] = packet["TCP"].sport
                result["dst_port"] = packet["TCP"].dport
            elif packet.haslayer("UDP"):
                result["src_port"] = packet["UDP"].sport
                result["dst_port"] = packet["UDP"].dport
            else:
                result["src_port"] = None
                result["dst_port"] = None

            # Size
            result["packet_size"] = len(packet)

            return result

        except Exception as exc:
            logger.debug("Failed to extract core fields: %s", exc)
            return None

    def _parse_tcp_flags(self, tcp_layer) -> str:
        """Parse TCP flags into human-readable string.

        Args:
            tcp_layer: Scapy TCP layer object.

        Returns:
            String of active flag names, e.g. 'SYN|ACK'.
        """
        try:
            flags_int = int(tcp_layer.flags)
            active_flags = []
            for flag_name, flag_mask in TCP_FLAGS.items():
                if flags_int & flag_mask:
                    active_flags.append(flag_name)
            return "|".join(active_flags) if active_flags else "NONE"
        except Exception:
            return "NONE"

    def _compute_payload_hash(self, packet, parsed: dict) -> str:
        """Compute SHA-256 hash for deduplication.

        Hash is computed from: src_ip + dst_ip + src_port + dst_port +
        first 64 bytes of payload.

        Args:
            packet: Raw Scapy packet.
            parsed: Already-parsed packet fields.

        Returns:
            Hex-encoded SHA-256 hash string.
        """
        try:
            hasher = hashlib.sha256()
            hasher.update(parsed["src_ip"].encode())
            hasher.update(parsed["dst_ip"].encode())
            hasher.update(str(parsed.get("src_port", "")).encode())
            hasher.update(str(parsed.get("dst_port", "")).encode())

            # Add first N bytes of payload
            if packet.haslayer("Raw"):
                payload_bytes = bytes(packet["Raw"].load[:MAX_PAYLOAD_HASH_BYTES])
                hasher.update(payload_bytes)

            return hasher.hexdigest()
        except Exception:
            return hashlib.sha256(bytes(packet)[:128]).hexdigest()

    def _is_duplicate(self, payload_hash: str) -> bool:
        """Check if packet hash exists in dedup sliding window.

        Thread-safe: uses lock for concurrent access from worker pool.

        Args:
            payload_hash: SHA-256 hash of the packet.

        Returns:
            True if the hash was already seen recently.
        """
        with self._dedup_lock:
            if payload_hash in self._dedup_cache:
                return True
            self._dedup_cache.append(payload_hash)
            return False

    def _compute_flow_id(self, parsed: dict) -> str:
        """Compute a bidirectional flow identifier.

        Normalizes the 5-tuple so that packets in either direction
        of the same connection produce the same flow ID.

        Args:
            parsed: Parsed packet dictionary.

        Returns:
            Flow ID string.
        """
        src = parsed["src_ip"]
        dst = parsed["dst_ip"]
        sport = parsed.get("src_port") or 0
        dport = parsed.get("dst_port") or 0
        proto = parsed.get("protocol", "Unknown")

        # Normalize direction: lower IP:port always first
        if (src, sport) <= (dst, dport):
            return f"{src}:{sport}-{dst}:{dport}-{proto}"
        else:
            return f"{dst}:{dport}-{src}:{sport}-{proto}"

    @property
    def stats(self) -> dict:
        """Return parser statistics."""
        return {
            "total_parsed": self._total_parsed,
            "total_deduped": self._total_deduped,
            "dedup_rate": (
                self._total_deduped / max(self._total_parsed + self._total_deduped, 1)
            ),
            "dedup_cache_size": len(self._dedup_cache),
        }

    def classify_tcp_connection_state(self, flags: str) -> str:
        """Classify TCP connection state from flag combination.

        Args:
            flags: Pipe-separated flag string (e.g. 'SYN|ACK').

        Returns:
            Connection state classification string.
        """
        if flags is None:
            return "unknown"

        flag_set = set(flags.split("|"))

        if flag_set == {"SYN"}:
            return "connection_attempt"
        elif flag_set == {"SYN", "ACK"}:
            return "connection_response"
        elif "RST" in flag_set:
            return "connection_reset"
        elif flag_set == {"FIN", "ACK"}:
            return "connection_closing"
        elif flag_set == {"FIN"}:
            return "connection_close"
        elif "ACK" in flag_set and "PSH" in flag_set:
            return "data_transfer"
        elif flag_set == {"ACK"}:
            return "acknowledgment"
        else:
            return "other"
