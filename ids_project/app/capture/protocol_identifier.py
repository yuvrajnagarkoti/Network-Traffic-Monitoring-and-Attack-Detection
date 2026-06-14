"""
Protocol identification for captured network packets.

Identifies protocols at Layer 3 (Network), Layer 4 (Transport),
and Layer 7 (Application) from Scapy packet objects.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Standard port-to-protocol mappings for Layer 7 identification
PORT_PROTOCOL_MAP: dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP",
    8443: "HTTPS",
    27017: "MONGODB",
}

# Protocols known to be used in attacks — prioritized in detection
ATTACK_RELEVANT_PORTS: set[int] = {
    21, 22, 23, 25, 53, 80, 443, 445, 587, 3389, 5900, 8080,
}


def identify_layer3(packet) -> str:
    """Identify the Layer 3 (Network) protocol.

    Args:
        packet: Scapy packet object.

    Returns:
        Protocol name string: 'IPv4', 'IPv6', 'ARP', or 'Unknown_L3'.
    """
    try:
        if packet.haslayer("IP"):
            return "IPv4"
        elif packet.haslayer("IPv6"):
            return "IPv6"
        elif packet.haslayer("ARP"):
            return "ARP"
        else:
            return "Unknown_L3"
    except Exception:
        return "Unknown_L3"


def identify_layer4(packet) -> str:
    """Identify the Layer 4 (Transport) protocol.

    Args:
        packet: Scapy packet object.

    Returns:
        Protocol name string: 'TCP', 'UDP', 'ICMP', 'ICMPv6', or 'Unknown_L4'.
    """
    try:
        if packet.haslayer("TCP"):
            return "TCP"
        elif packet.haslayer("UDP"):
            return "UDP"
        elif packet.haslayer("ICMP"):
            return "ICMP"
        elif packet.haslayer("ICMPv6"):
            return "ICMPv6"
        else:
            return "Unknown_L4"
    except Exception:
        return "Unknown_L4"


def identify_layer7(packet) -> str:
    """Identify the Layer 7 (Application) protocol.

    Uses a combination of port-based detection and payload inspection
    for more accurate identification on non-standard ports.

    Args:
        packet: Scapy packet object with IP and TCP/UDP layers.

    Returns:
        Application protocol name or 'Unknown'.
    """
    try:
        src_port = _get_src_port(packet)
        dst_port = _get_dst_port(packet)

        # Check Scapy's built-in application layer detection
        if packet.haslayer("DNS"):
            return "DNS"
        if packet.haslayer("HTTP"):
            return "HTTP"
        if packet.haslayer("HTTPRequest") or packet.haslayer("HTTPResponse"):
            return "HTTP"

        # Port-based identification (destination port takes priority)
        if dst_port and dst_port in PORT_PROTOCOL_MAP:
            return PORT_PROTOCOL_MAP[dst_port]
        if src_port and src_port in PORT_PROTOCOL_MAP:
            return PORT_PROTOCOL_MAP[src_port]

        # Payload-based fingerprinting for common protocols
        protocol = _fingerprint_payload(packet)
        if protocol:
            return protocol

        return "Unknown"
    except Exception:
        return "Unknown"


def _fingerprint_payload(packet) -> Optional[str]:
    """Inspect packet payload to identify protocol on non-standard ports.

    Examines the first bytes of the payload for known protocol signatures.

    Args:
        packet: Scapy packet object.

    Returns:
        Protocol name if identified, None otherwise.
    """
    try:
        if packet.haslayer("Raw"):
            payload = bytes(packet["Raw"].load[:20])
        elif packet.haslayer("TCP") and hasattr(packet["TCP"], "payload"):
            payload = bytes(packet["TCP"].payload)[:20]
        else:
            return None

        if not payload:
            return None

        # HTTP signatures
        http_methods = [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                        b"OPTIONS ", b"PATCH ", b"HTTP/"]
        for method in http_methods:
            if payload.startswith(method):
                return "HTTP"

        # SSH signature
        if payload.startswith(b"SSH-"):
            return "SSH"

        # FTP signatures
        ftp_responses = [b"220 ", b"221 ", b"230 ", b"331 ", b"530 "]
        for resp in ftp_responses:
            if payload.startswith(resp):
                return "FTP"

        # SMTP signatures
        if payload.startswith(b"EHLO ") or payload.startswith(b"HELO "):
            return "SMTP"
        if payload.startswith(b"250 "):
            return "SMTP"

        # TLS/SSL Client Hello
        if len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 0x03:
            return "TLS"

        # DNS over non-standard port (check for DNS header structure)
        if (len(payload) >= 12 and packet.haslayer("UDP")
                and payload[2] & 0x78 == 0):
            return "DNS"

        return None
    except Exception:
        return None


def _get_src_port(packet) -> Optional[int]:
    """Extract source port from packet."""
    try:
        if packet.haslayer("TCP"):
            return packet["TCP"].sport
        elif packet.haslayer("UDP"):
            return packet["UDP"].sport
    except Exception:
        pass
    return None


def _get_dst_port(packet) -> Optional[int]:
    """Extract destination port from packet."""
    try:
        if packet.haslayer("TCP"):
            return packet["TCP"].dport
        elif packet.haslayer("UDP"):
            return packet["UDP"].dport
    except Exception:
        pass
    return None


def identify_protocol(packet) -> dict:
    """Perform complete protocol identification across all layers.

    Args:
        packet: Scapy packet object.

    Returns:
        Dictionary with layer3, layer4, layer7 protocol names,
        plus ports and a combined protocol string.
    """
    l3 = identify_layer3(packet)
    l4 = identify_layer4(packet)
    l7 = identify_layer7(packet)

    src_port = _get_src_port(packet)
    dst_port = _get_dst_port(packet)

    # Build combined protocol string for display
    if l7 != "Unknown":
        combined = l7
    elif l4 != "Unknown_L4":
        combined = l4
    else:
        combined = l3

    return {
        "layer3": l3,
        "layer4": l4,
        "layer7": l7,
        "combined": combined,
        "src_port": src_port,
        "dst_port": dst_port,
    }


def is_attack_relevant_port(port: Optional[int]) -> bool:
    """Check if a port is commonly targeted in attacks.

    Args:
        port: Port number to check.

    Returns:
        True if the port is attack-relevant.
    """
    if port is None:
        return False
    return port in ATTACK_RELEVANT_PORTS
