"""
Packet capture engine using Scapy.

Captures packets from a live network interface (or simulates
traffic for development) and feeds them into the processing
pipeline via a thread-safe queue.
"""

import logging
import queue
import random
import string
import threading
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Default BPF filter to exclude broadcast/multicast noise
DEFAULT_BPF_FILTER = "ip"


class PacketCapture:
    """Real-time network packet capture engine.

    Runs Scapy's sniff() in a dedicated daemon thread and pushes
    raw packets into a bounded queue for processing workers.

    Supports a simulation mode for development/testing environments
    where no live network interface is available.
    """

    def __init__(
        self,
        interface: str = "eth0",
        bpf_filter: str = DEFAULT_BPF_FILTER,
        queue_size: int = 10000,
        simulation_mode: bool = False,
        simulation_pps: int = 100,
    ) -> None:
        """Initialize the capture engine.

        Args:
            interface: Network interface name to capture from.
            bpf_filter: Berkeley Packet Filter expression.
            queue_size: Maximum packets in the processing queue.
            simulation_mode: If True, generate synthetic packets
                instead of capturing from a live interface.
            simulation_pps: Packets per second in simulation mode.
        """
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.simulation_mode = simulation_mode
        self.simulation_pps = simulation_pps

        # Thread-safe packet queue (ring buffer)
        self.packet_queue: queue.Queue = queue.Queue(maxsize=queue_size)

        # Capture state
        self._running = False
        self._paused = False
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Statistics
        self._stats_lock = threading.Lock()
        self._packets_captured: int = 0
        self._packets_dropped: int = 0
        self._bytes_captured: int = 0
        self._start_time: Optional[float] = None
        self._last_packet_time: Optional[float] = None

    def start(self) -> None:
        """Start packet capture on the configured interface.

        Launches a daemon thread for capture. Non-blocking — returns
        immediately after thread start.
        """
        if self._running:
            logger.warning("Capture already running on %s", self.interface)
            return

        self._running = True
        self._paused = False
        self._stop_event.clear()
        self._start_time = time.time()

        if self.simulation_mode:
            self._capture_thread = threading.Thread(
                target=self._simulation_loop,
                daemon=True,
                name="capture-simulation",
            )
            logger.info(
                "Starting SIMULATION capture (%d pps)", self.simulation_pps
            )
        else:
            self._capture_thread = threading.Thread(
                target=self._capture_loop,
                daemon=True,
                name="capture-live",
            )
            logger.info(
                "Starting LIVE capture on %s (filter: %s)",
                self.interface,
                self.bpf_filter,
            )

        self._capture_thread.start()

    def stop(self) -> None:
        """Gracefully stop packet capture.

        Signals the capture thread to stop and waits for it
        to drain remaining packets.
        """
        if not self._running:
            return

        logger.info("Stopping capture engine...")
        self._running = False
        self._stop_event.set()

        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=10)

        logger.info(
            "Capture stopped. Total: %d captured, %d dropped",
            self._packets_captured,
            self._packets_dropped,
        )

    def pause(self) -> None:
        """Pause packet capture (packets are still captured but discarded)."""
        self._paused = True
        logger.info("Capture paused")

    def resume(self) -> None:
        """Resume packet capture after pause."""
        self._paused = False
        logger.info("Capture resumed")

    def _capture_loop(self) -> None:
        """Main capture loop using Scapy sniff().

        Runs in a dedicated thread. Each captured packet is
        pushed into the processing queue.
        """
        try:
            from scapy.all import sniff

            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError:
            logger.error(
                "Insufficient permissions to capture on %s. "
                "Run with CAP_NET_RAW or as root.",
                self.interface,
            )
            self._running = False
        except OSError as exc:
            logger.error(
                "Cannot open interface %s: %s. "
                "Falling back to simulation mode.",
                self.interface,
                exc,
            )
            self._running = False
        except Exception as exc:
            logger.error("Capture thread error: %s", exc, exc_info=True)
            self._running = False

    def _packet_callback(self, packet) -> None:
        """Callback invoked by Scapy for each captured packet.

        Pushes packet into queue. If queue is full, packet is dropped
        and the drop counter is incremented.

        Args:
            packet: Raw Scapy packet object.
        """
        if self._paused:
            return

        try:
            self.packet_queue.put_nowait(packet)
            with self._stats_lock:
                self._packets_captured += 1
                self._bytes_captured += len(packet)
                self._last_packet_time = time.time()
        except queue.Full:
            with self._stats_lock:
                self._packets_dropped += 1
            if self._packets_dropped % 1000 == 1:
                logger.warning(
                    "Packet queue full — dropped %d packets total",
                    self._packets_dropped,
                )

    def _simulation_loop(self) -> None:
        """Generate synthetic packets for development/testing.

        Creates realistic-looking Scapy packets without requiring
        a live network interface or elevated privileges.
        """
        try:
            from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, Raw

            interval = 1.0 / self.simulation_pps
            sim_protocols = ["TCP", "UDP", "DNS", "HTTP"]
            sim_src_ips = [f"192.168.1.{i}" for i in range(1, 51)]
            sim_dst_ips = [f"10.0.0.{i}" for i in range(1, 11)]
            common_ports = [22, 53, 80, 443, 3389, 8080]

            logger.info("Simulation loop started at %d pps", self.simulation_pps)

            while self._running and not self._stop_event.is_set():
                if self._paused:
                    time.sleep(0.1)
                    continue

                proto = random.choice(sim_protocols)
                src_ip = random.choice(sim_src_ips)
                dst_ip = random.choice(sim_dst_ips)
                dst_port = random.choice(common_ports)
                src_port = random.randint(1024, 65535)

                try:
                    if proto == "TCP" or proto == "HTTP":
                        flags = random.choice(["S", "SA", "A", "PA", "FA", "R"])
                        pkt = (
                            IP(src=src_ip, dst=dst_ip)
                            / TCP(sport=src_port, dport=dst_port, flags=flags)
                        )
                        if proto == "HTTP" and flags == "PA":
                            pkt = pkt / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    elif proto == "UDP":
                        pkt = (
                            IP(src=src_ip, dst=dst_ip)
                            / UDP(sport=src_port, dport=dst_port)
                            / Raw(load=b"\x00" * random.randint(10, 200))
                        )
                    elif proto == "DNS":
                        domain = (
                            "".join(random.choices(string.ascii_lowercase, k=8))
                            + ".com"
                        )
                        pkt = (
                            IP(src=src_ip, dst=dst_ip)
                            / UDP(sport=src_port, dport=53)
                            / DNS(rd=1, qd=DNSQR(qname=domain))
                        )
                    else:
                        pkt = IP(src=src_ip, dst=dst_ip) / TCP(
                            sport=src_port, dport=dst_port, flags="S"
                        )

                    self._packet_callback(pkt)
                except Exception as exc:
                    logger.debug("Simulation packet error: %s", exc)

                time.sleep(interval)

        except ImportError:
            logger.error("Scapy not installed — simulation mode unavailable")
            self._running = False
        except Exception as exc:
            logger.error("Simulation loop error: %s", exc, exc_info=True)
            self._running = False

    @property
    def is_running(self) -> bool:
        """Check if capture engine is currently running."""
        return self._running

    @property
    def is_paused(self) -> bool:
        """Check if capture is paused."""
        return self._paused

    @property
    def uptime_seconds(self) -> float:
        """Time since capture started in seconds."""
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time

    @property
    def current_pps(self) -> float:
        """Current packets per second (averaged over uptime)."""
        uptime = self.uptime_seconds
        if uptime <= 0:
            return 0.0
        return self._packets_captured / uptime

    @property
    def stats(self) -> dict:
        """Return capture statistics snapshot."""
        with self._stats_lock:
            return {
                "is_running": self._running,
                "is_paused": self._paused,
                "interface": self.interface,
                "simulation_mode": self.simulation_mode,
                "packets_captured": self._packets_captured,
                "packets_dropped": self._packets_dropped,
                "bytes_captured": self._bytes_captured,
                "queue_size": self.packet_queue.qsize(),
                "queue_capacity": self.packet_queue.maxsize,
                "drop_rate": (
                    self._packets_dropped
                    / max(self._packets_captured + self._packets_dropped, 1)
                ),
                "uptime_seconds": round(self.uptime_seconds, 2),
                "current_pps": round(self.current_pps, 2),
                "last_packet_at": (
                    datetime.fromtimestamp(
                        self._last_packet_time, tz=timezone.utc
                    ).isoformat()
                    if self._last_packet_time
                    else None
                ),
            }
