"""
Detection threshold configuration.

Loads thresholds from YAML with embedded defaults. Supports
hot-reload without application restart.
"""

import logging
import os
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

# ============================================
# Default detection thresholds
# ============================================
DEFAULT_THRESHOLDS: dict[str, Any] = {
    "port_scan": {
        "syn_scan": {
            "port_threshold": 15,
            "time_window_seconds": 10,
            "fast_scan_rate": 20.0,
            "slow_scan_rate": 5.0,
            "slow_scan_window_seconds": 300,
        },
        "stealth_scan": {
            "port_threshold": 3,
            "time_window_seconds": 60,
            "confidence": 0.95,
        },
        "udp_scan": {
            "port_threshold": 10,
            "time_window_seconds": 30,
        },
    },
    "brute_force": {
        "ssh": {
            "attempt_threshold": 5,
            "time_window_seconds": 60,
            "port": 22,
            "short_connection_seconds": 5,
        },
        "http": {
            "attempt_threshold": 10,
            "time_window_seconds": 30,
            "auth_endpoints": ["/login", "/admin", "/wp-login.php", "/api/auth"],
        },
        "generic": {
            "ftp": {"port": 21, "attempt_threshold": 5, "time_window_seconds": 60},
            "smtp": {"port": 25, "attempt_threshold": 5, "time_window_seconds": 60},
            "rdp": {"port": 3389, "attempt_threshold": 5, "time_window_seconds": 60},
        },
        "distributed": {
            "attempt_threshold": 50,
            "unique_ip_threshold": 5,
            "time_window_seconds": 300,
        },
    },
    "traffic_analysis": {
        "baseline": {
            "bootstrap_minutes": 60,
            "update_interval_minutes": 60,
        },
        "spike": {
            "z_score_threshold": 3.0,
            "min_baseline_samples": 10,
        },
        "protocol_anomaly": {
            "icmp_threshold_percent": 30,
            "dns_max_packet_size": 512,
            "max_connections_per_ip": 200,
            "half_open_threshold": 500,
        },
    },
    "ddos": {
        "syn_flood": {
            "syn_rate_threshold": 500,
            "completion_rate_threshold": 0.10,
            "time_window_seconds": 10,
        },
        "udp_flood": {
            "udp_rate_threshold": 1000,
            "time_window_seconds": 10,
            "amplification_ports": [53, 123, 1900],
        },
        "http_flood": {
            "request_rate_threshold": 500,
            "unique_ip_threshold": 50,
            "time_window_seconds": 10,
        },
        "severity": {
            "low_pps": 100,
            "medium_pps": 500,
            "high_pps": 2000,
            "critical_pps": 10000,
        },
    },
    "state_manager": {
        "resolve_timeout_seconds": 300,
        "max_tracked_attacks": 10000,
        "max_tracked_ips": 100000,
    },
}


class DetectionConfig:
    """Manages detection thresholds with hot-reload support.

    Loads from YAML file if available, falls back to embedded
    defaults. Thresholds can be updated at runtime via the API.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        """Initialize with optional YAML config file.

        Args:
            config_path: Path to detection_thresholds.yaml.
        """
        self._thresholds: dict = dict(DEFAULT_THRESHOLDS)
        self._config_path = config_path

        if config_path and os.path.exists(config_path):
            self.load_from_file(config_path)
            logger.info("Detection config loaded from %s", config_path)
        else:
            logger.info("Using default detection thresholds")

    def load_from_file(self, path: str) -> None:
        """Load thresholds from YAML file.

        Merges with defaults — file values override defaults,
        but missing keys keep their default values.

        Args:
            path: Path to YAML configuration file.
        """
        try:
            with open(path, "r") as f:
                file_config = yaml.safe_load(f) or {}
            self._deep_merge(self._thresholds, file_config)
            self._config_path = path
            logger.info("Reloaded detection config from %s", path)
        except Exception as exc:
            logger.error("Failed to load detection config: %s", exc)

    def reload(self) -> bool:
        """Hot-reload configuration from the original file.

        Returns:
            True if reload succeeded, False otherwise.
        """
        if self._config_path and os.path.exists(self._config_path):
            self.load_from_file(self._config_path)
            return True
        return False

    def get(self, *keys: str, default: Any = None) -> Any:
        """Get a nested threshold value by dot-path keys.

        Example:
            config.get("port_scan", "syn_scan", "port_threshold")

        Args:
            *keys: Sequence of dictionary keys.
            default: Default value if key not found.

        Returns:
            Threshold value or default.
        """
        value = self._thresholds
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key, default)
            else:
                return default
        return value

    def update(self, section: str, values: dict) -> None:
        """Update a configuration section at runtime.

        Args:
            section: Top-level config section (e.g., 'port_scan').
            values: Dictionary of new threshold values.
        """
        if section in self._thresholds:
            self._deep_merge(self._thresholds[section], values)
            logger.info("Detection config section '%s' updated", section)

    @property
    def all_thresholds(self) -> dict:
        """Return a copy of all thresholds."""
        return dict(self._thresholds)

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> None:
        """Recursively merge override dict into base dict.

        Args:
            base: Base dictionary (modified in place).
            override: Override dictionary.
        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                DetectionConfig._deep_merge(base[key], value)
            else:
                base[key] = value
