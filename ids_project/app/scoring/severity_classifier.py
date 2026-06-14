"""
Severity classifier.

Maps numeric threat scores to severity levels with
boundary definitions and color codes for UI rendering.
"""


class SeverityLevel:
    """Threat severity constants and classification logic.

    Severity bands:
        0–24  = LOW
        25–49 = MEDIUM
        50–74 = HIGH
        75–100 = CRITICAL
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    BANDS = {
        CRITICAL: {"min": 75, "max": 100, "color": "#DC2626", "priority": 0},
        HIGH:     {"min": 50, "max": 74,  "color": "#F97316", "priority": 1},
        MEDIUM:   {"min": 25, "max": 49,  "color": "#EAB308", "priority": 2},
        LOW:      {"min": 0,  "max": 24,  "color": "#22C55E", "priority": 3},
    }

    @staticmethod
    def classify(score: int) -> str:
        """Classify a 0–100 score into severity level.

        Args:
            score: Threat score (clamped 0–100).

        Returns:
            Severity level string.
        """
        score = max(0, min(100, score))
        if score >= 75:
            return SeverityLevel.CRITICAL
        elif score >= 50:
            return SeverityLevel.HIGH
        elif score >= 25:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    @staticmethod
    def get_band(severity: str) -> dict:
        """Get band metadata for a severity level.

        Args:
            severity: Severity level string.

        Returns:
            Band dict with min, max, color, priority.
        """
        return SeverityLevel.BANDS.get(severity, SeverityLevel.BANDS[SeverityLevel.LOW])

    @staticmethod
    def compare(a: str, b: str) -> int:
        """Compare two severity levels.

        Returns:
            Negative if a is more severe, positive if b is more severe, 0 if equal.
        """
        pa = SeverityLevel.BANDS.get(a, {}).get("priority", 99)
        pb = SeverityLevel.BANDS.get(b, {}).get("priority", 99)
        return pa - pb
