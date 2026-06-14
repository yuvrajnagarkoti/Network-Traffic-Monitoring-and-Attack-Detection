"""
Intelligence model aliases.

Re-exports existing models from threat.py and block.py under
the names expected by the intelligence package, for clean imports.
"""

# Re-export for intelligence package imports
from app.models.threat import IpReputation as IPReputation  # noqa: F401
from app.models.block import Blacklist  # noqa: F401
