"""
TM_M Utility Modules

This package contains utility functions for:
- Timestamp generation
- Configuration management
- Technology stack detection
"""

from .timestamp import get_timestamp, get_iso_timestamp
from .config import load_config

__all__ = ['get_timestamp', 'get_iso_timestamp', 'load_config']
