"""
Unified timestamp helper for TM_M

Provides consistent timestamp formatting across all modules.
"""

from datetime import datetime


def get_timestamp() -> str:
    """
    Get UTC timestamp in YYYYMMDD_HHMMSS format.

    This format is used for report filenames to ensure
    consistent naming and easy sorting.

    Returns:
        Timestamp string in format: YYYYMMDD_HHMMSS
    """
    return datetime.utcnow().strftime('%Y%m%d_%H%M%S')


def get_iso_timestamp() -> str:
    """
    Get ISO 8601 UTC timestamp.

    This format is used in SARIF reports and other
    machine-readable outputs.

    Returns:
        ISO 8601 timestamp string in format: YYYY-MM-DDTHH:MM:SSZ
    """
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
