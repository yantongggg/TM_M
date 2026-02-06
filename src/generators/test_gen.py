"""
Base Test Generator Module

Provides abstract base class for all test generators.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict


class BaseTestGenerator(ABC):
    """
    Abstract base class for test generators.

    All test generators must inherit from this class and
    implement the required methods.
    """

    def __init__(self, threats: List[Dict], repo_path: str):
        """
        Initialize the test generator.

        Args:
            threats: List of threat dictionaries
            repo_path: Path to the target repository
        """
        self.threats = threats
        self.repo_path = Path(repo_path).resolve()
        self.output_dir = self.repo_path / "tests" / "security"

    @abstractmethod
    def generate_tests(self) -> List[Path]:
        """
        Generate test files for detected threats.

        Returns:
            List of generated test file paths
        """
        pass

    def _ensure_output_dir(self):
        """Create output directory if it doesn't exist."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _sanitize_filename(self, name: str) -> str:
        """
        Sanitize a string for use as a filename.

        Args:
            name: String to sanitize

        Returns:
            Sanitized filename-safe string
        """
        # Replace invalid characters with underscores
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            name = name.replace(char, '_')
        return name.lower().replace(' ', '_')

    def _get_threat_id(self, threat: Dict) -> str:
        """
        Extract or generate a threat ID.

        Args:
            threat: Threat dictionary

        Returns:
            Threat ID string
        """
        return threat.get('id', f"threat_{hash(threat.get('title', '')) % 10000:04d}")
