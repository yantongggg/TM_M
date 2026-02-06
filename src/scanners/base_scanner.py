"""
Abstract Base Scanner Class

Provides the interface for all repository scanners.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any


class BaseScanner(ABC):
    """
    Abstract base class for repository scanners.

    All scanners must inherit from this class and implement
    the required methods.
    """

    def __init__(self, repo_path: str):
        """
        Initialize the scanner.

        Args:
            repo_path: Path to the repository root
        """
        self.repo_path = Path(repo_path).resolve()

    @abstractmethod
    def scan(self) -> Dict[str, Any]:
        """
        Scan repository and extract context.

        Returns:
            Dictionary containing:
                - components: List of detected components
                - dependencies: List of dependencies
                - patterns: Security-relevant code patterns
                - framework: Detected framework information
        """
        pass

    @abstractmethod
    def extract_dependencies(self) -> List[str]:
        """
        Extract dependency list from package files.

        Returns:
            List of dependency names
        """
        pass

    @abstractmethod
    def extract_code_patterns(self) -> Dict[str, List[str]]:
        """
        Extract security-relevant code patterns.

        Returns:
            Dictionary mapping pattern types to file lists
        """
        pass

    def _read_file_safe(self, file_path: Path) -> str:
        """
        Safely read file contents with error handling.

        Args:
            file_path: Path to the file

        Returns:
            File contents or empty string on error
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return ""

    def _find_files_by_extension(self, extensions: List[str]) -> List[Path]:
        """
        Find all files with given extensions.

        Args:
            extensions: List of file extensions (e.g., ['.py', '.js'])

        Returns:
            List of file paths
        """
        files = []
        for ext in extensions:
            files.extend(self.repo_path.rglob(f"*{ext}"))
        return files
