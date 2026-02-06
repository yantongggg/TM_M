"""
Mobile Scanner for Flutter/Dart Applications

Analyzes Flutter projects to extract components, dependencies,
and security-relevant patterns.
"""

import yaml
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class MobileScanner(BaseScanner):
    """
    Scanner for Flutter/Dart mobile applications.

    Detects:
    - Flutter/Dart components
    - Dependencies from pubspec.yaml
    - HTTP client usage
    - Data storage patterns
    - Native platform channels
    """

    def scan(self) -> Dict[str, Any]:
        """
        Scan Flutter repository and extract context.

        Returns:
            Dictionary with components, dependencies, and patterns
        """
        return {
            'components': self._extract_components(),
            'dependencies': self.extract_dependencies(),
            'patterns': self.extract_code_patterns(),
            'framework': self._detect_flutter_version()
        }

    def extract_dependencies(self) -> List[str]:
        """
        Extract dependencies from pubspec.yaml.

        Returns:
            List of dependency names
        """
        pubspec = self.repo_path / "pubspec.yaml"
        if not pubspec.exists():
            return []

        try:
            with open(pubspec, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            deps = data.get('dependencies', {}) or {}
            dev_deps = data.get('dev_dependencies', {}) or {}

            # Combine dependencies
            all_deps = list(deps.keys()) + list(dev_deps.keys())
            return all_deps

        except Exception:
            return []

    def extract_code_patterns(self) -> Dict[str, List[str]]:
        """
        Extract security-relevant Dart code patterns.

        Returns:
            Dictionary mapping pattern types to file lists
        """
        patterns = {
            'network_calls': [],
            'data_storage': [],
            'authentication': [],
            'crypto_usage': [],
            'platform_channels': []
        }

        # Find all .dart files
        dart_files = list(self.repo_path.rglob("*.dart"))

        for dart_file in dart_files:
            # Skip build directory
            if 'build' in str(dart_file) or '.dart_tool' in str(dart_file):
                continue

            try:
                with open(dart_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    rel_path = str(dart_file.relative_to(self.repo_path))

                    # Network calls
                    if any(pattern in content for pattern in [
                        'http.Client', 'http.get', 'http.post',
                        'http.put', 'http.delete', 'dio.Dio'
                    ]):
                        patterns['network_calls'].append(rel_path)

                    # Data storage
                    if any(pattern in content for pattern in [
                        'SharedPreferences', 'FlutterSecureStorage',
                        'sqflite', 'hive', 'objectbox'
                    ]):
                        patterns['data_storage'].append(rel_path)

                    # Authentication
                    if any(pattern in content for pattern in [
                        'FirebaseAuth', 'GoogleSignIn',
                        'authenticate', 'signIn', 'logIn'
                    ]):
                        patterns['authentication'].append(rel_path)

                    # Cryptography
                    if any(pattern in content for pattern in [
                        'encrypt', 'decrypt', 'hash', 'cipher',
                        'crypto', 'bcrypt', 'aes'
                    ]):
                        patterns['crypto_usage'].append(rel_path)

                    # Platform channels
                    if 'MethodChannel' in content or 'EventChannel' in content:
                        patterns['platform_channels'].append(rel_path)

            except Exception:
                pass

        return patterns

    def _extract_components(self) -> List[Dict[str, str]]:
        """
        Extract Flutter components from directory structure.

        Returns:
            List of component dictionaries
        """
        components = []

        # Check for lib/ directory structure
        lib_dir = self.repo_path / "lib"
        if lib_dir.exists():
            # Main app
            main = lib_dir / "main.dart"
            if main.exists():
                components.append({
                    'name': 'Flutter App',
                    'type': 'Mobile Application',
                    'file': 'lib/main.dart',
                    'description': 'Main Flutter application entry point'
                })

            # Screens
            screens = list(lib_dir.rglob("*screen*.dart"))
            for screen in screens[:5]:  # Limit to 5 screens
                components.append({
                    'name': screen.stem.replace('_', ' ').title(),
                    'type': 'UI Screen',
                    'file': str(screen.relative_to(self.repo_path)),
                    'description': f'Flutter screen: {screen.stem}'
                })

        return components

    def _detect_flutter_version(self) -> Dict[str, str]:
        """
        Detect Flutter version from pubspec.yaml.

        Returns:
            Dictionary with framework info
        """
        pubspec = self.repo_path / "pubspec.yaml"
        if not pubspec.exists():
            return {'framework': 'Flutter', 'version': 'unknown'}

        try:
            with open(pubspec, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            env = data.get('environment', {}) or {}
            sdk = env.get('sdk', 'unknown')

            return {
                'framework': 'Flutter',
                'language': 'Dart',
                'sdk_version': sdk
            }
        except Exception:
            return {'framework': 'Flutter', 'version': 'unknown'}
