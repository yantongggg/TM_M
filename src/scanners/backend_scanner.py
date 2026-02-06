"""
Backend Scanner for Python/Go/Java Applications

Analyzes backend projects to extract components, dependencies,
and security-relevant patterns.
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class BackendScanner(BaseScanner):
    """
    Scanner for backend applications.

    Detects:
    - Backend framework (Django, Flask, FastAPI, Express, Go, Java)
    - Dependencies from requirements.txt/go.mod/pom.xml
    - SQL query construction
    - File operations
    - Crypto usage
    - API endpoints
    """

    def scan(self) -> Dict[str, Any]:
        """
        Scan backend repository and extract context.

        Returns:
            Dictionary with components, dependencies, and patterns
        """
        return {
            'components': self._extract_components(),
            'dependencies': self.extract_dependencies(),
            'patterns': self.extract_code_patterns(),
            'framework': self._detect_framework()
        }

    def extract_dependencies(self) -> List[str]:
        """
        Extract dependencies from package files.

        Returns:
            List of dependency names
        """
        dependencies = []

        # Python requirements.txt
        req_file = self.repo_path / "requirements.txt"
        if req_file.exists():
            try:
                with open(req_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        # Extract package name (before == or >=)
                        if line and not line.startswith('#'):
                            match = re.match(r'^([a-zA-Z0-9_-]+)', line)
                            if match:
                                dependencies.append(match.group(1))
            except Exception:
                pass

        # Go go.mod
        go_mod = self.repo_path / "go.mod"
        if go_mod.exists():
            try:
                with open(go_mod, 'r', encoding='utf-8') as f:
                    in_require = False
                    for line in f:
                        line = line.strip()
                        if line.startswith('require ('):
                            in_require = True
                            continue
                        if in_require and line == ')':
                            break
                        if in_require or line.startswith('require\t'):
                            # Extract package name
                            parts = line.split()
                            if parts:
                                # Get last part of package path
                                pkg_name = parts[0].split('/')[-1]
                                dependencies.append(pkg_name)
            except Exception:
                pass

        return dependencies

    def extract_code_patterns(self) -> Dict[str, List[str]]:
        """
        Extract security-relevant backend code patterns.

        Returns:
            Dictionary mapping pattern types to file lists
        """
        patterns = {
            'sql_queries': [],
            'file_operations': [],
            'crypto_usage': [],
            'api_endpoints': [],
            'authentication': [],
            'input_validation': []
        }

        # Detect language from repo
        language = self._detect_language()

        if language == 'python':
            patterns.update(self._scan_python_files())
        elif language == 'go':
            patterns.update(self._scan_go_files())
        elif language == 'java':
            patterns.update(self._scan_java_files())

        return patterns

    def _scan_python_files(self) -> Dict[str, List[str]]:
        """Scan Python files for patterns."""
        patterns = {
            'sql_queries': [], 'file_operations': [],
            'crypto_usage': [], 'api_endpoints': [],
            'authentication': [], 'input_validation': []
        }

        for py_file in self.repo_path.rglob("*.py"):
            # Skip virtual environments
            if any(skip in str(py_file) for skip in ['venv', '.venv', '__pycache__']):
                continue

            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    rel_path = str(py_file.relative_to(self.repo_path))

                    # SQL queries
                    if any(pattern in content for pattern in [
                        'SELECT * FROM', 'INSERT INTO',
                        'UPDATE', 'DELETE FROM',
                        'execute(', 'executemany(',
                        'cursor.execute'
                    ]):
                        patterns['sql_queries'].append(rel_path)

                    # File operations
                    if any(pattern in content for pattern in [
                        'open(', 'Path(', 'os.path.join',
                        'File(', 'write(', 'read('
                    ]):
                        patterns['file_operations'].append(rel_path)

                    # Crypto
                    if any(pattern in content for pattern in [
                        'hashlib', 'cryptography', 'bcrypt',
                        'encrypt(', 'decrypt(', 'hash('
                    ]):
                        patterns['crypto_usage'].append(rel_path)

                    # API endpoints (Flask, FastAPI, Django)
                    if any(pattern in content for pattern in [
                        '@app.route', '@router.', '@api_view',
                        'path(', 'def post', 'def get', 'def put'
                    ]):
                        patterns['api_endpoints'].append(rel_path)

                    # Authentication
                    if any(pattern in content for pattern in [
                        'login_required', '@authenticate',
                        'jwt.', 'oauth', 'session[\'user\''
                    ]):
                        patterns['authentication'].append(rel_path)

                    # Input validation
                    if any(pattern in content for pattern in [
                        'validate_', 'schema', 'pydantic',
                        'Form(', 'Query('
                    ]):
                        patterns['input_validation'].append(rel_path)

            except Exception:
                pass

        return patterns

    def _scan_go_files(self) -> Dict[str, List[str]]:
        """Scan Go files for patterns."""
        patterns = {
            'sql_queries': [], 'file_operations': [],
            'crypto_usage': [], 'api_endpoints': [],
            'authentication': [], 'input_validation': []
        }

        for go_file in self.repo_path.rglob("*.go"):
            try:
                with open(go_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    rel_path = str(go_file.relative_to(self.repo_path))

                    # SQL queries
                    if 'db.Query(' in content or 'db.Exec(' in content:
                        patterns['sql_queries'].append(rel_path)

                    # File operations
                    if 'ioutil.ReadFile' in content or 'os.Open' in content:
                        patterns['file_operations'].append(rel_path)

                    # Crypto
                    if 'crypto/' in content:
                        patterns['crypto_usage'].append(rel_path)

                    # API endpoints
                    if 'http.HandleFunc' in content or 'func Handler' in content:
                        patterns['api_endpoints'].append(rel_path)

                    # Authentication
                    if 'jwt.' in content or 'middleware.Auth' in content:
                        patterns['authentication'].append(rel_path)

            except Exception:
                pass

        return patterns

    def _scan_java_files(self) -> Dict[str, List[str]]:
        """Scan Java files for patterns."""
        patterns = {
            'sql_queries': [], 'file_operations': [],
            'crypto_usage': [], 'api_endpoints': [],
            'authentication': [], 'input_validation': []
        }

        for java_file in self.repo_path.rglob("*.java"):
            try:
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    rel_path = str(java_file.relative_to(self.repo_path))

                    # SQL queries
                    if 'createQuery(' in content or 'nativeQuery(' in content:
                        patterns['sql_queries'].append(rel_path)

                    # File operations
                    if 'File(' in content or 'FileInputStream' in content:
                        patterns['file_operations'].append(rel_path)

                    # Crypto
                    if 'Cipher' in content or 'MessageDigest' in content:
                        patterns['crypto_usage'].append(rel_path)

                    # API endpoints
                    if '@GetMapping' in content or '@PostMapping' in content:
                        patterns['api_endpoints'].append(rel_path)

            except Exception:
                pass

        return patterns

    def _extract_components(self) -> List[Dict[str, str]]:
        """Extract backend components."""
        components = []

        # Detect language
        language = self._detect_language()

        if language == 'python':
            # Look for main.py, app.py, manage.py
            for main_file in ['main.py', 'app.py', 'manage.py', 'wsgi.py']:
                main = self.repo_path / main_file
                if main.exists():
                    components.append({
                        'name': f'Main Application ({main_file})',
                        'type': 'Application Entry Point',
                        'file': main_file,
                        'description': 'Main backend application entry point'
                    })
                    break

            # Look for API routes
            for routes_file in ['routes.py', 'views.py', 'urls.py', 'api.py']:
                routes = self.repo_path / routes_file
                if routes.exists():
                    components.append({
                        'name': f'API Routes ({routes_file})',
                        'type': 'API Routes',
                        'file': routes_file,
                        'description': 'API endpoint definitions'
                    })

        elif language == 'go':
            main = self.repo_path / "main.go"
            if main.exists():
                components.append({
                    'name': 'Main Application',
                    'type': 'Application Entry Point',
                    'file': 'main.go',
                    'description': 'Main Go application entry point'
                })

        return components

    def _detect_language(self) -> str:
        """Detect backend programming language."""
        if (self.repo_path / "requirements.txt").exists() or \
           (self.repo_path / "Pipfile").exists() or \
           (self.repo_path / "pyproject.toml").exists():
            return 'python'
        elif (self.repo_path / "go.mod").exists():
            return 'go'
        elif (self.repo_path / "pom.xml").exists() or \
             (self.repo_path / "build.gradle").exists():
            return 'java'
        return 'unknown'

    def _detect_framework(self) -> Dict[str, str]:
        """Detect backend framework."""
        language = self._detect_language()

        if language == 'python':
            req_file = self.repo_path / "requirements.txt"
            if req_file.exists():
                try:
                    with open(req_file, 'r') as f:
                        content = f.read().lower()
                        if 'django' in content:
                            return {'framework': 'Django', 'language': 'Python'}
                        elif 'flask' in content:
                            return {'framework': 'Flask', 'language': 'Python'}
                        elif 'fastapi' in content:
                            return {'framework': 'FastAPI', 'language': 'Python'}
                except:
                    pass

        elif language == 'go':
            return {'framework': 'Go', 'language': 'Go'}

        elif language == 'java':
            if (self.repo_path / "pom.xml").exists():
                return {'framework': 'Maven', 'language': 'Java'}
            elif (self.repo_path / "build.gradle").exists():
                return {'framework': 'Gradle', 'language': 'Java'}

        return {'framework': 'Unknown', 'language': language}
