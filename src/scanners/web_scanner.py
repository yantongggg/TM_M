"""
Web Scanner for JavaScript/TypeScript Applications

Analyzes web projects to extract components, dependencies,
and security-relevant patterns.
"""

import json
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class WebScanner(BaseScanner):
    """
    Scanner for JavaScript/TypeScript web applications.

    Detects:
    - Frontend framework (React, Vue, Angular, Next.js)
    - Dependencies from package.json
    - HTTP requests (fetch, axios)
    - Data storage (localStorage, sessionStorage, cookies)
    - XSS vectors (innerHTML, eval)
    - Cross-origin communication
    """

    def scan(self) -> Dict[str, Any]:
        """
        Scan web repository and extract context.

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
        Extract dependencies from package.json.

        Returns:
            List of dependency names
        """
        package_json = self.repo_path / "package.json"
        if not package_json.exists():
            return []

        try:
            with open(package_json, 'r', encoding='utf-8') as f:
                data = json.load(f)

            deps = data.get('dependencies', {}) or {}
            dev_deps = data.get('devDependencies', {}) or {}

            # Combine dependencies
            all_deps = list(deps.keys()) + list(dev_deps.keys())
            return all_deps

        except Exception:
            return []

    def extract_code_patterns(self) -> Dict[str, List[str]]:
        """
        Extract security-relevant JS/TS code patterns.

        Returns:
            Dictionary mapping pattern types to file lists
        """
        patterns = {
            'network_calls': [],
            'data_storage': [],
            'xss_vectors': [],
            'authentication': [],
            'crypto_usage': [],
            'cross_origin': []
        }

        # Find all JS/TS files
        js_files = (
            list(self.repo_path.rglob("*.js")) +
            list(self.repo_path.rglob("*.jsx")) +
            list(self.repo_path.rglob("*.ts")) +
            list(self.repo_path.rglob("*.tsx"))
        )

        for js_file in js_files:
            # Skip node_modules and build directories
            if any(skip in str(js_file) for skip in ['node_modules', 'dist', 'build', '.next']):
                continue

            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    rel_path = str(js_file.relative_to(self.repo_path))

                    # Network calls
                    if any(pattern in content for pattern in [
                        'fetch(', 'axios.get', 'axios.post',
                        'XMLHttpRequest', 'fetch('
                    ]):
                        patterns['network_calls'].append(rel_path)

                    # Data storage
                    if any(pattern in content for pattern in [
                        'localStorage', 'sessionStorage',
                        'document.cookie', 'IndexedDB'
                    ]):
                        patterns['data_storage'].append(rel_path)

                    # XSS vectors
                    if any(pattern in content for pattern in [
                        'innerHTML', 'outerHTML',
                        'eval(', 'document.write(',
                        'dangerouslySetInnerHTML'
                    ]):
                        patterns['xss_vectors'].append(rel_path)

                    # Authentication
                    if any(pattern in content for pattern in [
                        'localStorage.getItem(\'token\'',
                        'sessionStorage.getItem(\'token\'',
                        'jwt.decode', 'OAuth'
                    ]):
                        patterns['authentication'].append(rel_path)

                    # Cryptography
                    if any(pattern in content for pattern in [
                        'crypto.', 'CryptoJS', 'bcrypt',
                        'encrypt(', 'decrypt(', 'hash('
                    ]):
                        patterns['crypto_usage'].append(rel_path)

                    # Cross-origin communication
                    if 'postMessage' in content or 'window.parent' in content:
                        patterns['cross_origin'].append(rel_path)

            except Exception:
                pass

        return patterns

    def _extract_components(self) -> List[Dict[str, str]]:
        """
        Extract web components from directory structure.

        Returns:
            List of component dictionaries
        """
        components = []

        # Check for src/ directory
        src_dir = self.repo_path / "src"
        if src_dir.exists():
            # Main entry
            for entry in ['main.js', 'main.tsx', 'index.js', 'App.tsx']:
                main = src_dir / entry
                if main.exists():
                    components.append({
                        'name': f'Main Entry ({entry})',
                        'type': 'Application Entry Point',
                        'file': f'src/{entry}',
                        'description': 'Main application entry point'
                    })
                    break

            # Components
            components_dir = src_dir / "components"
            if components_dir.exists():
                for comp_file in components_dir.glob("*.{js,jsx,ts,tsx}"):
                    if len(components) >= 10:  # Limit components
                        break
                    components.append({
                        'name': comp_file.stem.replace('-', ' ').title(),
                        'type': 'UI Component',
                        'file': str(comp_file.relative_to(self.repo_path)),
                        'description': f'React/Vue component: {comp_file.stem}'
                    })

            # Pages
            pages_dir = src_dir / "pages"
            if pages_dir.exists():
                for page_file in pages_dir.glob("*.{js,jsx,ts,tsx}"):
                    if len(components) >= 15:  # Limit components
                        break
                    components.append({
                        'name': page_file.stem.replace('-', ' ').replace('_', ' ').title(),
                        'type': 'Page',
                        'file': str(page_file.relative_to(self.repo_path)),
                        'description': f'Page: {page_file.stem}'
                    })

        return components

    def _detect_framework(self) -> Dict[str, str]:
        """
        Detect frontend framework from package.json.

        Returns:
            Dictionary with framework info
        """
        package_json = self.repo_path / "package.json"
        if not package_json.exists():
            return {'framework': 'Unknown', 'language': 'JavaScript/TypeScript'}

        try:
            with open(package_json, 'r', encoding='utf-8') as f:
                data = json.load(f)

            deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}

            # Detect framework
            if 'next' in deps:
                framework = 'Next.js'
                language = 'TypeScript' if 'typescript' in deps else 'JavaScript'
                version = deps.get('next', 'unknown')
            elif 'react' in deps:
                framework = 'React'
                language = 'TypeScript' if 'typescript' in deps else 'JavaScript'
                version = deps.get('react', 'unknown')
            elif 'vue' in deps:
                framework = 'Vue.js'
                language = 'TypeScript' if 'typescript' in deps else 'JavaScript'
                version = deps.get('vue', 'unknown')
            elif 'angular' in deps:
                framework = 'Angular'
                language = 'TypeScript'
                version = deps.get('@angular/core', 'unknown')
            elif 'express' in deps:
                framework = 'Express.js'
                language = 'JavaScript'
                version = deps.get('express', 'unknown')
            elif 'nestjs' in deps:
                framework = 'NestJS'
                language = 'TypeScript'
                version = deps.get('@nestjs/core', 'unknown')
            else:
                framework = 'Unknown'
                language = 'TypeScript' if 'typescript' in deps else 'JavaScript'
                version = 'unknown'

            return {
                'framework': framework,
                'language': language,
                'version': version
            }
        except Exception:
            return {'framework': 'Unknown', 'language': 'JavaScript/TypeScript'}
