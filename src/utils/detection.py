"""
Enhanced Technology Stack Detection

Automatically detects repository technology stacks and frameworks.
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Set


def detect_tech_stack(repo_path: str) -> List[str]:
    """
    Detect repository technology stacks.

    Args:
        repo_path: Path to the repository root

    Returns:
        List of detected technology stack identifiers
    """
    stacks = []
    repo = Path(repo_path)

    # Mobile: Flutter
    if (repo / "pubspec.yaml").exists():
        stacks.append("MOBILE_FLUTTER")

    # Web: JavaScript/TypeScript
    if any((repo / f).exists() for f in ["package.json", "index.html"]):
        stacks.append("WEB_FRONTEND")

    # Backend: Python/Go/Java
    if any((repo / f).exists() for f in ["requirements.txt", "go.mod", "pom.xml", "build.gradle"]):
        stacks.append("BACKEND_API")

    return stacks


def detect_frameworks(repo_path: str) -> Dict[str, str]:
    """
    Detect specific frameworks and technologies.

    Args:
        repo_path: Path to the repository root

    Returns:
        Dictionary with framework information
    """
    repo = Path(repo_path)
    info = {
        'language': None,
        'framework': None,
        'version': None
    }

    # Check Flutter
    pubspec = repo / "pubspec.yaml"
    if pubspec.exists():
        info['language'] = 'Dart'
        try:
            import yaml
            with open(pubspec, 'r') as f:
                data = yaml.safe_load(f)
                info['framework'] = 'Flutter'
                info['version'] = data.get('environment', {}).get('sdk', 'unknown')
        except:
            info['framework'] = 'Flutter'

    # Check JavaScript/TypeScript
    package_json = repo / "package.json"
    if package_json.exists():
        try:
            with open(package_json, 'r') as f:
                data = json.load(f)
                deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}

                # Detect framework
                if 'next' in deps:
                    info['framework'] = 'Next.js'
                    info['language'] = 'TypeScript' if 'typescript' in deps else 'JavaScript'
                elif 'react' in deps:
                    info['framework'] = 'React'
                    info['language'] = 'TypeScript' if 'typescript' in deps else 'JavaScript'
                elif 'vue' in deps:
                    info['framework'] = 'Vue.js'
                    info['language'] = 'TypeScript' if 'typescript' in deps else 'JavaScript'
                elif 'angular' in deps:
                    info['framework'] = 'Angular'
                    info['language'] = 'TypeScript'
                elif 'express' in deps:
                    info['framework'] = 'Express.js'
                    info['language'] = 'JavaScript'
                elif 'nestjs' in deps:
                    info['framework'] = 'NestJS'
                    info['language'] = 'TypeScript'

                # Get version if available
                if info['framework'] and info['framework'].lower() in deps:
                    info['version'] = deps[info['framework'].lower()]
        except:
            pass

    # Check Python
    requirements = repo / "requirements.txt"
    if requirements.exists():
        info['language'] = 'Python'
        try:
            with open(requirements, 'r') as f:
                content = f.read().lower()
                if 'django' in content:
                    info['framework'] = 'Django'
                elif 'flask' in content:
                    info['framework'] = 'Flask'
                elif 'fastapi' in content:
                    info['framework'] = 'FastAPI'
        except:
            pass

    # Check Go
    go_mod = repo / "go.mod"
    if go_mod.exists():
        info['language'] = 'Go'
        try:
            with open(go_mod, 'r') as f:
                for line in f:
                    if line.startswith('module '):
                        info['framework'] = 'Go Module'
                        break
        except:
            info['framework'] = 'Go'

    # Check Java
    pom_xml = repo / "pom.xml"
    if pom_xml.exists():
        info['language'] = 'Java'
        info['framework'] = 'Maven'

    build_gradle = repo / "build.gradle"
    if build_gradle.exists():
        info['language'] = 'Java'
        info['framework'] = 'Gradle'

    return info


def detect_security_patterns(repo_path: str) -> Dict[str, List[str]]:
    """
    Detect security-relevant patterns in the codebase.

    Args:
        repo_path: Path to the repository root

    Returns:
        Dictionary mapping pattern categories to found patterns
    """
    repo = Path(repo_path)
    patterns = {
        'network_calls': [],
        'data_storage': [],
        'authentication': [],
        'crypto_usage': [],
        'input_validation': []
    }

    # Scan for common patterns based on detected tech stack
    stacks = detect_tech_stack(str(repo))

    # Flutter/Dart patterns
    if "MOBILE_FLUTTER" in stacks:
        for dart_file in repo.rglob("*.dart"):
            try:
                with open(dart_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if 'http.Client' in content or 'http.post' in content or 'http.get' in content:
                        patterns['network_calls'].append(str(dart_file.relative_to(repo)))
                    if 'SharedPreferences' in content:
                        patterns['data_storage'].append(str(dart_file.relative_to(repo)))
                    if 'FirebaseAuth' in content or 'authenticate' in content:
                        patterns['authentication'].append(str(dart_file.relative_to(repo)))
            except:
                pass

    # JavaScript/TypeScript patterns
    if "WEB_FRONTEND" in stacks:
        for js_file in repo.rglob("*.js") | repo.rglob("*.ts") | repo.rglob("*.tsx") | repo.rglob("*.jsx"):
            # Skip node_modules
            if 'node_modules' in str(js_file):
                continue
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if 'fetch(' in content or 'axios.' in content:
                        patterns['network_calls'].append(str(js_file.relative_to(repo)))
                    if 'localStorage' in content or 'sessionStorage' in content:
                        patterns['data_storage'].append(str(js_file.relative_to(repo)))
                    if 'document.cookie' in content:
                        patterns['data_storage'].append(str(js_file.relative_to(repo)))
                    if 'eval(' in content or 'innerHTML' in content:
                        patterns['input_validation'].append(str(js_file.relative_to(repo)))
            except:
                pass

    # Backend patterns
    if "BACKEND_API" in stacks:
        # Python
        for py_file in repo.rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if 'SELECT' in content or 'INSERT' in content or 'UPDATE' in content:
                        patterns['input_validation'].append(str(py_file.relative_to(repo)))
                    if 'hashlib' in content or 'cryptography' in content or 'bcrypt' in content:
                        patterns['crypto_usage'].append(str(py_file.relative_to(repo)))
            except:
                pass

        # Go
        for go_file in repo.rglob("*.go"):
            try:
                with open(go_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if 'http.Get' in content or 'http.Post' in content:
                        patterns['network_calls'].append(str(go_file.relative_to(repo)))
                    if 'bcrypt' in content or 'crypto/' in content:
                        patterns['crypto_usage'].append(str(go_file.relative_to(repo)))
            except:
                pass

    return patterns
