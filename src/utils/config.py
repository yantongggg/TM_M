"""
Configuration management for TM_M

Handles loading and validation of configuration files.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
import yaml


def load_config(config_path: str = "tm_m_config.yaml") -> Dict[str, Any]:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to configuration file

    Returns:
        Configuration dictionary with defaults applied

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid
    """
    # Default configuration
    default_config = {
        'api': {
            'provider': 'zhipu',
            'base_url': 'https://open.bigmodel.cn/api/paas/v4',
            'model': 'glm-4-plus',
            'temperature': 0.3,
            'max_tokens': 8192
        },
        'scanning': {
            'max_depth': 4,
            'max_files': 30,
            'ignore_dirs': [
                'node_modules', '__pycache__', '.git', '.idea', '.vscode',
                'venv', 'env', 'dist', 'build', 'target', 'bin', 'obj',
                '.venv', '.env', 'coverage', '.pytest_cache', '.next',
                '.nuxt', 'vendor', 'bower_components'
            ]
        },
        'output': {
            'directory': 'tm_m_reports',
            'formats': ['markdown', 'sarif'],
            'include_tests': True,
            'test_directory': 'tests/security'
        },
        'reporting': {
            'severity_threshold': 'medium',  # minimum severity to report
            'include_recommendations': True,
            'sarif_version': '2.1.0'
        }
    }

    # Check if config file exists
    config_file = Path(config_path)
    if not config_file.exists():
        # Try environment variable
        env_config = os.environ.get('TM_M_CONFIG')
        if env_config:
            config_file = Path(env_config)
        else:
            # Return defaults if no config found
            return default_config

    # Load YAML config
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            user_config = yaml.safe_load(f) or {}

        # Merge with defaults (user config overrides defaults)
        merged_config = _deep_merge(default_config, user_config)
        return merged_config

    except FileNotFoundError:
        # Return defaults if file not found
        return default_config
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML configuration: {e}")


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries.

    Args:
        base: Base dictionary
        override: Dictionary with override values

    Returns:
        Merged dictionary
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def get_api_key(config: Optional[Dict[str, Any]] = None) -> str:
    """
    Get API key from config or environment variable.

    Args:
        config: Configuration dictionary

    Returns:
        API key string

    Raises:
        ValueError: If no API key is found
    """
    # Check environment variable first
    api_key = os.environ.get('ZHIPU_API_KEY')
    if api_key:
        return api_key

    # Check config
    if config:
        api_key = config.get('api', {}).get('key')
        if api_key:
            return api_key

    raise ValueError(
        "No API key found. Set ZHIPU_API_KEY environment variable "
        "or provide in configuration file."
    )
