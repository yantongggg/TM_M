"""
Report Generation Module

Generates:
- SARIF v2.1.0 reports for GitHub Security integration
- Markdown reports for human readability
"""

import json
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

from ..utils.timestamp import get_timestamp, get_iso_timestamp


def generate_sarif_report(
    threats: List[Dict],
    repo_path: str,
    output_path: str,
    tool_name: str = "TM_M Threat Modeling",
    tool_version: str = "2.0.0"
) -> None:
    """
    Generate SARIF v2.1.0 report for GitHub Security integration.

    Args:
        threats: List of validated threat dictionaries
        repo_path: Path to the repository
        output_path: Where to save the SARIF report
        tool_name: Name of the tool
        tool_version: Version of the tool
    """
    timestamp = get_iso_timestamp()

    # Build SARIF rules from threats
    rules = []
    for threat in threats:
        rules.append({
            "id": threat.get('id', 'UNKNOWN'),
            "name": threat.get('title', 'Unknown Threat'),
            "shortDescription": {
                "text": threat.get('title', 'Unknown Threat')
            },
            "fullDescription": {
                "text": threat.get('description', '')
            },
            "help": {
                "text": threat.get('mitigation', 'No mitigation provided'),
                "markdown": f"**Mitigation:**\n{threat.get('mitigation', 'No mitigation provided')}\n\n**References:**\n{', '.join(threat.get('references', []))}"
            },
            "properties": {
                "category": threat.get('category', 'Unknown'),
                "severity": threat.get('severity', 'Unknown'),
                "likelihood": threat.get('likelihood', 'Unknown'),
                "confidence": threat.get('confidence', 50),
                "priority": threat.get('priority', 'P3')
            }
        })

    # Build SARIF results from threats
    results = []
    for threat in threats:
        results.append({
            "ruleId": threat.get('id', 'UNKNOWN'),
            "level": _map_severity_to_sarif_level(threat.get('severity', 'Medium')),
            "message": {
                "text": threat.get('description', '')
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": threat.get('component', '/'),
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": 1
                    }
                }
            }],
            "properties": {
                "attack_scenario": threat.get('attack_scenario', ''),
                "impact": threat.get('impact', ''),
                "mitigation": threat.get('mitigation', ''),
                "category": threat.get('category', ''),
                "likelihood": threat.get('likelihood', '')
            }
        })

    # Build complete SARIF document
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/yantongggg/TM_M",
                    "rules": rules
                }
            },
            "results": results,
            "invocations": [{
                "startTimeUtc": timestamp,
                "endTimeUtc": timestamp
            }]
        }]
    }

    # Write SARIF report
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(sarif, f, indent=2)

    print(f"  ✓ SARIF report: {output_path}")


def generate_markdown_report(
    threats: List[Dict],
    repo_path: str,
    output_path: str,
    tool_version: str = "2.0.0"
) -> None:
    """
    Generate human-readable Markdown report.

    Args:
        threats: List of validated threat dictionaries
        repo_path: Path to the repository
        output_path: Where to save the Markdown report
        tool_version: Version of the tool
    """
    timestamp = get_timestamp()
    summary = _count_by_severity(threats)

    # Build markdown content
    md = f"""# Threat Model Report

**Generated:** {timestamp} UTC
**Repository:** `{repo_path}`
**Total Threats:** {len(threats)}

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {summary['critical']} |
| 🟠 High | {summary['high']} |
| 🟡 Medium | {summary['medium']} |
| 🟢 Low | {summary['low']} |

---

## Threat Details

"""

    # Sort threats by severity (Critical first)
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    sorted_threats = sorted(threats, key=lambda t: severity_order.get(t.get('severity', 'Low'), 4))

    for threat in sorted_threats:
        severity_emoji = {
            'Critical': '🔴',
            'High': '🟠',
            'Medium': '🟡',
            'Low': '🟢'
        }.get(threat.get('severity', 'Low'), '⚪')

        md += f"""### {severity_emoji} {threat.get('title', 'Unknown Threat')}

**ID:** `{threat.get('id', 'N/A')}`  \n
**Category:** {threat.get('category', 'Unknown')}  \n
**Severity:** {threat.get('severity', 'Unknown')}  \n
**Component:** `{threat.get('component', 'Unknown')}`  \n
**Likelihood:** {threat.get('likelihood', 'Unknown')}  \n
**Confidence:** {threat.get('confidence', 'N/A')}%  \n
**Priority:** {threat.get('priority', 'N/A')}

#### Description
{threat.get('description', 'No description provided.')}

#### Attack Scenario
{threat.get('attack_scenario', 'No attack scenario provided.')}

#### Impact
{threat.get('impact', 'No impact information provided.')}

#### Mitigation
{threat.get('mitigation', 'No mitigation provided.')}

**References:** {', '.join(threat.get('references', []))}

---

"""

    # Add footer
    md += f"""
---
*Generated by [TM_M](https://github.com/yantongggg/TM_M) v{tool_version}*
*Automated Threat Modeling & Security Test Generation*
"""

    # Write Markdown report
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(md)

    print(f"  ✓ Markdown report: {output_path}")


def _map_severity_to_sarif_level(severity: str) -> str:
    """
    Map threat severity to SARIF level.

    Args:
        severity: Threat severity string

    Returns:
        SARIF level string
    """
    severity_map = {
        'Critical': 'error',
        'High': 'error',
        'Medium': 'warning',
        'Low': 'note'
    }
    return severity_map.get(severity, 'warning')


def _count_by_severity(threats: List[Dict]) -> Dict[str, int]:
    """
    Count threats by severity level.

    Args:
        threats: List of threat dictionaries

    Returns:
        Dictionary with counts for each severity
    """
    summary = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }

    for threat in threats:
        severity = threat.get('severity', 'Low').lower()
        if severity == 'critical':
            summary['critical'] += 1
        elif severity == 'high':
            summary['high'] += 1
        elif severity == 'medium':
            summary['medium'] += 1
        elif severity == 'low':
            summary['low'] += 1

    return summary
