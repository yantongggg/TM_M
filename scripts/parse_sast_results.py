#!/usr/bin/env python3
"""
Parse Semgrep SAST results from JSON to JSON format

This script converts Semgrep JSON output to a standardized JSON format
compatible with the threat modeling report structure.
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime


def load_semgrep_results(json_path: str) -> Dict[str, Any]:
    """
    Load Semgrep results from JSON file.

    Args:
        json_path: Path to semgrep.json

    Returns:
        Parsed JSON dictionary
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: SAST results file not found: {json_path}", file=sys.stderr)
        return {'results': []}
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON: {e}", file=sys.stderr)
        sys.exit(1)


def calculate_severity(semgrep_severity: str) -> str:
    """
    Map Semgrep severity to standard severity levels.

    Args:
        semgrep_severity: Semgrep severity (ERROR, WARNING, INFO)

    Returns:
        Standardized severity (Critical, High, Medium, Low)
    """
    severity_map = {
        'ERROR': 'High',  # Semgrep's highest severity
        'WARNING': 'Medium',
        'INFO': 'Low'
    }
    return severity_map.get(semgrep_severity, 'Low')


def get_cwe_from_metadata(metadata: Dict[str, Any]) -> str:
    """
    Extract CWE identifier from rule metadata.

    Args:
        metadata: Rule metadata dictionary

    Returns:
        CWE identifier string (e.g., "CWE-89")
    """
    if not metadata:
        return None

    # Check for 'cwe' field
    cwe = metadata.get('cwe')
    if cwe:
        if isinstance(cwe, list):
            return cwe[0] if cwe else None
        return str(cwe)

    # Check for 'technology' field which may contain security context
    tech = metadata.get('technology', [])
    if isinstance(tech, list) and 'security' in tech:
        return 'CWE'  # Generic CWE reference

    return None


def convert_finding_to_dict(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a single Semgrep finding to JSON format.

    Args:
        finding: Single Semgrep result

    Returns:
        Dictionary representing the finding
    """
    rule_id = finding.get('check_id', 'unknown')
    severity = calculate_severity(finding.get('extra', {}).get('severity', 'INFO'))
    message = finding.get('extra', {}).get('message', 'No description available')

    # Get code location
    path = finding.get('path', 'unknown')
    start_line = finding.get('start', {}).get('line', 0)
    end_line = finding.get('end', {}).get('line', 0)
    location = f"{path}:{start_line}-{end_line}" if start_line != end_line else f"{path}:{start_line}"

    # Get code snippet
    code_snippet = finding.get('extra', {}).get('lines', '')

    # Get rule metadata
    metadata = finding.get('extra', {}).get('metadata', {})
    cwe = get_cwe_from_metadata(metadata)
    owasp = metadata.get('owasp', '')
    category = metadata.get('category', 'Implementation')

    # Build threat dictionary
    threat = {
        'category': category,
        'severity': severity,
        'source': 'code',
        'title': message[:100] + "..." if len(message) > 100 else message,
        'component': location,
        'description': {
            'issue': message,
            'location': location,
            'rule_id': rule_id,
            'vulnerable_code': code_snippet.strip() if code_snippet else None,
            'cwe': cwe,
            'owasp': owasp
        },
        'attack_scenario': (
            f"An attacker could exploit this vulnerability by crafting malicious input "
            f"that targets the code pattern detected at {location}. This type of vulnerability "
            f"can lead to security breaches depending on the specific issue and context."
        ),
        'impact': (
            f"Potential security impact includes: data exposure, unauthorized access, "
            f"system compromise, or other security violations depending on the specific "
            f"vulnerability type and execution context."
        ),
        'likelihood': "Medium" if severity == "Medium" else "High",
        'mitigation': build_mitigation(rule_id, location),
        'references': build_references(rule_id, cwe, owasp),
        'rule_id': rule_id,
        'cwe': cwe
    }

    return threat


def build_mitigation(rule_id: str, location: str) -> List[str]:
    """Build mitigation recommendations based on vulnerability type."""
    mitigation_text = [
        f"**Recommended Fix:**",
        f"1. Review the code at {location}",
        f"2. Apply secure coding practices for this vulnerability type",
    ]

    if "sql" in rule_id.lower() or "injection" in rule_id.lower():
        mitigation_text.extend([
            f"3. Use parameterized queries or prepared statements",
            f"4. Implement input validation and sanitization"
        ])
    elif "xss" in rule_id.lower() or "cross-site" in rule_id.lower():
        mitigation_text.extend([
            f"3. Encode user-supplied data before rendering",
            f"4. Use Content Security Policy (CSP) headers",
            f"5. Implement proper output encoding"
        ])
    elif "command" in rule_id.lower():
        mitigation_text.extend([
            f"3. Avoid shell command execution with user input",
            f"4. Use safe APIs instead of system/shell commands",
            f"5. Implement strict allow-lists for commands"
        ])
    else:
        mitigation_text.append(f"3. Follow security best practices for this vulnerability type")

    return mitigation_text


def build_references(rule_id: str, cwe: str, owasp: str) -> List[str]:
    """Build reference list for the finding."""
    refs = [
        f"Semgrep Rule: {rule_id}"
    ]

    if cwe:
        refs.append(f"CWE: {cwe}")

    if owasp:
        refs.append(f"OWASP: {owasp}")

    # Add general references
    refs.extend([
        "https://semgrep.dev/docs/",
        "https://owasp.org/www-project-top-ten/"
    ])

    return refs


def count_severity(threats: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Count threats by severity level.

    Args:
        threats: List of threat dictionaries

    Returns:
        Dictionary with counts for each severity
    """
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

    for threat in threats:
        severity = threat.get('severity', 'Low')
        if severity in counts:
            counts[severity] += 1

    return counts


def generate_sast_json_report(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate complete JSON report from Semgrep findings.

    Args:
        findings: List of Semgrep result dictionaries

    Returns:
        Complete JSON report dictionary
    """
    # Convert findings to threat dictionaries
    threats = []
    for finding in findings:
        try:
            threat_dict = convert_finding_to_dict(finding)
            threats.append(threat_dict)
        except Exception as e:
            print(f"Warning: Failed to convert finding: {e}", file=sys.stderr)
            continue

    # Count severity
    counts = count_severity(threats)
    total = sum(counts.values())

    # Build report
    report = {
        'report_type': 'SAST Security Scan',
        'system_name': 'SAST Security Scan',
        'analysis_date': datetime.now().strftime('%Y-%m-%d'),
        'summary': {
            'total_threats': total,
            'critical_count': counts['Critical'],
            'high_count': counts['High'],
            'medium_count': counts['Medium'],
            'low_count': counts['Low'],
            'overview': (
                f"SAST scan identified {total} potential code-level security issues. "
                f"Critical: {counts['Critical']}, High: {counts['High']}, "
                f"Medium: {counts['Medium']}, Low: {counts['Low']}. "
                f"These findings represent implementation vulnerabilities detected through static code analysis."
            )
        },
        'threats': threats
    }

    return report


def main():
    """Main entry point."""
    import os

    # Get paths
    script_dir = Path(__file__).parent.parent
    input_path = os.environ.get('SEMGREP_RESULTS_PATH',
                               str(script_dir / 'semgrep.json'))
    output_path = os.environ.get('SAST_OUTPUT_PATH',
                                str(script_dir / 'sast_report.json'))

    print(f"📂 Loading SAST results from: {input_path}")

    # Load results
    results = load_semgrep_results(input_path)
    findings = results.get('results', [])

    if not findings:
        print("✅ No SAST findings detected.")
        # Generate empty report
        findings = []

    print(f"🔍 Found {len(findings)} SAST findings")

    # Generate JSON report
    report = generate_sast_json_report(findings)

    # Save report
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"✅ SAST report saved to: {output_path}")

    # Print summary
    summary = report['summary']
    print(f"\n📊 Severity breakdown:")
    print(f"  Critical: {summary['critical_count']}")
    print(f"  High: {summary['high_count']}")
    print(f"  Medium: {summary['medium_count']}")
    print(f"  Low: {summary['low_count']}")

    # Exit with error if Critical/High found
    if summary['critical_count'] > 0 or summary['high_count'] > 0:
        print("\n⚠️  Critical or High severity findings detected!")
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
