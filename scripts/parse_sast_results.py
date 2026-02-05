#!/usr/bin/env python3
"""
Parse Semgrep SAST results from JSON to XML format

This script converts Semgrep JSON output to an XML format compatible
with the threat modeling report structure.
"""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any


def load_semgrep_results(json_path: str) -> Dict[str, Any]:
    """
    Load Semgrep results from JSON file.

    Args:
        json_path: Path to semgrep-results.json

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


def convert_finding_to_xml(finding: Dict[str, Any]) -> ET.Element:
    """
    Convert a single Semgrep finding to XML format.

    Args:
        finding: Single Semgrep result

    Returns:
        XML Element representing the finding
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

    # Create threat element
    threat = ET.Element('Threat')
    threat.set('category', category)
    threat.set('severity', severity)
    threat.set('source', 'code')

    # Build descriptive title from message
    title = message[:100] + "..." if len(message) > 100 else message
    title_elem = ET.SubElement(threat, 'Title')
    title_elem.text = title

    # Component
    component_elem = ET.SubElement(threat, 'Component')
    component_elem.text = location

    # Description
    description_elem = ET.SubElement(threat, 'Description')
    description_lines = [
        f"**Security Issue Detected:** {message}",
        f"",
        f"**Location:** {location}",
        f"**Rule ID:** {rule_id}",
    ]

    if code_snippet:
        description_lines.extend([
            f"**Vulnerable Code:**",
            f"```",
            code_snippet.strip(),
            f"```"
        ])

    if cwe:
        description_lines.append(f"**CWE Reference:** {cwe}")

    if owasp:
        description_lines.append(f"**OWASP Category:** {owasp}")

    description_elem.text = "\n".join(description_lines)

    # Attack scenario (how this could be exploited)
    attack_scenario = ET.SubElement(threat, 'AttackScenario')
    attack_scenario.text = (
        f"An attacker could exploit this vulnerability by crafting malicious input "
        f"that targets the code pattern detected at {location}. This type of vulnerability "
        f"can lead to security breaches depending on the specific issue and context."
    )

    # Impact
    impact_elem = ET.SubElement(threat, 'Impact')
    impact_elem.text = (
        f"Potential security impact includes: data exposure, unauthorized access, "
        f"system compromise, or other security violations depending on the specific "
        f"vulnerability type and execution context."
    )

    # Likelihood
    likelihood_elem = ET.SubElement(threat, 'Likelihood')
    likelihood_elem.text = "Medium" if severity == "Medium" else "High"

    # Mitigation
    mitigation_elem = ET.SubElement(threat, 'Mitigation')
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

    mitigation_elem.text = "\n".join(mitigation_text)

    # References
    references_elem = ET.SubElement(threat, 'References')
    refs = [
        "Semgrep Rule: " + rule_id
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

    references_elem.text = "\n".join(refs)

    # Add technical fields
    rule_id_elem = ET.SubElement(threat, 'RuleID')
    rule_id_elem.text = rule_id

    if cwe:
        cwe_elem = ET.SubElement(threat, 'CWE')
        cwe_elem.text = str(cwe)

    return threat


def count_severity(threats: List[ET.Element]) -> Dict[str, int]:
    """
    Count threats by severity level.

    Args:
        threats: List of threat XML elements

    Returns:
        Dictionary with counts for each severity
    """
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

    for threat in threats:
        severity = threat.get('severity', 'Low')
        if severity in counts:
            counts[severity] += 1

    return counts


def generate_sast_xml_report(findings: List[Dict[str, Any]]) -> str:
    """
    Generate complete XML report from Semgrep findings.

    Args:
        findings: List of Semgrep result dictionaries

    Returns:
        Complete XML string
    """
    # Create root element
    root = ET.Element('ThreatModel')

    # Create summary
    summary = ET.SubElement(root, 'Summary')

    system_name = ET.SubElement(summary, 'SystemName')
    system_name.text = "SAST Security Scan"

    analysis_date = ET.SubElement(summary, 'AnalysisDate')
    from datetime import datetime
    analysis_date.text = datetime.now().strftime('%Y-%m-%d')

    # Convert findings to XML threats
    threats = []
    for finding in findings:
        try:
            threat_xml = convert_finding_to_xml(finding)
            threats.append(threat_xml)
        except Exception as e:
            print(f"Warning: Failed to convert finding: {e}", file=sys.stderr)
            continue

    # Count severity
    counts = count_severity(threats)
    total = sum(counts.values())

    total_threats = ET.SubElement(summary, 'TotalThreats')
    total_threats.text = str(total)

    critical_count = ET.SubElement(summary, 'CriticalCount')
    critical_count.text = str(counts['Critical'])

    high_count = ET.SubElement(summary, 'HighCount')
    high_count.text = str(counts['High'])

    medium_count = ET.SubElement(summary, 'MediumCount')
    medium_count.text = str(counts['Medium'])

    low_count = ET.SubElement(summary, 'LowCount')
    low_count.text = str(counts['Low'])

    overview = ET.SubElement(summary, 'Overview')
    overview.text = (
        f"SAST scan identified {total} potential code-level security issues. "
        f"Critical: {counts['Critical']}, High: {counts['High']}, "
        f"Medium: {counts['Medium']}, Low: {counts['Low']}. "
        f"These findings represent implementation vulnerabilities detected through static code analysis."
    )

    # Add threats section
    threats_element = ET.SubElement(root, 'Threats')
    for threat in threats:
        threats_element.append(threat)

    # Pretty print and return
    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding='unicode')


def main():
    """Main entry point."""
    import os

    # Get paths
    script_dir = Path(__file__).parent.parent
    input_path = os.environ.get('SEMGREP_RESULTS_PATH',
                               str(script_dir / 'semgrep-results.json'))
    output_path = os.environ.get('SAST_OUTPUT_PATH',
                                str(script_dir / 'sast_report.xml'))

    print(f"Loading SAST results from: {input_path}")

    # Load results
    results = load_semgrep_results(input_path)
    findings = results.get('results', [])

    if not findings:
        print("No SAST findings detected.")
        # Generate empty report
        findings = []

    print(f"Found {len(findings)} SAST findings")

    # Generate XML report
    xml_report = generate_sast_xml_report(findings)

    # Save report
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(xml_report)

    print(f"SAST report saved to: {output_path}")

    # Print summary
    counts = count_severity(list(ET.fromstring(xml_report).findall('.//Threat')))
    print(f"Severity breakdown:")
    print(f"  Critical: {counts['Critical']}")
    print(f"  High: {counts['High']}")
    print(f"  Medium: {counts['Medium']}")
    print(f"  Low: {counts['Low']}")

    # Exit with error if Critical/High found
    if counts['Critical'] > 0 or counts['High'] > 0:
        print("\n⚠️  Critical or High severity findings detected!")
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
