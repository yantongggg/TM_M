#!/usr/bin/env python3
"""
Aggregate SAST and Threat Modeling results into unified security report

This script merges design-level threats from STRIDE analysis with
code-level threats from SAST scanning into a single unified report.
"""

import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional
from datetime import datetime


def parse_xml_file(xml_path: str) -> Optional[ET.ElementTree]:
    """
    Parse an XML file and return the root element.

    Args:
        xml_path: Path to XML file

    Returns:
        Parsed XML root element, or None if file doesn't exist
    """
    try:
        tree = ET.parse(xml_path)
        return tree.getroot()
    except FileNotFoundError:
        print(f"Warning: File not found: {xml_path}", file=sys.stderr)
        return None
    except ET.ParseError as e:
        print(f"Error: Failed to parse XML {xml_path}: {e}", file=sys.stderr)
        return None


def extract_summary_counts(root: ET.Element) -> dict:
    """
    Extract summary counts from XML report.

    Args:
        root: XML root element

    Returns:
        Dictionary with summary counts
    """
    summary = root.find('Summary')
    if summary is None:
        return {
            'total': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

    return {
        'total': int(summary.findtext('TotalThreats', '0')),
        'critical': int(summary.findtext('CriticalCount', '0')),
        'high': int(summary.findtext('HighCount', '0')),
        'medium': int(summary.findtext('MediumCount', '0')),
        'low': int(summary.findtext('LowCount', '0'))
    }


def merge_threats(design_root: Optional[ET.Element],
                 sast_root: Optional[ET.Element]) -> List[ET.Element]:
    """
    Merge threats from design and SAST reports.

    Args:
        design_root: Design threat model XML root (or None)
        sast_root: SAST scan XML root (or None)

    Returns:
        List of merged threat elements
    """
    all_threats = []

    # Add design-level threats
    if design_root is not None:
        design_threats = design_root.find('Threats')
        if design_threats is not None:
            for threat in design_threats.findall('Threat'):
                # Ensure source attribute is set
                if threat.get('source') is None:
                    threat.set('source', 'design')
                all_threats.append(threat)

    # Add code-level threats (SAST)
    if sast_root is not None:
        sast_threats = sast_root.find('Threats')
        if sast_threats is not None:
            for threat in sast_threats.findall('Threat'):
                # Ensure source attribute is set
                if threat.get('source') is None:
                    threat.set('source', 'code')
                all_threats.append(threat)

    return all_threats


def count_threats_by_severity_and_source(threats: List[ET.Element]) -> dict:
    """
    Count threats by severity and source.

    Args:
        threats: List of threat elements

    Returns:
        Dictionary with detailed counts
    """
    counts = {
        'total': len(threats),
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'design_threats': 0,
        'code_threats': 0
    }

    for threat in threats:
        severity = threat.get('severity', 'Low')
        if severity in ['critical', 'Critical']:
            counts['critical'] += 1
        elif severity in ['high', 'High']:
            counts['high'] += 1
        elif severity in ['medium', 'Medium']:
            counts['medium'] += 1
        elif severity in ['low', 'Low']:
            counts['low'] += 1

        source = threat.get('source', 'unknown')
        if source == 'design':
            counts['design_threats'] += 1
        elif source == 'code':
            counts['code_threats'] += 1

    return counts


def generate_unified_report(design_root: Optional[ET.Element],
                           sast_root: Optional[ET.Element],
                           system_name: str = "Unified Security Assessment") -> str:
    """
    Generate unified security report.

    Args:
        design_root: Design threat model XML root (or None)
        sast_root: SAST scan XML root (or None)
        system_name: Name for the unified system

    Returns:
        Unified XML string
    """
    # Merge threats
    threats = merge_threats(design_root, sast_root)
    counts = count_threats_by_severity_and_source(threats)

    # Create unified XML
    root = ET.Element('ThreatModel')

    # Create summary
    summary = ET.SubElement(root, 'Summary')

    system_name_elem = ET.SubElement(summary, 'SystemName')
    system_name_elem.text = system_name

    analysis_date = ET.SubElement(summary, 'AnalysisDate')
    analysis_date.text = datetime.now().strftime('%Y-%m-%d')

    total_threats = ET.SubElement(summary, 'TotalThreats')
    total_threats.text = str(counts['total'])

    critical_count = ET.SubElement(summary, 'CriticalCount')
    critical_count.text = str(counts['critical'])

    high_count = ET.SubElement(summary, 'HighCount')
    high_count.text = str(counts['high'])

    medium_count = ET.SubElement(summary, 'MediumCount')
    medium_count.text = str(counts['medium'])

    low_count = ET.SubElement(summary, 'LowCount')
    low_count.text = str(counts['low'])

    # Add source breakdown
    design_threats_elem = ET.SubElement(summary, 'DesignThreats')
    design_threats_elem.text = str(counts['design_threats'])

    code_threats_elem = ET.SubElement(summary, 'CodeThreats')
    code_threats_elem.text = str(counts['code_threats'])

    # Create overview
    overview = ET.SubElement(summary, 'Overview')
    overview_parts = [
        f"Unified security assessment combining design-level threat modeling "
        f"and code-level static analysis (SAST).",
        f"",
        f"**Summary:** {counts['total']} total security findings identified",
        f"- Design-level threats (STRIDE): {counts['design_threats']}",
        f"- Code-level threats (SAST): {counts['code_threats']}",
        f"",
        f"**Severity Distribution:**",
        f"- Critical: {counts['critical']}",
        f"- High: {counts['high']}",
        f"- Medium: {counts['medium']}",
        f"- Low: {counts['low']}"
    ]

    if counts['critical'] > 0 or counts['high'] > 0:
        overview_parts.extend([
            f"",
            f"⚠️ **ATTENTION REQUIRED:** {counts['critical'] + counts['high']} "
            f"Critical/High severity findings need immediate remediation."
        ])

    overview.text = "\n".join(overview_parts)

    # Add threats section
    threats_element = ET.SubElement(root, 'Threats')

    # Sort threats by severity (Critical first, then High, Medium, Low)
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}

    def sort_key(threat):
        severity = threat.get('severity', 'Low')
        return severity_order.get(severity, 99)

    threats.sort(key=sort_key)

    for threat in threats:
        threats_element.append(threat)

    # Pretty print and return
    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding='unicode')


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Aggregate design and code-level security findings'
    )
    parser.add_argument(
        '--design-report',
        default=None,
        help='Path to design threat model XML (threat_report.xml)'
    )
    parser.add_argument(
        '--sast-report',
        default=None,
        help='Path to SAST scan XML (sast_report.xml)'
    )
    parser.add_argument(
        '--output',
        default=None,
        help='Path to output unified report (security_report.xml)'
    )
    parser.add_argument(
        '--system-name',
        default='Unified Security Assessment',
        help='Name for the unified system'
    )

    args = parser.parse_args()

    # Get paths from args or environment
    script_dir = Path(__file__).parent.parent

    design_report_path = args.design_report or os.environ.get(
        'DESIGN_REPORT_PATH',
        str(script_dir / 'threat_report.xml')
    )

    sast_report_path = args.sast_report or os.environ.get(
        'SAST_REPORT_PATH',
        str(script_dir / 'sast_report.xml')
    )

    output_path = args.output or os.environ.get(
        'UNIFIED_REPORT_PATH',
        str(script_dir / 'security_report.xml')
    )

    print("=" * 60)
    print("AGGREGATING SECURITY RESULTS")
    print("=" * 60)
    print(f"Design report: {design_report_path}")
    print(f"SAST report: {sast_report_path}")
    print(f"Output: {output_path}")
    print("=" * 60)

    # Parse XML files
    print("\nLoading reports...")
    design_root = parse_xml_file(design_report_path)
    sast_root = parse_xml_file(sast_report_path)

    if design_root is None and sast_root is None:
        print("Error: No valid reports found to aggregate", file=sys.stderr)
        sys.exit(1)

    # Generate unified report
    print("\nGenerating unified report...")
    unified_xml = generate_unified_report(
        design_root,
        sast_root,
        args.system_name
    )

    # Save unified report
    print(f"Saving unified report to: {output_path}")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(unified_xml)

    # Parse and display summary
    root = ET.fromstring(unified_xml)
    summary = root.find('Summary')

    print("\n" + "=" * 60)
    print("UNIFIED SECURITY SUMMARY")
    print("=" * 60)

    for child in summary:
        if child.tag in ['TotalThreats', 'CriticalCount', 'HighCount',
                        'MediumCount', 'LowCount', 'DesignThreats', 'CodeThreats']:
            print(f"{child.tag}: {child.text}")

    # Check severity for CI exit code
    critical = int(summary.findtext('CriticalCount', '0'))
    high = int(summary.findtext('HighCount', '0'))

    print("\n" + "=" * 60)
    if critical > 0 or high > 0:
        print(f"❌ FAIL: {critical} Critical, {high} High severity findings")
        print("=" * 60)
        sys.exit(1)
    else:
        print(f"✅ PASS: No Critical or High severity findings")
        print("=" * 60)
        sys.exit(0)


if __name__ == '__main__':
    main()
