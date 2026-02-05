#!/usr/bin/env python3
"""
Check security report severity and exit accordingly

This script checks a security report XML for Critical/High severity findings
and exits with code 1 if any are found (for CI/CD blocking behavior).
"""

import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def check_severity(xml_path: str, mode: str = 'audit') -> int:
    """
    Check security report severity and determine exit code.

    Args:
        xml_path: Path to security report XML
        mode: Operating mode ('audit' or 'block')

    Returns:
        Exit code (0 for pass, 1 for fail)
    """
    try:
        root = ET.parse(xml_path)
        summary = root.find('Summary')

        if summary is None:
            print("Error: Invalid XML format - missing Summary element", file=sys.stderr)
            return 1

        critical = int(summary.findtext('CriticalCount', '0'))
        high = int(summary.findtext('HighCount', '0'))
        medium = int(summary.findtext('MediumCount', '0'))
        low = int(summary.findtext('LowCount', '0'))
        total = int(summary.findtext('TotalThreats', '0'))

        print("=" * 60)
        print("SECURITY SEVERITY CHECK")
        print("=" * 60)
        print(f"Mode: {mode.upper()}")
        print(f"Total Findings: {total}")
        print(f"Critical: {critical}")
        print(f"High: {high}")
        print(f"Medium: {medium}")
        print(f"Low: {low}")
        print("=" * 60)

        if mode == 'block':
            if critical > 0 or high > 0:
                print(f"\n❌ FAIL: {critical} Critical, {high} High")
                print(f"Build blocked due to Critical/High severity findings")
                return 1
            else:
                print(f"\n✅ PASS: No Critical or High severity findings")
                return 0
        else:  # audit mode
            print(f"\n✅ AUDIT MODE: Report generated, build continues")
            print(f"Total findings: {critical + high + medium + low}")
            return 0

    except FileNotFoundError:
        print(f"Error: Report file not found: {xml_path}", file=sys.stderr)
        return 1
    except ET.ParseError as e:
        print(f"Error: Failed to parse XML: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def main():
    """Main entry point."""
    # Get configuration from environment
    report_path = os.environ.get(
        'SECURITY_REPORT_PATH',
        str(Path(__file__).parent.parent / 'security_report.xml')
    )

    mode = os.environ.get('SECURITY_MODE', 'audit').lower()

    if mode not in ['audit', 'block']:
        print(f"Warning: Invalid SECURITY_MODE '{mode}', defaulting to 'audit'",
              file=sys.stderr)
        mode = 'audit'

    exit(check_severity(report_path, mode))


if __name__ == '__main__':
    main()
