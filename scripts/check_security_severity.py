#!/usr/bin/env python3
"""
Check security report severity and exit accordingly

This script checks a security report JSON for Critical/High severity findings
and exits with code 1 if any are found (for CI/CD blocking behavior).
"""

import os
import sys
import json
from pathlib import Path


def check_severity(json_path: str, mode: str = 'audit') -> int:
    """
    Check security report severity and determine exit code.

    Args:
        json_path: Path to security report JSON
        mode: Operating mode ('audit' or 'block')

    Returns:
        Exit code (0 for pass, 1 for fail)
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            report = json.load(f)

        summary = report.get('summary', {})

        if not summary:
            print("Error: Invalid JSON format - missing summary element", file=sys.stderr)
            return 1

        critical = summary.get('critical_count', 0)
        high = summary.get('high_count', 0)
        medium = summary.get('medium_count', 0)
        low = summary.get('low_count', 0)
        total = summary.get('total_threats', 0)

        print("=" * 60)
        print("SECURITY SEVERITY CHECK")
        print("=" * 60)
        print(f"📄 Report: {json_path}")
        print(f"🔧 Mode: {mode.upper()}")
        print(f"📊 Total Findings: {total}")
        print(f"🔴 Critical: {critical}")
        print(f"🟠 High: {high}")
        print(f"🟡 Medium: {medium}")
        print(f"🟢 Low: {low}")
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
        if mode == 'audit':
            print(f"⚠️  Warning: Report file not found: {json_path}", file=sys.stderr)
            print("=" * 60)
            print("AUDIT MODE: No security report available")
            print("=" * 60)
            print("\n✅ AUDIT MODE: Continuing without security report")
            print("💡 Tip: Check previous workflow steps to see why report wasn't generated")
            return 0
        else:
            print(f"❌ Error: Report file not found: {json_path}", file=sys.stderr)
            print("=" * 60)
            print("BLOCK MODE: Requires security report to proceed")
            print("=" * 60)
            return 1
    except json.JSONDecodeError as e:
        print(f"❌ Error: Failed to parse JSON: {e}", file=sys.stderr)
        print(f"📄 File: {json_path}")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        print(f"📄 File: {json_path}")
        return 1


def main():
    """Main entry point."""
    # Get configuration from environment
    report_path = os.environ.get(
        'SECURITY_REPORT_PATH',
        str(Path(__file__).parent.parent / 'security_report.json')
    )

    mode = os.environ.get('SECURITY_MODE', 'audit').lower()

    if mode not in ['audit', 'block']:
        print(f"⚠️  Warning: Invalid SECURITY_MODE '{mode}', defaulting to 'audit'",
              file=sys.stderr)
        mode = 'audit'

    exit_code = check_severity(report_path, mode)

    # Print report location for clarity
    if exit_code == 0:
        print(f"\n📂 Report location: {report_path}")

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
