#!/usr/bin/env python3
"""
TM_M: Repo-First Intelligent Security Orchestration

Main CLI entry point for automated threat modeling and
security test generation.
"""

import argparse
import os
import sys
from pathlib import Path
from typing import List, Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.utils.detection import detect_tech_stack, detect_frameworks, detect_security_patterns
from src.utils.config import load_config, get_api_key
from src.utils.timestamp import get_timestamp, get_iso_timestamp
from src.scanners.mobile_scanner import MobileScanner
from src.scanners.web_scanner import WebScanner
from src.scanners.backend_scanner import BackendScanner
from src.agents.threat_engine import ThreeAgentThreatEngine
from src.generators.playwright_gen import PlaywrightTestGenerator
from src.generators.flutter_gen import FlutterTestGenerator
from src.generators.fuzzing_gen import FuzzingTestGenerator
from src.generators.report_gen import generate_markdown_report, generate_sarif_report


console = Console()


def print_banner():
    """Print TM_M banner."""
    console.print(Panel.fit(
        "[bold cyan]TM_M[/bold cyan]: [bold white]Repo-First Intelligent Security Orchestration[/bold white]\n"
        "[dim]Automated Threat Modeling & Security Test Generation[/dim]\n\n"
        "Version 2.0.0 | https://github.com/yantongggg/TM_M",
        border_style="cyan"
    ))


def scan_repository(repo_path: str, stacks: List[str]) -> Dict:
    """
    Scan repository using appropriate scanners.

    Args:
        repo_path: Path to repository
        stacks: Detected tech stacks

    Returns:
        Scanning context dictionary
    """
    context = {
        'repo_path': repo_path,
        'tech_stacks': stacks,
        'components': [],
        'dependencies': [],
        'patterns': {}
    }

    with console.status("[bold green]Scanning repository..."):
        # Mobile: Flutter
        if "MOBILE_FLUTTER" in stacks:
            console.print("  [cyan]→[/cyan] Scanning Flutter/Dart mobile app...")
            scanner = MobileScanner(repo_path)
            mobile_context = scanner.scan()
            context['components'].extend(mobile_context['components'])
            context['dependencies'].extend(mobile_context['dependencies'])
            context['patterns'].update(mobile_context['patterns'])

        # Web: JavaScript/TypeScript
        if "WEB_FRONTEND" in stacks:
            console.print("  [cyan]→[/cyan] Scanning JavaScript/TypeScript web app...")
            scanner = WebScanner(repo_path)
            web_context = scanner.scan()
            context['components'].extend(web_context['components'])
            context['dependencies'].extend(web_context['dependencies'])
            context['patterns'].update(web_context['patterns'])

        # Backend: Python/Go/Java
        if "BACKEND_API" in stacks:
            console.print("  [cyan]→[/cyan] Scanning backend API...")
            scanner = BackendScanner(repo_path)
            backend_context = scanner.scan()
            context['components'].extend(backend_context['components'])
            context['dependencies'].extend(backend_context['dependencies'])
            context['patterns'].update(backend_context['patterns'])

    return context


def run_threat_modeling(context: Dict, config: Dict) -> List[Dict]:
    """
    Run AI threat modeling.

    Args:
        context: Scanning context
        config: Configuration dictionary

    Returns:
        List of validated threats
    """
    # Build architecture from context
    architecture = build_architecture_from_context(context)

    # Get API key
    try:
        api_key = get_api_key(config)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    # Run threat modeling
    with console.status("[bold green]Running 3-agent AI threat modeling..."):
        engine = ThreeAgentThreatEngine(
            api_key=api_key,
            base_url=config['api']['base_url']
        )
        threats = engine.run_full_pipeline(architecture)

    return threats


def build_architecture_from_context(context: Dict) -> Dict:
    """
    Build architecture YAML from scanning context.

    Args:
        context: Scanning context

    Returns:
        Architecture dictionary
    """
    frameworks = detect_frameworks(context['repo_path'])

    architecture = {
        'system': {
            'name': frameworks.get('name', 'Unknown System'),
            'description': f"Auto-detected from repository with {', '.join(context['tech_stacks'])}",
            'version': '1.0.0'
        },
        'components': [],
        'data_flows': [],
        'trust_boundaries': [],
        'security_context': {
            'compliance_requirements': [],
            'threat_modeling_scope': ['web_security', 'api_security', 'data_protection'],
            'assumptions': ['Auto-generated from codebase analysis']
        }
    }

    # Add components
    for component in context['components']:
        architecture['components'].append({
            'name': component.get('name', 'Unknown'),
            'type': component.get('type', 'Unknown'),
            'technology': f"{frameworks.get('language', 'Unknown')} / {frameworks.get('framework', 'Unknown')}",
            'description': component.get('description', ''),
            'exposed': True,
            'trust_zone': 'Internet' if component.get('type') in ['Web Application', 'API'] else 'Private Network'
        })

    # Add data flows based on patterns
    if context['patterns'].get('network_calls'):
        architecture['data_flows'].append({
            'source': 'Client',
            'destination': 'Backend API',
            'protocol': 'HTTPS',
            'data_type': 'JSON data',
            'authentication': 'JWT / OAuth'
        })

    # Add trust boundaries
    architecture['trust_boundaries'].append({
        'name': 'Internet-to-Application',
        'type': 'Network Boundary',
        'description': 'Boundary between external users and application',
        'controls': ['WAF', 'Rate Limiting', 'Authentication']
    })

    return architecture


def generate_tests(threats: List[Dict], repo_path: str, stacks: List[str]) -> Dict[str, int]:
    """
    Generate security test code.

    Args:
        threats: List of validated threats
        repo_path: Path to repository
        stacks: Detected tech stacks

    Returns:
        Dictionary with test generation counts
    """
    generated = {
        'playwright': 0,
        'flutter': 0,
        'fuzzing': 0,
        'total': 0
    }

    with console.status("[bold green]Generating security tests..."):
        # Mobile: Flutter tests
        if "MOBILE_FLUTTER" in stacks and threats:
            console.print("  [cyan]→[/cyan] Generating Flutter integration tests...")
            gen = FlutterTestGenerator(threats, repo_path)
            tests = gen.generate_tests()
            generated['flutter'] = len(tests)
            generated['total'] += len(tests)

        # Web: Playwright tests
        if "WEB_FRONTEND" in stacks and threats:
            console.print("  [cyan]→[/cyan] Generating Playwright security tests...")
            gen = PlaywrightTestGenerator(threats, repo_path)
            tests = gen.generate_tests()
            generated['playwright'] = len(tests)
            generated['total'] += len(tests)

        # Backend: Fuzzing tests
        if "BACKEND_API" in stacks and threats:
            console.print("  [cyan]→[/cyan] Generating API fuzzing tests...")
            gen = FuzzingTestGenerator(threats, repo_path)
            tests = gen.generate_tests()
            generated['fuzzing'] = len(tests)
            generated['total'] += len(tests)

    return generated


def generate_reports(
    threats: List[Dict],
    repo_path: str,
    output_dir: Path,
    config: Dict
) -> Dict[str, str]:
    """
    Generate security reports.

    Args:
        threats: List of validated threats
        repo_path: Path to repository
        output_dir: Output directory
        config: Configuration dictionary

    Returns:
        Dictionary with report paths
    """
    reports = {}

    timestamp = get_timestamp()
    iso_timestamp = get_iso_timestamp()

    with console.status("[bold green]Generating security reports..."):
        # Markdown report
        if 'markdown' in config['output']['formats']:
            md_path = output_dir / f"threat_model_{timestamp}.md"
            generate_markdown_report(
                threats,
                repo_path,
                str(md_path),
                tool_version="2.0.0"
            )
            reports['markdown'] = str(md_path)

        # SARIF report
        if 'sarif' in config['output']['formats']:
            sarif_path = output_dir / f"security_scan_{timestamp}.sarif"
            generate_sarif_report(
                threats,
                repo_path,
                str(sarif_path),
                tool_name="TM_M Threat Modeling",
                tool_version="2.0.0"
            )
            reports['sarif'] = str(sarif_path)

    return reports


def print_summary(threats: List[Dict], generated: Dict, reports: Dict, repo_path: Path):
    """Print execution summary."""
    console.print("\n")

    # Threats summary
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for threat in threats:
        severity = threat.get('severity', 'Low')
        if severity in severity_counts:
            severity_counts[severity] += 1

    threats_table = Table(title="Threats Detected", show_header=True, header_style="bold magenta")
    threats_table.add_column("Severity", style="cyan")
    threats_table.add_column("Count", justify="right")

    for severity, count in severity_counts.items():
        emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}[severity]
        threats_table.add_row(f"{emoji} {severity}", str(count))

    console.print(threats_table)

    # Tests generated
    if generated['total'] > 0:
        console.print("\n")
        tests_table = Table(title="Tests Generated", show_header=True, header_style="bold green")
        tests_table.add_column("Type", style="cyan")
        tests_table.add_column("Count", justify="right")

        if generated['playwright'] > 0:
            tests_table.add_row("Playwright (Web)", str(generated['playwright']))
        if generated['flutter'] > 0:
            tests_table.add_row("Flutter (Mobile)", str(generated['flutter']))
        if generated['fuzzing'] > 0:
            tests_table.add_row("Fuzzing (API)", str(generated['fuzzing']))

        tests_table.add_row("Bold", f"[bold]{generated['total']}[/bold]")
        console.print(tests_table)

    # Reports
    console.print("\n[bold]Reports Generated:[/bold]")
    for report_type, report_path in reports.items():
        console.print(f"  [cyan]•[/cyan] {report_type.upper()}: {report_path}")

    console.print(f"\n[bold]Tests Directory:[/bold]")
    console.print(f"  [cyan]•[/cyan] {repo_path}/tests/security/")

    console.print("\n[green]✓[/green] TM_M analysis complete!")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="TM_M: Automated Threat Modeling & Security Test Generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze current directory
  python src/main.py

  # Analyze specific repository
  python src/main.py --repo-path /path/to/repo

  # Generate tests
  python src/main.py --generate-tests

  # Use custom config
  python src/main.py --config my_config.yaml

  # Specify API key
  python src/main.py --api-key YOUR_API_KEY
        """
    )

    parser.add_argument(
        "--repo-path",
        type=str,
        default=".",
        help="Path to target repository (default: current directory)"
    )

    parser.add_argument(
        "--api-key",
        type=str,
        help="LLM API key (or set ZHIPU_API_KEY env var)"
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default="tm_m_reports",
        help="Output directory for reports (default: tm_m_reports/)"
    )

    parser.add_argument(
        "--config",
        type=str,
        default="tm_m_config.yaml",
        help="Configuration file (default: tm_m_config.yaml)"
    )

    parser.add_argument(
        "--generate-tests",
        action="store_true",
        help="Generate executable security test code"
    )

    parser.add_argument(
        "--no-sarif",
        action="store_true",
        help="Skip SARIF report generation"
    )

    args = parser.parse_args()

    # Print banner
    print_banner()

    # Load configuration
    config = load_config(args.config)

    # Override API key if provided
    if args.api_key:
        config['api']['key'] = args.api_key

    # Adjust output formats
    if args.no_sarif:
        config['output']['formats'] = ['markdown']

    # Resolve paths
    repo_path = Path(args.repo_path).resolve()
    output_dir = Path(args.output_dir).resolve()

    if not repo_path.exists():
        console.print(f"[red]Error:[/red] Repository path not found: {repo_path}")
        sys.exit(1)

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"\n[bold]Analyzing:[/bold] {repo_path}")
    console.print(f"[bold]Output:[/bold] {output_dir}\n")

    # Step 1: Detect tech stack
    console.print("[bold cyan]Step 1:[/bold cyan] Detecting technology stack...")
    stacks = detect_tech_stack(str(repo_path))
    if not stacks:
        console.print("[yellow]⚠[/yellow] No recognized technology stacks found")
        console.print("[dim]Supported: Flutter (pubspec.yaml), Web (package.json), Backend (requirements.txt/go.mod/pom.xml)[/dim]")
        sys.exit(1)

    for stack in stacks:
        console.print(f"  [green]✓[/green] {stack}")
    console.print("")

    # Step 2: Scan repository
    console.print("[bold cyan]Step 2:[/bold cyan] Scanning repository...")
    context = scan_repository(str(repo_path), stacks)
    console.print(f"  [green]✓[/green] Found {len(context['components'])} components")
    console.print(f"  [green]✓[/green] Found {len(context['dependencies'])} dependencies")
    console.print("")

    # Step 3: Threat modeling
    console.print("[bold cyan]Step 3:[/bold cyan] Performing AI threat modeling...")
    threats = run_threat_modeling(context, config)
    console.print(f"  [green]✓[/green] Found {len(threats)} threats\n")

    if not threats:
        console.print("[yellow]⚠[/yellow] No threats detected")
        sys.exit(0)

    # Step 4: Generate tests (if requested)
    generated = {'playwright': 0, 'flutter': 0, 'fuzzing': 0, 'total': 0}
    if args.generate_tests:
        console.print("[bold cyan]Step 4:[/bold cyan] Generating security tests...")
        generated = generate_tests(threats, str(repo_path), stacks)
        console.print(f"  [green]✓[/green] Generated {generated['total']} tests\n")
    else:
        console.print("[dim]Step 4: Skipped (use --generate-tests to enable)[/dim]\n")

    # Step 5: Generate reports
    console.print("[bold cyan]Step 5:[/bold cyan] Generating reports...")
    reports = generate_reports(threats, str(repo_path), output_dir, config)
    console.print("")

    # Print summary
    print_summary(threats, generated, reports, repo_path)

    # Exit with error if Critical/High threats found
    critical_high = sum(1 for t in threats if t.get('severity') in ['Critical', 'High'])
    if critical_high > 0:
        console.print(f"\n[red]⚠ {critical_high} Critical/High severity threats detected[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
