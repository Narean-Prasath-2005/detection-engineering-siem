#!/usr/bin/env python3
"""
coverage_analysis.py

Analyze MITRE ATT&CK coverage from detection rules.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.detector import load_rules
from core.mitre_attack import get_mitre_attack
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

console = Console()


def analyze_coverage():
    """Analyze detection coverage against MITRE ATT&CK."""

    console.print(Panel.fit(
        "[bold cyan]MITRE ATT&CK Coverage Analysis[/bold cyan]",
        border_style="cyan"
    ))

    # Load MITRE framework
    console.print("\n[cyan]Loading MITRE ATT&CK framework...[/cyan]")
    mitre = get_mitre_attack()

    if not mitre.data:
        console.print("[red]✗ MITRE ATT&CK framework not loaded[/red]")
        console.print("[yellow]Run: python core/mitre_attack.py --download[/yellow]")
        return

    console.print(f"[green]✓ Loaded {len(mitre.get_all_techniques())} techniques, {len(mitre.get_all_tactics())} tactics[/green]")

    # Load detection rules
    console.print("\n[cyan]Loading detection rules...[/cyan]")
    rules = load_rules("rules/")
    console.print(f"[green]✓ Loaded {len(rules)} detection rules[/green]")

    # Generate coverage matrix
    console.print("\n[cyan]Calculating coverage...[/cyan]")
    coverage = mitre.get_coverage_matrix(rules)

    # Overall statistics
    console.print("\n" + "="*70)
    console.print(Panel.fit(
        f"[bold white]Overall Coverage Statistics[/bold white]\n\n"
        f"[cyan]Total MITRE Techniques:[/cyan] {coverage['total_techniques']}\n"
        f"[green]Techniques Detected:[/green] {coverage['detected_techniques']}\n"
        f"[yellow]Techniques Missing:[/yellow] {coverage['missing_count']}\n"
        f"[bold]Coverage:[/bold] [{'green' if coverage['coverage_percent'] > 10 else 'yellow'}]{coverage['coverage_percent']:.1f}%[/]",
        border_style="cyan"
    ))

    # Coverage by tactic
    console.print("\n[bold white]Coverage by MITRE Tactic[/bold white]\n")

    table = Table(title="Tactic Coverage")
    table.add_column("Tactic", style="cyan", no_wrap=False)
    table.add_column("Detected", style="green", justify="right")
    table.add_column("Total", style="white", justify="right")
    table.add_column("Coverage", style="yellow", justify="right")
    table.add_column("Bar", style="bold")

    tactic_coverage = coverage['by_tactic']

    for tactic_id in sorted(tactic_coverage.keys()):
        tactic_data = tactic_coverage[tactic_id]

        detected = tactic_data['detected_techniques']
        total = tactic_data['total_techniques']
        percent = tactic_data['coverage_percent']

        # Coverage bar
        bar_length = int(percent / 5)  # 20 chars = 100%
        bar = "█" * bar_length + "░" * (20 - bar_length)

        # Color based on coverage
        if percent >= 50:
            color = "green"
        elif percent >= 20:
            color = "yellow"
        else:
            color = "red"

        table.add_row(
            tactic_data['name'][:30],
            str(detected),
            str(total),
            f"[{color}]{percent:.1f}%[/{color}]",
            f"[{color}]{bar}[/{color}]"
        )

    console.print(table)

    # Detected techniques
    console.print("\n[bold white]Detected Techniques[/bold white]")

    if coverage['detected_ids']:
        detected_table = Table(title=f"Your {len(coverage['detected_ids'])} Detections")
        detected_table.add_column("ID", style="cyan")
        detected_table.add_column("Name", style="green")
        detected_table.add_column("Tactics", style="yellow")

        for technique_id in sorted(coverage['detected_ids']):
            name = mitre.get_technique_name(technique_id)
            tactics = ', '.join(mitre.get_technique_tactics(technique_id))

            detected_table.add_row(
                technique_id,
                name[:50],
                tactics
            )

        console.print(detected_table)
    else:
        console.print("[yellow]No techniques detected yet[/yellow]")

    # Gap analysis - show missing critical techniques
    console.print("\n[bold white]Gap Analysis - High-Priority Missing Techniques[/bold white]")

    # Common/critical techniques to prioritize
    critical_techniques = [
        "T1003",      # OS Credential Dumping
        "T1059",      # Command and Scripting Interpreter
        "T1071",      # Application Layer Protocol
        "T1078",      # Valid Accounts
        "T1082",      # System Information Discovery
        "T1083",      # File and Directory Discovery
        "T1087",      # Account Discovery
        "T1110",      # Brute Force
        "T1135",      # Network Share Discovery
        "T1204",      # User Execution
        "T1486",      # Data Encrypted for Impact
        "T1566",      # Phishing
    ]

    missing_critical = []
    for tech_id in critical_techniques:
        if tech_id not in coverage['detected_ids']:
            # Check if any sub-techniques are covered
            subtechniques = mitre.get_technique_subtechniques(tech_id)
            covered_subs = [st for st in subtechniques if st in coverage['detected_ids']]

            if not covered_subs:
                missing_critical.append(tech_id)

    if missing_critical:
        gap_table = Table(title="High-Priority Gaps (Commonly Exploited)")
        gap_table.add_column("ID", style="red")
        gap_table.add_column("Name", style="yellow")
        gap_table.add_column("Tactics", style="cyan")

        for tech_id in missing_critical[:10]:  # Show top 10
            name = mitre.get_technique_name(tech_id)
            tactics = ', '.join(mitre.get_technique_tactics(tech_id))

            gap_table.add_row(tech_id, name[:50], tactics)

        console.print(gap_table)
    else:
        console.print("[green]✓ All high-priority techniques covered![/green]")

    # Export option
    console.print("\n[dim]Tip: Use --export to save coverage report to JSON[/dim]")


def export_coverage(filename: str = "coverage_report.json"):
    """Export coverage report to JSON."""
    import json

    mitre = get_mitre_attack()
    rules = load_rules("rules/")
    coverage = mitre.get_coverage_matrix(rules)

    with open(filename, 'w') as f:
        json.dump(coverage, f, indent=2)

    console.print(f"[green]✓ Coverage report exported to {filename}[/green]")


def show_technique_details(technique_id: str):
    """Show detailed information about a specific technique."""

    mitre = get_mitre_attack()
    technique = mitre.get_technique(technique_id)

    if not technique:
        console.print(f"[red]✗ Technique {technique_id} not found[/red]")
        return

    console.print(Panel.fit(
        f"[bold cyan]{technique.get('name')}[/bold cyan]\n"
        f"[yellow]ID:[/yellow] {technique_id}\n"
        f"[yellow]Tactics:[/yellow] {', '.join(mitre.get_technique_tactics(technique_id))}",
        title=f"Technique Details",
        border_style="cyan"
    ))

    console.print(f"\n[bold]Description:[/bold]")
    console.print(technique.get('description', 'No description available'))

    # Sub-techniques
    subtechniques = mitre.get_technique_subtechniques(technique_id)
    if subtechniques:
        console.print(f"\n[bold]Sub-techniques ({len(subtechniques)}):[/bold]")
        for st in subtechniques:
            name = mitre.get_technique_name(st)
            console.print(f"  • {st} - {name}")

    console.print(f"\n[cyan]URL:[/cyan] https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Coverage Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show coverage analysis
  python coverage_analysis.py

  # Export coverage report
  python coverage_analysis.py --export coverage.json

  # Show technique details
  python coverage_analysis.py --technique T1059.001
        """
    )

    parser.add_argument(
        '--export',
        metavar='FILE',
        help='Export coverage report to JSON file'
    )

    parser.add_argument(
        '--technique',
        metavar='ID',
        help='Show details for specific technique'
    )

    args = parser.parse_args()

    if args.export:
        export_coverage(args.export)
    elif args.technique:
        show_technique_details(args.technique)
    else:
        analyze_coverage()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)
