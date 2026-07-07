#!/usr/bin/env python3
"""
query_alerts.py

CLI tool for querying and analyzing stored alerts.
"""

import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.storage import AlertStorage
from rich.console import Console
from rich.table import Table
from rich.panel import Panel


console = Console()


def display_alerts(alerts):
    """Display alerts in a formatted table."""

    if not alerts:
        console.print("[yellow]No alerts found.[/yellow]")
        return

    table = Table(title=f"Detection Alerts ({len(alerts)} results)")

    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Timestamp", style="green")
    table.add_column("Severity", style="bold")
    table.add_column("Rule", style="blue")
    table.add_column("Hostname", style="magenta")
    table.add_column("MITRE", style="yellow")

    for alert in alerts:
        # Color code severity
        severity = alert["severity"]
        if severity == "critical":
            severity_str = f"[red bold]{severity}[/red bold]"
        elif severity == "high":
            severity_str = f"[orange1]{severity}[/orange1]"
        elif severity == "medium":
            severity_str = f"[yellow]{severity}[/yellow]"
        else:
            severity_str = f"[green]{severity}[/green]"

        # Format MITRE info
        mitre_str = alert.get("mitre_attack_id", "N/A")

        table.add_row(
            str(alert["id"]),
            alert["timestamp"][:19] if alert["timestamp"] else "N/A",
            severity_str,
            alert["title"][:40],
            alert.get("hostname", "N/A"),
            mitre_str
        )

    console.print(table)


def display_statistics(stats):
    """Display alert statistics."""

    console.print("\n")
    console.print(Panel.fit(
        f"[bold cyan]Total Alerts:[/bold cyan] {stats['total_alerts']}",
        title="📊 Alert Statistics"
    ))

    # Severity breakdown
    console.print("\n[bold]By Severity:[/bold]")
    for severity, count in sorted(stats["by_severity"].items(), key=lambda x: x[1], reverse=True):
        console.print(f"  • {severity.capitalize()}: {count}")

    # Top rules
    if stats["top_rules"]:
        console.print("\n[bold]Top Detection Rules:[/bold]")
        for idx, rule in enumerate(stats["top_rules"], 1):
            console.print(f"  {idx}. {rule['title']} ({rule['count']} alerts)")

    # MITRE tactics
    if stats["by_tactic"]:
        console.print("\n[bold]By MITRE Tactic:[/bold]")
        for tactic, count in sorted(stats["by_tactic"].items(), key=lambda x: x[1], reverse=True):
            console.print(f"  • {tactic}: {count}")


def display_alert_detail(alert):
    """Display detailed information about a single alert."""

    console.print(Panel.fit(
        f"[bold cyan]{alert['title']}[/bold cyan]\n"
        f"[yellow]Rule ID:[/yellow] {alert['rule_id']}\n"
        f"[yellow]Severity:[/yellow] {alert['severity']}",
        title=f"Alert #{alert['id']}"
    ))

    console.print("\n[bold]Event Details:[/bold]")
    console.print(f"  Timestamp: {alert['timestamp']}")
    console.print(f"  Hostname: {alert.get('hostname', 'N/A')}")
    console.print(f"  User: {alert.get('username', 'N/A')}")
    console.print(f"  Process: {alert.get('process_name', 'N/A')}")

    if alert.get('command_line'):
        console.print(f"\n[bold]Command Line:[/bold]\n  {alert['command_line']}")

    console.print("\n[bold]MITRE ATT&CK:[/bold]")
    console.print(f"  Tactic: {alert.get('mitre_tactic', 'N/A')}")
    console.print(f"  Technique: {alert.get('mitre_technique', 'N/A')}")
    console.print(f"  Attack ID: {alert.get('mitre_attack_id', 'N/A')}")

    # Show full event data as JSON
    if alert.get('event_data'):
        console.print("\n[bold]Full Event Data:[/bold]")
        try:
            event_data = json.loads(alert['event_data'])
            console.print_json(data=event_data)
        except:
            console.print(alert['event_data'])


def main():
    parser = argparse.ArgumentParser(
        description="Query and analyze detection alerts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show last 20 alerts
  python query_alerts.py

  # Show critical alerts only
  python query_alerts.py --severity critical

  # Show alerts from last 24 hours
  python query_alerts.py --last 24h

  # Show alerts for specific rule
  python query_alerts.py --rule DET-0001

  # Show statistics
  python query_alerts.py --stats

  # Show alert details
  python query_alerts.py --id 42
        """
    )

    parser.add_argument(
        "--db",
        default="siem.db",
        help="Database path (default: siem.db)"
    )

    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        help="Filter by severity level"
    )

    parser.add_argument(
        "--rule",
        help="Filter by rule ID"
    )

    parser.add_argument(
        "--last",
        help="Show alerts from last N hours/days (e.g., 24h, 7d)"
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of results (default: 20)"
    )

    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show alert statistics"
    )

    parser.add_argument(
        "--id",
        type=int,
        help="Show detailed info for specific alert ID"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON"
    )

    args = parser.parse_args()

    # Open database
    storage = AlertStorage(args.db)

    try:
        # Show statistics
        if args.stats:
            stats = storage.get_alert_statistics()
            if args.json:
                print(json.dumps(stats, indent=2))
            else:
                display_statistics(stats)
            return

        # Show specific alert detail
        if args.id:
            alerts = storage.query_alerts(limit=1000)  # Get all to find by ID
            alert = next((a for a in alerts if a["id"] == args.id), None)

            if not alert:
                console.print(f"[red]Alert ID {args.id} not found.[/red]")
                return

            if args.json:
                print(json.dumps(alert, indent=2))
            else:
                display_alert_detail(alert)
            return

        # Parse time range
        start_time = None
        if args.last:
            unit = args.last[-1].lower()
            value = int(args.last[:-1])

            if unit == 'h':
                delta = timedelta(hours=value)
            elif unit == 'd':
                delta = timedelta(days=value)
            else:
                console.print("[red]Invalid time format. Use 24h or 7d[/red]")
                return

            start_time = (datetime.utcnow() - delta).isoformat()

        # Query alerts
        alerts = storage.query_alerts(
            severity=args.severity,
            rule_id=args.rule,
            start_time=start_time,
            limit=args.limit
        )

        if args.json:
            print(json.dumps(alerts, indent=2))
        else:
            display_alerts(alerts)

    finally:
        storage.close()


if __name__ == "__main__":
    main()
