#!/usr/bin/env python3
"""
main.py

Detection Engineering SIEM - Main entry point
Enhanced detection engine with persistent storage and improved matching.
"""

import argparse
import json
import sys
from pathlib import Path

from core.detector import load_rules, match_rule, generate_alert, detect_event
from core.storage import AlertStorage
from core.mitre_attack import get_mitre_attack
from parsers.windows_parser import normalize_windows_event
from parsers.auditd_parser import parse_audit_event
from rich.console import Console
from rich.panel import Panel


console = Console()


def detect_and_store(event, rules, storage, source="unknown", mitre=None):
    """
    Run detection on an event and store results.

    Args:
        event: Normalized event dictionary
        rules: List of detection rules
        storage: AlertStorage instance
        source: Event source (windows, auditd, etc.)
        mitre: MITRE ATT&CK instance for enrichment

    Returns:
        List of generated alerts
    """
    alerts = []

    for rule in rules:
        if match_rule(event, rule):
            alert = generate_alert(event, rule)

            # Enrich with MITRE data if available
            if mitre:
                alert = mitre.enrich_alert(alert)

            alerts.append(alert)

            # Store alert in database
            alert_id = storage.store_alert(alert)

            # Update rule metrics
            storage.update_rule_metrics(rule.get("id"), matched=True)

            console.print(f"[green]✓[/green] Alert #{alert_id} generated: {alert['title']}")
        else:
            # Track execution even without match
            storage.update_rule_metrics(rule.get("id"), matched=False)

    # Store raw event
    storage.store_event(event, source=source)

    return alerts


def display_alert(alert):
    """Display alert in formatted output."""
    console.print(Panel.fit(
        f"[bold red]{alert['title']}[/bold red]\n\n"
        f"[yellow]Rule ID:[/yellow] {alert['rule_id']}\n"
        f"[yellow]Severity:[/yellow] {alert['severity']}\n"
        f"[yellow]Hostname:[/yellow] {alert.get('hostname', 'N/A')}\n"
        f"[yellow]User:[/yellow] {alert.get('user', 'N/A')}\n\n"
        f"[cyan]MITRE ATT&CK:[/cyan]\n"
        f"  Tactic: {alert.get('mitre_tactic', 'N/A')}\n"
        f"  Technique: {alert.get('mitre_technique', 'N/A')}\n"
        f"  Attack ID: {alert.get('mitre_attack_id', 'N/A')}\n\n"
        f"[cyan]Process:[/cyan] {alert.get('process_name', 'N/A')}\n"
        f"[cyan]Command:[/cyan] {alert.get('command_line', 'N/A')[:80]}",
        title="🚨 SECURITY ALERT",
        border_style="red"
    ))


def process_windows_events(events_file, storage, mitre=None):
    """Process Windows event log JSON file."""
    console.print(f"[cyan]Processing Windows events from:[/cyan] {events_file}")

    with open(events_file, "r") as f:
        events = json.load(f)

    rules = load_rules()
    console.print(f"[cyan]Loaded {len(rules)} detection rules[/cyan]\n")

    alert_count = 0

    for raw_event in events:
        try:
            # Filter for process creation events
            event_id = raw_event["Event"]["System"]["EventID"]["#text"]

            if event_id == "4688":
                event = normalize_windows_event(raw_event)
                alerts = detect_and_store(event, rules, storage, source="windows", mitre=mitre)

                for alert in alerts:
                    display_alert(alert)
                    alert_count += 1

        except Exception as e:
            console.print(f"[yellow]Warning: Failed to process event: {e}[/yellow]")

    console.print(f"\n[bold green]Detection Complete[/bold green]")
    console.print(f"Total alerts generated: {alert_count}")


def process_auditd_logs(log_file, storage, mitre=None):
    """Process Linux auditd log file."""
    console.print(f"[cyan]Processing auditd logs from:[/cyan] {log_file}")

    with open(log_file, "r") as f:
        logs = f.readlines()

    event = parse_audit_event(logs)
    rules = load_rules()

    console.print(f"[cyan]Loaded {len(rules)} detection rules[/cyan]\n")

    alerts = detect_and_store(event, rules, storage, source="auditd", mitre=mitre)

    for alert in alerts:
        display_alert(alert)

    console.print(f"\n[bold green]Detection Complete[/bold green]")
    console.print(f"Total alerts generated: {len(alerts)}")


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Detection Engineering SIEM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process Windows events
  python main_enhanced.py --windows samples/normalized/windows/.../events.json

  # Process Linux auditd logs
  python main_enhanced.py --auditd samples/sample_audit.log

  # Use custom database
  python main_enhanced.py --windows events.json --db custom_siem.db
        """
    )

    parser.add_argument(
        "--windows",
        help="Process Windows event log JSON file"
    )

    parser.add_argument(
        "--auditd",
        help="Process Linux auditd log file"
    )

    parser.add_argument(
        "--db",
        default="siem.db",
        help="Database path (default: siem.db)"
    )

    args = parser.parse_args()

    if not args.windows and not args.auditd:
        parser.print_help()
        sys.exit(1)

    # Initialize storage
    storage = AlertStorage(args.db)

    # Initialize MITRE ATT&CK
    console.print("[dim]Loading MITRE ATT&CK framework...[/dim]")
    try:
        mitre = get_mitre_attack()
        if mitre.data:
            console.print("[dim green]✓ MITRE ATT&CK loaded[/dim green]")
        else:
            console.print("[dim yellow]⚠ MITRE ATT&CK not available (enrichment disabled)[/dim yellow]")
            mitre = None
    except Exception as e:
        console.print(f"[dim yellow]⚠ MITRE ATT&CK load failed: {e}[/dim yellow]")
        mitre = None

    try:
        if args.windows:
            process_windows_events(args.windows, storage, mitre)
        elif args.auditd:
            process_auditd_logs(args.auditd, storage, mitre)

        # Show statistics
        console.print("\n" + "="*60)
        stats = storage.get_alert_statistics()
        console.print(f"[bold cyan]Database Statistics:[/bold cyan]")
        console.print(f"  Total alerts stored: {stats['total_alerts']}")
        console.print(f"  By severity: {stats['by_severity']}")

    finally:
        storage.close()


if __name__ == "__main__":
    main()
