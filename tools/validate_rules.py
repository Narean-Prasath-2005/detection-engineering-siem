"""
validate_rules.py

Validates all detection rules in the rules/ directory.
"""

import re

from core.database import (
    load_rules,
    get_all_rules,
    get_rule_count,
)

# -----------------------------------------------------
# Configuration
# -----------------------------------------------------

REQUIRED_FIELDS = [
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "mitre",
    
]

VALID_LEVELS = {
    "low",
    "medium",
    "high",
    "critical",
}

VALID_PRODUCTS = {
    "windows",
    "linux",
}

ATTACK_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


# -----------------------------------------------------
# Validation Functions
# -----------------------------------------------------

def validate_required_fields(rules):
    issues = []

    for rule in rules:
        missing = []

        for field in REQUIRED_FIELDS:
            if field not in rule:
                missing.append(field)

        if missing:
            issues.append(
                f"[{rule['_filename']}] Missing fields: {', '.join(missing)}"
            )

    return issues


def validate_duplicate_titles(rules):
    issues = []
    titles = {}

    for rule in rules:

        title = rule.get("title", "").strip()

        if title in titles:
            issues.append(
                f"Duplicate title '{title}' "
                f"({titles[title]} and {rule['_filename']})"
            )
        else:
            titles[title] = rule["_filename"]

    return issues


def validate_severity(rules):
    issues = []

    for rule in rules:

        level = rule.get("level", "").lower()

        if level not in VALID_LEVELS:
            issues.append(
                f"[{rule['_filename']}] Invalid severity: {level}"
            )

    return issues


def validate_attack_ids(rules):
    issues = []

    for rule in rules:

        attack_id = (
            rule.get("mitre", {})
            .get("attack_id", "")
        )

        if not ATTACK_ID_PATTERN.match(attack_id):
            issues.append(
                f"[{rule['_filename']}] Invalid ATT&CK ID: {attack_id}"
            )

    return issues


def validate_logsource(rules):
    issues = []

    for rule in rules:

        product = (
            rule.get("logsource", {})
            .get("product", "")
            .lower()
        )

        if product not in VALID_PRODUCTS:
            issues.append(
                f"[{rule['_filename']}] Invalid logsource product: {product}"
            )

    return issues


def validate_detection(rules):
    issues = []

    for rule in rules:

        detection = rule.get("detection")

        if not detection:
            issues.append(
                f"[{rule['_filename']}] Missing detection section"
            )
            continue

        if "selection" not in detection:
            issues.append(
                f"[{rule['_filename']}] Missing detection.selection"
            )

        if "condition" not in detection:
            issues.append(
                f"[{rule['_filename']}] Missing detection.condition"
            )

    return issues


# -----------------------------------------------------
# Summary
# -----------------------------------------------------

def print_issues(title, issues):

    print(f"\n{title}")

    if not issues:
        print("  PASS")
        return

    print(f"  FAIL ({len(issues)})")

    for issue in issues:
        print(f"   - {issue}")


# -----------------------------------------------------
# Main
# -----------------------------------------------------

def main():

    print("=" * 50)
    print("Detection Rule Validator")
    print("=" * 50)

    load_rules()

    rules = get_all_rules()

    print(f"\nRules Loaded : {get_rule_count()}")

    required = validate_required_fields(rules)
    duplicate_titles = validate_duplicate_titles(rules)
    severity = validate_severity(rules)
    attack_ids = validate_attack_ids(rules)
    logsource = validate_logsource(rules)
    detection = validate_detection(rules)

    print_issues("Required Fields", required)
    print_issues("Duplicate Titles", duplicate_titles)
    print_issues("Severity", severity)
    print_issues("ATT&CK IDs", attack_ids)
    print_issues("Log Source", logsource)
    print_issues("Detection", detection)

    total_issues = (
        len(required)
        + len(duplicate_titles)
        + len(severity)
        + len(attack_ids)
        + len(logsource)
        + len(detection)
    )

    print("\n" + "=" * 50)

    if total_issues == 0:
        print("VALIDATION PASSED")
    else:
        print(f"VALIDATION FAILED ({total_issues} issues found)")

    print("=" * 50)


if __name__ == "__main__":
    main()