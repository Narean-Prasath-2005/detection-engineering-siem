import os
import re
import yaml
from typing import Any, Dict, List, Union


def load_rules(rule_directory="rules"):
    rules = []

    for file in os.listdir(rule_directory):

        if not (file.endswith(".yaml") or file.endswith(".yml")):
            continue

        rule_path = os.path.join(rule_directory, file)

        try:
            with open(rule_path, "r") as f:
                rule = yaml.safe_load(f)

            # Skip empty YAML files
            if rule is None:
                print(f"[INFO] Skipping empty rule file: {file}")
                continue

            rules.append(rule)

        except Exception as e:
            print(f"[ERROR] Failed loading rule {file}: {e}")

    return rules


def match_field(event_value: Any, expected_value: Any, operator: str = "equals", case_sensitive: bool = False) -> bool:
    """
    Match a field value against an expected value using the specified operator.

    Supported operators:
    - equals: exact match
    - contains: substring match
    - startswith: prefix match
    - endswith: suffix match
    - regex: regex pattern match
    - gt: greater than (numeric)
    - lt: less than (numeric)
    - gte: greater than or equal (numeric)
    - lte: less than or equal (numeric)
    """

    if event_value is None:
        return False

    # Convert to string for text operations
    if operator in ["equals", "contains", "startswith", "endswith", "regex"]:
        event_str = str(event_value)
        expected_str = str(expected_value)

        # Handle case sensitivity
        if not case_sensitive:
            event_str = event_str.lower()
            expected_str = expected_str.lower()

        if operator == "equals":
            return event_str == expected_str
        elif operator == "contains":
            return expected_str in event_str
        elif operator == "startswith":
            return event_str.startswith(expected_str)
        elif operator == "endswith":
            return event_str.endswith(expected_str)
        elif operator == "regex":
            try:
                flags = 0 if case_sensitive else re.IGNORECASE
                return bool(re.search(expected_str, event_str, flags))
            except re.error:
                print(f"[WARNING] Invalid regex pattern: {expected_str}")
                return False

    # Numeric comparisons
    elif operator in ["gt", "lt", "gte", "lte"]:
        try:
            event_num = float(event_value)
            expected_num = float(expected_value)

            if operator == "gt":
                return event_num > expected_num
            elif operator == "lt":
                return event_num < expected_num
            elif operator == "gte":
                return event_num >= expected_num
            elif operator == "lte":
                return event_num <= expected_num
        except (ValueError, TypeError):
            return False

    return False


def evaluate_selection(event: Dict, selection: Dict, case_sensitive: bool = False) -> bool:
    """
    Evaluate a detection selection block against an event.

    Supports:
    - Simple field matching: field_name: value
    - List matching (ANY): field_name: [val1, val2]
    - Operator syntax: field_name|operator: value
    """

    for field_expr, expected_values in selection.items():

        # Parse field expression (e.g., "process_name|contains")
        if "|" in field_expr:
            field_name, operator = field_expr.split("|", 1)
        else:
            field_name = field_expr
            operator = "equals"

        # Get event field value (support nested fields with dot notation)
        event_value = event.get(field_name)

        # Handle list of expected values (OR logic)
        if isinstance(expected_values, list):
            matched = False
            for expected_val in expected_values:
                if match_field(event_value, expected_val, operator, case_sensitive):
                    matched = True
                    break
            if not matched:
                return False
        else:
            # Single value match
            if not match_field(event_value, expected_values, operator, case_sensitive):
                return False

    return True


def match_rule(event, rule):
    """
    Enhanced rule matching with support for complex conditions.

    Supports legacy format and new enhanced format:

    Legacy (backwards compatible):
      detection:
        event_id: 4688
        process_name: powershell.exe
        commandline_contains: ["-enc"]

    Enhanced:
      detection:
        selection:
          process_name|contains: powershell
          command_line|regex: '-(enc|encodedcommand)'
        condition: selection
    """

    detection = rule.get("detection", {})

    # Enhanced format with selection blocks
    if "selection" in detection:
        condition = detection.get("condition", "selection")
        case_sensitive = detection.get("case_sensitive", False)

        # Evaluate selection block
        selection_result = evaluate_selection(event, detection["selection"], case_sensitive)

        # For now, simple condition support (just "selection")
        # Future: parse complex conditions like "selection and not filter"
        if condition == "selection":
            return selection_result
        else:
            # TODO: Implement complex condition parsing
            return selection_result

    # Legacy format (backwards compatible)
    else:
        # Event ID matching
        if "event_id" in detection:
            if event.get("event_id") != str(detection["event_id"]):
                return False

        # Process matching
        if "process_name" in detection:
            process_name = event.get("process_name", "").lower()
            expected_process = detection["process_name"].lower()

            if expected_process not in process_name:
                return False

        # Command line keyword matching
        if "commandline_contains" in detection:
            command_line = event.get("command_line", "").lower()

            for keyword in detection["commandline_contains"]:
                if keyword.lower() not in command_line:
                    return False

        # File target matching (Linux auditd support)
        if "target" in detection:
            if event.get("target") != detection["target"]:
                return False

        return True


def generate_alert(event, rule):

    return {
        "rule_id": rule.get("id"),
        "title": rule.get("title"),
        "severity": rule.get("severity") or rule.get("level"),  # Support both severity and level

        "mitre_tactic": rule.get("mitre", {}).get("tactic"),
        "mitre_technique": rule.get("mitre", {}).get("technique"),
        "mitre_attack_id": rule.get("mitre", {}).get("attack_id"),

        "hostname": event.get("hostname"),
        "user": event.get("username"),
        "timestamp": event.get("timestamp"),

        "process_name": event.get("process_name"),
        "command_line": event.get("command_line"),

        # Store full event for investigation
        "event": event
    }


def detect_event(event):

    alerts = []

    rules = load_rules()

    for rule in rules:

        if match_rule(event, rule):
            alert = generate_alert(event, rule)
            alerts.append(alert)

    return alerts