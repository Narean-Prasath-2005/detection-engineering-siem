import os
import yaml


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


def match_rule(event, rule):

    detection = rule.get("detection", {})

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
        "severity": rule.get("severity"),

        "mitre_tactic": rule.get("mitre", {}).get("tactic"),
        "mitre_technique": rule.get("mitre", {}).get("technique"),

        "hostname": event.get("hostname"),
        "user": event.get("username"),
        "timestamp": event.get("timestamp"),

        "process_name": event.get("process_name"),
        "command_line": event.get("command_line")
    }


def detect_event(event):

    alerts = []

    rules = load_rules()

    for rule in rules:

        if match_rule(event, rule):
            alert = generate_alert(event, rule)
            alerts.append(alert)

    return alerts