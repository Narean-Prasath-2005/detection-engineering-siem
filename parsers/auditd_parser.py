import re


def parse_audit_event(log_lines):
    event = {
        "timestamp": None,
        "event_type": None,
        "process": None,
        "executable": None,
        "target": None,
        "rule_key": None,
        "raw_event": log_lines
    }

    for line in log_lines:
        if line.startswith("type=SYSCALL"):
            process_match = re.search(r'comm="([^"]+)"', line)
            exe_match = re.search(r'exe="([^"]+)"', line)
            key_match = re.search(r'key="([^"]+)"', line)
            timestamp_match = re.search(r'audit\(([\d\.]+):', line)

            if process_match:
                event["process"] = process_match.group(1)

            if exe_match:
                event["executable"] = exe_match.group(1)

            if key_match:
                event["rule_key"] = key_match.group(1)

            if timestamp_match:
                event["timestamp"] = timestamp_match.group(1)

        elif line.startswith("type=PATH"):
            path_match = re.search(r'name="([^"]+)"', line)

            if path_match:
                event["target"] = path_match.group(1)

    if event["target"] == "/etc/shadow":
        event["event_type"] = "credential_access"

    return event