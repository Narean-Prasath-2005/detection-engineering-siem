from parsers.auditd_parser import parse_audit_event
from core.detector import detect

with open("samples/sample_audit.log", "r") as f:
    logs = f.readlines()

event = parse_audit_event(logs)

result = detect(
    event,
    "rules/shadow_access.yaml"
)

if result["alert"]:
    print("\n========== ALERT ==========")
    print(f"Rule: {result['title']}")
    print(f"Severity: {result['severity']}")
    print(f"Tactic: {result['mitre_tactic']}")
    print(f"Technique: {result['mitre_technique']}")