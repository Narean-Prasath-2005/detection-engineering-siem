import os
import yaml

RULES = [
    {
        "filename": "encoded_powershell.yaml",
        "title": "Encoded PowerShell Execution",
        "id": "DET-003",
        "severity": "HIGH",
        "event_id": "4688",
        "process_name": "powershell.exe",
        "commandline_contains": [
            "-enc",
            "-encodedcommand"
        ],
        "tactic": "Execution",
        "technique": "T1059.001"
    },

    {
        "filename": "event_log_clear.yaml",
        "title": "Windows Event Log Clearing",
        "id": "DET-004",
        "severity": "HIGH",
        "event_id": "4688",
        "process_name": "wevtutil.exe",
        "commandline_contains": [
            "cl",
            "Security"
        ],
        "tactic": "Defense Evasion",
        "technique": "T1070.001"
    },

    {
        "filename": "firewall_disable.yaml",
        "title": "Firewall Disabled",
        "id": "DET-005",
        "severity": "HIGH",
        "event_id": "4688",
        "process_name": "netsh.exe",
        "commandline_contains": [
            "firewall",
            "off"
        ],
        "tactic": "Defense Evasion",
        "technique": "T1562.004"
    },

    {
        "filename": "certutil_download.yaml",
        "title": "Certutil Download Activity",
        "id": "DET-006",
        "severity": "MEDIUM",
        "event_id": "4688",
        "process_name": "certutil.exe",
        "commandline_contains": [
            "-urlcache",
            "-f"
        ],
        "tactic": "Command and Control",
        "technique": "T1105"
    },

    {
        "filename": "bloodhound_enum.yaml",
        "title": "BloodHound Enumeration Activity",
        "id": "DET-007",
        "severity": "HIGH",
        "event_id": "4688",
        "process_name": "powershell.exe",
        "commandline_contains": [
            "Invoke-BloodHound"
        ],
        "tactic": "Discovery",
        "technique": "T1069"
    },

    {
        "filename": "dcsync.yaml",
        "title": "DCSync Activity",
        "id": "DET-008",
        "severity": "CRITICAL",
        "event_id": "4662",
        "process_name": "",
        "commandline_contains": [],
        "tactic": "Credential Access",
        "technique": "T1003.006"
    }
]


os.makedirs("rules", exist_ok=True)

for rule in RULES:

    yaml_rule = {
        "title": rule["title"],
        "id": rule["id"],
        "severity": rule["severity"],

        "detection": {
            "event_id": rule["event_id"],
            "process_name": rule["process_name"],
            "commandline_contains": rule["commandline_contains"]
        },

        "mitre": {
            "tactic": rule["tactic"],
            "technique": rule["technique"]
        }
    }

    with open(
        os.path.join("rules", rule["filename"]),
        "w"
    ) as f:
        yaml.dump(
            yaml_rule,
            f,
            default_flow_style=False,
            sort_keys=False
        )

    print(f"[+] Generated {rule['filename']}")

print("\nRule generation completed.")