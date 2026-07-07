# Detection Engineering SIEM - Quick Reference Guide

## 🚀 Getting Started

### Run All Tests
```bash
python -m pytest tests/ -v
```

### Process Events
```bash
# Windows events
python main_enhanced.py --windows samples/normalized/windows/.../events.json

# Linux auditd logs
python main_enhanced.py --auditd samples/sample_audit.log

# Custom database
python main_enhanced.py --windows events.json --db custom.db
```

### Query Alerts
```bash
# Show recent alerts
python tools/query_alerts.py

# Show statistics
python tools/query_alerts.py --stats

# Filter by severity
python tools/query_alerts.py --severity critical

# Last 24 hours
python tools/query_alerts.py --last 24h

# Specific rule
python tools/query_alerts.py --rule DET-0001

# Alert details
python tools/query_alerts.py --id 42

# JSON output
python tools/query_alerts.py --json
```

---

## 📝 Detection Rule Format

### Enhanced Format (Recommended)

```yaml
title: Your Detection Rule Name

id: DET-XXXX

status: stable

description: What this rule detects and why it matters

author: Your Name

date: 2026-07-07

logsource:
  product: windows  # or linux
  category: process_creation  # or security, auditd, etc.

detection:
  selection:
    # Use operators with pipe syntax
    process_name|contains: suspicious_process
    command_line|regex: 'regex.*pattern'
    event_id: 4688  # Exact match (default)
    
    # Multiple values (OR logic)
    file_path:
      - C:\Windows\Temp
      - C:\Users\Public
  
  condition: selection
  case_sensitive: false  # Optional, default is false

falsepositives:
  - Legitimate use case 1
  - Legitimate use case 2

level: high  # critical, high, medium, low

mitre:
  tactic: Credential Access
  technique: OS Credential Dumping
  attack_id: T1003.001

tags:
  - windows
  - credential-access
  - attack.t1003

references:
  - https://attack.mitre.org/techniques/T1003/001/
```

---

## 🔧 Detection Operators

| Operator | Syntax | Example | Description |
|----------|--------|---------|-------------|
| **equals** | `field: value` | `process_name: mimikatz.exe` | Exact match (default) |
| **contains** | `field\|contains: value` | `command_line\|contains: -enc` | Substring match |
| **startswith** | `field\|startswith: value` | `file_path\|startswith: C:\Windows` | Prefix match |
| **endswith** | `field\|endswith: value` | `file_name\|endswith: .exe` | Suffix match |
| **regex** | `field\|regex: pattern` | `command_line\|regex: '-(enc\|e)'` | Regex pattern |
| **gt** | `field\|gt: number` | `file_size\|gt: 1000000` | Greater than |
| **lt** | `field\|lt: number` | `pid\|lt: 1000` | Less than |
| **gte** | `field\|gte: number` | `count\|gte: 5` | Greater/equal |
| **lte** | `field\|lte: number` | `score\|lte: 50` | Less/equal |

---

## 📊 Python API

### Detection Engine

```python
from core.detector import match_field, evaluate_selection, match_rule, load_rules

# Field matching
match_field("powershell.exe", "powershell", "contains")  # True
match_field("cmd.exe", r"\.exe$", "regex")  # True

# Selection evaluation
event = {"process_name": "mimikatz.exe"}
selection = {"process_name|contains": "mimikatz"}
evaluate_selection(event, selection)  # True

# Load and match rules
rules = load_rules("rules/")
for rule in rules:
    if match_rule(event, rule):
        print(f"Alert: {rule['title']}")
```

### Storage API

```python
from core.storage import AlertStorage

# Initialize
storage = AlertStorage("siem.db")

# Store alert
alert = {
    "rule_id": "DET-0001",
    "title": "Suspicious Activity",
    "severity": "high",
    "timestamp": "2026-07-07T12:00:00",
    # ... other fields
}
alert_id = storage.store_alert(alert)

# Query alerts
alerts = storage.query_alerts(
    severity="critical",
    start_time="2026-07-01T00:00:00",
    limit=100
)

# Get statistics
stats = storage.get_alert_statistics()
print(f"Total alerts: {stats['total_alerts']}")
print(f"By severity: {stats['by_severity']}")

# Rule metrics
storage.update_rule_metrics("DET-0001", matched=True)
metrics = storage.get_rule_metrics("DET-0001")

# Cleanup
storage.close()

# Or use context manager
with AlertStorage("siem.db") as storage:
    alerts = storage.query_alerts()
```

---

## 🎯 Common Detection Patterns

### 1. Encoded PowerShell
```yaml
detection:
  selection:
    process_name|contains: powershell
    command_line|regex: '-(enc|encodedcommand|e|en)'
  condition: selection
```

### 2. Credential Dumping
```yaml
detection:
  selection:
    process_name:
      - mimikatz.exe
      - sekurlsa.exe
    command_line|regex: '(sekurlsa|lsadump|kerberos)::'
  condition: selection
```

### 3. Suspicious File Access
```yaml
detection:
  selection:
    file_path:
      - /etc/shadow
      - /etc/passwd
      - C:\Windows\System32\config\SAM
  condition: selection
```

### 4. Process Creation Chain
```yaml
detection:
  selection:
    parent_process|contains: cmd.exe
    process_name|contains: powershell.exe
    command_line|contains: -nop
  condition: selection
```

### 5. Network Activity
```yaml
detection:
  selection:
    process_name|contains: certutil.exe
    command_line|regex: '-urlcache.*http'
  condition: selection
```

---

## 🔍 Regex Pattern Examples

```yaml
# Base64 encoded strings (100+ chars)
command_line|regex: '[A-Za-z0-9+/]{100,}={0,2}'

# IPv4 addresses
command_line|regex: '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

# Email addresses
data|regex: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

# File paths (Windows)
file_path|regex: '[A-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'

# Suspicious PowerShell flags
command_line|regex: '-(enc|e|en|encodedcommand|w hidden|nop|noni)'

# Common exploit patterns
command_line|regex: '(exec|eval|system|shell|invoke).*\('

# Mimikatz modules
command_line|regex: '(sekurlsa|lsadump|kerberos|crypto|vault)::'

# Multiple spaces (obfuscation)
command_line|regex: '\s{2,}'
```

---

## 📈 Database Schema

### Alerts Table
```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    rule_id TEXT,
    title TEXT,
    severity TEXT,
    mitre_tactic TEXT,
    mitre_technique TEXT,
    mitre_attack_id TEXT,
    hostname TEXT,
    username TEXT,
    process_name TEXT,
    command_line TEXT,
    event_data TEXT
);
```

### Events Table
```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    event_type TEXT,
    source TEXT,
    hostname TEXT,
    raw_data TEXT,
    processed BOOLEAN
);
```

### Rule Metrics Table
```sql
CREATE TABLE rule_metrics (
    id INTEGER PRIMARY KEY,
    rule_id TEXT,
    execution_count INTEGER,
    match_count INTEGER,
    last_match TEXT,
    last_execution TEXT
);
```

---

## 🛠️ Troubleshooting

### Issue: No alerts generated
```bash
# 1. Verify rules loaded
python -c "from core.detector import load_rules; print(len(load_rules()))"

# 2. Test rule matching manually
python -c "
from core.detector import match_rule
event = {'process_name': 'powershell.exe'}
rule = {'detection': {'selection': {'process_name|contains': 'powershell'}, 'condition': 'selection'}}
print(match_rule(event, rule))
"

# 3. Check event format
python -c "
from parsers.windows_parser import normalize_windows_event
import json
with open('sample.json') as f:
    event = json.load(f)[0]
print(normalize_windows_event(event))
"
```

### Issue: Database locked
```bash
# Close all connections
python -c "from core.storage import AlertStorage; AlertStorage('siem.db').close()"

# Or delete and recreate
rm siem.db
python main_enhanced.py --windows events.json
```

### Issue: Regex not matching
```python
# Test regex separately
import re
pattern = r'-(enc|encodedcommand)'
text = 'powershell.exe -EncodedCommand ABC'
print(bool(re.search(pattern, text, re.IGNORECASE)))  # Should be True
```

---

## 📦 File Structure

```
detection_engineering_siem/
├── core/
│   ├── database.py          # Rule loading (legacy)
│   ├── detector.py          # Enhanced detection engine ⭐
│   ├── mapper.py            # MITRE mapping (placeholder)
│   └── storage.py           # SQLite storage layer ⭐
├── parsers/
│   ├── auditd_parser.py     # Linux auditd parser
│   └── windows_parser.py    # Windows event parser
├── rules/
│   ├── *.yaml               # Detection rules
│   └── enhanced_*.yaml      # Enhanced format examples ⭐
├── tools/
│   ├── query_alerts.py      # Alert query CLI ⭐
│   ├── validate_rules.py    # Rule validator
│   └── generate_rules.py    # Rule generator
├── tests/
│   ├── test_enhanced_detector.py  # Detector tests ⭐
│   └── test_storage.py            # Storage tests ⭐
├── main_enhanced.py         # Enhanced main script ⭐
├── IMPROVEMENTS.md          # Full documentation ⭐
└── QUICK_REFERENCE.md       # This file ⭐

⭐ = New/enhanced in Phase 1+2
```

---

## 🎓 Best Practices

### Rule Writing
1. ✅ Use specific operators (`contains`, `regex`) instead of broad matches
2. ✅ Include false positives section
3. ✅ Map to MITRE ATT&CK framework
4. ✅ Test rules against known-good and known-bad samples
5. ✅ Use case-insensitive matching for process names
6. ✅ Document why the detection matters in description

### Performance
1. ✅ Use `contains` for simple substrings (faster than regex)
2. ✅ Avoid greedy regex patterns (`.*` at the start)
3. ✅ Use indexed fields for queries (timestamp, severity, rule_id)
4. ✅ Limit query results with `--limit` flag
5. ✅ Clean up old alerts periodically

### Testing
1. ✅ Run pytest before committing changes
2. ✅ Test rules against sample data
3. ✅ Verify backward compatibility with legacy rules
4. ✅ Check database integrity after bulk operations

---

## 📞 Quick Commands Cheat Sheet

```bash
# Run all tests
pytest tests/ -v

# Process events and store alerts
python main_enhanced.py --windows events.json

# View recent critical alerts
python tools/query_alerts.py --severity critical --last 24h

# Show statistics
python tools/query_alerts.py --stats

# Validate all rules
python tools/validate_rules.py

# Test single rule
pytest tests/test_enhanced_detector.py::TestRuleMatching::test_enhanced_format_regex -v

# Export alerts as JSON
python tools/query_alerts.py --json > alerts.json

# Show database size
ls -lh siem.db
```

---

**For detailed documentation, see:** `IMPROVEMENTS.md`

**Status:** Phase 1 + 2 Complete ✅
