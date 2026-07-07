"""
test_enhanced_detector.py

Test suite for enhanced detection engine with regex and operators.
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.detector import match_field, evaluate_selection, match_rule


class TestFieldMatching:
    """Test individual field matching operations."""

    def test_equals_operator(self):
        assert match_field("powershell.exe", "powershell.exe", "equals")
        assert not match_field("cmd.exe", "powershell.exe", "equals")

    def test_contains_operator(self):
        assert match_field("C:\\Windows\\System32\\cmd.exe", "cmd.exe", "contains")
        assert not match_field("powershell.exe", "mimikatz", "contains")

    def test_startswith_operator(self):
        assert match_field("powershell.exe -enc", "powershell", "startswith")
        assert not match_field("cmd.exe", "powershell", "startswith")

    def test_endswith_operator(self):
        assert match_field("malware.exe", ".exe", "endswith")
        assert not match_field("script.ps1", ".exe", "endswith")

    def test_regex_operator(self):
        assert match_field("powershell.exe -enc ABC123", r"-(enc|encodedcommand)", "regex")
        assert match_field("mimikatz.exe sekurlsa::logonpasswords", r"sekurlsa::", "regex")
        assert not match_field("normal.exe", r"mimikatz", "regex")

    def test_case_sensitivity(self):
        # Case insensitive (default)
        assert match_field("POWERSHELL.EXE", "powershell.exe", "equals", case_sensitive=False)

        # Case sensitive
        assert not match_field("POWERSHELL.EXE", "powershell.exe", "equals", case_sensitive=True)
        assert match_field("PowerShell.exe", "PowerShell.exe", "equals", case_sensitive=True)

    def test_numeric_operators(self):
        assert match_field(100, 50, "gt")
        assert match_field(25, 50, "lt")
        assert match_field(50, 50, "gte")
        assert match_field(50, 50, "lte")

        assert not match_field(30, 50, "gt")
        assert not match_field(75, 50, "lt")


class TestSelectionEvaluation:
    """Test selection block evaluation."""

    def test_simple_selection(self):
        event = {
            "process_name": "powershell.exe",
            "event_id": "4688"
        }

        selection = {
            "process_name": "powershell.exe",
            "event_id": "4688"
        }

        assert evaluate_selection(event, selection)

    def test_selection_with_list(self):
        event = {
            "process_name": "cmd.exe"
        }

        selection = {
            "process_name": ["powershell.exe", "cmd.exe", "wscript.exe"]
        }

        assert evaluate_selection(event, selection)

    def test_selection_with_operator(self):
        event = {
            "command_line": "powershell.exe -encodedcommand ABCD1234"
        }

        selection = {
            "command_line|contains": "-encodedcommand"
        }

        assert evaluate_selection(event, selection)

    def test_selection_with_regex(self):
        event = {
            "command_line": "powershell.exe -enc ABCD"
        }

        selection = {
            "command_line|regex": r"-(enc|encodedcommand)"
        }

        assert evaluate_selection(event, selection)

    def test_selection_no_match(self):
        event = {
            "process_name": "explorer.exe"
        }

        selection = {
            "process_name": "mimikatz.exe"
        }

        assert not evaluate_selection(event, selection)


class TestRuleMatching:
    """Test complete rule matching logic."""

    def test_enhanced_format_simple(self):
        event = {
            "event_id": "4688",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc ABCD"
        }

        rule = {
            "id": "TEST-001",
            "title": "Encoded PowerShell",
            "detection": {
                "selection": {
                    "process_name": "powershell.exe",
                    "command_line|contains": "-enc"
                },
                "condition": "selection"
            }
        }

        assert match_rule(event, rule)

    def test_enhanced_format_regex(self):
        event = {
            "command_line": "rundll32.exe comsvcs.dll,MiniDump 644 C:\\lsass.dmp full"
        }

        rule = {
            "id": "TEST-002",
            "title": "LSASS Dump",
            "detection": {
                "selection": {
                    "command_line|regex": r"comsvcs\.dll.*MiniDump"
                },
                "condition": "selection"
            }
        }

        assert match_rule(event, rule)

    def test_enhanced_format_list(self):
        event = {
            "process_name": "wmic.exe",
            "command_line": "wmic process call create"
        }

        rule = {
            "id": "TEST-003",
            "title": "Suspicious Process",
            "detection": {
                "selection": {
                    "process_name": ["wmic.exe", "psexec.exe", "wmiexec.py"]
                },
                "condition": "selection"
            }
        }

        assert match_rule(event, rule)

    def test_legacy_format_backwards_compatible(self):
        """Ensure old rule format still works."""
        event = {
            "event_id": "4688",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc ABCD"
        }

        rule = {
            "id": "TEST-004",
            "title": "Legacy Format",
            "detection": {
                "event_id": "4688",
                "process_name": "powershell.exe",
                "commandline_contains": ["-enc"]
            }
        }

        assert match_rule(event, rule)

    def test_rule_no_match(self):
        event = {
            "process_name": "notepad.exe"
        }

        rule = {
            "id": "TEST-005",
            "title": "Mimikatz",
            "detection": {
                "selection": {
                    "process_name": "mimikatz.exe"
                },
                "condition": "selection"
            }
        }

        assert not match_rule(event, rule)


class TestRealWorldScenarios:
    """Test realistic detection scenarios."""

    def test_mimikatz_detection(self):
        event = {
            "event_id": "4688",
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords"
        }

        rule = {
            "id": "DET-0013",
            "title": "Mimikatz Execution",
            "detection": {
                "selection": {
                    "process_name|contains": "mimikatz",
                    "command_line|regex": r"(sekurlsa::|lsadump::)"
                },
                "condition": "selection"
            }
        }

        assert match_rule(event, rule)

    def test_encoded_powershell_detection(self):
        event = {
            "event_id": "4688",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBi"
        }

        rule = {
            "id": "DET-0001",
            "title": "Encoded PowerShell",
            "detection": {
                "selection": {
                    "process_name|contains": "powershell",
                    "command_line|regex": r"-(enc|encodedcommand)"
                },
                "condition": "selection"
            }
        }

        assert match_rule(event, rule)

    def test_linux_shadow_access(self):
        event = {
            "target": "/etc/shadow",
            "process": "cat",
            "executable": "/bin/cat"
        }

        rule = {
            "id": "DET-0008",
            "title": "Shadow File Access",
            "detection": {
                "selection": {
                    "target": "/etc/shadow"
                },
                "condition": "selection"
            }
        }

        assert match_rule(event, rule)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
