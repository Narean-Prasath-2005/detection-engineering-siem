"""
Tests for core/database.py - Rule loading and management
"""

import pytest
import tempfile
import shutil
from pathlib import Path
import yaml
import logging

from core import database


class TestRuleLoading:
    """Test rule loading functionality"""

    def setup_method(self):
        """Create temporary rules directory for testing"""
        self.temp_dir = tempfile.mkdtemp()
        self.rules_path = Path(self.temp_dir) / "rules"
        self.rules_path.mkdir()

    def teardown_method(self):
        """Clean up temporary directory"""
        shutil.rmtree(self.temp_dir)
        # Clear global rules
        database._rules.clear()

    def create_rule_file(self, filename, rule_data):
        """Helper to create a rule YAML file"""
        rule_file = self.rules_path / filename
        with open(rule_file, 'w') as f:
            yaml.safe_dump(rule_data, f)
        return rule_file

    def test_load_valid_rule(self):
        """Test loading a valid rule"""
        rule = {
            'id': 'TEST-001',
            'title': 'Test Rule',
            'detection': {'selection': {'field': 'value'}},
            'level': 'high'
        }
        self.create_rule_file('test.yaml', rule)

        database.RULES_DIR = self.rules_path
        database.load_rules()

        assert database.get_rule_count() == 1
        loaded = database.get_rule('TEST-001')
        assert loaded is not None
        assert loaded['title'] == 'Test Rule'

    def test_duplicate_rule_id_detection(self):
        """Test that duplicate rule IDs are detected and handled"""
        rule1 = {
            'id': 'DUP-001',
            'title': 'First Rule',
            'detection': {'selection': {'field': 'value1'}},
            'level': 'high'
        }
        rule2 = {
            'id': 'DUP-001',  # Same ID
            'title': 'Second Rule',
            'detection': {'selection': {'field': 'value2'}},
            'level': 'critical'
        }

        self.create_rule_file('rule1.yaml', rule1)
        self.create_rule_file('rule2.yaml', rule2)

        database.RULES_DIR = self.rules_path

        # Should only load first rule, skip duplicate (logs error but doesn't raise)
        database.load_rules()

        # Should have loaded only one rule (the first one encountered)
        assert database.get_rule_count() == 1

        loaded = database.get_rule('DUP-001')
        assert loaded is not None
        # Should be whichever rule was loaded first
        assert loaded['id'] == 'DUP-001'
        # Verify it's not loading both
        assert loaded['title'] in ['First Rule', 'Second Rule']

    def test_rule_without_id(self):
        """Test that rules without ID are skipped"""
        rule = {
            'title': 'Rule Without ID',
            'detection': {'selection': {'field': 'value'}},
            'level': 'medium'
        }
        self.create_rule_file('no_id.yaml', rule)

        database.RULES_DIR = self.rules_path
        database.load_rules()

        assert database.get_rule_count() == 0

    def test_invalid_yaml(self):
        """Test handling of invalid YAML files"""
        invalid_yaml = self.rules_path / "invalid.yaml"
        with open(invalid_yaml, 'w') as f:
            f.write("invalid: yaml: content:\n  - broken")

        database.RULES_DIR = self.rules_path
        database.load_rules()

        # Should not crash, just skip the invalid file
        assert database.get_rule_count() == 0

    def test_non_dict_yaml(self):
        """Test handling of YAML files that don't contain dictionaries"""
        rule_file = self.rules_path / "list.yaml"
        with open(rule_file, 'w') as f:
            yaml.safe_dump(['item1', 'item2'], f)

        database.RULES_DIR = self.rules_path
        database.load_rules()

        assert database.get_rule_count() == 0

    def test_multiple_valid_rules(self):
        """Test loading multiple valid rules"""
        for i in range(5):
            rule = {
                'id': f'TEST-{i:03d}',
                'title': f'Test Rule {i}',
                'detection': {'selection': {'field': f'value{i}'}},
                'level': 'medium'
            }
            self.create_rule_file(f'rule{i}.yaml', rule)

        database.RULES_DIR = self.rules_path
        database.load_rules()

        assert database.get_rule_count() == 5

        # Verify all rules are accessible
        for i in range(5):
            rule = database.get_rule(f'TEST-{i:03d}')
            assert rule is not None
            assert rule['title'] == f'Test Rule {i}'

    def test_get_all_rules(self):
        """Test retrieving all rules"""
        rules_data = [
            {'id': 'A-001', 'title': 'Rule A', 'detection': {}, 'level': 'low'},
            {'id': 'B-002', 'title': 'Rule B', 'detection': {}, 'level': 'high'},
            {'id': 'C-003', 'title': 'Rule C', 'detection': {}, 'level': 'critical'},
        ]

        for i, rule in enumerate(rules_data):
            self.create_rule_file(f'rule{i}.yaml', rule)

        database.RULES_DIR = self.rules_path
        database.load_rules()

        all_rules = database.get_all_rules()
        assert len(all_rules) == 3

        # Check all rules are present
        rule_ids = {r['id'] for r in all_rules}
        assert rule_ids == {'A-001', 'B-002', 'C-003'}

    def test_reload_rules(self):
        """Test reloading rules"""
        rule = {
            'id': 'RELOAD-001',
            'title': 'Initial Rule',
            'detection': {},
            'level': 'high'
        }
        self.create_rule_file('rule.yaml', rule)

        database.RULES_DIR = self.rules_path
        database.load_rules()

        assert database.get_rule_count() == 1

        # Add another rule
        rule2 = {
            'id': 'RELOAD-002',
            'title': 'Second Rule',
            'detection': {},
            'level': 'medium'
        }
        self.create_rule_file('rule2.yaml', rule2)

        # Reload
        database.reload_rules()

        assert database.get_rule_count() == 2

    def test_get_nonexistent_rule(self):
        """Test getting a rule that doesn't exist"""
        database.RULES_DIR = self.rules_path
        database.load_rules()

        rule = database.get_rule('NONEXISTENT')
        assert rule is None

    def test_filename_metadata(self):
        """Test that filename metadata is stored correctly"""
        rule = {
            'id': 'META-001',
            'title': 'Metadata Test',
            'detection': {},
            'level': 'low'
        }
        self.create_rule_file('metadata_test.yaml', rule)

        database.RULES_DIR = self.rules_path
        database.load_rules()

        loaded = database.get_rule('META-001')
        assert loaded is not None
        assert loaded['_filename'] == 'metadata_test.yaml'


class TestRuleRetrieval:
    """Test rule retrieval functions"""

    def setup_method(self):
        """Set up test rules"""
        database._rules.clear()
        database._rules = {
            'RULE-001': {
                'id': 'RULE-001',
                'title': 'Test Rule 1',
                '_filename': 'rule1.yaml'
            },
            'RULE-002': {
                'id': 'RULE-002',
                'title': 'Test Rule 2',
                '_filename': 'rule2.yaml'
            }
        }

    def test_get_rule(self):
        """Test getting a specific rule"""
        rule = database.get_rule('RULE-001')
        assert rule is not None
        assert rule['title'] == 'Test Rule 1'

    def test_get_rule_count(self):
        """Test getting rule count"""
        count = database.get_rule_count()
        assert count == 2

    def test_get_all_rules(self):
        """Test getting all rules"""
        rules = database.get_all_rules()
        assert len(rules) == 2
        assert all(isinstance(r, dict) for r in rules)
