"""
test_mapper.py

Test suite for MITRE ATT&CK mapper.
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.mapper import MitreMapper, get_mitre_mapper
from core.detector import load_rules


@pytest.fixture
def sample_rules():
    """Sample rules for testing."""
    return [
        {
            'id': 'TEST-001',
            'title': 'PowerShell Execution',
            'severity': 'high',
            'mitre': {
                'tactic': 'Execution',
                'technique': 'PowerShell',
                'attack_id': 'T1059.001'
            }
        },
        {
            'id': 'TEST-002',
            'title': 'LSASS Dump',
            'severity': 'critical',
            'mitre': {
                'tactic': 'Credential Access',
                'technique': 'LSASS Memory',
                'attack_id': 'T1003.001'
            }
        },
        {
            'id': 'TEST-003',
            'title': 'No MITRE Mapping',
            'severity': 'medium'
        }
    ]


class TestMapperInitialization:
    """Test mapper initialization."""

    def test_mapper_creation(self):
        mapper = MitreMapper()
        assert mapper.mitre is not None

    def test_singleton_mapper(self):
        mapper1 = get_mitre_mapper()
        mapper2 = get_mitre_mapper()
        assert mapper1 is mapper2


class TestRuleMapping:
    """Test rule-to-technique mapping."""

    def test_map_rules(self, sample_rules):
        mapper = MitreMapper()
        mapper.map_rules(sample_rules)

        assert len(mapper.rule_to_techniques) == 2  # 2 rules with MITRE data
        assert len(mapper.technique_to_rules) == 2  # 2 unique techniques

    def test_get_techniques_for_rule(self, sample_rules):
        mapper = MitreMapper()
        mapper.map_rules(sample_rules)

        techniques = mapper.get_techniques_for_rule('TEST-001')
        assert techniques == ['T1059.001']

    def test_get_rules_for_technique(self, sample_rules):
        mapper = MitreMapper()
        mapper.map_rules(sample_rules)

        rules = mapper.get_rules_for_technique('T1059.001')
        assert 'TEST-001' in rules

    def test_rule_without_mitre(self, sample_rules):
        mapper = MitreMapper()
        mapper.map_rules(sample_rules)

        techniques = mapper.get_techniques_for_rule('TEST-003')
        assert techniques == []


class TestCoverageAnalysis:
    """Test coverage analysis functionality."""

    def test_get_covered_techniques(self, sample_rules):
        mapper = MitreMapper()
        mapper.map_rules(sample_rules)

        covered = mapper.get_covered_techniques()
        assert 'T1059.001' in covered
        assert 'T1003.001' in covered

    def test_get_uncovered_techniques(self, sample_rules):
        mapper = MitreMapper()
        mapper.map_rules(sample_rules)

        uncovered = mapper.get_uncovered_techniques()
        assert len(uncovered) > 0
        assert 'T1059.001' not in uncovered  # Should be covered

    def test_get_covered_techniques_by_tactic(self, sample_rules):
        mapper = MitreMapper()
        mapper.map_rules(sample_rules)

        covered = mapper.get_covered_techniques('execution')
        assert 'T1059.001' in covered

    def test_get_coverage_by_tactic(self, sample_rules):
        mapper = MitreMapper()
        mapper.map_rules(sample_rules)

        coverage = mapper.get_coverage_by_tactic(sample_rules)
        assert 'execution' in coverage
        assert 'credential-access' in coverage


class TestTechniqueInfo:
    """Test technique information retrieval."""

    def test_get_technique_info(self):
        mapper = MitreMapper()

        info = mapper.get_technique_info('T1059.001')
        assert info['id'] == 'T1059.001'
        assert info['name'] == 'PowerShell'
        assert 'execution' in info['tactics']
        assert 'url' in info

    def test_get_technique_info_invalid(self):
        mapper = MitreMapper()

        info = mapper.get_technique_info('T9999.999')
        assert info['id'] == 'T9999.999'
        assert info['name'] == 'Unknown'

    def test_get_tactic_for_rule(self, sample_rules):
        mapper = MitreMapper()

        tactic = mapper.get_tactic_for_rule(sample_rules[0])
        assert tactic == 'execution'


class TestDetectionMatrix:
    """Test detection matrix generation."""

    def test_get_detection_matrix(self, sample_rules):
        mapper = MitreMapper()

        matrix = mapper.get_detection_matrix(sample_rules)

        assert matrix['total_rules'] == 3
        assert matrix['rules_with_mitre'] == 2
        assert matrix['total_techniques_covered'] == 2
        assert len(matrix['rules']) == 3

    def test_detection_matrix_structure(self, sample_rules):
        mapper = MitreMapper()

        matrix = mapper.get_detection_matrix(sample_rules)
        first_rule = matrix['rules'][0]

        assert 'rule_id' in first_rule
        assert 'title' in first_rule
        assert 'severity' in first_rule
        assert 'techniques' in first_rule
        assert 'technique_names' in first_rule


class TestRuleSuggestions:
    """Test rule suggestion functionality."""

    def test_suggest_rules_for_tactic(self, sample_rules):
        mapper = MitreMapper()
        mapper.map_rules(sample_rules)

        suggestions = mapper.suggest_rules_for_tactic('execution', limit=5)

        assert len(suggestions) <= 5
        assert all('technique_id' in s for s in suggestions)
        assert all('name' in s for s in suggestions)
        assert all('priority' in s for s in suggestions)


class TestValidation:
    """Test rule validation functionality."""

    def test_validate_rule_mapping_valid(self):
        mapper = MitreMapper()

        rule = {
            'id': 'TEST-001',
            'mitre': {
                'tactic': 'Execution',
                'attack_id': 'T1059.001'
            }
        }

        result = mapper.validate_rule_mapping(rule)
        assert result['valid'] is True

    def test_validate_rule_mapping_missing_attack_id(self):
        mapper = MitreMapper()

        rule = {
            'id': 'TEST-001',
            'mitre': {
                'tactic': 'Execution'
            }
        }

        result = mapper.validate_rule_mapping(rule)
        assert result['valid'] is False
        assert len(result['errors']) > 0

    def test_validate_rule_mapping_invalid_format(self):
        mapper = MitreMapper()

        rule = {
            'id': 'TEST-001',
            'mitre': {
                'attack_id': 'INVALID'
            }
        }

        result = mapper.validate_rule_mapping(rule)
        assert len(result['warnings']) > 0


class TestRealRules:
    """Test with actual detection rules."""

    def test_map_real_rules(self):
        mapper = MitreMapper()
        rules = load_rules("rules/")

        mapper.map_rules(rules)

        assert len(mapper.rule_to_techniques) > 0
        assert len(mapper.technique_to_rules) > 0

    def test_real_coverage_by_tactic(self):
        mapper = MitreMapper()
        rules = load_rules("rules/")

        coverage = mapper.get_coverage_by_tactic(rules)

        assert 'execution' in coverage
        assert coverage['execution']['detected_techniques'] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
