"""
test_mitre_attack.py

Test suite for MITRE ATT&CK integration.
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.mitre_attack import MitreAttack, get_mitre_attack
from core.detector import load_rules


class TestMitreFramework:
    """Test MITRE ATT&CK framework loading."""

    def test_framework_loaded(self):
        mitre = get_mitre_attack()
        assert mitre.data is not None

    def test_techniques_loaded(self):
        mitre = get_mitre_attack()
        techniques = mitre.get_all_techniques()
        assert len(techniques) > 800  # Should have 800+ techniques

    def test_tactics_loaded(self):
        mitre = get_mitre_attack()
        tactics = mitre.get_all_tactics()
        assert len(tactics) == 15  # Should have 15 tactics


class TestTechniqueLookup:
    """Test technique lookup functionality."""

    def test_get_technique(self):
        mitre = get_mitre_attack()
        technique = mitre.get_technique("T1059.001")

        assert technique is not None
        assert technique.get('name') == 'PowerShell'

    def test_get_technique_name(self):
        mitre = get_mitre_attack()
        name = mitre.get_technique_name("T1059.001")

        assert name == "PowerShell"

    def test_get_technique_description(self):
        mitre = get_mitre_attack()
        description = mitre.get_technique_description("T1059.001")

        assert len(description) > 0
        assert "PowerShell" in description

    def test_get_nonexistent_technique(self):
        mitre = get_mitre_attack()
        technique = mitre.get_technique("T9999.999")

        assert technique is None


class TestTacticLookup:
    """Test tactic lookup functionality."""

    def test_get_tactic(self):
        mitre = get_mitre_attack()
        tactic = mitre.get_tactic("execution")

        assert tactic is not None
        assert tactic.get('name') == 'Execution'

    def test_get_tactic_case_insensitive(self):
        mitre = get_mitre_attack()
        tactic1 = mitre.get_tactic("Execution")
        tactic2 = mitre.get_tactic("execution")

        assert tactic1 is not None
        assert tactic2 is not None
        assert tactic1 == tactic2


class TestRelationships:
    """Test technique-tactic relationships."""

    def test_get_technique_tactics(self):
        mitre = get_mitre_attack()
        tactics = mitre.get_technique_tactics("T1059.001")

        assert 'execution' in tactics

    def test_get_tactic_techniques(self):
        mitre = get_mitre_attack()
        techniques = mitre.get_tactic_techniques("execution")

        assert len(techniques) > 0
        assert "T1059.001" in techniques


class TestSubtechniques:
    """Test sub-technique functionality."""

    def test_is_subtechnique(self):
        mitre = get_mitre_attack()

        assert mitre.is_subtechnique("T1059.001") is True
        assert mitre.is_subtechnique("T1059") is False

    def test_get_subtechniques(self):
        mitre = get_mitre_attack()
        subtechniques = mitre.get_technique_subtechniques("T1059")

        assert len(subtechniques) > 0
        assert "T1059.001" in subtechniques


class TestSearch:
    """Test technique search functionality."""

    def test_search_techniques(self):
        mitre = get_mitre_attack()
        results = mitre.search_techniques("powershell")

        assert len(results) > 0

        # Check that PowerShell technique is in results
        technique_ids = [r['id'] for r in results]
        assert "T1059.001" in technique_ids

    def test_search_no_results(self):
        mitre = get_mitre_attack()
        results = mitre.search_techniques("xyznonexistent")

        assert len(results) == 0


class TestAlertEnrichment:
    """Test alert enrichment functionality."""

    def test_enrich_alert(self):
        mitre = get_mitre_attack()

        alert = {
            'rule_id': 'TEST-001',
            'title': 'Test Alert',
            'mitre_attack_id': 'T1059.001'
        }

        enriched = mitre.enrich_alert(alert)

        assert 'mitre_enriched' in enriched
        assert enriched['mitre_enriched']['technique_name'] == 'PowerShell'
        assert 'execution' in enriched['mitre_enriched']['tactics']
        assert 'https://attack.mitre.org/techniques/T1059/001' in enriched['mitre_enriched']['url']

    def test_enrich_alert_no_technique(self):
        mitre = get_mitre_attack()

        alert = {
            'rule_id': 'TEST-001',
            'title': 'Test Alert'
        }

        enriched = mitre.enrich_alert(alert)

        assert 'mitre_enriched' not in enriched


class TestCoverage:
    """Test coverage analysis functionality."""

    def test_coverage_matrix(self):
        mitre = get_mitre_attack()
        rules = load_rules("rules/")

        coverage = mitre.get_coverage_matrix(rules)

        assert 'total_techniques' in coverage
        assert 'detected_techniques' in coverage
        assert 'coverage_percent' in coverage
        assert 'by_tactic' in coverage
        assert 'detected_ids' in coverage

        # Should have detected some techniques
        assert coverage['detected_techniques'] > 0

    def test_coverage_by_tactic(self):
        mitre = get_mitre_attack()
        detected = ["T1059.001", "T1003.001"]

        coverage = mitre.get_coverage_by_tactic(detected)

        assert 'execution' in coverage
        assert 'credential-access' in coverage

        # Check execution tactic has T1059.001
        exec_tactic = coverage['execution']
        assert 'T1059.001' in exec_tactic['detected_ids']

    def test_coverage_empty_rules(self):
        mitre = get_mitre_attack()

        coverage = mitre.get_coverage_matrix([])

        assert coverage['detected_techniques'] == 0
        assert coverage['coverage_percent'] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
