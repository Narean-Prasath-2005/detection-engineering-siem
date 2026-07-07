"""
mapper.py

MITRE ATT&CK mapper - provides rule-to-technique mapping and coverage utilities.
"""

import logging
from typing import Dict, List, Set, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


class MitreMapper:
    """
    Maps detection rules to MITRE ATT&CK techniques and provides
    coverage analysis utilities.
    """

    def __init__(self, mitre_instance=None):
        """
        Initialize MITRE mapper.

        Args:
            mitre_instance: MitreAttack instance (optional, will create if None)
        """
        if mitre_instance:
            self.mitre = mitre_instance
        else:
            from core.mitre_attack import get_mitre_attack
            self.mitre = get_mitre_attack()

        self.rule_to_techniques = {}  # rule_id -> [technique_ids]
        self.technique_to_rules = defaultdict(list)  # technique_id -> [rule_ids]

    def map_rules(self, rules: List[Dict]):
        """
        Build mapping between rules and techniques.

        Args:
            rules: List of detection rules
        """
        self.rule_to_techniques.clear()
        self.technique_to_rules.clear()

        for rule in rules:
            rule_id = rule.get('id')
            technique_id = rule.get('mitre', {}).get('attack_id')

            if rule_id and technique_id:
                self.rule_to_techniques[rule_id] = [technique_id]
                self.technique_to_rules[technique_id].append(rule_id)

                logger.debug(f"Mapped {rule_id} -> {technique_id}")

        logger.info(f"Mapped {len(self.rule_to_techniques)} rules to {len(self.technique_to_rules)} techniques")

    def get_rules_for_technique(self, technique_id: str) -> List[str]:
        """
        Get all rules that detect a specific technique.

        Args:
            technique_id: MITRE technique ID (e.g., "T1059.001")

        Returns:
            List of rule IDs
        """
        return self.technique_to_rules.get(technique_id, [])

    def get_techniques_for_rule(self, rule_id: str) -> List[str]:
        """
        Get all techniques detected by a specific rule.

        Args:
            rule_id: Rule identifier

        Returns:
            List of technique IDs
        """
        return self.rule_to_techniques.get(rule_id, [])

    def get_coverage_by_tactic(self, rules: List[Dict]) -> Dict[str, Dict]:
        """
        Calculate detection coverage by MITRE tactic.

        Args:
            rules: List of detection rules

        Returns:
            Dictionary with coverage per tactic
        """
        if not self.rule_to_techniques:
            self.map_rules(rules)

        detected_techniques = set(self.technique_to_rules.keys())
        return self.mitre.get_coverage_by_tactic(list(detected_techniques))

    def get_tactic_for_rule(self, rule: Dict) -> Optional[str]:
        """
        Get primary MITRE tactic for a rule.

        Args:
            rule: Detection rule

        Returns:
            Tactic name or None
        """
        tactic = rule.get('mitre', {}).get('tactic')
        if tactic:
            return tactic.lower().replace(' ', '-')
        return None

    def get_technique_info(self, technique_id: str) -> Dict:
        """
        Get detailed information about a technique.

        Args:
            technique_id: MITRE technique ID

        Returns:
            Dictionary with technique details
        """
        technique = self.mitre.get_technique(technique_id)

        if not technique:
            return {
                'id': technique_id,
                'name': 'Unknown',
                'description': 'Technique not found',
                'tactics': [],
                'covered': False
            }

        return {
            'id': technique_id,
            'name': technique.get('name', 'Unknown'),
            'description': technique.get('description', ''),
            'tactics': self.mitre.get_technique_tactics(technique_id),
            'url': f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
            'covered': technique_id in self.technique_to_rules,
            'detecting_rules': self.get_rules_for_technique(technique_id)
        }

    def get_uncovered_techniques(self, tactic: Optional[str] = None) -> List[str]:
        """
        Get techniques that have no detection coverage.

        Args:
            tactic: Optional tactic filter

        Returns:
            List of uncovered technique IDs
        """
        if tactic:
            all_techniques = set(self.mitre.get_tactic_techniques(tactic))
        else:
            all_techniques = set(self.mitre.get_all_techniques())

        covered_techniques = set(self.technique_to_rules.keys())
        uncovered = all_techniques - covered_techniques

        return sorted(uncovered)

    def get_covered_techniques(self, tactic: Optional[str] = None) -> List[str]:
        """
        Get techniques that have detection coverage.

        Args:
            tactic: Optional tactic filter

        Returns:
            List of covered technique IDs
        """
        if tactic:
            tactic_techniques = set(self.mitre.get_tactic_techniques(tactic))
            covered = tactic_techniques & set(self.technique_to_rules.keys())
        else:
            covered = set(self.technique_to_rules.keys())

        return sorted(covered)

    def get_detection_matrix(self, rules: List[Dict]) -> Dict:
        """
        Generate a detection matrix showing rule-to-technique mappings.

        Args:
            rules: List of detection rules

        Returns:
            Detection matrix with mappings
        """
        if not self.rule_to_techniques:
            self.map_rules(rules)

        matrix = {
            'total_rules': len(rules),
            'rules_with_mitre': len(self.rule_to_techniques),
            'total_techniques_covered': len(self.technique_to_rules),
            'rules': []
        }

        for rule in rules:
            rule_id = rule.get('id')
            techniques = self.get_techniques_for_rule(rule_id)

            rule_info = {
                'rule_id': rule_id,
                'title': rule.get('title', 'Unknown'),
                'severity': rule.get('severity') or rule.get('level'),
                'tactic': self.get_tactic_for_rule(rule),
                'techniques': techniques,
                'technique_names': [self.mitre.get_technique_name(t) for t in techniques]
            }

            matrix['rules'].append(rule_info)

        return matrix

    def suggest_rules_for_tactic(self, tactic: str, limit: int = 10) -> List[Dict]:
        """
        Suggest high-priority techniques in a tactic that need detection rules.

        Args:
            tactic: MITRE tactic name
            limit: Maximum number of suggestions

        Returns:
            List of technique suggestions
        """
        uncovered = self.get_uncovered_techniques(tactic)

        # Priority techniques (commonly exploited)
        priority_techniques = [
            'T1003', 'T1059', 'T1071', 'T1078', 'T1082', 'T1083',
            'T1087', 'T1110', 'T1135', 'T1204', 'T1486', 'T1566'
        ]

        suggestions = []

        # Prioritize common techniques
        for tech_id in uncovered:
            if any(tech_id.startswith(p) for p in priority_techniques):
                suggestions.append({
                    'technique_id': tech_id,
                    'name': self.mitre.get_technique_name(tech_id),
                    'tactics': self.mitre.get_technique_tactics(tech_id),
                    'priority': 'high'
                })

        # Add other techniques
        for tech_id in uncovered:
            if not any(tech_id.startswith(p) for p in priority_techniques):
                suggestions.append({
                    'technique_id': tech_id,
                    'name': self.mitre.get_technique_name(tech_id),
                    'tactics': self.mitre.get_technique_tactics(tech_id),
                    'priority': 'medium'
                })

        return suggestions[:limit]

    def validate_rule_mapping(self, rule: Dict) -> Dict:
        """
        Validate MITRE mapping in a rule.

        Args:
            rule: Detection rule

        Returns:
            Validation result
        """
        result = {
            'valid': True,
            'warnings': [],
            'errors': []
        }

        mitre_data = rule.get('mitre', {})

        # Check for attack_id
        attack_id = mitre_data.get('attack_id')
        if not attack_id:
            result['valid'] = False
            result['errors'].append('Missing MITRE attack_id')
            return result

        # Validate attack_id format
        import re
        if not re.match(r'^T\d{4}(?:\.\d{3})?$', attack_id):
            result['warnings'].append(f'Invalid attack_id format: {attack_id}')

        # Check if technique exists
        technique = self.mitre.get_technique(attack_id)
        if not technique:
            result['warnings'].append(f'Technique {attack_id} not found in MITRE framework')

        # Check tactic mapping
        rule_tactic = mitre_data.get('tactic', '').lower().replace(' ', '-')
        if technique:
            valid_tactics = self.mitre.get_technique_tactics(attack_id)
            if rule_tactic not in valid_tactics:
                result['warnings'].append(
                    f'Tactic "{rule_tactic}" not valid for {attack_id}. '
                    f'Valid tactics: {", ".join(valid_tactics)}'
                )

        return result

    def export_coverage_csv(self, rules: List[Dict], filename: str = "coverage.csv"):
        """
        Export coverage data to CSV format.

        Args:
            rules: List of detection rules
            filename: Output filename
        """
        import csv

        if not self.rule_to_techniques:
            self.map_rules(rules)

        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Technique ID', 'Technique Name', 'Tactic', 'Covered', 'Rules'])

            for technique_id in sorted(self.mitre.get_all_techniques()):
                name = self.mitre.get_technique_name(technique_id)
                tactics = ', '.join(self.mitre.get_technique_tactics(technique_id))
                covered = 'Yes' if technique_id in self.technique_to_rules else 'No'
                rules_list = ', '.join(self.get_rules_for_technique(technique_id))

                writer.writerow([technique_id, name, tactics, covered, rules_list])

        logger.info(f"Exported coverage to {filename}")


# Global instance
_mapper = None


def get_mitre_mapper():
    """Get global MITRE mapper instance (singleton)."""
    global _mapper
    if _mapper is None:
        _mapper = MitreMapper()
    return _mapper


if __name__ == "__main__":
    # Test/demo
    from core.detector import load_rules

    mapper = MitreMapper()
    rules = load_rules("rules/")

    mapper.map_rules(rules)

    print(f"\nMITRE Mapper Test")
    print(f"Rules mapped: {len(mapper.rule_to_techniques)}")
    print(f"Techniques covered: {len(mapper.technique_to_rules)}")

    # Show some mappings
    print("\nExample mappings:")
    for rule_id, techniques in list(mapper.rule_to_techniques.items())[:5]:
        print(f"  {rule_id} -> {techniques}")

    # Show coverage for a tactic
    print("\nExecution tactic coverage:")
    covered = mapper.get_covered_techniques("execution")
    print(f"  Covered: {covered}")
