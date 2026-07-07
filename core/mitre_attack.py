"""
mitre_attack.py

MITRE ATT&CK Framework integration.
Provides access to tactics, techniques, and relationships.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class MitreAttack:
    """
    MITRE ATT&CK Framework data loader and query interface.
    """

    def __init__(self, framework_path: str = "mitre/enterprise-attack.json"):
        self.framework_path = Path(framework_path)
        self.data = None

        # Indexed data structures
        self.techniques = {}  # technique_id -> technique object
        self.tactics = {}  # tactic_id -> tactic object
        self.relationships = []  # All relationships
        self.technique_to_tactics = defaultdict(list)  # technique_id -> [tactic_ids]
        self.tactic_to_techniques = defaultdict(list)  # tactic_id -> [technique_ids]

        # Load data
        self._load_framework()
        self._index_data()

    def _load_framework(self):
        """Load MITRE ATT&CK framework from JSON file."""

        if not self.framework_path.exists():
            logger.error(f"MITRE ATT&CK framework not found: {self.framework_path}")
            logger.info("Run: python -m core.mitre_attack --download")
            return

        try:
            with open(self.framework_path, 'r') as f:
                self.data = json.load(f)

            logger.info(f"Loaded MITRE ATT&CK framework: {len(self.data.get('objects', []))} objects")

        except Exception as e:
            logger.error(f"Failed to load MITRE ATT&CK framework: {e}")

    def _index_data(self):
        """Index framework data for quick lookups."""

        if not self.data:
            return

        for obj in self.data.get('objects', []):
            obj_type = obj.get('type')

            # Index techniques (attack-pattern)
            if obj_type == 'attack-pattern':
                # Get technique ID (e.g., T1059.001)
                external_refs = obj.get('external_references', [])
                for ref in external_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id')
                        if technique_id:
                            self.techniques[technique_id] = obj
                            break

            # Index tactics (x-mitre-tactic)
            elif obj_type == 'x-mitre-tactic':
                tactic_id = obj.get('x_mitre_shortname')
                if tactic_id:
                    self.tactics[tactic_id] = obj

            # Store relationships
            elif obj_type == 'relationship':
                self.relationships.append(obj)

        # Build technique <-> tactic mappings
        for obj in self.data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                # Get technique ID
                technique_id = None
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id')
                        break

                if not technique_id:
                    continue

                # Get kill chain phases (tactics)
                for phase in obj.get('kill_chain_phases', []):
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        tactic_name = phase.get('phase_name')
                        self.technique_to_tactics[technique_id].append(tactic_name)
                        self.tactic_to_techniques[tactic_name].append(technique_id)

        logger.info(f"Indexed {len(self.techniques)} techniques and {len(self.tactics)} tactics")

    def get_technique(self, technique_id: str) -> Optional[Dict]:
        """
        Get technique details by ID.

        Args:
            technique_id: Technique ID (e.g., "T1059.001")

        Returns:
            Technique object or None
        """
        return self.techniques.get(technique_id)

    def get_tactic(self, tactic_id: str) -> Optional[Dict]:
        """
        Get tactic details by ID.

        Args:
            tactic_id: Tactic short name (e.g., "execution")

        Returns:
            Tactic object or None
        """
        return self.tactics.get(tactic_id.lower())

    def get_technique_name(self, technique_id: str) -> str:
        """Get human-readable technique name."""
        technique = self.get_technique(technique_id)
        if technique:
            return technique.get('name', technique_id)
        return technique_id

    def get_technique_description(self, technique_id: str) -> str:
        """Get technique description."""
        technique = self.get_technique(technique_id)
        if technique:
            return technique.get('description', 'No description available')
        return 'Technique not found'

    def get_technique_tactics(self, technique_id: str) -> List[str]:
        """Get all tactics associated with a technique."""
        return self.technique_to_tactics.get(technique_id, [])

    def get_tactic_techniques(self, tactic_id: str) -> List[str]:
        """Get all techniques associated with a tactic."""
        return self.tactic_to_techniques.get(tactic_id.lower(), [])

    def get_all_techniques(self) -> List[str]:
        """Get list of all technique IDs."""
        return sorted(self.techniques.keys())

    def get_all_tactics(self) -> List[str]:
        """Get list of all tactic IDs."""
        return sorted(self.tactics.keys())

    def search_techniques(self, query: str) -> List[Dict]:
        """
        Search techniques by name or description.

        Args:
            query: Search query (case-insensitive)

        Returns:
            List of matching techniques
        """
        query = query.lower()
        results = []

        for technique_id, technique in self.techniques.items():
            name = technique.get('name', '').lower()
            description = technique.get('description', '').lower()

            if query in name or query in description:
                results.append({
                    'id': technique_id,
                    'name': technique.get('name'),
                    'description': technique.get('description', '')[:200] + '...'
                })

        return results

    def enrich_alert(self, alert: Dict) -> Dict:
        """
        Enrich alert with MITRE ATT&CK details.

        Args:
            alert: Alert dictionary

        Returns:
            Enriched alert with MITRE data
        """
        technique_id = alert.get('mitre_attack_id')

        if not technique_id:
            return alert

        technique = self.get_technique(technique_id)

        if technique:
            alert['mitre_enriched'] = {
                'technique_id': technique_id,
                'technique_name': technique.get('name'),
                'technique_description': technique.get('description', '')[:300],
                'tactics': self.get_technique_tactics(technique_id),
                'url': f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
            }

        return alert

    def get_coverage_by_tactic(self, detected_techniques: List[str]) -> Dict[str, Dict]:
        """
        Calculate coverage statistics by tactic.

        Args:
            detected_techniques: List of technique IDs that have detections

        Returns:
            Coverage statistics per tactic
        """
        coverage = {}

        for tactic_id in self.get_all_tactics():
            tactic = self.get_tactic(tactic_id)
            all_techniques = set(self.get_tactic_techniques(tactic_id))
            detected = set(detected_techniques) & all_techniques

            coverage[tactic_id] = {
                'name': tactic.get('name', tactic_id) if tactic else tactic_id,
                'total_techniques': len(all_techniques),
                'detected_techniques': len(detected),
                'coverage_percent': (len(detected) / len(all_techniques) * 100) if all_techniques else 0,
                'detected_ids': sorted(detected),
                'missing_ids': sorted(all_techniques - detected)
            }

        return coverage

    def get_coverage_matrix(self, rules: List[Dict]) -> Dict:
        """
        Generate coverage matrix from detection rules.

        Args:
            rules: List of detection rules

        Returns:
            Coverage statistics
        """
        detected_techniques = set()

        for rule in rules:
            technique_id = rule.get('mitre', {}).get('attack_id')
            if technique_id:
                detected_techniques.add(technique_id)

        total_techniques = len(self.get_all_techniques())
        detected_count = len(detected_techniques)

        return {
            'total_techniques': total_techniques,
            'detected_techniques': detected_count,
            'coverage_percent': (detected_count / total_techniques * 100) if total_techniques else 0,
            'by_tactic': self.get_coverage_by_tactic(list(detected_techniques)),
            'detected_ids': sorted(detected_techniques),
            'missing_count': total_techniques - detected_count
        }

    def get_technique_subtechniques(self, technique_id: str) -> List[str]:
        """
        Get all sub-techniques for a parent technique.

        Args:
            technique_id: Parent technique ID (e.g., "T1059")

        Returns:
            List of sub-technique IDs
        """
        subtechniques = []

        for tid in self.techniques.keys():
            if tid.startswith(technique_id + '.'):
                subtechniques.append(tid)

        return sorted(subtechniques)

    def is_subtechnique(self, technique_id: str) -> bool:
        """Check if a technique ID is a sub-technique."""
        return '.' in technique_id


# Global instance
_mitre = None

def get_mitre_attack() -> MitreAttack:
    """Get global MITRE ATT&CK instance (singleton)."""
    global _mitre
    if _mitre is None:
        _mitre = MitreAttack()
    return _mitre


def download_framework():
    """Download latest MITRE ATT&CK framework."""
    import urllib.request

    url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    output_path = 'mitre/enterprise-attack.json'

    print(f"Downloading MITRE ATT&CK Enterprise framework...")
    print(f"URL: {url}")

    try:
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read())

        # Ensure directory exists
        Path('mitre').mkdir(exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"✓ Successfully downloaded to {output_path}")
        print(f"  Objects: {len(data.get('objects', []))}")

    except Exception as e:
        print(f"✗ Error: {e}")
        return False

    return True


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == '--download':
        download_framework()
    else:
        # Test/demo
        mitre = MitreAttack()

        print(f"\nMITRE ATT&CK Framework Loaded")
        print(f"Techniques: {len(mitre.get_all_techniques())}")
        print(f"Tactics: {len(mitre.get_all_tactics())}")

        # Test technique lookup
        technique = mitre.get_technique("T1059.001")
        if technique:
            print(f"\nExample Technique: T1059.001")
            print(f"Name: {technique.get('name')}")
            print(f"Tactics: {mitre.get_technique_tactics('T1059.001')}")
