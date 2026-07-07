"""
database.py

Loads and manages detection rules from the rules/ directory.
"""

from pathlib import Path
import logging
import yaml

logger = logging.getLogger(__name__)

# In-memory rule storage
_rules = {}

# Rules directory
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def load_rules():
    """
    Load all detection rules from the rules directory.
    """

    global _rules
    _rules.clear()

    if not RULES_DIR.exists():
        logger.error(f"Rules directory not found: {RULES_DIR}")
        return

    for rule_file in RULES_DIR.glob("*.yaml"):

        try:
            with open(rule_file, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)

            if not isinstance(rule, dict):
                logger.warning(f"{rule_file.name} is not a valid rule. Skipping.")
                continue

            rule_id = rule.get("id")

            if not rule_id:
                logger.warning(f"{rule_file.name} has no rule ID. Skipping.")
                continue

            # Check for duplicate rule ID
            if rule_id in _rules:
                existing_file = _rules[rule_id].get("_filename", "unknown")
                logger.error(
                    f"Duplicate rule ID '{rule_id}' found in {rule_file.name}. "
                    f"Already exists in {existing_file}. Skipping."
                )
                continue

            # Store metadata for validator/debugging
            rule["_filename"] = rule_file.name

            _rules[rule_id] = rule

            logger.info(f"Loaded rule: {rule_id} ({rule_file.name})")

        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error in {rule_file.name}: {e}")

        except Exception as e:
            logger.error(f"Failed to load {rule_file.name}: {e}")


def get_all_rules():
    """
    Return all loaded rules.
    """
    return list(_rules.values())


def get_rule(rule_id):
    """
    Return a rule by its ID.
    """
    return _rules.get(rule_id)


def get_rule_count():
    """
    Return the number of loaded rules.
    """
    return len(_rules)


def reload_rules():
    """
    Reload all rules.
    """
    load_rules()