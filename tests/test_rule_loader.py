from core.database import load_rules, get_all_rules

load_rules()

rules = get_all_rules()

print(f"{len(rules)} rules loaded.")

for rule in rules:
    print(rule["id"], "-", rule["title"])