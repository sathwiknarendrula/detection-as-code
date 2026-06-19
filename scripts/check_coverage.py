#!/usr/bin/env python3
"""
check_coverage.py

Parses the `tags` field of every Sigma rule in sigma_rules/ to extract
MITRE ATT&CK technique IDs (e.g. attack.t1059.001) and reports current
coverage. Used as a CI gate: fails the build if a rule has no ATT&CK
mapping at all, since untagged detections can't be tracked against
coverage goals.

This is a lightweight, dependency-free coverage check (no external
MITRE API calls), suitable for running in CI without network access.
"""

import re
import sys
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).parent.parent / "sigma_rules"
TECHNIQUE_PATTERN = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$")


def extract_techniques(tags: list[str]) -> list[str]:
    techniques = []
    for tag in tags:
        match = TECHNIQUE_PATTERN.match(tag)
        if match:
            base, sub = match.groups()
            technique_id = f"T{base}" + (f".{sub}" if sub else "")
            techniques.append(technique_id)
    return techniques


def main():
    rule_files = sorted(RULES_DIR.glob("*.yml"))
    if not rule_files:
        print(f"No rules found in {RULES_DIR}")
        sys.exit(1)

    print("=" * 60)
    print("MITRE ATT&CK COVERAGE REPORT")
    print("=" * 60)

    all_techniques = set()
    untagged_rules = []

    for rule_path in rule_files:
        with open(rule_path) as f:
            rule = yaml.safe_load(f)

        title = rule.get("title", rule_path.stem)
        tags = rule.get("tags", [])
        techniques = extract_techniques(tags)

        if not techniques:
            untagged_rules.append(title)
            print(f"\n{title}")
            print("  [WARN] No ATT&CK technique tags found")
        else:
            print(f"\n{title}")
            for t in techniques:
                print(f"  -> {t}")
            all_techniques.update(techniques)

    print("\n" + "=" * 60)
    print(f"Total unique techniques covered: {len(all_techniques)}")
    print(f"Techniques: {', '.join(sorted(all_techniques))}")
    print("=" * 60)

    if untagged_rules:
        print(f"\n[FAIL] {len(untagged_rules)} rule(s) missing ATT&CK tags: {', '.join(untagged_rules)}")
        sys.exit(1)
    else:
        print("\n[PASS] All rules have at least one ATT&CK technique mapped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
