#!/usr/bin/env python3
"""
convert_rules.py

Converts all Sigma detection rules in sigma_rules/ into both Splunk SPL
and Microsoft Sentinel KQL, writing results into converted/splunk/ and
converted/sentinel/ respectively.

This script is the core of the Detection-as-Code pipeline: it is invoked
both locally during development and inside the GitHub Actions CI workflow
on every push, ensuring converted queries always stay in sync with the
source Sigma rules.

Usage:
    python3 scripts/convert_rules.py
    python3 scripts/convert_rules.py --rules-dir sigma_rules --output-dir converted
"""

import argparse
import subprocess
import sys
from pathlib import Path


def convert_to_splunk(rule_path: Path, output_path: Path) -> bool:
    """Convert a single Sigma rule to Splunk SPL using the splunk_windows pipeline."""
    result = subprocess.run(
        ["sigma", "convert", "-t", "splunk", "-p", "splunk_windows", str(rule_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  [FAIL] Splunk conversion failed for {rule_path.name}:")
        print(f"         {result.stderr.strip()}")
        return False

    output_path.write_text(result.stdout.strip() + "\n")
    return True


def convert_to_kusto(rule_path: Path, output_path: Path) -> bool:
    """Convert a single Sigma rule to Kusto Query Language (KQL) for Sentinel."""
    result = subprocess.run(
        ["sigma", "convert", "-t", "kusto", "--without-pipeline", str(rule_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  [FAIL] KQL conversion failed for {rule_path.name}:")
        print(f"         {result.stderr.strip()}")
        return False

    output_path.write_text(result.stdout.strip() + "\n")
    return True


def main():
    parser = argparse.ArgumentParser(description="Convert Sigma rules to SPL and KQL")
    parser.add_argument("--rules-dir", default="sigma_rules", help="Directory containing .yml Sigma rules")
    parser.add_argument("--output-dir", default="converted", help="Directory to write converted queries")
    args = parser.parse_args()

    rules_dir = Path(args.rules_dir)
    splunk_out = Path(args.output_dir) / "splunk"
    sentinel_out = Path(args.output_dir) / "sentinel"
    splunk_out.mkdir(parents=True, exist_ok=True)
    sentinel_out.mkdir(parents=True, exist_ok=True)

    rule_files = sorted(rules_dir.glob("*.yml"))
    if not rule_files:
        print(f"No Sigma rules found in {rules_dir}/")
        sys.exit(1)

    print(f"Found {len(rule_files)} Sigma rule(s) in {rules_dir}/\n")

    failures = 0
    for rule_path in rule_files:
        stem = rule_path.stem
        print(f"Converting {rule_path.name} ...")

        spl_ok = convert_to_splunk(rule_path, splunk_out / f"{stem}.spl")
        kql_ok = convert_to_kusto(rule_path, sentinel_out / f"{stem}.kql")

        if spl_ok:
            print(f"  [OK] -> converted/splunk/{stem}.spl")
        if kql_ok:
            print(f"  [OK] -> converted/sentinel/{stem}.kql")

        if not (spl_ok and kql_ok):
            failures += 1

    print()
    if failures:
        print(f"{failures} rule(s) failed to convert.")
        sys.exit(1)
    else:
        print(f"All {len(rule_files)} rule(s) converted successfully.")


if __name__ == "__main__":
    main()
