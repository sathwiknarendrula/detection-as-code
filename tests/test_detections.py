#!/usr/bin/env python3
"""
test_detections.py

Validates each Sigma detection rule against curated sample logs to confirm:
  1. True positives  - the rule fires on logs representing the attack it targets
  2. True negatives   - the rule does NOT fire on benign activity (false positive check)

This is a simplified field-matching test harness (not a full Sigma evaluation
engine) built to validate detection *logic* during development, independent
of any specific SIEM. It re-implements each rule's selection/filter logic in
Python against the same JSONL sample logs used for manual review, so a rule
author gets immediate pass/fail feedback before converting to SPL/KQL and
deploying to a real SIEM.

Run as part of CI on every push (see .github/workflows/detection-ci.yml).
"""

import json
import sys
from pathlib import Path

SAMPLE_LOGS_DIR = Path(__file__).parent / "sample_logs"


def load_logs(filename: str) -> list[dict]:
    path = SAMPLE_LOGS_DIR / filename
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def matches_encoded_powershell(log: dict) -> bool:
    image = log.get("Image", "")
    cmdline = log.get("CommandLine", "")
    if not (image.endswith("powershell.exe") or image.endswith("pwsh.exe")):
        return False
    has_encoding = any(flag in cmdline for flag in ["-enc ", "-EncodedCommand", "-e "])
    has_suspicious_flag = any(
        flag in cmdline for flag in ["-w hidden", "-windowstyle hidden", "-nop", "-noprofile"]
    )
    return has_encoding and has_suspicious_flag


def matches_lsass_dump(log: dict) -> bool:
    target = log.get("TargetImage", "")
    source = log.get("SourceImage", "")
    access = log.get("GrantedAccess", "")
    if not target.endswith("lsass.exe"):
        return False
    if access not in {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff"}:
        return False
    if source.endswith("MsMpEng.exe") or source.endswith("dllhost.exe"):
        return False
    return True


def matches_kerberoasting(log: dict) -> bool:
    if log.get("EventID") != 4769:
        return False
    if log.get("TicketEncryptionType") != "0x17":
        return False
    if log.get("ServiceName", "").endswith("$"):
        return False
    return True


RULES = {
    "encoded_powershell": matches_encoded_powershell,
    "lsass_dump": matches_lsass_dump,
    "kerberoasting": matches_kerberoasting,
}


def run_tests() -> bool:
    benign_logs = load_logs("benign_activity.jsonl")
    malicious_logs = load_logs("malicious_activity.jsonl")

    all_passed = True

    print("=" * 60)
    print("DETECTION TEST SUITE")
    print("=" * 60)

    for rule_name, matcher in RULES.items():
        print(f"\nRule: {rule_name}")

        # True negative check: rule must NOT fire on any benign log
        false_positives = [log for log in benign_logs if matcher(log)]
        if false_positives:
            print(f"  [FAIL] False positive(s) on benign logs: {len(false_positives)} match(es)")
            for fp in false_positives:
                print(f"         -> {fp.get('Hostname', 'unknown')} @ {fp.get('timestamp', 'unknown')}")
            all_passed = False
        else:
            print(f"  [PASS] No false positives on {len(benign_logs)} benign log(s)")

        # True positive check: rule MUST fire on at least one malicious log
        true_positives = [log for log in malicious_logs if matcher(log)]
        if true_positives:
            print(f"  [PASS] Detected {len(true_positives)} true positive(s) in malicious logs")
        else:
            print(f"  [FAIL] Rule did not fire on any malicious log (missed detection)")
            all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("RESULT: All detection rules passed validation.")
    else:
        print("RESULT: One or more rules failed validation.")
    print("=" * 60)

    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
