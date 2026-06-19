# Detection-as-Code CI/CD Pipeline

A CI/CD pipeline for managing the full lifecycle of security detection rules: author once in Sigma, automatically convert to multiple SIEM query languages, validate detection logic against sample logs, enforce MITRE ATT&CK coverage, and deploy on merge.

## Why this exists

Most SOC teams write detection rules directly in their SIEM's native query language (SPL, KQL, etc.), which creates two problems: rules become locked to a single platform, and there is no automated way to verify a rule still catches what it's supposed to catch after edits. This project treats detection content the way software teams treat application code — version controlled, tested, and deployed through CI.

## What it does

1. **Author** detection logic once, in vendor-neutral [Sigma](https://github.com/SigmaHQ/sigma) YAML format
2. **Convert** automatically to Splunk SPL and Microsoft Sentinel KQL using the official [pySigma](https://github.com/SigmaHQ/pySigma) conversion library
3. **Test** each rule against curated sample logs to confirm it fires on malicious activity and stays silent on benign activity
4. **Gate** on MITRE ATT&CK coverage — every rule must map to at least one technique
5. **Deploy** converted queries as build artifacts on every merge to `main`, ready to paste into a SIEM

## Architecture

```
sigma_rules/              Source of truth — Sigma YAML detection rules
  encoded_powershell.yml
  lsass_dump.yml
  kerberoasting.yml

converted/                 Auto-generated, do not edit by hand
  splunk/*.spl              SPL queries for Splunk
  sentinel/*.kql            KQL queries for Microsoft Sentinel

tests/
  sample_logs/             Synthetic benign + malicious log samples (JSONL)
  test_detections.py        Validates rule logic against sample logs

scripts/
  convert_rules.py          Runs the Sigma -> SPL/KQL conversion
  check_coverage.py         Reports MITRE ATT&CK technique coverage

.github/workflows/
  detection-ci.yml           GitHub Actions pipeline tying it all together
```

## Current detections

| Rule | ATT&CK Technique | Severity |
|---|---|---|
| Suspicious Encoded PowerShell Execution | T1059.001, T1027 | High |
| LSASS Memory Dump via Process Access | T1003.001 | Critical |
| Potential Kerberoasting via Kerberos TGS Request | T1558.003 | Medium |

## Running it locally

```bash
pip install -r requirements.txt

# Run detection logic tests
python3 tests/test_detections.py

# Check MITRE ATT&CK coverage
python3 scripts/check_coverage.py

# Convert all Sigma rules to SPL + KQL
python3 scripts/convert_rules.py
```

Example output from the test suite:

```
Rule: kerberoasting
  [PASS] No false positives on 5 benign log(s)
  [PASS] Detected 3 true positive(s) in malicious logs
```

## Example: one rule, two SIEMs

The Sigma source for the LSASS dump detection ([sigma_rules/lsass_dump.yml](sigma_rules/lsass_dump.yml)) compiles to:

**Splunk SPL:**
```spl
TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff") NOT (SourceImage IN ("*\\MsMpEng.exe", "*\\dllhost.exe"))
```

**Microsoft Sentinel KQL:**
```kql
TargetImage endswith "\\lsass.exe" and (GrantedAccess in~ ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")) and (not((SourceImage endswith "\\MsMpEng.exe" or SourceImage endswith "\\dllhost.exe")))
```

One source of truth, two SIEM-native queries, generated automatically.

## What the CI pipeline checks on every push

- All Sigma rules parse without syntax errors
- Detection logic correctly identifies malicious activity in test logs
- Detection logic does not false-positive on benign activity in test logs
- Every rule has at least one MITRE ATT&CK technique tagged
- Converted SPL and KQL output is regenerated and committed automatically

A pull request that breaks any of these checks fails CI and is blocked from merging — the same gate a production detection engineering team would enforce.

## Limitations and next steps

- Sample logs are hand-crafted JSONL, not pulled from a live SIEM — sufficient for validating rule logic in isolation, not a substitute for testing against real production log volume and noise
- The test harness re-implements each rule's matching logic in Python rather than using a full Sigma evaluation engine against the sample logs directly; this was a deliberate tradeoff to keep the test suite SIEM-independent and dependency-light
- Coverage currently spans 3 ATT&CK techniques across credential access and defense evasion; expanding into discovery and lateral movement techniques is the next priority
- No automated deployment to a live Splunk/Sentinel instance yet — converted queries are produced as CI artifacts for manual review and deployment

## Author

Sathwik Narendrula — [GitHub](https://github.com/sathwiknarendrula) · [LinkedIn](https://linkedin.com/in/sathwiknarendrula)
