# hunt-report v2

Turn raw scan output into submission-ready vulnerability reports for bug bounty hunters.

## Features

- Parse multiple input formats: markdown findings, EXPLOIT.md, raw HTTP/curl output, Nuclei JSON, deep probe JSON, scope files
- Generate 4-file deliverable set: findings.md, bounty-report.md, poc.md, targets.md
- Auto-classification: TIER-1 through TIER-5 based on evidence quality
- CVSS v3.1 auto-calculation
- HackerOne submission format: h1-submission.md and h1-submission.txt
- Validation mode: evidence quality analysis and submit-first recommendations

## Install

```bash
pip install .
# or
pip install git+https://github.com/yourname/hunt-report.git
```

## Usage

```bash
# Standard mode (4 files)
hunt-report generate --input ./scan-results/ --output ./reports/

# HackerOne mode (6 files, includes h1-submission.md/txt)
hunt-report generate --input ./scan-results/ --output ./reports/ --mode h1

# Validation mode (5 files, includes validation-report.md)
hunt-report generate --input ./scan-results/ --output ./reports/ --mode validate

# Validate evidence quality
hunt-report validate --input ./scan-results/ --output ./validation/

# Show statistics
hunt-report stats --input ./scan-results/
```

## Pricing

- **Individual**: $19/month - unlimited scans, all formats
- **Team**: $79/month (up to 5 hunters)
- **One-shot**: $9 for a single scan report batch

## Example

```bash
$ hunt-report generate --input ./cloudflare-scan/ --output ./reports/ --mode h1

[hunt-report] Scanning ./cloudflare-scan/ for input files...
  Parsed findings.md -> 6 findings (findings_md)
  Parsed exploit.md -> 3 findings (exploit_md)
  Parsed deep_probe.json -> 2 findings (json_results)

[hunt-report] Found 11 findings, 1 targets
[hunt-report] Done! Generated 6 files:
  - ./reports/findings.md
  - ./reports/bounty-report.md
  - ./reports/poc.md
  - ./reports/targets.md
  - ./reports/h1-submission.md
  - ./reports/h1-submission.txt

[hunt-report] Classification Summary:
  TIER-1: 3 findings
  TIER-2: 4 findings
  TIER-3: 2 findings
  TIER-5: 2 findings

[hunt-report] High-value findings (submit these first):
  [TIER-1] Salesforce CSP Bypass (Evidence: 9/10, CVSS: 9.8)
  [TIER-1] Next.js SSRF (Evidence: 8/10, CVSS: 9.8)
  [TIER-2] Workers API Token (Evidence: 7/10, CVSS: 6.5)
```
