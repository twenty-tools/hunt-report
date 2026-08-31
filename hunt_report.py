#!/usr/bin/env python3
"""
hunt-report v2: CLI tool that turns raw scan output into submission-ready reports.

Supports:
- Markdown findings files (findings.md, EXPLOIT.md)
- Raw HTTP/curl response files
- Nuclei JSON output
- Deep probe JSON
- Scope/asset inventory files

Produces:
- findings.md - detailed findings with raw HTTP and CVSS
- bounty-report.md - executive summary with tier classification
- poc.md - proof of concept curl commands
- targets.md - asset inventory with status
- h1-submission.md - HackerOne-ready submission body
- h1-submission.txt - HackerOne-ready plain text body

Usage:
    hunt-report generate --input ./scan-results/ --output ./reports/
    hunt-report validate --input ./scan-results/
    hunt-report stats --input ./scan-results/
"""
import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import hashlib


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class Finding:
    title: str = ""
    vuln_class: str = "General"
    endpoint: str = ""
    method: str = "GET"
    severity: str = ""
    tier: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    description: str = ""
    impact: str = ""
    remediation: str = ""
    poc_commands: list = field(default_factory=list)
    raw_response: str = ""
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    response_body: str = ""
    evidence: str = ""
    h1_ineligible: bool = False
    ineligible_reason: str = ""
    tags: list = field(default_factory=list)
    evidence_score: int = 0  # 0-10 scale for tier classification
    duplicate_of: str = ""
    reference_id: str = ""

    def __post_init__(self):
        if not self.tier:
            self.tier = self._auto_classify()
        if not self.cvss_score:
            self.cvss_score, self.cvss_vector = self._auto_cvss()
        if not self.reference_id:
            self.reference_id = hashlib.md5((self.title + self.endpoint).encode()).hexdigest()[:8]

    def _auto_classify(self) -> str:
        """Auto-classify finding tier based on evidence quality (0-10 scale)."""
        score = 0
        evidence_parts = []

        # Evidence scoring: raw HTTP response (strongest)
        if self.raw_response and len(self.raw_response) > 20:
            score += 3
            evidence_parts.append("raw HTTP body present")

        # Status code
        if self.status_code:
            score += 1
            evidence_parts.append(f"HTTP {self.status_code}")

        # Headers present
        if self.headers:
            score += 1
            evidence_parts.append("headers captured")

        # PoC commands exist
        if self.poc_commands:
            score += 2
            evidence_parts.append("PoC commands available")

        # CVSS >= 7.0
        if self.cvss_score >= 7.0:
            score += 2
            evidence_parts.append(f"CVSS {self.cvss_score}")

        # Impact description > 50 chars
        if self.impact and len(self.impact) > 50:
            score += 1
            evidence_parts.append("detailed impact")

        # Remediation present
        if self.remediation:
            score += 1
            evidence_parts.append("remediation documented")

        # Response body has content (not empty/blank)
        if self.response_body and len(self.response_body.strip()) > 10:
            score += 1
            evidence_parts.append("response body content")

        # Penalties
        if self.h1_ineligible:
            score -= 2

        # Cap at 0-10
        score = max(0, min(10, score))
        self.evidence_score = score

        # Map evidence score to tier
        if score >= 8:
            return "TIER-1"  # Strong: raw HTTP + PoC + CVSS >= 7
        elif score >= 6:
            return "TIER-2"  # Good: PoC + some HTTP evidence
        elif score >= 4:
            return "TIER-3"  # Partial: PoC or HTTP, not both
        elif score >= 2:
            return "TIER-4"  # Thin: just status codes or minimal
        else:
            return "TIER-5"  # Very thin: likely ineligible

    def _auto_cvss(self) -> Tuple[float, str]:
        """Auto-calculate CVSS v3.1 score."""
        base_scores = {
            "RCE": (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "SSRF": (9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/A:N"),
            "SQLi": (9.0, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/A:N"),
            "Auth Bypass": (9.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            "IDOR": (8.2, "AV:N/AC:L/PR:L/UI:N/S:C/C:H/A:N"),
            "Path Traversal": (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            "XSS": (6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            "CORS": (6.5, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            "Header Leak": (5.3, "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N"),
            "Session Fixation": (6.5, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            "JNDI": (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "Signature Replay": (7.5, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
            "Default": (5.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        }
        for key, (score, vector) in base_scores.items():
            if key.lower() in self.vuln_class.lower():
                return score, vector
        return base_scores["Default"]

    def _infer_vuln_class(self) -> str:
        """Infer vulnerability class from title and evidence."""
        combined = (self.title + self.description + self.impact).lower()

        vuln_patterns = {
            "RCE": ["rce", "remote code execution", "command injection", "exec(", "system(", "eval(", "shell"],
            "SSRF": ["ssrf", "server side request", "fetch url", "getaddrinfo", "urllib", "requests.get", "internal"],
            "SQLi": ["sqli", "sql injection", "sqlstate", "mysql", "syntax near", "union select", "error"],
            "XSS": ["xss", "cross-site scripting", "alert(", "document.cookie", "referrer", "location"],
            "CORS": ["cors", "cross-origin", "access-control-allow-origin", "origin"],
            "IDOR": ["idor", "insecure direct object", "user/", "api/", "order/", "invoice/"],
            "Path Traversal": ["path traversal", "directory traversal", "../", "etc/passwd"],
            "Auth Bypass": ["auth bypass", "authentication bypass", "jwt", "token", "authorization"],
            "Header Leak": ["header", "x-powered-by", "server:", "x-aspnet", "x-pingback"],
            "Session Fixation": ["session", "jsessionid", "session fixation", "cookie"],
            "JNDI": ["jndi", "log4j", "lookup", "jndi:ldap", "jndi:rmi"],
            "Signature Replay": ["signature", "replay", "timestamp", "nonce"],
            "Default": [],
        }

        for vuln, patterns in vuln_patterns.items():
            if vuln == "Default":
                continue
            for pattern in patterns:
                if pattern in combined:
                    return vuln
        return "General"

    def generate_h1_body(self) -> str:
        """Generate HackerOne submission body markdown."""
        lines = []
        lines.append(f"## {self.title}")
        lines.append("")
        lines.append("### Summary")
        lines.append("")
        lines.append(f"A {self.vuln_class.lower().replace(' ', '-')} vulnerability in {self.endpoint} allows [impact].")
        lines.append("")
        lines.append("### Proof of Concept")
        lines.append("")
        lines.append("```")
        for cmd in self.poc_commands:
            lines.append(cmd)
        lines.append("```")
        lines.append("")

        if self.raw_response:
            lines.append("### HTTP Response")
            lines.append("")
            lines.append("```http")
            lines.append(f"HTTP/1.1 {self.status_code}")
            for k, v in self.headers.items():
                lines.append(f"{k}: {v}")
            lines.append("")
            lines.append(self.raw_response[:500])
            lines.append("```")
            lines.append("")

        lines.append("### Impact")
        lines.append("")
        lines.append(self.impact if self.impact else "The vulnerability impacts the confidentiality and/or integrity of the application.")
        lines.append("")
        lines.append("### Suggested Priority")
        lines.append("")
        if self.cvss_score >= 9.0:
            lines.append("Critical (CVSS {}/10)".format(self.cvss_score))
        elif self.cvss_score >= 7.0:
            lines.append("High (CVSS {}/10)".format(self.cvss_score))
        elif self.cvss_score >= 4.0:
            lines.append("Medium (CVSS {}/10)".format(self.cvss_score))
        else:
            lines.append("Low (CVSS {}/10)".format(self.cvss_score))
        lines.append("")

        if self.remediation:
            lines.append("### Recommended Fix")
            lines.append("")
            lines.append(self.remediation)
            lines.append("")

        return "\n".join(lines)

    def to_h1_json(self) -> dict:
        """Convert to HackerOne API submission format."""
        return {
            "title": self.title,
            "vulnerability_class_id": self._vuln_class_id(),
            "severity_verbosity": "hidden",
            "body": self.generate_h1_body(),
            "tags": self.tags,
            "custom_fields": {
                "cvss_score": self.cvss_score,
                "evidence_score": self.evidence_score,
                "tier": self.tier,
            }
        }

    def _vuln_class_id(self) -> int:
        """Map to HackerOne vulnerability class IDs."""
        class_map = {
            "RCE": 2,  # Remote Code Execution
            "SSRF": 4,  # Server-Side Request Forgery
            "SQLi": 7,  # SQL Injection
            "XSS": 9,  # Cross-Site Scripting
            "CORS": 13,  # Cross-Origin Resource Sharing
            "IDOR": 14,  # Insecure Direct Object Reference
            "Path Traversal": 16,  # Path Traversal
            "Auth Bypass": 21,  # Authentication Bypass
            "Header Leak": 18,  # Information Disclosure
            "Session Fixation": 24,  # Session Fixation
            "JNDI": 2,  # Remote Code Execution (Log4j)
            "Signature Replay": 7,  # SQL Injection (reuse)
        }
        for key, vid in class_map.items():
            if key.lower() in self.vuln_class.lower():
                return vid
        return 18  # Information Disclosure (fallback)


@dataclass
class Target:
    domain: str
    status_code: Optional[int] = None
    server: str = ""
    tech_stack: list = field(default_factory=list)
    security_headers: list = field(default_factory=list)
    cookies: list = field(default_factory=list)
    ingress: str = ""
    scope_tier: str = ""
    notes: str = ""
    ports: list = field(default_factory=list)
    ip: str = ""


# ============================================================
# INPUT PARSERS
# ============================================================

class InputParser:
    """Parse various input formats into Finding and Target objects."""

    @staticmethod
    def parse_findings_md(filepath: str) -> list:
        """Parse a findings.md file into Findings."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        findings = []

        # Split by finding sections
        # Split on any ## or ### section header that looks like a finding or major section
        # This catches both "### Finding 1:" and "## Executive Summary", "## Findings", etc.
        sections = re.split(
            r'(?=^#{2,3}\s*(?:Finding|Vulnerability|Exploit|Issue|Executive|Ineligible|Actionable|Infrastructure|Summary|Recon)\s*(?:\d*)\s*:?)',
            content,
            flags=re.MULTILINE | re.IGNORECASE
        )

        for section in sections:
            if not section.strip():
                continue

            finding = Finding(title="")

            # Extract title
            # Extract title - try multiple patterns for robustness
            title_match = re.search(
                r'^(?:##|###)\s*(?:Finding|Vulnerability|Exploit|Issue)\s*\d*:\s*(.+)$',
                section,
                re.MULTILINE | re.IGNORECASE
            )
            if not title_match:
                # Fallback: just get the section header text
                title_match = re.search(
                    r'^(?:##|###)\s*(.+)$',
                    section,
                    re.MULTILINE | re.IGNORECASE
                )
            if title_match:
                finding.title = title_match.group(1).strip()

            # Extract severity
            sev_match = re.search(r'(?:Severity|CVSS)\s*[:\\-]*\s*([A-Z]+|[0-9]+\.?[0-9]*)', section)
            if sev_match:
                finding.severity = sev_match.group(1).strip()

            # Extract H1 ineligible
            if "h1 ineligible" in section.lower() or "ineligible" in section.lower():
                finding.h1_ineligible = True
                reason_match = re.search(r'H1 Ineligible\s*[:\\-]*\s*(.+?)(?:\n|$)', section, re.IGNORECASE)
                if reason_match:
                    finding.ineligible_reason = reason_match.group(1).strip()

            # Extract endpoint (cleaner regex)
            endpoint_match = re.search(r'(?:Endpoint|URL|Path)\s*[:\-*]\s*\*?\*?\*?(.+?)(?:\n|$)', section)
            if endpoint_match:
                finding.endpoint = endpoint_match.group(1).strip().strip('*')

            # Extract HTTP method
            method_match = re.search(r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s', section, re.IGNORECASE)
            if method_match:
                finding.method = method_match.group(1).upper()

            # Extract impact
            if "impact" in section.lower():
                impact_section = re.search(r'##?\s*Impact\s*\n(.*?)(?=\n##|\n---|\Z)', section, re.DOTALL | re.IGNORECASE)
                if impact_section:
                    finding.impact = impact_section.group(1).strip()

            # Extract remediation
            if "remediation" in section.lower() or "fix" in section.lower():
                fix_section = re.search(
                    r'##?\s*(?:Remediation|Fix|Solution)\s*\n(.*?)(?=\n##|\n---|\Z)',
                    section,
                    re.DOTALL | re.IGNORECASE
                )
                if fix_section:
                    finding.remediation = fix_section.group(1).strip()

            # Extract PoC commands
            code_blocks = re.findall(r'```(?:bash|http|sh)?\n(.*?)```', section, re.DOTALL)
            for block in code_blocks:
                lines = [l.strip() for l in block.strip().split('\n') if l.strip()]
                if lines:
                    finding.poc_commands.append('\n'.join(lines))

            # Extract description
            if "description" in section.lower():
                desc_section = re.search(
                    r'##?\s*Description\s*\n(.*?)(?=\n##|\nProof|\nImpact|\nRemediation|\n---|\Z)',
                    section,
                    re.DOTALL | re.IGNORECASE
                )
                if desc_section:
                    finding.description = desc_section.group(1).strip()

            # Extract raw response (between http code blocks or labeled)
            raw_match = re.search(
                r'Raw Response.*?```http\n(.*?)```',
                section,
                re.DOTALL | re.IGNORECASE
            )
            if raw_match:
                finding.raw_response = raw_match.group(1).strip()

            # Extract status code
            sc_match = re.search(r'(?:Status Code|HTTP/1\.\d)\s*(\d{3})', section)
            if sc_match:
                finding.status_code = int(sc_match.group(1))

            # Infer vuln class
            finding.vuln_class = finding._infer_vuln_class()

            if finding.title and finding.title != "":
                # Clean title: strip leading colons, numbers, hashes, fragments
                finding.title = re.sub(r'^(#{1,3}\s*|\d*:\s*)', '', finding.title).strip()
                # Strip ALL markdown bold markers (**, **, ***) from start, end, and middle
                finding.title = re.sub(r'\*{1,3}', '', finding.title).strip()
                # Clean up any double spaces that resulted from bold removal
                finding.title = re.sub(r'\s{2,}', ' ', finding.title).strip()

                # Filter out non-finding sections (these are document sections, not vulnerabilities)
                non_finding_headers = [
                    "Executive Summary", "Summary", "Findings", "Ineligible Findings",
                    "Actionable Findings", "Infrastructure Map", "Asset Inventory",
                    "Infrastructure Stack", "Attack Surface", "Recon", "Conclusion",
                    "Recommendations", "Next Steps", "Appendix", "Appendix A",
                    "Overview", "Recon Plan", "Infrastructure", "Asset Scope Check",
                    "Status: COMPLETE", "Results", "Target:", "Phase",
                    "Introduction", "Scope", "Methodology", "Limitations",
                    "Disclaimer", "Notes", "Footnotes",
                ]
                title_lower = finding.title.lower()
                if finding.title in non_finding_headers:
                    continue

                # If title is just a single short word without a domain or endpoint,
                # it's probably a section header, not a finding
                if len(finding.title) < 10 and not any(
                    kw in title_lower for kw in ["bypass", "leak", "injection", "xss", "cors", "sqli", "rce", "ssrf", "idor", "csrf", "ssrf", "header", "cookie", "token", "auth", "session", "xss", "xss", "lfi", "rfi", "open redirect", "redirect", "expose", "missing", "missing", "lack"]
                ):
                    # Check if the section has any vulnerability indicators
                    has_vuln_indicators = (
                        "HTTP/" in section or "curl" in section or "200" in section or
                        "403" in section or "500" in section or "502" in section or
                        "404" in section or "error" in section.lower() or
                        "endpoint" in section.lower() or "url" in section.lower() or
                        "http" in section.lower() or "response" in section.lower() or
                        "poc" in section.lower() or "proof" in section.lower()
                    )
                    if not has_vuln_indicators:
                        continue

                findings.append(finding)

        return findings

    @staticmethod
    def parse_raw_http(filepath: str) -> list:
        """Parse raw HTTP/curl response files into Findings."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        findings = []
        finding = Finding()

        # Try to extract HTTP status code
        status_match = re.search(r'(HTTP/1\.\\d)\s*(\d{3})', content)
        if status_match:
            finding.status_code = int(status_match.group(2))

        # Extract headers
        header_section = re.search(r'(HTTP/\d\.\d\s+\d{3}\s.*?)(?=\n\n|\n\n\n)', content, re.DOTALL)
        if header_section:
            header_text = header_section.group(1)
            for line in header_text.split('\n')[1:]:  # skip status line
                if ':' in line:
                    key, _, value = line.partition(':')
                    finding.headers[key.strip()] = value.strip() if value.strip() else ""

        # Extract body
        body_match = re.search(r'\n\n(.*?)(\n\.\.\.\[truncated\])?$', content, re.DOTALL)
        if body_match:
            finding.response_body = body_match.group(1).strip()
            finding.raw_response = body_match.group(1).strip()

        # Try to detect vuln class from content
        finding.vuln_class = finding._infer_vuln_class()
        finding.title = f"HTTP Response: {os.path.basename(filepath)}"
        finding.tags = [f"http-{finding.status_code}"] if finding.status_code else ["http-response"]

        findings.append(finding)

        return findings

    @staticmethod
    def parse_nuclei_json(filepath: str) -> list:
        """Parse Nuclei scan JSON output into Findings."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        findings = []

        # Handle array format (multiple results)
        items = data if isinstance(data, list) else data.get("results", [])

        for item in items:
            finding = Finding()
            finding.title = item.get("template-id", item.get("template", "Unknown"))
            finding.vuln_class = finding._infer_vuln_class()
            finding.endpoint = item.get("host", "")
            finding.raw_response = item.get("matched-at", "")
            finding.status_code = item.get("status-code", 0)
            finding.severity = item.get("info", {}).get("severity", "")
            finding.description = item.get("info", {}).get("description", "")
            finding.impact = item.get("info", {}).get("impact", "")
            finding.remediation = item.get("info", {}).get("remediation", "")
            finding.tags = [item.get("template-id", "")]

            # Extract response body
            if item.get("extracted-results"):
                finding.raw_response = str(item["extracted-results"])[:1000]

            findings.append(finding)

        return findings

    @staticmethod
    def parse_json_results(filepath: str) -> list:
        """Parse JSON scan results into Findings."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        findings = []

        def extract_finding(item: dict, context="") -> Finding:
            finding = Finding()
            finding.title = item.get("title", "")
            finding.vuln_class = item.get("vuln_class", item.get("class", "General"))
            finding.endpoint = item.get("endpoint", item.get("url", item.get("uri", item.get("matched-at", ""))))
            finding.raw_response = item.get("response", item.get("body", item.get("response_body", "")))
            finding.status_code = item.get("status_code", item.get("status", 0))
            finding.headers = item.get("headers", {})
            finding.response_body = item.get("body", item.get("response_body", ""))
            finding.description = item.get("description", "")
            finding.impact = item.get("impact", "")
            finding.remediation = item.get("remediation", item.get("fix", ""))
            finding.severity = item.get("severity", "")
            finding.tags = item.get("tags", [])
            finding.method = item.get("method", "GET")

            if "h1_ineligible" in item or "ineligible" in item:
                finding.h1_ineligible = True
                finding.ineligible_reason = item.get("ineligible_reason", "")

            if item.get("poc"):
                finding.poc_commands = [item["poc"]] if isinstance(item["poc"], str) else item["poc"]

            finding.vuln_class = finding._infer_vuln_class()
            return finding

        if isinstance(data, list):
            for item in data:
                findings.append(extract_finding(item) if isinstance(item, dict) else Finding())
        elif isinstance(data, dict):
            # Handle nested structures
            if "findings" in data:
                for item in data["findings"]:
                    findings.append(extract_finding(item))
            elif "deep_probe_results" in data:
                for key, val in data["deep_probe_results"].items():
                    if isinstance(val, dict):
                        f = extract_finding({
                            "title": key,
                            "vuln_class": "General",
                            "endpoint": val.get("url", key),
                            "status_code": val.get("status", val.get("status_code", 0)),
                            "body": val.get("body", val.get("response", "")),
                            "headers": val.get("headers", {}),
                            "description": val.get("description", ""),
                        })
                        findings.append(f)
                    elif isinstance(val, str) and len(val) > 20:
                        findings.append(extract_finding({
                            "title": key,
                            "vuln_class": "General",
                            "status_code": 0,
                            "body": val[:500],
                        }))
            else:
                findings.append(extract_finding(data))

        return findings

    @staticmethod
    def parse_scope_json(filepath: str) -> list:
        """Parse scope JSON into Targets."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        targets = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    domain = item.get("asset_identifier", item.get("domain", item.get("host", "")))
                    if domain:
                        target = Target(domain=domain)
                        target.scope_tier = item.get("max_severity", "")
                        target.notes = item.get("instruction", "")
                        target.ports = item.get("ports", [])
                        target.ip = item.get("ip", "")
                        targets.append(target)
        return targets

    @staticmethod
    def parse_target_md(filepath: str) -> list:
        """Parse target/SCOPE markdown into Targets."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        targets = []
        # Extract domains from markdown (look for domain patterns)
        domains = re.findall(r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', content)
        for domain in set(domains):
            targets.append(Target(domain=domain))
        return targets

    @staticmethod
    def parse_exploit_md(filepath: str) -> list:
        """Parse EXPLOIT.md files with exploit proofs."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        findings = []
        # Split by exploit sections (## ## ## Exploit or similar)
        sections = re.split(
            r'(?=##?\s*Exploit|##?\s*Vulnerability|##?\s*Finding\s*\d+|##?\s*#?\d+)',
            content,
            flags=re.MULTILINE | re.IGNORECASE
        )

        for section in sections:
            if not section.strip():
                continue

            finding = Finding(title="")

            # Try to extract exploit title
            title_match = re.search(r'(?:Exploit|Vulnerability|Finding|#[\d]+)\s*(.+)', section[:200])
            if title_match:
                finding.title = title_match.group(1).strip()

            # Extract PoC commands
            code_blocks = re.findall(r'```(?:bash|http|sh)?\n(.*?)```', section, re.DOTALL)
            for block in code_blocks:
                lines = [l.strip() for l in block.strip().split('\n') if l.strip()]
                if lines:
                    finding.poc_commands.append('\n'.join(lines))

            # Extract raw response
            raw_match = re.search(r'```(?:http|raw)\s*\n(.*?)```', section, re.DOTALL)
            if raw_match:
                finding.raw_response = raw_match.group(1).strip()
                finding.status_code = 0
                # Try to get status from response
                sc = re.search(r'HTTP/1\.\d\s+(\d{3})', raw_match.group(1))
                if sc:
                    finding.status_code = int(sc.group(1))

            # Extract vuln class from title
            finding.vuln_class = finding._infer_vuln_class()

            if finding.title:
                # Clean title - strip markdown bold, hashes, numbers, fragments
                finding.title = re.sub(r'^(#{1,3}\s*|\d*:\s*)', '', finding.title).strip()
                finding.title = re.sub(r'\*{1,3}', '', finding.title).strip()
                finding.title = re.sub(r'\s{2,}', ' ', finding.title).strip()

                # Filter out fragments: titles shorter than 8 chars are likely section markers
                if len(finding.title) < 8:
                    continue

                # Filter out non-finding sections
                non_finding_headers = [
                    "Executive Summary", "Summary", "Findings", "Ineligible Findings",
                    "Actionable Findings", "Infrastructure Map", "Asset Inventory",
                    "Infrastructure Stack", "Attack Surface", "Recon", "Conclusion",
                    "Recommendations", "Next Steps", "Appendix", "Exploit", "EXPLOIT",
                    "s"
                ]
                if finding.title in non_finding_headers:
                    continue

                findings.append(finding)

        return findings

    @classmethod
    def detect_format(cls, filepath: str) -> str:
        """Auto-detect the format of an input file."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(1000)

        filepath_lower = os.path.basename(filepath).lower()
        filepath_stem = os.path.splitext(filepath_lower)[0]

        # Check by filename first (most specific patterns)
        if "nuclei" in filepath_lower:
            return "nuclei_json"
        if filepath_stem == "exploit" or "exploit" in filepath_lower:
            return "exploit_md"
        if "findings" in filepath_lower:
            return "findings_md"

        # Scope detection: check if it's actually JSON before classifying
        if "scope" in filepath_lower:
            # Try JSON first - scope files should be valid JSON
            if content.strip().startswith('{') or content.strip().startswith('['):
                try:
                    json.loads(content)
                    return "scope"
                except json.JSONDecodeError:
                    # Not JSON, treat as markdown
                    pass
            # If it doesn't start with JSON, check if it's markdown
            if "##" in content or "###" in content:
                return "findings_md"
            # Otherwise fall through to generic detection
        elif filepath_lower.endswith('.json'):
            # Any other .json file - try to parse as JSON
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    if data and isinstance(data[0], dict) and "template" in str(data[0]):
                        return "nuclei_json"
                    return "json_results"
                elif "findings" in data:
                    return "json_results"
                elif "deep_probe_results" in data:
                    return "json_results"
                return "json_results"
            except json.JSONDecodeError:
                pass

        # Check by content patterns
        if "HTTP/" in content or "curl" in content or "200 OK" in content:
            return "raw_http"

        if "##" in content or "###" in content:
            return "findings_md"

        return "unknown"


# ============================================================
# OUTPUT GENERATORS
# ============================================================

class ReportGenerator:
    """Generate the deliverable set from Findings and Targets."""

    def __init__(self, findings: list, targets: list, scan_info: dict = None):
        self.findings = findings
        self.targets = targets
        self.scan_info = scan_info or {}
        self.date = datetime.now().strftime("%Y-%m-%d %H:%M")
        self.target_name = self.scan_info.get("target", "Target")
        self.hunter = self.scan_info.get("hunter", "Hunter")
        self.mode = self.scan_info.get("mode", "standard")  # standard, h1, compact

    def generate_findings_md(self) -> str:
        """Generate findings.md - detailed with raw HTTP output and CVSS vector."""
        lines = [
            f"# {self.target_name} - Detailed Findings",
            f"",
            f"**Target:** {self.target_name}",
            f"**Date:** {self.date}",
            f"**Hunter:** {self.hunter}",
            f"**Mode:** {self.mode}",
            f"**Total Findings:** {len(self.findings)}",
            f"**Critical:** {sum(1 for f in self.findings if f.cvss_score >= 9.0)}",
            f"**High:** {sum(1 for f in self.findings if 7.0 <= f.cvss_score < 9.0)}",
            f"**Medium:** {sum(1 for f in self.findings if 4.0 <= f.cvss_score < 7.0)}",
            f"**Low:** {sum(1 for f in self.findings if f.cvss_score < 4.0)}",
            f"",
            f"---",
            f"",
            f"## Classification Legend",
            f"",
            f"| Tier | Evidence Score | Description |",
            f"|------|---------------|-------------|",
            f"| TIER-1 | 8-10 | Strong evidence with PoC, raw HTTP, and CVSS >= 7 |",
            f"| TIER-2 | 6-7 | Good evidence, PoC with minor HTTP gaps |",
            f"| TIER-3 | 4-5 | Partial evidence (PoC or HTTP, not both) |",
            f"| TIER-4 | 2-3 | Thin evidence (status codes only) |",
            f"| TIER-5 | 0-1 | Very thin / likely ineligible |",
            f"",
            f"---",
            f"",
        ]

        # Sort by CVSS score descending
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (f.cvss_score, f.evidence_score),
            reverse=True
        )

        for i, f in enumerate(sorted_findings, 1):
            lines.extend([
                f"### Finding {i}: {f.title} [ID: {f.reference_id}]",
                f"",
                f"- **Vulnerability Class:** {f.vuln_class}",
                f"- **Severity:** {f.severity or 'Auto-assigned'}",
                f"- **CVSS 3.1 Score:** {f.cvss_score}",
                f"- **CVSS Vector:** {f.cvss_vector}",
                f"- **Tier:** {f.tier} (Evidence: {f.evidence_score}/10)",
                f"- **Endpoint:** {f.endpoint}",
                f"- **Method:** {f.method}",
                f"- **Status Code:** {f.status_code}",
                f"- **Reference ID:** {f.reference_id}",
            ])

            if f.h1_ineligible:
                lines.extend([
                    f"",
                    f"- **H1 Ineligible:** Yes - {f.ineligible_reason}",
                ])

            if f.description:
                lines.extend([
                    f"",
                    f"**Description:**",
                    f"{f.description}",
                ])

            if f.poc_commands:
                lines.extend([
                    f"",
                    f"**Proof of Concept:**",
                    f"",
                ])
                for j, cmd in enumerate(f.poc_commands, 1):
                    lines.append(f"```bash")
                    lines.append(f"# Command {j}")
                    for cmd_line in cmd.split('\n'):
                        lines.append(cmd_line)
                    lines.append(f"```")

            if f.raw_response:
                lines.extend([
                    f"",
                    f"**Raw Response:**",
                    f"",
                    f"```http",
                    f"HTTP/1.1 {f.status_code}",
                ])
                for k, v in f.headers.items():
                    lines.append(f"{k}: {v}")
                lines.append(f"")
                response_display = f.raw_response[:500]
                if len(f.raw_response) > 500:
                    lines.append(f"{response_display}...[truncated]")
                else:
                    lines.append(f"{response_display}")
                lines.append(f"```")

            lines.extend([
                f"",
                f"---",
                f"",
            ])

        return '\n'.join(lines)

    def generate_bounty_report(self) -> str:
        """Generate bounty-report.md - executive summary prioritized by tier."""
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (f.cvss_score, f.evidence_score),
            reverse=True
        )
        actionable = [f for f in sorted_findings if not f.h1_ineligible]
        ineligible = [f for f in sorted_findings if f.h1_ineligible]

        lines = [
            f"# {self.target_name} - Bounty Report",
            f"",
            f"**Target:** {self.target_name}",
            f"**Date:** {self.date}",
            f"**Hunter:** {self.hunter}",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"Security assessment of {self.target_name}.",
            f"Identified {len(actionable)} actionable findings out of {len(self.findings)} total findings.",
            f"",
            f"### Key Metrics",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Findings | {len(self.findings)} |",
            f"| Actionable | {len(actionable)} |",
            f"| Ineligible | {len(ineligible)} |",
            f"| Critical (CVSS 9.0+) | {sum(1 for f in self.findings if f.cvss_score >= 9.0)} |",
            f"| High (CVSS 7.0-8.9) | {sum(1 for f in self.findings if 7.0 <= f.cvss_score < 9.0)} |",
            f"| Medium (CVSS 4.0-6.9) | {sum(1 for f in self.findings if 4.0 <= f.cvss_score < 7.0)} |",
            f"| Low (CVSS <4.0) | {sum(1 for f in self.findings if f.cvss_score < 4.0)} |",
            f"| TIER-1 (Strong) | {sum(1 for f in self.findings if f.tier == 'TIER-1')} |",
            f"| TIER-2 (Good) | {sum(1 for f in self.findings if f.tier == 'TIER-2')} |",
            f"| TIER-3 (Partial) | {sum(1 for f in self.findings if f.tier == 'TIER-3')} |",
            f"| TIER-4 (Thin) | {sum(1 for f in self.findings if f.tier == 'TIER-4')} |",
            f"| TIER-5 (Very Thin) | {sum(1 for f in self.findings if f.tier == 'TIER-5')} |",
            f"",
            f"---",
            f"",
            f"## Actionable Findings",
            f"",
            f"| # | Finding | Class | Severity | CVSS | Tier | Evidence |",
            f"|---|---------|-------|----------|------|------|----------|",
        ]

        for i, f in enumerate(actionable, 1):
            evidence_display = f"{f.evidence_score}/10"
            lines.append(
                f"| {i} | {f.title} | {f.vuln_class} | {f.severity or 'Auto'} | {f.cvss_score} | {f.tier} | **{evidence_display}** |"
            )

        if ineligible:
            lines.extend([
                f"",
                f"---",
                f"",
                f"## Ineligible Findings",
                f"",
                f"| # | Finding | Reason |",
                f"|---|---------|--------|",
            ])
            for i, f in enumerate(ineligible, 1):
                lines.append(f"| {i} | {f.title} | {f.ineligible_reason or 'General'} |")

        lines.extend([
            f"",
            f"---",
            f"",
            f"**Generated by hunt-report v2 on {self.date}**",
        ])

        return '\n'.join(lines)

    def generate_poc_md(self) -> str:
        """Generate poc.md - curl commands to reproduce."""
        actionable = [f for f in self.findings if not f.h1_ineligible]

        lines = [
            f"# {self.target_name} - Proof of Concept Commands",
            f"",
            f"**Target:** {self.target_name}",
            f"**Date:** {self.date}",
            f"",
            f"---",
            f"",
        ]

        for i, f in enumerate(actionable, 1):
            lines.extend([
                f"## PoC {i}: {f.title}",
                f"",
                f"**Vulnerability Class:** {f.vuln_class}",
                f"**Endpoint:** {f.endpoint}",
                f"**Method:** {f.method}",
                f"**CVSS:** {f.cvss_score} ({f.cvss_vector})",
                f"**Evidence Score:** {f.evidence_score}/10",
                f"",
                f"```bash",
                f"# === {f.title} ===",
                f"# Class: {f.vuln_class}",
                f"# CVSS: {f.cvss_score}/10",
                f"",
            ])
            for j, cmd in enumerate(f.poc_commands, 1):
                lines.append(f"# Command {j}")
                for cmd_line in cmd.split('\n'):
                    lines.append(cmd_line)
                lines.append(f"")

            lines.extend([
                f"```",
                f"",
                f"---",
                f"",
            ])

        lines.extend([
            f"**Generated by hunt-report v2 on {self.date}**",
        ])

        return '\n'.join(lines)

    def generate_targets_md(self) -> str:
        """Generate targets.md - discovered assets with status."""
        lines = [
            f"# {self.target_name} - Asset Inventory",
            f"",
            f"**Target:** {self.target_name}",
            f"**Date:** {self.date}",
            f"",
            f"---",
            f"",
            f"| # | Domain | Status | Server | Ingress | Scope Tier |",
            f"|---|--------|--------|--------|---------|------------|",
        ]

        for i, t in enumerate(self.targets, 1):
            status_display = f"HTTP {t.status_code}" if t.status_code else "N/A"
            lines.append(
                f"| {i} | {t.domain} | {status_display} | {t.server or 'N/A'} | {t.ingress or 'N/A'} | {t.scope_tier or 'N/A'} |"
            )

        lines.extend([
            f"",
            f"---",
            f"",
            f"**Generated by hunt-report v2 on {self.date}**",
        ])

        return '\n'.join(lines)

    def generate_h1_submission_md(self) -> str:
        """Generate HackerOne submission markdown (single finding per section)."""
        lines = [
            f"# {self.target_name} - HackerOne Submission",
            f"",
            f"**Date:** {self.date}",
            f"**Hunter:** {self.hunter}",
            f"",
            f"---",
            f"",
        ]

        actionable = [f for f in self.findings if not f.h1_ineligible and f.poc_commands]

        if not actionable:
            lines.append("No findings with PoC commands available for submission.")
            lines.append("")
            lines.append("Recommend: run additional validation to capture HTTP responses.")
            lines.append("")
            return '\n'.join(lines)

        for i, f in enumerate(actionable, 1):
            lines.append(f"---")
            lines.append(f"")
            lines.append(f"## Finding {i}: {f.title}")
            lines.append(f"")
            lines.append(f"```")
            lines.append(f"ID: {f.reference_id}")
            lines.append(f"Class: {f.vuln_class}")
            lines.append(f"CVSS: {f.cvss_score}/10")
            lines.append(f"Tier: {f.tier}")
            lines.append(f"```")
            lines.append(f"")
            lines.append(f"```")
            for cmd in f.poc_commands:
                lines.append(cmd)
            lines.append(f"```")
            lines.append(f"")

        lines.extend([
            f"---",
            f"",
            f"**Generated by hunt-report v2 on {self.date}**",
        ])

        return '\n'.join(lines)

    def generate_h1_submission_txt(self) -> str:
        """Generate HackerOne submission plain text (no markdown formatting)."""
        lines = [
            f"Target: {self.target_name}",
            f"Date: {self.date}",
            f"Hunter: {self.hunter}",
            f"",
            f"=== FINDINGS ===",
            f"",
        ]

        actionable = [f for f in self.findings if not f.h1_ineligible and f.poc_commands]

        for i, f in enumerate(actionable, 1):
            lines.append(f"[{i}] {f.title}")
            lines.append(f"    Class: {f.vuln_class}")
            lines.append(f"    CVSS: {f.cvss_score}/10")
            lines.append(f"    Endpoint: {f.endpoint}")
            lines.append(f"    PoC:")
            for cmd in f.poc_commands:
                for cmd_line in cmd.split('\n'):
                    lines.append(f"        {cmd_line}")
            lines.append(f"")

        lines.extend([
            f"=== END ===",
            f"Generated by hunt-report v2 on {self.date}",
        ])

        return '\n'.join(lines)

    def generate_validation_report(self) -> str:
        """Generate validation report showing evidence quality analysis."""
        lines = [
            f"# {self.target_name} - Validation Report",
            f"",
            f"**Date:** {self.date}",
            f"**Hunter:** {self.hunter}",
            f"",
            f"---",
            f"",
            f"## Evidence Quality Analysis",
            f"",
            f"| Finding | Class | CVSS | Tier | Evidence | PoC | HTTP Body | Verdict |",
            f"|---------|-------|------|------|----------|-----|-----------|---------|",
        ]

        for f in sorted(self.findings, key=lambda x: x.evidence_score, reverse=True):
            poc_display = "YES" if f.poc_commands else "NO"
            http_display = "YES" if f.raw_response else "NO"

            # Determine verdict
            if f.evidence_score >= 8:
                verdict = "Submit"
            elif f.evidence_score >= 6:
                verdict = "Validate HTTP"
            elif f.evidence_score >= 4:
                verdict = "Needs PoC or HTTP"
            elif f.evidence_score >= 2:
                verdict = "Thin - validate before submit"
            else:
                verdict = "Drop (thin evidence)"

            lines.append(
                f"| {f.title[:40]} | {f.vuln_class} | {f.cvss_score} | {f.tier} | {f.evidence_score}/10 | {poc_display} | {http_display} | **{verdict}** |"
            )

        lines.extend([
            f"",
            f"---",
            f"",
            f"## Recommendations",
            f"",
        ])

        needs_http = [f for f in self.findings if f.poc_commands and not f.raw_response and f.evidence_score < 6]
        needs_poc = [f for f in self.findings if f.raw_response and not f.poc_commands]

        if needs_http:
            lines.append(f"### Needs HTTP Response Capture")
            lines.append(f"These findings have PoC commands but missing HTTP responses:")
            lines.append(f"")
            for f in needs_http[:5]:
                lines.append(f"- {f.title} (CVSS {f.cvss_score})")
            lines.append(f"")

        if needs_poc:
            lines.append(f"### Needs PoC Commands")
            lines.append(f"These findings have HTTP responses but missing PoC:")
            lines.append(f"")
            for f in needs_poc[:5]:
                lines.append(f"- {f.title} (CVSS {f.cvss_score})")
            lines.append(f"")

        lines.extend([
            f"---",
            f"",
            f"**Generated by hunt-report v2 on {self.date}**",
        ])

        return '\n'.join(lines)


# ============================================================
# CLI
# ============================================================

def cmd_generate(args):
    """Generate report files from input."""
    input_dir = Path(args.input)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    scan_info = {
        "target": args.target,
        "hunter": args.hunter,
        "mode": args.mode,
    }

    print(f"[hunt-report] Scanning {input_dir} for input files...")

    all_findings = []
    all_targets = []
    format_counts = {}

    for filepath in sorted(input_dir.rglob("*")):
        if filepath.is_file():
            fmt = InputParser.detect_format(str(filepath))
            format_counts[fmt] = format_counts.get(fmt, 0) + 1

            if fmt == "findings_md":
                findings = InputParser.parse_findings_md(str(filepath))
                all_findings.extend(findings)
                print(f"  Parsed {filepath.name} -> {len(findings)} findings ({fmt})")

            elif fmt == "exploit_md":
                findings = InputParser.parse_exploit_md(str(filepath))
                all_findings.extend(findings)
                print(f"  Parsed {filepath.name} -> {len(findings)} findings ({fmt})")

            elif fmt == "raw_http":
                findings = InputParser.parse_raw_http(str(filepath))
                all_findings.extend(findings)
                print(f"  Parsed {filepath.name} -> {len(findings)} findings ({fmt})")

            elif fmt == "nuclei_json":
                findings = InputParser.parse_nuclei_json(str(filepath))
                all_findings.extend(findings)
                print(f"  Parsed {filepath.name} -> {len(findings)} findings ({fmt})")

            elif fmt == "json_results":
                findings = InputParser.parse_json_results(str(filepath))
                all_findings.extend(findings)
                print(f"  Parsed {filepath.name} -> {len(findings)} findings ({fmt})")

            elif fmt == "scope":
                targets = InputParser.parse_scope_json(str(filepath))
                all_targets.extend(targets)
                print(f"  Parsed {filepath.name} -> {len(targets)} targets ({fmt})")

            elif fmt == "unknown":
                print(f"  Skipped {filepath.name} (unknown format)")

    if not all_findings:
        print(f"\n[hunt-report] No findings found. Check input directory.")
        sys.exit(1)

    # Deduplicate by title + endpoint
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = f"{f.title}|{f.endpoint}|{f.reference_id}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    all_findings = unique_findings
    print(f"\n[hunt-report] Found {len(all_findings)} findings, {len(all_targets)} targets")
    print(f"[hunt-report] Format breakdown: {json.dumps(format_counts, indent=2)}")

    # Generate reports
    gen = ReportGenerator(all_findings, all_targets, scan_info)

    files_generated = []

    if args.mode == "standard":
        files = {
            "findings.md": gen.generate_findings_md(),
            "bounty-report.md": gen.generate_bounty_report(),
            "poc.md": gen.generate_poc_md(),
            "targets.md": gen.generate_targets_md(),
        }
    elif args.mode == "h1":
        files = {
            "findings.md": gen.generate_findings_md(),
            "bounty-report.md": gen.generate_bounty_report(),
            "poc.md": gen.generate_poc_md(),
            "targets.md": gen.generate_targets_md(),
            "h1-submission.md": gen.generate_h1_submission_md(),
            "h1-submission.txt": gen.generate_h1_submission_txt(),
        }
    elif args.mode == "validate":
        files = {
            "findings.md": gen.generate_findings_md(),
            "bounty-report.md": gen.generate_bounty_report(),
            "poc.md": gen.generate_poc_md(),
            "targets.md": gen.generate_targets_md(),
            "validation-report.md": gen.generate_validation_report(),
        }
    else:
        files = {
            "findings.md": gen.generate_findings_md(),
            "bounty-report.md": gen.generate_bounty_report(),
            "poc.md": gen.generate_poc_md(),
            "targets.md": gen.generate_targets_md(),
        }

    for filename, content in files.items():
        output_path = output_dir / filename
        output_path.write_text(content, encoding="utf-8")
        files_generated.append(str(output_path))
        print(f"  Written: {output_path}")

    # Classification summary
    tier_counts = {}
    for f in all_findings:
        tier_counts[f.tier] = tier_counts.get(f.tier, 0) + 1

    print(f"\n[hunt-report] Done! Generated {len(files_generated)} files:")
    for f in files_generated:
        print(f"  - {f}")

    if tier_counts:
        print(f"\n[hunt-report] Classification Summary:")
        for tier in ["TIER-1", "TIER-2", "TIER-3", "TIER-4", "TIER-5"]:
            count = tier_counts.get(tier, 0)
            if count:
                print(f"  {tier}: {count} findings")

    # Show high-value findings
    high_value = [f for f in all_findings if f.evidence_score >= 6]
    if high_value:
        print(f"\n[hunt-report] High-value findings (submit these first):")
        for f in sorted(high_value, key=lambda x: x.evidence_score, reverse=True)[:5]:
            print(f"  [{f.tier}] {f.title} (Evidence: {f.evidence_score}/10, CVSS: {f.cvss_score})")


def cmd_validate(args):
    """Validate input and show evidence quality."""
    input_dir = Path(args.input)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    scan_info = {
        "target": args.target,
        "hunter": args.hunter,
        "mode": "validate",
    }

    print(f"[hunt-report] Scanning {input_dir} for input files...")

    all_findings = []

    for filepath in sorted(input_dir.rglob("*")):
        if filepath.is_file():
            fmt = InputParser.detect_format(str(filepath))
            if fmt in ("findings_md", "exploit_md", "json_results", "nuclei_json", "raw_http"):
                if fmt == "findings_md":
                    findings = InputParser.parse_findings_md(str(filepath))
                elif fmt == "exploit_md":
                    findings = InputParser.parse_exploit_md(str(filepath))
                elif fmt == "json_results":
                    findings = InputParser.parse_json_results(str(filepath))
                elif fmt == "nuclei_json":
                    findings = InputParser.parse_nuclei_json(str(filepath))
                elif fmt == "raw_http":
                    findings = InputParser.parse_raw_http(str(filepath))
                all_findings.extend(findings)
                print(f"  Parsed {filepath.name} -> {len(findings)} findings")

    if not all_findings:
        print(f"\n[hunt-report] No findings found.")
        sys.exit(1)

    print(f"\n[hunt-report] Found {len(all_findings)} findings")

    gen = ReportGenerator(all_findings, [], scan_info)
    output_path = output_dir / "validation-report.md"
    output_path.write_text(gen.generate_validation_report(), encoding="utf-8")
    print(f"\n[validate] Written: {output_path}")

    # Summary
    print(f"\n[hunt-report] Validation Summary:")
    submit_first = [f for f in all_findings if f.evidence_score >= 8]
    validate_http = [f for f in all_findings if 6 <= f.evidence_score < 8]
    needs_work = [f for f in all_findings if f.evidence_score < 6]

    print(f"  Ready to submit: {len(submit_first)}")
    print(f"  Validate HTTP first: {len(validate_http)}")
    print(f"  Needs more evidence: {len(needs_work)}")


def cmd_stats(args):
    """Show statistics about input files."""
    input_dir = Path(args.input)

    print(f"[hunt-report] Statistics for {input_dir}")
    print(f"")

    total_findings = 0
    total_targets = 0
    format_counts = {}

    for filepath in sorted(input_dir.rglob("*")):
        if filepath.is_file():
            fmt = InputParser.detect_format(str(filepath))
            format_counts[fmt] = format_counts.get(fmt, 0) + 1
            print(f"  {filepath.name:40s} ({fmt})")

    print(f"\nTotal input files: {len(list(input_dir.rglob('*')))}")
    print(f"Format breakdown: {json.dumps(format_counts, indent=2)}")


def main():
    parser = argparse.ArgumentParser(
        prog="hunt-report",
        description="Turn raw scan output into submission-ready vulnerability reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  hunt-report generate --input ./scan-results/ --output ./reports/
  hunt-report generate --input ./scan-results/ --output ./reports/ --mode h1
  hunt-report generate --input ./scan-results/ --output ./reports/ --mode validate
  hunt-report validate --input ./scan-results/ --output ./validation/
  hunt-report stats --input ./scan-results/
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Generate command
    gen_parser = subparsers.add_parser("generate", help="Generate report files")
    gen_parser.add_argument("--input", "-i", required=True, help="Input directory with scan results")
    gen_parser.add_argument("--output", "-o", required=True, help="Output directory for reports")
    gen_parser.add_argument("--target", "-t", default="Target", help="Target name")
    gen_parser.add_argument("--hunter", "-H", default="Hunter", help="Hunter name")
    gen_parser.add_argument("--mode", "-m", default="standard", choices=["standard", "h1", "validate"],
                          help="Report mode (default: standard)")

    # Validate command
    val_parser = subparsers.add_parser("validate", help="Validate evidence quality")
    val_parser.add_argument("--input", "-i", required=True, help="Input directory with scan results")
    val_parser.add_argument("--output", "-o", required=True, help="Output directory for reports")
    val_parser.add_argument("--target", "-t", default="Target", help="Target name")
    val_parser.add_argument("--hunter", "-H", default="Hunter", help="Hunter name")

    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show statistics")
    stats_parser.add_argument("--input", "-i", required=True, help="Input directory with scan results")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "generate":
        cmd_generate(args)
    elif args.command == "validate":
        cmd_validate(args)
    elif args.command == "stats":
        cmd_stats(args)


if __name__ == "__main__":
    main()
