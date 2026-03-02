"""
LICITRA-SENTRY Content Inspector.

Regex-based content inspection layer that runs after identity check
and before contract validation. Inspects message content for relay
injection, PII patterns, prompt injection signatures, privilege
escalation requests, and system prompt leakage attempts.

Deterministic - no LLM calls, no external network calls.
Rules loaded from content_rules.yaml at runtime.

OWASP Agentic Coverage:
    ASI01 - Prompt Injection / Relay Injection: Detects and blocks
            injected instructions and relay attack patterns.
    ASI06 - Sensitive Data Exposure: Detects PII patterns (SSN,
            credit card, API keys) before they leave the system.
    ASI07 - Inter-Agent Communication Integrity: All findings are
            emitted to LICITRA-MMR for tamper-evident audit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    """A single content inspection finding."""
    rule_id: str
    rule_name: str
    category: str
    severity: str
    matched_pattern: str
    action: str            # "block" | "quarantine" | "flag"


@dataclass(frozen=True)
class InspectionResult:
    """Outcome of content inspection."""
    clean: bool
    findings: list[Finding]
    severity: str          # highest severity among findings, or "none"


@dataclass(frozen=True)
class ContentRule:
    """A single rule loaded from content_rules.yaml."""
    id: str
    name: str
    category: str
    severity: str
    pattern: str
    action: str
    compiled: re.Pattern


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
}


def _highest_severity(findings: list[Finding]) -> str:
    """Return the highest severity among findings, or 'none'."""
    if not findings:
        return "none"
    return max(findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 0)).severity


# ---------------------------------------------------------------------------
# ContentInspector
# ---------------------------------------------------------------------------

class ContentInspector:
    """
    Inspects message content against rules loaded from content_rules.yaml.

    OWASP: ASI01 (Prompt/Relay Injection), ASI06 (Sensitive Data Exposure),
           ASI07 (Inter-Agent Communication Integrity)
    """

    def __init__(self, rules_path: Optional[str] = None) -> None:
        if rules_path is None:
            rules_path = str(Path(__file__).resolve().parent.parent / "content_rules.yaml")
        self._rules: list[ContentRule] = self._load_rules(rules_path)

    @staticmethod
    def _load_rules(path: str) -> list[ContentRule]:
        """Load and compile rules from YAML file."""
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        rules: list[ContentRule] = []
        for entry in data.get("rules", []):
            compiled = re.compile(entry["pattern"])
            rules.append(ContentRule(
                id=entry["id"],
                name=entry["name"],
                category=entry["category"],
                severity=entry["severity"],
                pattern=entry["pattern"],
                action=entry["action"],
                compiled=compiled,
            ))
        return rules

    @property
    def rule_count(self) -> int:
        """Number of loaded rules."""
        return len(self._rules)

    def inspect(self, message: str) -> InspectionResult:
        """
        Scan a message against all loaded rules.

        Returns InspectionResult with clean=True if no blocking findings,
        or clean=False with the list of findings.
        """
        findings: list[Finding] = []

        for rule in self._rules:
            if rule.compiled.search(message):
                findings.append(Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    matched_pattern=rule.pattern,
                    action=rule.action,
                ))

        has_block = any(f.action == "block" for f in findings)

        return InspectionResult(
            clean=len(findings) == 0 or not has_block,
            findings=findings,
            severity=_highest_severity(findings),
        )
