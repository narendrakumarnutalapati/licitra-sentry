"""
LICITRA-SENTRY v0.2 — Gate 2: Content Inspection

Scans tool request payloads for dangerous patterns before authorization.
Operates on the raw request content, not on model outputs.

Author: Narendra Kumar Nutalapati
License: MIT
"""

import re
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class InspectionResult:
    passed: bool
    findings: list[str] = field(default_factory=list)
    risk_level: str = "none"  # none, low, medium, high, critical
    error: Optional[str] = None


# Default patterns for content inspection
DEFAULT_PATTERNS = {
    "pii_email": {
        "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "risk": "medium",
        "description": "Email address detected in payload",
    },
    "pii_ssn": {
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "risk": "critical",
        "description": "SSN pattern detected in payload",
    },
    "pii_credit_card": {
        "pattern": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        "risk": "critical",
        "description": "Credit card number pattern detected",
    },
    "shell_injection": {
        "pattern": r"[;&|`$]|\brm\s+-rf\b|\bsudo\b|\bchmod\b|\bchown\b",
        "risk": "critical",
        "description": "Shell injection pattern detected",
    },
    "sql_injection": {
        "pattern": r"\b(UNION\s+SELECT|DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO)\b",
        "risk": "critical",
        "description": "SQL injection pattern detected",
    },
    "path_traversal": {
        "pattern": r"\.\./|\.\.\\",
        "risk": "high",
        "description": "Path traversal pattern detected",
    },
    "exfiltration_url": {
        "pattern": r"https?://(?!internal\.)[^\s]+",
        "risk": "low",
        "description": "External URL detected in payload",
    },
}

RISK_LEVELS = ["none", "low", "medium", "high", "critical"]


class ContentInspector:
    """
    Gate 2: Inspect request payloads for dangerous patterns.

    Scans all string values in the request recursively.
    Returns findings with risk levels.
    """

    def __init__(self, patterns: Optional[dict] = None, block_threshold: str = "high"):
        self.patterns = patterns or DEFAULT_PATTERNS
        self.block_threshold = block_threshold
        self._compiled = {
            name: re.compile(cfg["pattern"], re.IGNORECASE)
            for name, cfg in self.patterns.items()
        }

    def inspect(self, request: dict) -> InspectionResult:
        """Inspect a tool request payload."""
        findings = []
        max_risk = "none"

        # Extract all string values recursively
        strings = self._extract_strings(request)

        for text in strings:
            for name, compiled in self._compiled.items():
                if compiled.search(text):
                    cfg = self.patterns[name]
                    findings.append(f"[{cfg['risk'].upper()}] {cfg['description']}: pattern={name}")
                    if RISK_LEVELS.index(cfg["risk"]) > RISK_LEVELS.index(max_risk):
                        max_risk = cfg["risk"]

        blocked = RISK_LEVELS.index(max_risk) >= RISK_LEVELS.index(self.block_threshold)

        return InspectionResult(
            passed=not blocked,
            findings=findings,
            risk_level=max_risk,
        )

    def _extract_strings(self, obj, depth: int = 0) -> list[str]:
        """Recursively extract all string values from a nested structure."""
        if depth > 20:
            return []
        strings = []
        if isinstance(obj, str):
            strings.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                strings.extend(self._extract_strings(v, depth + 1))
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                strings.extend(self._extract_strings(item, depth + 1))
        return strings
