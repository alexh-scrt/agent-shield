"""Core data models for agent_shield.

Defines the fundamental dataclasses used throughout the scanning pipeline:
- Severity: enumeration of finding severity levels
- Rule: metadata describing a detection rule
- Finding: a concrete vulnerability instance discovered during scanning
- AgentConfig: normalised internal representation of a loaded agent configuration
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Enumeration of finding severity levels in descending order of criticality."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other: "Severity") -> bool:
        """Allow severity comparison by rank."""
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        return order.index(self.value) < order.index(other.value)

    def __le__(self, other: "Severity") -> bool:
        """Allow severity comparison by rank."""
        return self == other or self < other

    def __gt__(self, other: "Severity") -> bool:
        """Allow severity comparison by rank."""
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        return order.index(self.value) > order.index(other.value)

    def __ge__(self, other: "Severity") -> bool:
        """Allow severity comparison by rank."""
        return self == other or self > other

    @property
    def rank(self) -> int:
        """Return numeric rank (higher is more severe)."""
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        return order.index(self.value)

    @property
    def rich_color(self) -> str:
        """Return a Rich-compatible color string for terminal display."""
        colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }
        return colors[self.value]


@dataclass(frozen=True)
class Rule:
    """Metadata describing a single detection rule.

    Attributes:
        rule_id: Unique identifier for the rule (e.g. "PI-001").
        severity: The severity level assigned to findings from this rule.
        title: Short human-readable title for the rule.
        description: Detailed description of what the rule detects.
        remediation: Actionable advice for resolving the issue.
        category: Broad category the rule belongs to (e.g. "prompt_injection").
    """

    rule_id: str
    severity: Severity
    title: str
    description: str
    remediation: str
    category: str

    def to_dict(self) -> dict[str, Any]:
        """Serialise the rule to a plain dictionary."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "category": self.category,
        }


@dataclass
class Finding:
    """A concrete vulnerability instance discovered during a scan.

    Attributes:
        rule: The Rule that triggered this finding.
        file_path: Path to the file where the issue was found.
        location: Human-readable location string (e.g. field name, line number).
        evidence: The snippet of text or value that triggered the rule.
        detail: Optional additional context specific to this finding instance.
    """

    rule: Rule
    file_path: Path
    location: str
    evidence: str
    detail: str = ""

    @property
    def severity(self) -> Severity:
        """Convenience accessor returning this finding's severity."""
        return self.rule.severity

    @property
    def rule_id(self) -> str:
        """Convenience accessor returning the rule ID."""
        return self.rule.rule_id

    def to_dict(self) -> dict[str, Any]:
        """Serialise the finding to a plain dictionary suitable for JSON output."""
        return {
            "rule_id": self.rule.rule_id,
            "severity": self.rule.severity.value,
            "category": self.rule.category,
            "title": self.rule.title,
            "description": self.rule.description,
            "remediation": self.rule.remediation,
            "file": str(self.file_path),
            "location": self.location,
            "evidence": self.evidence,
            "detail": self.detail,
        }

    def __str__(self) -> str:
        """Return a brief string representation of the finding."""
        return (
            f"[{self.rule.severity.value}] {self.rule.rule_id}: {self.rule.title} "
            f"in {self.file_path} at {self.location}"
        )


@dataclass
class AgentConfig:
    """Normalised internal representation of a loaded agent configuration file.

    This is the common structure passed to all check functions, regardless of
    the original file format (JSON, YAML, or plain text).

    Attributes:
        source_path: Original file path the config was loaded from.
        raw_text: The raw text content of the file.
        format: The detected file format (``"json"``, ``"yaml"``, or ``"text"``).
        data: Parsed structured data (dict or list) when format is JSON/YAML.
              Empty dict when format is plain text.
        system_prompt: Extracted system prompt string, if present.
        tools: List of tool/function definitions extracted from the config.
        metadata: Additional key-value metadata extracted from the config.
    """

    source_path: Path
    raw_text: str
    format: str  # "json", "yaml", or "text"
    data: dict[str, Any] | list[Any] = field(default_factory=dict)
    system_prompt: str = ""
    tools: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_all_string_values(self) -> list[tuple[str, str]]:
        """Recursively extract all string values from ``data`` as (path, value) pairs.

        Returns a flat list of tuples where the first element is a dot-separated
        path describing the location of the value in the structure, and the
        second element is the string value itself.

        Returns:
            List of ``(location_path, string_value)`` tuples.
        """
        results: list[tuple[str, str]] = []
        self._extract_strings(self.data, "", results)
        return results

    def _extract_strings(
        self,
        node: Any,
        path: str,
        results: list[tuple[str, str]],
    ) -> None:
        """Recursively walk a nested structure collecting string leaf values.

        Args:
            node: Current node being traversed.
            path: Dot-separated path accumulated so far.
            results: Accumulator list that is mutated in place.
        """
        if isinstance(node, str):
            results.append((path, node))
        elif isinstance(node, dict):
            for key, value in node.items():
                child_path = f"{path}.{key}" if path else key
                self._extract_strings(value, child_path, results)
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                child_path = f"{path}[{idx}]"
                self._extract_strings(item, child_path, results)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the AgentConfig to a plain dictionary (excluding raw_text)."""
        return {
            "source_path": str(self.source_path),
            "format": self.format,
            "system_prompt": self.system_prompt,
            "tools_count": len(self.tools),
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        """Return a developer-friendly string representation."""
        return (
            f"AgentConfig(source_path={self.source_path!r}, "
            f"format={self.format!r}, "
            f"tools={len(self.tools)}, "
            f"has_system_prompt={bool(self.system_prompt)})"
        )


@dataclass
class ScanResult:
    """Aggregated result of scanning one or more agent configuration files.

    Attributes:
        findings: All Finding objects discovered during the scan.
        scanned_files: Paths of all files that were successfully scanned.
        errors: Mapping of file path to error message for files that failed.
    """

    findings: list[Finding] = field(default_factory=list)
    scanned_files: list[Path] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def has_high_or_critical(self) -> bool:
        """Return True if any finding has severity HIGH or CRITICAL."""
        return any(
            f.severity in (Severity.HIGH, Severity.CRITICAL) for f in self.findings
        )

    @property
    def finding_count(self) -> int:
        """Return the total number of findings."""
        return len(self.findings)

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Return all findings matching the given severity.

        Args:
            severity: The Severity level to filter by.

        Returns:
            List of findings with the specified severity.
        """
        return [f for f in self.findings if f.severity == severity]

    def findings_at_or_above(self, min_severity: Severity) -> list[Finding]:
        """Return all findings at or above the given minimum severity.

        Args:
            min_severity: The minimum Severity level (inclusive).

        Returns:
            List of findings at or above the specified severity.
        """
        return [f for f in self.findings if f.severity >= min_severity]

    def sorted_findings(self) -> list[Finding]:
        """Return findings sorted by severity descending, then rule_id ascending.

        Returns:
            Sorted list of Finding objects.
        """
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, f.rule_id),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise the scan result to a plain dictionary for JSON output."""
        severity_counts: dict[str, int] = {
            sev.value: len(self.findings_by_severity(sev)) for sev in Severity
        }
        return {
            "summary": {
                "total_findings": self.finding_count,
                "scanned_files": len(self.scanned_files),
                "errors": len(self.errors),
                "has_high_or_critical": self.has_high_or_critical,
                "severity_counts": severity_counts,
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "scanned_files": [str(p) for p in self.scanned_files],
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialise the scan result to a JSON string.

        Args:
            indent: Number of spaces to use for JSON indentation.

        Returns:
            Pretty-printed JSON string.
        """
        return json.dumps(self.to_dict(), indent=indent)
