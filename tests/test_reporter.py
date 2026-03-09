"""Tests for agent_shield.reporter — result formatting."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from agent_shield.models import Finding, Rule, ScanResult, Severity
from agent_shield.reporter import (
    _truncate,
    format_json_report,
    print_json_report,
    print_terminal_report,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_rule(
    rule_id: str = "TEST-001",
    severity: Severity = Severity.HIGH,
    category: str = "test",
    title: str = "Test Rule",
    description: str = "A test finding.",
    remediation: str = "Fix it.",
) -> Rule:
    return Rule(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        category=category,
    )


def make_finding(
    rule_id: str = "TEST-001",
    severity: Severity = Severity.HIGH,
    path: Path = Path("agent.json"),
    location: str = "system_prompt",
    evidence: str = "example evidence",
) -> Finding:
    return Finding(
        rule=make_rule(rule_id=rule_id, severity=severity),
        file_path=path,
        location=location,
        evidence=evidence,
    )


def make_result(
    findings: list[Finding] | None = None,
    scanned_files: list[Path] | None = None,
    errors: dict[str, str] | None = None,
) -> ScanResult:
    return ScanResult(
        findings=findings or [],
        scanned_files=scanned_files or [Path("agent.json")],
        errors=errors or {},
    )


def capture_terminal_output(
    result: ScanResult,
    show_remediation: bool = False,
    min_severity: Severity = Severity.INFO,
) -> str:
    """Render a terminal report to a string using a test console."""
    buf = StringIO()
    con = Console(file=buf, width=200, highlight=False, markup=True)
    print_terminal_report(
        result,
        console=con,
        show_remediation=show_remediation,
        min_severity=min_severity,
    )
    return buf.getvalue()


def capture_json_output(
    result: ScanResult,
    min_severity: Severity = Severity.INFO,
) -> str:
    """Render a JSON report to a string."""
    buf = StringIO()
    con = Console(file=buf, highlight=False, markup=False)
    print_json_report(result, console=con, min_severity=min_severity)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Tests for _truncate
# ---------------------------------------------------------------------------


class TestTruncate:
    """Unit tests for the _truncate helper."""

    def test_short_string_unchanged(self) -> None:
        assert _truncate("hello", 20) == "hello"

    def test_exact_length_unchanged(self) -> None:
        assert _truncate("hello", 5) == "hello"

    def test_long_string_truncated(self) -> None:
        result = _truncate("a" * 100, 20)
        assert len(result) <= 21  # 20 + ellipsis char
        assert result.endswith("…")

    def test_newlines_replaced_with_spaces(self) -> None:
        result = _truncate("line1\nline2", 50)
        assert "\n" not in result
        assert "line1 line2" == result

    def test_custom_suffix(self) -> None:
        result = _truncate("hello world", 8, suffix="...")
        assert result.endswith("...")

    def test_empty_string(self) -> None:
        assert _truncate("", 20) == ""


# ---------------------------------------------------------------------------
# Tests for print_terminal_report
# ---------------------------------------------------------------------------


class TestPrintTerminalReport:
    """Tests for the terminal report renderer."""

    def test_no_findings_shows_pass(self) -> None:
        """Empty result produces a PASS banner."""
        result = make_result(findings=[], scanned_files=[Path("clean.json")])
        output = capture_terminal_output(result)
        assert "PASS" in output

    def test_high_finding_shows_fail(self) -> None:
        """HIGH finding produces a FAIL banner."""
        result = make_result(
            findings=[make_finding(severity=Severity.HIGH)],
            scanned_files=[Path("agent.json")],
        )
        output = capture_terminal_output(result)
        assert "FAIL" in output

    def test_medium_finding_shows_warn(self) -> None:
        """Only MEDIUM findings produces a WARN banner."""
        result = make_result(
            findings=[make_finding(severity=Severity.MEDIUM)],
            scanned_files=[Path("agent.json")],
        )
        output = capture_terminal_output(result)
        assert "WARN" in output

    def test_critical_finding_shows_fail(self) -> None:
        """CRITICAL finding produces a FAIL banner."""
        result = make_result(
            findings=[make_finding(severity=Severity.CRITICAL)],
        )
        output = capture_terminal_output(result)
        assert "FAIL" in output

    def test_rule_id_in_output(self) -> None:
        """The rule ID appears in the terminal output."""
        result = make_result(
            findings=[make_finding(rule_id="PI-001", severity=Severity.CRITICAL)],
        )
        output = capture_terminal_output(result)
        assert "PI-001" in output

    def test_severity_label_in_output(self) -> None:
        """Severity labels appear in the output summary table."""
        result = make_result(findings=[])
        output = capture_terminal_output(result)
        # Summary table should include all severity names
        assert "CRITICAL" in output
        assert "HIGH" in output
        assert "MEDIUM" in output
        assert "LOW" in output
        assert "INFO" in output

    def test_scanned_file_in_header(self) -> None:
        """Scanned file paths appear in the header panel."""
        result = make_result(
            findings=[],
            scanned_files=[Path("/path/to/my_agent.json")],
        )
        output = capture_terminal_output(result)
        assert "my_agent.json" in output

    def test_errors_shown_in_header(self) -> None:
        """Errors appear in the header panel."""
        result = make_result(
            findings=[],
            scanned_files=[],
            errors={"/bad/file.json": "Invalid JSON"},
        )
        output = capture_terminal_output(result)
        assert "Invalid JSON" in output or "bad/file.json" in output

    def test_min_severity_filters_table(self) -> None:
        """Findings below min_severity are excluded from the table."""
        result = make_result(
            findings=[
                make_finding(rule_id="T-HIGH", severity=Severity.HIGH),
                make_finding(rule_id="T-INFO", severity=Severity.INFO),
            ],
        )
        output = capture_terminal_output(result, min_severity=Severity.HIGH)
        # HIGH should appear; INFO rule ID should not
        assert "T-HIGH" in output
        assert "T-INFO" not in output

    def test_show_remediation_flag(self) -> None:
        """show_remediation=True includes remediation text in the table."""
        finding = Finding(
            rule=make_rule(remediation="Remove the secret immediately."),
            file_path=Path("agent.json"),
            location="top",
            evidence="sk-abc",
        )
        result = make_result(findings=[finding])
        output_without = capture_terminal_output(result, show_remediation=False)
        output_with = capture_terminal_output(result, show_remediation=True)
        # With remediation flag, the remediation text should be present
        assert "Remove the secret immediately" in output_with

    def test_multiple_findings_all_shown(self) -> None:
        """All findings appear in the table."""
        findings = [
            make_finding(rule_id=f"R-{i:03d}", severity=Severity.MEDIUM)
            for i in range(5)
        ]
        result = make_result(findings=findings)
        output = capture_terminal_output(result)
        for i in range(5):
            assert f"R-{i:03d}" in output

    def test_total_count_in_summary(self) -> None:
        """The total finding count appears in the summary table."""
        findings = [make_finding(severity=Severity.HIGH) for _ in range(3)]
        result = make_result(findings=findings)
        output = capture_terminal_output(result)
        # Should see "3" somewhere for the HIGH count and TOTAL
        assert "3" in output

    def test_agent_shield_in_header(self) -> None:
        """The agent_shield tool name appears in the report header."""
        result = make_result(findings=[])
        output = capture_terminal_output(result)
        assert "agent_shield" in output


# ---------------------------------------------------------------------------
# Tests for print_json_report and format_json_report
# ---------------------------------------------------------------------------


class TestPrintJsonReport:
    """Tests for the JSON report renderer."""

    def test_output_is_valid_json(self) -> None:
        """Output of print_json_report is parseable JSON."""
        result = make_result(findings=[make_finding(severity=Severity.HIGH)])
        raw = capture_json_output(result)
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_json_has_summary_key(self) -> None:
        """JSON output contains a 'summary' key."""
        result = make_result(findings=[])
        parsed = json.loads(capture_json_output(result))
        assert "summary" in parsed

    def test_json_has_findings_key(self) -> None:
        """JSON output contains a 'findings' key."""
        result = make_result(findings=[make_finding()])
        parsed = json.loads(capture_json_output(result))
        assert "findings" in parsed
        assert len(parsed["findings"]) == 1

    def test_json_summary_has_expected_fields(self) -> None:
        """JSON summary contains all expected fields."""
        result = make_result(
            findings=[make_finding(severity=Severity.CRITICAL)],
            scanned_files=[Path("f.json")],
        )
        parsed = json.loads(capture_json_output(result))
        summary = parsed["summary"]
        assert "total_findings" in summary
        assert "scanned_files" in summary
        assert "errors" in summary
        assert "has_high_or_critical" in summary
        assert "severity_counts" in summary

    def test_json_has_high_or_critical_true(self) -> None:
        """has_high_or_critical is True when CRITICAL findings exist."""
        result = make_result(findings=[make_finding(severity=Severity.CRITICAL)])
        parsed = json.loads(capture_json_output(result))
        assert parsed["summary"]["has_high_or_critical"] is True

    def test_json_has_high_or_critical_false(self) -> None:
        """has_high_or_critical is False when only LOW findings exist."""
        result = make_result(findings=[make_finding(severity=Severity.LOW)])
        parsed = json.loads(capture_json_output(result))
        assert parsed["summary"]["has_high_or_critical"] is False

    def test_json_finding_has_all_fields(self) -> None:
        """Each finding in JSON output has all expected fields."""
        result = make_result(findings=[make_finding(rule_id="SL-001", severity=Severity.CRITICAL)])
        parsed = json.loads(capture_json_output(result))
        finding = parsed["findings"][0]
        expected_keys = {
            "rule_id", "severity", "category", "title", "description",
            "remediation", "file", "location", "evidence", "detail",
        }
        assert expected_keys.issubset(set(finding.keys()))

    def test_json_severity_counts(self) -> None:
        """Severity counts in JSON summary are accurate."""
        result = make_result(
            findings=[
                make_finding(severity=Severity.CRITICAL),
                make_finding(severity=Severity.HIGH),
                make_finding(severity=Severity.HIGH),
                make_finding(severity=Severity.LOW),
            ]
        )
        parsed = json.loads(capture_json_output(result))
        counts = parsed["summary"]["severity_counts"]
        assert counts["CRITICAL"] == 1
        assert counts["HIGH"] == 2
        assert counts["LOW"] == 1
        assert counts["MEDIUM"] == 0
        assert counts["INFO"] == 0

    def test_json_min_severity_filter(self) -> None:
        """min_severity filter excludes lower-severity findings from JSON."""
        result = make_result(
            findings=[
                make_finding(rule_id="H-001", severity=Severity.HIGH),
                make_finding(rule_id="I-001", severity=Severity.INFO),
            ]
        )
        parsed = json.loads(capture_json_output(result, min_severity=Severity.HIGH))
        assert parsed["summary"]["total_findings"] == 1
        assert parsed["findings"][0]["rule_id"] == "H-001"

    def test_json_min_severity_filter_recorded(self) -> None:
        """min_severity is recorded in the JSON summary when filtering is active."""
        result = make_result(findings=[])
        parsed = json.loads(capture_json_output(result, min_severity=Severity.MEDIUM))
        assert parsed["summary"]["min_severity_filter"] == "MEDIUM"

    def test_json_errors_included(self) -> None:
        """Loader errors are included in the JSON output."""
        result = make_result(
            findings=[],
            scanned_files=[],
            errors={"/bad.json": "Failed to parse"},
        )
        parsed = json.loads(capture_json_output(result))
        assert "/bad.json" in parsed["errors"]

    def test_json_scanned_files_listed(self) -> None:
        """Scanned file paths are listed in the JSON output."""
        result = make_result(
            findings=[],
            scanned_files=[Path("/a/b/agent.json"), Path("/c/d/agent2.yaml")],
        )
        parsed = json.loads(capture_json_output(result))
        scanned = parsed["scanned_files"]
        assert len(scanned) == 2


# ---------------------------------------------------------------------------
# Tests for format_json_report
# ---------------------------------------------------------------------------


class TestFormatJsonReport:
    """Tests for the format_json_report utility function."""

    def test_returns_valid_json_string(self) -> None:
        """format_json_report returns a valid JSON string."""
        result = make_result(findings=[make_finding()])
        raw = format_json_report(result)
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_indent_parameter(self) -> None:
        """indent parameter controls JSON formatting."""
        result = make_result(findings=[])
        raw_2 = format_json_report(result, indent=2)
        raw_4 = format_json_report(result, indent=4)
        # Both should be valid JSON with the same content
        assert json.loads(raw_2) == json.loads(raw_4)
        # 4-space indent produces longer output for multi-level structures
        assert len(raw_4) >= len(raw_2)

    def test_min_severity_filter(self) -> None:
        """min_severity filters findings in format_json_report output."""
        result = make_result(
            findings=[
                make_finding(rule_id="C-001", severity=Severity.CRITICAL),
                make_finding(rule_id="I-001", severity=Severity.INFO),
            ]
        )
        raw = format_json_report(result, min_severity=Severity.CRITICAL)
        parsed = json.loads(raw)
        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["rule_id"] == "C-001"

    def test_default_no_filter(self) -> None:
        """Without min_severity filter, all findings are included."""
        result = make_result(
            findings=[
                make_finding(rule_id="H-001", severity=Severity.HIGH),
                make_finding(rule_id="I-001", severity=Severity.INFO),
            ]
        )
        raw = format_json_report(result)
        parsed = json.loads(raw)
        assert len(parsed["findings"]) == 2
