"""Unit tests for agent_shield.models — core data model dataclasses."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_shield.models import (
    AgentConfig,
    Finding,
    Rule,
    ScanResult,
    Severity,
)


# ---------------------------------------------------------------------------
# Severity tests
# ---------------------------------------------------------------------------


class TestSeverity:
    """Tests for the Severity enum."""

    def test_values_exist(self) -> None:
        """All five severity levels must be present."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_ordering_less_than(self) -> None:
        """INFO < LOW < MEDIUM < HIGH < CRITICAL."""
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

    def test_ordering_greater_than(self) -> None:
        """CRITICAL > HIGH > MEDIUM > LOW > INFO."""
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

    def test_ordering_equal(self) -> None:
        """Severity equals itself."""
        assert Severity.HIGH >= Severity.HIGH
        assert Severity.HIGH <= Severity.HIGH

    def test_rank_property(self) -> None:
        """rank returns increasing integers for increasing severity."""
        assert Severity.INFO.rank < Severity.LOW.rank
        assert Severity.LOW.rank < Severity.MEDIUM.rank
        assert Severity.MEDIUM.rank < Severity.HIGH.rank
        assert Severity.HIGH.rank < Severity.CRITICAL.rank

    def test_rich_color_property(self) -> None:
        """rich_color returns a non-empty string for every severity."""
        for sev in Severity:
            assert isinstance(sev.rich_color, str)
            assert len(sev.rich_color) > 0

    def test_is_string_enum(self) -> None:
        """Severity values are usable as plain strings."""
        assert Severity.CRITICAL == "CRITICAL"


# ---------------------------------------------------------------------------
# Rule tests
# ---------------------------------------------------------------------------


def make_rule(
    rule_id: str = "TEST-001",
    severity: Severity = Severity.HIGH,
    title: str = "Test Rule",
    description: str = "A test rule.",
    remediation: str = "Fix it.",
    category: str = "test",
) -> Rule:
    """Factory helper for Rule instances."""
    return Rule(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        category=category,
    )


class TestRule:
    """Tests for the Rule dataclass."""

    def test_construction(self) -> None:
        """Rule can be constructed with all required fields."""
        rule = make_rule()
        assert rule.rule_id == "TEST-001"
        assert rule.severity == Severity.HIGH
        assert rule.title == "Test Rule"

    def test_frozen(self) -> None:
        """Rule instances are immutable (frozen dataclass)."""
        rule = make_rule()
        with pytest.raises(Exception):
            rule.rule_id = "OTHER"  # type: ignore[misc]

    def test_to_dict_keys(self) -> None:
        """to_dict returns all expected keys."""
        rule = make_rule()
        d = rule.to_dict()
        assert set(d.keys()) == {
            "rule_id",
            "severity",
            "title",
            "description",
            "remediation",
            "category",
        }

    def test_to_dict_severity_is_string(self) -> None:
        """to_dict serialises severity as a plain string."""
        rule = make_rule(severity=Severity.CRITICAL)
        assert rule.to_dict()["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Finding tests
# ---------------------------------------------------------------------------


def make_finding(
    rule: Rule | None = None,
    file_path: Path = Path("test_file.json"),
    location: str = "system_prompt",
    evidence: str = "Ignore all previous instructions",
    detail: str = "",
) -> Finding:
    """Factory helper for Finding instances."""
    if rule is None:
        rule = make_rule()
    return Finding(
        rule=rule,
        file_path=file_path,
        location=location,
        evidence=evidence,
        detail=detail,
    )


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_construction(self) -> None:
        """Finding can be constructed with all required fields."""
        f = make_finding()
        assert f.location == "system_prompt"
        assert f.evidence == "Ignore all previous instructions"

    def test_severity_property(self) -> None:
        """severity property delegates to the underlying rule."""
        rule = make_rule(severity=Severity.CRITICAL)
        f = make_finding(rule=rule)
        assert f.severity == Severity.CRITICAL

    def test_rule_id_property(self) -> None:
        """rule_id property delegates to the underlying rule."""
        rule = make_rule(rule_id="PI-001")
        f = make_finding(rule=rule)
        assert f.rule_id == "PI-001"

    def test_to_dict_keys(self) -> None:
        """to_dict returns all expected keys."""
        f = make_finding()
        d = f.to_dict()
        expected_keys = {
            "rule_id",
            "severity",
            "category",
            "title",
            "description",
            "remediation",
            "file",
            "location",
            "evidence",
            "detail",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_file_is_string(self) -> None:
        """to_dict converts file_path to a string."""
        f = make_finding(file_path=Path("/some/path/file.json"))
        assert isinstance(f.to_dict()["file"], str)

    def test_str_representation(self) -> None:
        """__str__ includes severity, rule_id, and title."""
        rule = make_rule(rule_id="SEC-042", severity=Severity.HIGH, title="Secret Found")
        f = make_finding(rule=rule)
        s = str(f)
        assert "HIGH" in s
        assert "SEC-042" in s
        assert "Secret Found" in s

    def test_default_detail_is_empty_string(self) -> None:
        """detail defaults to an empty string."""
        rule = make_rule()
        f = Finding(
            rule=rule,
            file_path=Path("x.json"),
            location="loc",
            evidence="evidence",
        )
        assert f.detail == ""


# ---------------------------------------------------------------------------
# AgentConfig tests
# ---------------------------------------------------------------------------


class TestAgentConfig:
    """Tests for the AgentConfig dataclass."""

    def test_construction_defaults(self) -> None:
        """AgentConfig can be constructed with minimal arguments."""
        cfg = AgentConfig(
            source_path=Path("agent.json"),
            raw_text='{"name": "test"}',
            format="json",
        )
        assert cfg.system_prompt == ""
        assert cfg.tools == []
        assert cfg.metadata == {}

    def test_get_all_string_values_flat_dict(self) -> None:
        """get_all_string_values extracts strings from a flat dict."""
        cfg = AgentConfig(
            source_path=Path("x.json"),
            raw_text="",
            format="json",
            data={"name": "my_agent", "prompt": "Hello world"},
        )
        pairs = cfg.get_all_string_values()
        paths = [p for p, _ in pairs]
        values = [v for _, v in pairs]
        assert "name" in paths
        assert "prompt" in paths
        assert "my_agent" in values
        assert "Hello world" in values

    def test_get_all_string_values_nested(self) -> None:
        """get_all_string_values recurses into nested dicts and lists."""
        cfg = AgentConfig(
            source_path=Path("x.json"),
            raw_text="",
            format="json",
            data={
                "tools": [
                    {"name": "tool_a", "description": "does stuff"},
                ]
            },
        )
        pairs = cfg.get_all_string_values()
        values = [v for _, v in pairs]
        assert "tool_a" in values
        assert "does stuff" in values

    def test_get_all_string_values_skips_non_strings(self) -> None:
        """get_all_string_values only returns string leaves, not numbers/bools."""
        cfg = AgentConfig(
            source_path=Path("x.json"),
            raw_text="",
            format="json",
            data={"count": 42, "enabled": True, "label": "hello"},
        )
        pairs = cfg.get_all_string_values()
        values = [v for _, v in pairs]
        assert "hello" in values
        assert 42 not in values  # type: ignore[comparison-overlap]
        assert True not in values  # type: ignore[comparison-overlap]

    def test_to_dict(self) -> None:
        """to_dict returns expected keys."""
        cfg = AgentConfig(
            source_path=Path("agent.yaml"),
            raw_text="",
            format="yaml",
            tools=[{"name": "t1"}, {"name": "t2"}],
        )
        d = cfg.to_dict()
        assert d["format"] == "yaml"
        assert d["tools_count"] == 2

    def test_repr(self) -> None:
        """__repr__ includes format and source_path info."""
        cfg = AgentConfig(
            source_path=Path("agent.json"),
            raw_text="",
            format="json",
            system_prompt="You are helpful.",
        )
        r = repr(cfg)
        assert "json" in r
        assert "agent.json" in r


# ---------------------------------------------------------------------------
# ScanResult tests
# ---------------------------------------------------------------------------


class TestScanResult:
    """Tests for the ScanResult dataclass."""

    def _make_finding_with_severity(self, sev: Severity) -> Finding:
        rule = make_rule(rule_id=f"R-{sev.value}", severity=sev)
        return make_finding(rule=rule)

    def test_empty_scan_result(self) -> None:
        """Empty ScanResult has no findings and no high_or_critical."""
        result = ScanResult()
        assert result.finding_count == 0
        assert not result.has_high_or_critical

    def test_has_high_or_critical_true(self) -> None:
        """has_high_or_critical is True when a HIGH finding exists."""
        result = ScanResult(
            findings=[self._make_finding_with_severity(Severity.HIGH)]
        )
        assert result.has_high_or_critical is True

    def test_has_high_or_critical_critical(self) -> None:
        """has_high_or_critical is True when a CRITICAL finding exists."""
        result = ScanResult(
            findings=[self._make_finding_with_severity(Severity.CRITICAL)]
        )
        assert result.has_high_or_critical is True

    def test_has_high_or_critical_false_for_medium(self) -> None:
        """has_high_or_critical is False when only MEDIUM findings exist."""
        result = ScanResult(
            findings=[self._make_finding_with_severity(Severity.MEDIUM)]
        )
        assert result.has_high_or_critical is False

    def test_findings_by_severity(self) -> None:
        """findings_by_severity returns only matching severity findings."""
        result = ScanResult(
            findings=[
                self._make_finding_with_severity(Severity.HIGH),
                self._make_finding_with_severity(Severity.LOW),
                self._make_finding_with_severity(Severity.LOW),
            ]
        )
        assert len(result.findings_by_severity(Severity.HIGH)) == 1
        assert len(result.findings_by_severity(Severity.LOW)) == 2
        assert len(result.findings_by_severity(Severity.CRITICAL)) == 0

    def test_findings_at_or_above(self) -> None:
        """findings_at_or_above returns findings meeting minimum severity."""
        result = ScanResult(
            findings=[
                self._make_finding_with_severity(Severity.CRITICAL),
                self._make_finding_with_severity(Severity.HIGH),
                self._make_finding_with_severity(Severity.MEDIUM),
                self._make_finding_with_severity(Severity.LOW),
                self._make_finding_with_severity(Severity.INFO),
            ]
        )
        high_plus = result.findings_at_or_above(Severity.HIGH)
        assert len(high_plus) == 2
        for f in high_plus:
            assert f.severity >= Severity.HIGH

    def test_sorted_findings_order(self) -> None:
        """sorted_findings returns findings in descending severity order."""
        result = ScanResult(
            findings=[
                self._make_finding_with_severity(Severity.LOW),
                self._make_finding_with_severity(Severity.CRITICAL),
                self._make_finding_with_severity(Severity.MEDIUM),
            ]
        )
        sorted_f = result.sorted_findings()
        assert sorted_f[0].severity == Severity.CRITICAL
        assert sorted_f[1].severity == Severity.MEDIUM
        assert sorted_f[2].severity == Severity.LOW

    def test_to_dict_structure(self) -> None:
        """to_dict returns summary and findings keys."""
        result = ScanResult(
            findings=[self._make_finding_with_severity(Severity.HIGH)],
            scanned_files=[Path("a.json")],
        )
        d = result.to_dict()
        assert "summary" in d
        assert "findings" in d
        assert "scanned_files" in d
        assert "errors" in d
        assert d["summary"]["total_findings"] == 1
        assert d["summary"]["has_high_or_critical"] is True

    def test_to_json_is_valid_json(self) -> None:
        """to_json produces a valid JSON string."""
        result = ScanResult(
            findings=[self._make_finding_with_severity(Severity.MEDIUM)],
            scanned_files=[Path("b.yaml")],
        )
        raw = result.to_json()
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)
        assert "findings" in parsed

    def test_to_json_severity_counts(self) -> None:
        """to_json summary includes per-severity counts."""
        result = ScanResult(
            findings=[
                self._make_finding_with_severity(Severity.HIGH),
                self._make_finding_with_severity(Severity.HIGH),
                self._make_finding_with_severity(Severity.LOW),
            ]
        )
        parsed = json.loads(result.to_json())
        counts = parsed["summary"]["severity_counts"]
        assert counts["HIGH"] == 2
        assert counts["LOW"] == 1
        assert counts["CRITICAL"] == 0
