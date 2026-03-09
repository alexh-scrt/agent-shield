"""Unit tests for agent_shield.rules — rule registry."""

from __future__ import annotations

import pytest

from agent_shield.models import Severity
from agent_shield.rules import (
    KNOWN_CATEGORIES,
    RULES,
    all_rule_ids,
    get_rule,
    iter_rules,
    rules_by_category,
)


class TestRuleRegistry:
    """Tests for the RULES registry dict."""

    def test_rules_not_empty(self) -> None:
        """RULES must contain at least one rule."""
        assert len(RULES) > 0

    def test_all_expected_prefixes_present(self) -> None:
        """At least one rule per prefix category must exist."""
        rule_ids = set(RULES.keys())
        prefixes = {"PI", "SL", "EP", "TS"}
        found = {rid.split("-")[0] for rid in rule_ids}
        assert prefixes.issubset(found)

    def test_rule_ids_are_unique(self) -> None:
        """Every rule ID in the registry must be unique."""
        ids = list(RULES.keys())
        assert len(ids) == len(set(ids))

    def test_all_rules_have_required_fields(self) -> None:
        """Every rule must have non-empty id, title, description, remediation."""
        for rule_id, rule in RULES.items():
            assert rule.rule_id == rule_id
            assert rule.title.strip(), f"Rule {rule_id} has empty title"
            assert rule.description.strip(), f"Rule {rule_id} has empty description"
            assert rule.remediation.strip(), f"Rule {rule_id} has empty remediation"
            assert rule.category.strip(), f"Rule {rule_id} has empty category"

    def test_all_rules_have_valid_severity(self) -> None:
        """Every rule must have a valid Severity value."""
        for rule_id, rule in RULES.items():
            assert isinstance(rule.severity, Severity), (
                f"Rule {rule_id} severity is not a Severity instance"
            )

    def test_known_categories_matches_rules(self) -> None:
        """KNOWN_CATEGORIES must equal the set of categories used by rules."""
        actual = frozenset(rule.category for rule in RULES.values())
        assert KNOWN_CATEGORIES == actual


class TestGetRule:
    """Tests for the get_rule() helper."""

    def test_returns_correct_rule(self) -> None:
        """get_rule returns the Rule with the given ID."""
        first_id = next(iter(RULES))
        rule = get_rule(first_id)
        assert rule.rule_id == first_id

    def test_raises_key_error_for_unknown_id(self) -> None:
        """get_rule raises KeyError for an unrecognised ID."""
        with pytest.raises(KeyError):
            get_rule("NONEXISTENT-999")

    def test_pi_001_is_critical(self) -> None:
        """PI-001 must be CRITICAL severity."""
        rule = get_rule("PI-001")
        assert rule.severity == Severity.CRITICAL

    def test_sl_001_is_critical(self) -> None:
        """SL-001 must be CRITICAL severity."""
        rule = get_rule("SL-001")
        assert rule.severity == Severity.CRITICAL

    def test_ts_001_is_critical(self) -> None:
        """TS-001 must be CRITICAL severity."""
        rule = get_rule("TS-001")
        assert rule.severity == Severity.CRITICAL


class TestRulesByCategory:
    """Tests for rules_by_category()."""

    def test_prompt_injection_category(self) -> None:
        """prompt_injection category must return rules."""
        rules = rules_by_category("prompt_injection")
        assert len(rules) > 0
        for rule in rules:
            assert rule.category == "prompt_injection"

    def test_secret_leakage_category(self) -> None:
        """secret_leakage category must return rules."""
        rules = rules_by_category("secret_leakage")
        assert len(rules) > 0
        for rule in rules:
            assert rule.category == "secret_leakage"

    def test_permissions_category(self) -> None:
        """permissions category must return rules."""
        rules = rules_by_category("permissions")
        assert len(rules) > 0
        for rule in rules:
            assert rule.category == "permissions"

    def test_tool_schema_category(self) -> None:
        """tool_schema category must return rules."""
        rules = rules_by_category("tool_schema")
        assert len(rules) > 0
        for rule in rules:
            assert rule.category == "tool_schema"

    def test_unknown_category_returns_empty(self) -> None:
        """Unknown category returns an empty list."""
        rules = rules_by_category("nonexistent_category")
        assert rules == []

    def test_returned_rules_sorted_by_id(self) -> None:
        """rules_by_category returns rules sorted by rule_id."""
        for cat in KNOWN_CATEGORIES:
            rules = rules_by_category(cat)
            ids = [r.rule_id for r in rules]
            assert ids == sorted(ids), f"Category {cat!r} rules not sorted"


class TestAllRuleIds:
    """Tests for all_rule_ids()."""

    def test_returns_sorted_list(self) -> None:
        """all_rule_ids returns a sorted list."""
        ids = all_rule_ids()
        assert ids == sorted(ids)

    def test_length_matches_registry(self) -> None:
        """all_rule_ids returns same count as RULES dict."""
        assert len(all_rule_ids()) == len(RULES)


class TestIterRules:
    """Tests for iter_rules()."""

    def test_yields_all_rules(self) -> None:
        """iter_rules yields every rule in the registry."""
        rules = list(iter_rules())
        assert len(rules) == len(RULES)

    def test_yields_in_id_order(self) -> None:
        """iter_rules yields rules in ascending rule_id order."""
        rules = list(iter_rules())
        ids = [r.rule_id for r in rules]
        assert ids == sorted(ids)
