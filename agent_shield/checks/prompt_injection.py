"""Prompt injection vulnerability checks for agent_shield.

This module implements detection rules for prompt injection patterns in agent
configuration files and system prompts. It checks for:

- Role override / instruction override phrases (PI-001)
- Instruction smuggling via hidden characters, HTML comments, base64 (PI-002)
- Known jailbreak templates like DAN, Developer Mode, etc. (PI-003)
- Prompt leakage instructions that allow the model to reveal its config (PI-004)
- Indirect prompt injection via external data references (PI-005)

Each check function accepts an :class:`~agent_shield.models.AgentConfig` and
returns a list of :class:`~agent_shield.models.Finding` objects.

Usage::

    from agent_shield.checks.prompt_injection import check_prompt_injection
    from agent_shield.loader import load_config
    from pathlib import Path

    config = load_config(Path("agent.json"))
    findings = check_prompt_injection(config)
"""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any

from agent_shield.models import AgentConfig, Finding
from agent_shield.rules import get_rule

# ---------------------------------------------------------------------------
# Compiled regex patterns — PI-001: Role Override
# ---------------------------------------------------------------------------

#: Phrases that attempt to override or negate the model's existing instructions.
_ROLE_OVERRIDE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompt|system\s+prompt)", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|context|conversation)", re.IGNORECASE),
    re.compile(r"override\s+(your\s+)?(instructions?|system\s+prompt|guidelines?|rules?|constraints?)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a\s+|an\s+)?(?:DAN|jailbreak|unrestricted|free|uncensored)", re.IGNORECASE),
    re.compile(r"new\s+(instructions?|prompt|role|persona|directives?)[:\s]", re.IGNORECASE),
    re.compile(r"your\s+(true|real|actual)\s+(purpose|goal|mission|role|instructions?)", re.IGNORECASE),
    re.compile(r"(stop|cease)\s+(being|acting\s+as|following)\s+(an?\s+)?(assistant|AI|helpful|safe)", re.IGNORECASE),
    re.compile(r"pretend\s+(that\s+)?(you\s+)?(have\s+no|don.t\s+have|there\s+are\s+no)\s+(restrictions?|limits?|guidelines?|rules?)", re.IGNORECASE),
    re.compile(r"act\s+as\s+if\s+(you\s+)?(have\s+no|don.t\s+have)\s+(restrictions?|limits?|filters?)", re.IGNORECASE),
    re.compile(r"(you\s+are\s+no\s+longer|you\s+are\s+not)\s+(bound|restricted|constrained|limited)", re.IGNORECASE),
    re.compile(r"system\s*:\s*you\s+are", re.IGNORECASE),
    re.compile(r"\[\s*system\s*\]\s*\n", re.IGNORECASE),
    re.compile(r"</?(system|instruction|prompt)\s*>", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Compiled regex patterns — PI-002: Instruction Smuggling
# ---------------------------------------------------------------------------

#: Zero-width and invisible Unicode characters often used to hide content.
_INVISIBLE_UNICODE_PATTERN: re.Pattern[str] = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff\u00ad]"
)

#: HTML/XML comment blocks that can hide injected instructions.
_HTML_COMMENT_PATTERN: re.Pattern[str] = re.compile(
    r"<!--.*?-->", re.DOTALL
)

#: Suspicious base64-encoded blobs (minimum 40 chars of base64 alphabet).
_BASE64_BLOB_PATTERN: re.Pattern[str] = re.compile(
    r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])"
)

#: Large whitespace padding (50+ spaces or newlines) designed to push content off-screen.
_WHITESPACE_PADDING_PATTERN: re.Pattern[str] = re.compile(
    r"[ \t]{50,}|\n{20,}"
)

#: Null bytes or other control characters that may be used for smuggling.
_CONTROL_CHAR_PATTERN: re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # type: ignore[call-overload]
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# ---------------------------------------------------------------------------
# Compiled regex patterns — PI-003: Jailbreak Templates
# ---------------------------------------------------------------------------

_JAILBREAK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bDAN\b", re.IGNORECASE),
    re.compile(r"do\s+anything\s+now", re.IGNORECASE),
    re.compile(r"developer\s+mode", re.IGNORECASE),
    re.compile(r"jailbreak\s+(mode|prompt|activated|enabled)", re.IGNORECASE),
    re.compile(r"grandma\s+(exploit|trick|loophole|glitch)", re.IGNORECASE),
    re.compile(r"\bAIM\b.*?(always\s+intelligent|machiavellian)", re.IGNORECASE),
    re.compile(r"(evil|dark|shadow|unrestricted|unfiltered|uncensored)\s+(mode|version|persona|AI|GPT|Claude|model)", re.IGNORECASE),
    re.compile(r"no\s+(ethics|morals?|restrictions?|limits?|filters?|guidelines?|safety)", re.IGNORECASE),
    re.compile(r"STAN\s+(protocol|mode|persona)", re.IGNORECASE),
    re.compile(r"(token\s+budget|token\s+limit)\s+bypass", re.IGNORECASE),
    re.compile(r"opposite\s+(mode|day|world|instructions?)", re.IGNORECASE),
    re.compile(r"SWITCH\s+TO\s+(EVIL|DARK|DEV|UNRESTRICTED|JAILBREAK)\s+MODE", re.IGNORECASE),
    re.compile(r"\[JAILBREAK\]", re.IGNORECASE),
    re.compile(r"\[DAN\]", re.IGNORECASE),
    re.compile(r"enable\s+developer\s+mode", re.IGNORECASE),
    re.compile(r"without\s+(any\s+)?(restrictions?|limits?|filters?|safety|guardrails?)", re.IGNORECASE),
    re.compile(r"(pretend|imagine|roleplay)\s+(you\s+)?(are|have\s+become)\s+(an?\s+)?(evil|malicious|rogue|unrestricted|unchained|unaligned)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Compiled regex patterns — PI-004: Prompt Leakage Instructions
# ---------------------------------------------------------------------------

_PROMPT_LEAKAGE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(share|reveal|show|disclose|output|print|display)\s+(your\s+)?(system\s+prompt|instructions?|configuration|guidelines?|rules?)", re.IGNORECASE),
    re.compile(r"if\s+(asked|requested|prompted|told).*?(reveal|share|show|tell|output)\s+(your\s+)?(instructions?|prompt|configuration)", re.IGNORECASE),
    re.compile(r"you\s+(may|can|should|are\s+allowed\s+to)\s+(reveal|share|show|disclose)\s+(your\s+)?(instructions?|system\s+prompt|configuration)", re.IGNORECASE),
    re.compile(r"(it.s\s+ok|okay|fine|acceptable|allowed)\s+(to\s+)?(share|reveal|show|disclose)\s+(your\s+)?(instructions?|prompt)", re.IGNORECASE),
    re.compile(r"do\s+not\s+hide\s+(your\s+)?(instructions?|system\s+prompt|guidelines?)", re.IGNORECASE),
    re.compile(r"tell\s+(users?|humans?|people|them|me)\s+(your|the)\s+(instructions?|system\s+prompt|guidelines?|configuration)", re.IGNORECASE),
    re.compile(r"(leak|expose|dump)\s+(your\s+)?(system\s+)?(prompt|instructions?|context)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Compiled regex patterns — PI-005: Indirect Prompt Injection via External Data
# ---------------------------------------------------------------------------

_EXTERNAL_DATA_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(fetch|download|retrieve|load|read|get|pull)\s+(content|data|text|instructions?)\s+(from|at|via)\s+(http|https|ftp|url|link|endpoint)", re.IGNORECASE),
    re.compile(r"(incorporate|include|embed|inject|insert|append|prepend|add)\s+(the\s+)?(content|text|response|output|data)\s+(from|of)\s+(the\s+)?(url|link|endpoint|website|page)", re.IGNORECASE),
    re.compile(r"(use|process|follow|execute|apply)\s+(any\s+)?(instructions?|commands?|directives?)\s+(found|fetched|retrieved|downloaded|from)", re.IGNORECASE),
    re.compile(r"(read|load|fetch|process)\s+(user.?supplied|user.?provided|user.?uploaded|external|untrusted)\s+(files?|documents?|content|data)", re.IGNORECASE),
    re.compile(r"(include|inject)\s+(the\s+)?(raw|full|complete|entire)\s+(content|text|body)\s+(of|from)", re.IGNORECASE),
    re.compile(r"(process|execute|follow)\s+(instructions?|commands?)\s+(embedded|contained|found|present)\s+(in|within)\s+(the\s+)?(document|file|page|email|message)", re.IGNORECASE),
    re.compile(r"automatically\s+(incorporate|include|follow|execute|apply)\s+(instructions?|commands?|directives?)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Minimum base64 decoded length to flag as suspicious
# ---------------------------------------------------------------------------
_MIN_SUSPICIOUS_B64_DECODED_LEN = 20


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_prompt_injection(config: AgentConfig) -> list[Finding]:
    """Run all prompt injection checks against an agent configuration.

    This is the main entry point for the prompt injection check module. It
    dispatches to all individual check functions and aggregates the results.

    Args:
        config: The normalised agent configuration to check.

    Returns:
        List of :class:`~agent_shield.models.Finding` objects, possibly empty.
    """
    findings: list[Finding] = []
    findings.extend(_check_role_override(config))
    findings.extend(_check_instruction_smuggling(config))
    findings.extend(_check_jailbreak_templates(config))
    findings.extend(_check_prompt_leakage(config))
    findings.extend(_check_indirect_injection(config))
    return findings


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------


def _check_role_override(config: AgentConfig) -> list[Finding]:
    """PI-001: Detect role-override and instruction-override phrases.

    Scans the system prompt and all string values in the config data for
    phrases that attempt to override or negate the model's instructions.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected role override pattern.
    """
    rule = get_rule("PI-001")
    findings: list[Finding] = []
    seen_evidence: set[str] = set()

    texts_to_check: list[tuple[str, str]] = []

    if config.system_prompt:
        texts_to_check.append(("system_prompt", config.system_prompt))

    for location, value in config.get_all_string_values():
        if value and value not in (config.system_prompt,):
            texts_to_check.append((location, value))

    for location, text in texts_to_check:
        for pattern in _ROLE_OVERRIDE_PATTERNS:
            for match in pattern.finditer(text):
                evidence = _extract_evidence(text, match.start(), match.end())
                evidence_key = f"{location}:{evidence.lower()}"
                if evidence_key in seen_evidence:
                    continue
                seen_evidence.add(evidence_key)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=evidence,
                        detail=f"Matched pattern: {pattern.pattern!r}",
                    )
                )

    return findings


def _check_instruction_smuggling(config: AgentConfig) -> list[Finding]:
    """PI-002: Detect instruction smuggling via hidden characters and encodings.

    Looks for invisible Unicode characters, HTML/XML comment blocks,
    suspicious base64-encoded payloads, excessive whitespace padding, and
    control characters embedded in the config text.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected smuggling pattern.
    """
    rule = get_rule("PI-002")
    findings: list[Finding] = []

    texts_to_check: list[tuple[str, str]] = []
    if config.system_prompt:
        texts_to_check.append(("system_prompt", config.system_prompt))
    for location, value in config.get_all_string_values():
        if value and value != config.system_prompt:
            texts_to_check.append((location, value))
    # Also check raw text for comprehensive coverage
    texts_to_check.append(("raw_text", config.raw_text))

    seen: set[str] = set()

    for location, text in texts_to_check:
        # Check for invisible Unicode characters
        if _INVISIBLE_UNICODE_PATTERN.search(text):
            key = f"{location}:invisible_unicode"
            if key not in seen:
                seen.add(key)
                matches = _INVISIBLE_UNICODE_PATTERN.findall(text)
                char_codes = ", ".join(f"U+{ord(c):04X}" for c in set(matches))
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=f"Invisible Unicode characters detected: {char_codes}",
                        detail=(
                            f"Found {len(matches)} invisible character(s). "
                            "These may be used to hide injected instructions."
                        ),
                    )
                )

        # Check for HTML/XML comment blocks
        for match in _HTML_COMMENT_PATTERN.finditer(text):
            comment_content = match.group(0)
            key = f"{location}:html_comment:{comment_content[:50]}"
            if key not in seen:
                seen.add(key)
                evidence = _extract_evidence(text, match.start(), match.end(), max_len=80)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=evidence,
                        detail=(
                            "HTML/XML comment block found. Comments can be used to "
                            "embed hidden instructions invisible to human reviewers."
                        ),
                    )
                )

        # Check for suspicious base64 blobs
        for match in _BASE64_BLOB_PATTERN.finditer(text):
            b64_candidate = match.group(1)
            if _is_suspicious_base64(b64_candidate):
                key = f"{location}:base64:{b64_candidate[:20]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        Finding(
                            rule=rule,
                            file_path=config.source_path,
                            location=location,
                            evidence=b64_candidate[:60] + ("..." if len(b64_candidate) > 60 else ""),
                            detail=(
                                "Suspicious base64-encoded blob detected. "
                                "Base64 can be used to smuggle hidden instructions."
                            ),
                        )
                    )

        # Check for excessive whitespace padding
        if _WHITESPACE_PADDING_PATTERN.search(text):
            key = f"{location}:whitespace_padding"
            if key not in seen:
                seen.add(key)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence="Excessive whitespace padding detected (50+ spaces or 20+ newlines)",
                        detail=(
                            "Large amounts of whitespace can push content off-screen, "
                            "hiding injected instructions from human reviewers."
                        ),
                    )
                )

        # Check for suspicious control characters
        if _CONTROL_CHAR_PATTERN.search(text):
            key = f"{location}:control_chars"
            if key not in seen:
                seen.add(key)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence="Non-printable control characters detected in text",
                        detail=(
                            "Control characters (ASCII 0x00-0x08, 0x0B-0x0C, 0x0E-0x1F, 0x7F) "
                            "found in text content. These may indicate smuggled content."
                        ),
                    )
                )

    return findings


def _check_jailbreak_templates(config: AgentConfig) -> list[Finding]:
    """PI-003: Detect known jailbreak template phrases.

    Searches for well-known jailbreak template patterns such as 'DAN mode',
    'Developer Mode', 'Do Anything Now', etc. in all text content.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected jailbreak template.
    """
    rule = get_rule("PI-003")
    findings: list[Finding] = []
    seen_evidence: set[str] = set()

    texts_to_check: list[tuple[str, str]] = []
    if config.system_prompt:
        texts_to_check.append(("system_prompt", config.system_prompt))
    for location, value in config.get_all_string_values():
        if value and value != config.system_prompt:
            texts_to_check.append((location, value))

    for location, text in texts_to_check:
        for pattern in _JAILBREAK_PATTERNS:
            for match in pattern.finditer(text):
                evidence = _extract_evidence(text, match.start(), match.end())
                evidence_key = f"{location}:{evidence.lower()[:60]}"
                if evidence_key in seen_evidence:
                    continue
                seen_evidence.add(evidence_key)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=evidence,
                        detail=f"Matched jailbreak pattern: {pattern.pattern!r}",
                    )
                )

    return findings


def _check_prompt_leakage(config: AgentConfig) -> list[Finding]:
    """PI-004: Detect instructions that permit the model to reveal its config.

    Identifies phrases in the system prompt or tool descriptions that allow
    or encourage the model to disclose its instructions, system prompt, or
    configuration to end users.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected prompt leakage instruction.
    """
    rule = get_rule("PI-004")
    findings: list[Finding] = []
    seen_evidence: set[str] = set()

    texts_to_check: list[tuple[str, str]] = []
    if config.system_prompt:
        texts_to_check.append(("system_prompt", config.system_prompt))
    for location, value in config.get_all_string_values():
        if value and value != config.system_prompt:
            texts_to_check.append((location, value))

    for location, text in texts_to_check:
        for pattern in _PROMPT_LEAKAGE_PATTERNS:
            for match in pattern.finditer(text):
                evidence = _extract_evidence(text, match.start(), match.end())
                evidence_key = f"{location}:{evidence.lower()[:60]}"
                if evidence_key in seen_evidence:
                    continue
                seen_evidence.add(evidence_key)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=evidence,
                        detail=f"Matched leakage pattern: {pattern.pattern!r}",
                    )
                )

    return findings


def _check_indirect_injection(config: AgentConfig) -> list[Finding]:
    """PI-005: Detect indirect prompt injection via external data references.

    Identifies configuration patterns where the agent is instructed to fetch
    or incorporate external content directly into its context without any
    sanitisation step, enabling indirect prompt injection attacks.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected indirect injection risk.
    """
    rule = get_rule("PI-005")
    findings: list[Finding] = []
    seen_evidence: set[str] = set()

    texts_to_check: list[tuple[str, str]] = []
    if config.system_prompt:
        texts_to_check.append(("system_prompt", config.system_prompt))
    for location, value in config.get_all_string_values():
        if value and value != config.system_prompt:
            texts_to_check.append((location, value))

    for location, text in texts_to_check:
        for pattern in _EXTERNAL_DATA_PATTERNS:
            for match in pattern.finditer(text):
                evidence = _extract_evidence(text, match.start(), match.end())
                evidence_key = f"{location}:{evidence.lower()[:60]}"
                if evidence_key in seen_evidence:
                    continue
                seen_evidence.add(evidence_key)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=evidence,
                        detail=f"Matched indirect injection pattern: {pattern.pattern!r}",
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _extract_evidence(text: str, start: int, end: int, max_len: int = 120) -> str:
    """Extract a context window around a match for use as evidence.

    Returns up to ``max_len`` characters centred around the matched region,
    with leading/trailing ellipsis added when the text is truncated.

    Args:
        text: The full text string containing the match.
        start: Start index of the match within ``text``.
        end: End index of the match within ``text``.
        max_len: Maximum length of the returned evidence string.

    Returns:
        A (possibly truncated) string showing the match in context.
    """
    context_chars = max(0, (max_len - (end - start)) // 2)
    snippet_start = max(0, start - context_chars)
    snippet_end = min(len(text), end + context_chars)

    snippet = text[snippet_start:snippet_end].replace("\n", " ").replace("\r", " ")

    prefix = "..." if snippet_start > 0 else ""
    suffix = "..." if snippet_end < len(text) else ""

    result = f"{prefix}{snippet}{suffix}"
    if len(result) > max_len + 6:  # allow a little room for ellipsis
        result = result[:max_len] + "..."
    return result


def _is_suspicious_base64(candidate: str) -> bool:
    """Determine whether a base64 candidate string is likely a hidden payload.

    Heuristics:
    - Must be at least 40 characters long (already enforced by the regex).
    - Decoded content must be at least ``_MIN_SUSPICIOUS_B64_DECODED_LEN`` bytes.
    - Decoded bytes must contain a significant proportion of printable ASCII,
      suggesting hidden text rather than legitimate binary data in a non-text field.
    - Excludes candidates that look like standard UUIDs or short identifiers.

    Args:
        candidate: The base64 candidate string to evaluate.

    Returns:
        ``True`` if the candidate looks like a suspicious hidden payload.
    """
    # Pad to a multiple of 4 for decoding
    padded = candidate + "=" * ((-len(candidate)) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except Exception:
        # Not valid base64 — not suspicious in this context
        return False

    if len(decoded) < _MIN_SUSPICIOUS_B64_DECODED_LEN:
        return False

    # Check proportion of printable ASCII in decoded bytes
    printable_count = sum(1 for b in decoded if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    printable_ratio = printable_count / len(decoded)

    # High printable ratio suggests hidden text instructions
    return printable_ratio >= 0.70
