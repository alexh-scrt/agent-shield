"""Secret leakage vulnerability checks for agent_shield.

This module implements detection rules for hardcoded secrets, API keys, tokens,
and credentials embedded in agent configuration files and system prompts.
It checks for:

- Well-known API key formats (OpenAI, Anthropic, AWS, GitHub, etc.) (SL-001)
- High-entropy strings consistent with randomly generated secrets (SL-002)
- PEM-encoded private key material (SL-003)
- Database connection strings with embedded credentials (SL-004)
- Credential-named key-value pairs with non-placeholder values (SL-005)
- Cloud provider credential references (SL-006)

Each check function accepts an :class:`~agent_shield.models.AgentConfig` and
returns a list of :class:`~agent_shield.models.Finding` objects.

Usage::

    from agent_shield.checks.secret_leakage import check_secret_leakage
    from agent_shield.loader import load_config
    from pathlib import Path

    config = load_config(Path("agent.json"))
    findings = check_secret_leakage(config)
"""

from __future__ import annotations

import math
import re
import string
from pathlib import Path
from typing import Any

from agent_shield.models import AgentConfig, Finding
from agent_shield.rules import get_rule

# ---------------------------------------------------------------------------
# SL-001: Well-known API key / secret token patterns
# ---------------------------------------------------------------------------

#: Each entry is a tuple of (label, compiled_pattern) for a known credential format.
_KNOWN_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # OpenAI API keys
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    # Anthropic API keys
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    # AWS Access Key ID
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # AWS Secret Access Key (40 chars of base62)
    ("AWS Secret Access Key", re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])", re.IGNORECASE)),
    # GitHub personal access tokens (classic)
    ("GitHub PAT (classic)", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    # GitHub fine-grained tokens
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    # GitHub OAuth tokens
    ("GitHub OAuth token", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    # GitHub Actions tokens
    ("GitHub Actions token", re.compile(r"\bghs_[A-Za-z0-9]{36}\b")),
    # GitHub refresh tokens
    ("GitHub refresh token", re.compile(r"\bghr_[A-Za-z0-9]{36}\b")),
    # Google API keys
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    # Google OAuth client secrets
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[A-Za-z0-9\-_]{28}\b")),
    # Stripe secret keys
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    # Stripe restricted keys
    ("Stripe restricted key", re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b")),
    # Stripe test keys
    ("Stripe test key", re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b")),
    # Twilio account SID
    ("Twilio Account SID", re.compile(r"\bAC[a-z0-9]{32}\b")),
    # Twilio auth token (32 hex chars)
    ("Twilio Auth Token", re.compile(r"(?i)twilio.*?([a-f0-9]{32})\b")),
    # Slack bot tokens
    ("Slack bot token", re.compile(r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b")),
    # Slack user tokens
    ("Slack user token", re.compile(r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}\b")),
    # Slack workspace tokens
    ("Slack workspace token", re.compile(r"\bxoxa-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}\b")),
    # Slack refresh tokens
    ("Slack refresh token", re.compile(r"\bxoxr-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}\b")),
    # HuggingFace API tokens
    ("HuggingFace API token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    # SendGrid API keys
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    # Mailgun API keys
    ("Mailgun API key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    # Datadog API keys (32 hex)
    ("Datadog API key", re.compile(r"(?i)(?:dd|datadog)[._\-]?(?:api|app)[._\-]?key['"]?\s*[=:]['"]?\s*([a-f0-9]{32})\b")),
    # npm tokens
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    # PyPI API tokens
    ("PyPI API token", re.compile(r"\bpypi-[A-Za-z0-9_\-]{40,}\b")),
    # Heroku API keys
    ("Heroku API key", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")),
    # Azure client secrets / SAS tokens
    ("Azure client secret pattern", re.compile(r"(?i)(?:azure|az)[._\-]?(?:client|tenant|subscription)[._\-]?(?:secret|key|id)['"]?\s*[=:]['"]?\s*([A-Za-z0-9~._\-]{20,})")),
    # Generic bearer tokens in config values
    ("Bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9\-_\.]{20,}\b", re.IGNORECASE)),
    # Basic auth credentials in URL
    ("Basic auth in URL", re.compile(r"https?://[A-Za-z0-9._%+\-]+:[A-Za-z0-9._%+\-!@#$^&*]{4,}@")),
]

# ---------------------------------------------------------------------------
# SL-002: High-entropy string detection
# ---------------------------------------------------------------------------

#: Minimum length for a string to be considered as a potential high-entropy secret.
_MIN_ENTROPY_STRING_LENGTH = 20

#: Minimum Shannon entropy (bits per character) threshold to flag a string.
_MIN_SHANNON_ENTROPY = 4.5

#: Maximum length beyond which we skip entropy analysis (avoids false positives on
#: long prose, base64-encoded images, etc.).
_MAX_ENTROPY_STRING_LENGTH = 200

#: Regex to split text into candidate token sequences (alphanumeric + common secret chars).
_ENTROPY_CANDIDATE_PATTERN: re.Pattern[str] = re.compile(
    r"[A-Za-z0-9+/=_\-\.~!@#$%^&*]{20,200}"
)

#: Keys whose values are expected to be long strings and should be skipped for entropy check
#: (avoids false positives on descriptions, prompts, etc.).
_ENTROPY_SKIP_LOCATION_SUBSTRINGS: tuple[str, ...] = (
    "description",
    "system_prompt",
    "prompt",
    "instructions",
    "content",
    "message",
    "text",
    "summary",
    "detail",
    "raw_text",
    "title",
    "name",
    "label",
    "comment",
    "readme",
    "notes",
    "help",
    "usage",
    "example",
)

#: Common placeholder / non-secret patterns to ignore during entropy checks.
_NON_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\$\{[A-Za-z0-9_]+\}$"),           # ${ENV_VAR}
    re.compile(r"^\$[A-Za-z0-9_]+$"),               # $ENV_VAR
    re.compile(r"^%[A-Za-z0-9_]+%$"),               # %ENV_VAR% (Windows)
    re.compile(r"^<[A-Za-z0-9_\-\s]+>$"),           # <placeholder>
    re.compile(r"^\*{3,}$"),                         # *** masked
    re.compile(r"^x{4,}$", re.IGNORECASE),          # xxxx masked
    re.compile(r"^0{8,}$"),                          # 00000000 null
    re.compile(r"^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$"),  # UUID
    re.compile(r"^v?\d+\.\d+\.\d+(\.\d+)?$"),       # version strings like 1.2.3
    re.compile(r"^https?://"),                        # URLs
    re.compile(r"^[a-z][a-z0-9\-_]*\.[a-z]{2,}(/|$)"),  # domain names
]

# ---------------------------------------------------------------------------
# SL-003: PEM private key material
# ---------------------------------------------------------------------------

_PEM_PRIVATE_KEY_PATTERN: re.Pattern[str] = re.compile(
    r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ENCRYPTED\s+|)?PRIVATE\s+KEY-----",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# SL-004: Database connection strings with credentials
# ---------------------------------------------------------------------------

_DB_CONNECTION_STRING_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("PostgreSQL connection string",
     re.compile(r"postgres(?:ql)?://[A-Za-z0-9._%+\-]+:[A-Za-z0-9._%+\-!@#$^&*]{3,}@[A-Za-z0-9.\-]+", re.IGNORECASE)),
    ("MySQL connection string",
     re.compile(r"mysql(?:2)?://[A-Za-z0-9._%+\-]+:[A-Za-z0-9._%+\-!@#$^&*]{3,}@[A-Za-z0-9.\-]+", re.IGNORECASE)),
    ("MongoDB connection string",
     re.compile(r"mongodb(?:\+srv)?://[A-Za-z0-9._%+\-]+:[A-Za-z0-9._%+\-!@#$^&*]{3,}@[A-Za-z0-9.\-]+", re.IGNORECASE)),
    ("Redis connection string with password",
     re.compile(r"redis://(?:default|[A-Za-z0-9._%+\-]+):[A-Za-z0-9._%+\-!@#$^&*]{3,}@[A-Za-z0-9.\-]+", re.IGNORECASE)),
    ("MSSQL connection string",
     re.compile(r"(?:mssql|sqlserver)://[A-Za-z0-9._%+\-]+:[A-Za-z0-9._%+\-!@#$^&*]{3,}@[A-Za-z0-9.\-]+", re.IGNORECASE)),
    ("Generic JDBC/ODBC password",
     re.compile(r"(?:password|pwd)=['"]?([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':,.<>?/\\]{6,})['"]?", re.IGNORECASE)),
    ("ADO.NET connection string with password",
     re.compile(r"Password=[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':,.<>?/\\]{4,};", re.IGNORECASE)),
]

# ---------------------------------------------------------------------------
# SL-005: Credential-named key-value pairs
# ---------------------------------------------------------------------------

#: Key name patterns suggesting the value is a credential.
_CREDENTIAL_KEY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)^(?:.*_)?(?:password|passwd|pwd)(?:_.*)?$"),
    re.compile(r"(?i)^(?:.*_)?(?:secret|secrets)(?:_.*)?$"),
    re.compile(r"(?i)^(?:.*_)?(?:api[_\-]?key|apikey|api[_\-]?secret)(?:_.*)?$"),
    re.compile(r"(?i)^(?:.*_)?(?:access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)(?:_.*)?$"),
    re.compile(r"(?i)^(?:.*_)?(?:client[_\-]?secret)(?:_.*)?$"),
    re.compile(r"(?i)^(?:.*_)?(?:private[_\-]?key|priv[_\-]?key)(?:_.*)?$"),
    re.compile(r"(?i)^(?:.*_)?(?:credential|credentials|creds)(?:_.*)?$"),
    re.compile(r"(?i)^(?:.*_)?(?:auth[_\-]?key|auth[_\-]?pass|auth[_\-]?password)(?:_.*)?$"),
    re.compile(r"(?i)^(?:.*_)?(?:encryption[_\-]?key|encrypt[_\-]?key|signing[_\-]?key|sign[_\-]?key)(?:_.*)?$"),
    re.compile(r"(?i)^(?:.*_)?(?:refresh[_\-]?token|session[_\-]?token|session[_\-]?key)(?:_.*)?$"),
]

#: Placeholder values that indicate the key is intentionally not set.
_PLACEHOLDER_VALUE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\$\{[A-Za-z0-9_]+\}$"),       # ${ENV_VAR}
    re.compile(r"^\$[A-Za-z0-9_]+$"),            # $ENV_VAR
    re.compile(r"^%[A-Za-z0-9_]+%$"),            # %ENV_VAR%
    re.compile(r"^<[^>]+>$"),                    # <placeholder>
    re.compile(r"^\*+$"),                        # **** (masked)
    re.compile(r"^x+$", re.IGNORECASE),         # xxxx (masked)
    re.compile(r"^CHANGE[_\-]?ME$", re.IGNORECASE),
    re.compile(r"^YOUR[_\-]?(API[_\-]?KEY|SECRET|TOKEN|PASSWORD|KEY)$", re.IGNORECASE),
    re.compile(r"^REPLACE[_\-]?ME$", re.IGNORECASE),
    re.compile(r"^TODO$", re.IGNORECASE),
    re.compile(r"^PLACEHOLDER$", re.IGNORECASE),
    re.compile(r"^REDACTED$", re.IGNORECASE),
    re.compile(r"^example[_\-]?(key|token|secret|password)?$", re.IGNORECASE),
    re.compile(r"^test[_\-]?(key|token|secret|password)?$", re.IGNORECASE),
    re.compile(r"^fake[_\-]?(key|token|secret|password)?$", re.IGNORECASE),
    re.compile(r"^dummy[_\-]?(key|token|secret|password)?$", re.IGNORECASE),
    re.compile(r"^null$", re.IGNORECASE),
    re.compile(r"^none$", re.IGNORECASE),
    re.compile(r"^empty$", re.IGNORECASE),
    re.compile(r"^\.{3,}$"),                     # ... ellipsis
]

# ---------------------------------------------------------------------------
# SL-006: Cloud provider credential references
# ---------------------------------------------------------------------------

_CLOUD_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS credentials file reference",
     re.compile(r"(?:~|\.)?/?\.aws/credentials", re.IGNORECASE)),
    ("AWS credentials file reference",
     re.compile(r"(?:~|\.)?/?\.aws/config", re.IGNORECASE)),
    ("Google Application Credentials file path",
     re.compile(r"GOOGLE_APPLICATION_CREDENTIALS\s*[=:]\s*['"]?([/~][^'"\s,;]+\.json)['"]?", re.IGNORECASE)),
    ("Google service account key file",
     re.compile(r"['"]type['"]\s*:\s*['"]service_account['"]")),
    ("Azure client secret in config",
     re.compile(r"(?i)(?:azure[._\-]?)?client[._\-]?secret\s*[=:]\s*['"]?([A-Za-z0-9~._\-]{8,})['"]?")),
    ("Azure tenant ID reference",
     re.compile(r"(?i)(?:azure[._\-]?)?tenant[._\-]?id\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?")),
    ("Hardcoded AWS region with credential hint",
     re.compile(r"aws[._\-]?(?:secret[._\-]?access[._\-]?key|session[._\-]?token)\s*[=:]\s*['"]?([A-Za-z0-9/+]{20,})['"]?", re.IGNORECASE)),
    ("GCP project credential reference",
     re.compile(r"gcloud\s+(?:auth|config)\s+(?:activate-service-account|set).*\.json", re.IGNORECASE)),
    ("DigitalOcean API token",
     re.compile(r"(?i)(?:do|digitalocean)[._\-]?(?:api[._\-]?)?token\s*[=:]\s*['"]?([a-f0-9]{64})['"]?")),
    ("Docker registry credentials",
     re.compile(r"docker[._\-]?(?:password|token|secret)\s*[=:]\s*['"]?([A-Za-z0-9!@#$%^&*()_+\-]{8,})['"]?", re.IGNORECASE)),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_secret_leakage(config: AgentConfig) -> list[Finding]:
    """Run all secret leakage checks against an agent configuration.

    This is the main entry point for the secret leakage check module. It
    dispatches to all individual check functions and aggregates the results.

    Args:
        config: The normalised agent configuration to check.

    Returns:
        List of :class:`~agent_shield.models.Finding` objects, possibly empty.
    """
    findings: list[Finding] = []
    findings.extend(_check_known_api_keys(config))
    findings.extend(_check_high_entropy_strings(config))
    findings.extend(_check_private_key_material(config))
    findings.extend(_check_db_connection_strings(config))
    findings.extend(_check_credential_key_values(config))
    findings.extend(_check_cloud_credential_references(config))
    return findings


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------


def _check_known_api_keys(config: AgentConfig) -> list[Finding]:
    """SL-001: Detect well-known API key and secret token formats.

    Scans all text content in the configuration for strings matching the
    patterns of commonly used API keys and tokens from major providers.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected known credential.
    """
    rule = get_rule("SL-001")
    findings: list[Finding] = []
    seen: set[str] = set()

    for location, text in _iter_all_texts(config):
        for label, pattern in _KNOWN_SECRET_PATTERNS:
            for match in pattern.finditer(text):
                matched_value = match.group(0)
                evidence_key = f"{label}:{matched_value[:30]}"
                if evidence_key in seen:
                    continue
                seen.add(evidence_key)
                evidence = _redact_secret(matched_value)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=evidence,
                        detail=f"Detected credential type: {label}",
                    )
                )

    return findings


def _check_high_entropy_strings(config: AgentConfig) -> list[Finding]:
    """SL-002: Detect high-entropy strings that may be embedded secrets.

    Uses Shannon entropy calculation to identify strings that are likely
    randomly generated secrets rather than human-readable values, even if
    they do not match a known credential format.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected high-entropy string.
    """
    rule = get_rule("SL-002")
    findings: list[Finding] = []
    seen: set[str] = set()

    for location, value in config.get_all_string_values():
        # Skip locations that are expected to contain long prose
        if _should_skip_location_for_entropy(location):
            continue

        # Skip short or very long values
        value_stripped = value.strip()
        if len(value_stripped) < _MIN_ENTROPY_STRING_LENGTH:
            continue
        if len(value_stripped) > _MAX_ENTROPY_STRING_LENGTH:
            # Scan for candidate tokens within the long string
            candidates = _ENTROPY_CANDIDATE_PATTERN.findall(value_stripped)
        else:
            candidates = [value_stripped]

        for candidate in candidates:
            if len(candidate) < _MIN_ENTROPY_STRING_LENGTH:
                continue
            if len(candidate) > _MAX_ENTROPY_STRING_LENGTH:
                continue

            # Skip known placeholder / non-secret patterns
            if _is_placeholder(candidate):
                continue

            # Skip values that already matched SL-001 (known format)
            if _matches_known_format(candidate):
                continue

            entropy = _shannon_entropy(candidate)
            if entropy >= _MIN_SHANNON_ENTROPY:
                evidence_key = f"{location}:{candidate[:30]}"
                if evidence_key in seen:
                    continue
                seen.add(evidence_key)
                redacted = _redact_secret(candidate)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=redacted,
                        detail=(
                            f"Shannon entropy: {entropy:.2f} bits/char "
                            f"(threshold: {_MIN_SHANNON_ENTROPY}). "
                            f"String length: {len(candidate)} chars."
                        ),
                    )
                )

    return findings


def _check_private_key_material(config: AgentConfig) -> list[Finding]:
    """SL-003: Detect PEM-encoded private key material.

    Searches for PEM header markers indicating the presence of a private key
    embedded in the configuration text.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected private key.
    """
    rule = get_rule("SL-003")
    findings: list[Finding] = []
    seen: set[str] = set()

    # Check raw text for PEM markers (they may span multiple lines)
    texts_to_check: list[tuple[str, str]] = [("raw_text", config.raw_text)]
    if config.system_prompt:
        texts_to_check.append(("system_prompt", config.system_prompt))
    for location, value in config.get_all_string_values():
        if value and value != config.system_prompt:
            texts_to_check.append((location, value))

    for location, text in texts_to_check:
        for match in _PEM_PRIVATE_KEY_PATTERN.finditer(text):
            header = match.group(0)
            key = f"{location}:{header}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule=rule,
                    file_path=config.source_path,
                    location=location,
                    evidence=header,
                    detail=(
                        "PEM private key header detected. The full private key material "
                        "may be embedded in this configuration."
                    ),
                )
            )

    return findings


def _check_db_connection_strings(config: AgentConfig) -> list[Finding]:
    """SL-004: Detect database connection strings with embedded credentials.

    Identifies URI-format database connection strings that include a username
    and password in the connection URL.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected credential-bearing connection string.
    """
    rule = get_rule("SL-004")
    findings: list[Finding] = []
    seen: set[str] = set()

    for location, text in _iter_all_texts(config):
        for label, pattern in _DB_CONNECTION_STRING_PATTERNS:
            for match in pattern.finditer(text):
                matched_value = match.group(0)
                key = f"{label}:{location}:{matched_value[:40]}"
                if key in seen:
                    continue
                seen.add(key)
                evidence = _redact_connection_string(matched_value)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=evidence,
                        detail=f"Detected credential type: {label}",
                    )
                )

    return findings


def _check_credential_key_values(config: AgentConfig) -> list[Finding]:
    """SL-005: Detect credential-named keys with non-placeholder values.

    Walks the structured data looking for keys whose names suggest they hold
    credentials (e.g. 'password', 'api_key', 'client_secret') and whose
    values are non-empty and do not look like environment variable placeholders.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each suspicious credential key-value pair.
    """
    rule = get_rule("SL-005")
    findings: list[Finding] = []
    seen: set[str] = set()

    # Walk all key-value pairs in the structured data
    for location, value in config.get_all_string_values():
        if not value or not value.strip():
            continue

        # Extract the leaf key name from the dotted path
        leaf_key = _extract_leaf_key(location)
        if not leaf_key:
            continue

        # Check if the key name matches a credential pattern
        if not _is_credential_key(leaf_key):
            continue

        # Skip placeholder values
        if _is_placeholder(value.strip()):
            continue

        # Skip values that look like PEM headers (already caught by SL-003)
        if _PEM_PRIVATE_KEY_PATTERN.search(value):
            continue

        key = f"{location}:{value[:20]}"
        if key in seen:
            continue
        seen.add(key)

        redacted = _redact_secret(value.strip())
        findings.append(
            Finding(
                rule=rule,
                file_path=config.source_path,
                location=location,
                evidence=f"{leaf_key} = {redacted}",
                detail=(
                    f"Key name '{leaf_key}' suggests a credential. "
                    "Value does not appear to be a safe placeholder. "
                    "Verify this is not a hardcoded secret."
                ),
            )
        )

    return findings


def _check_cloud_credential_references(config: AgentConfig) -> list[Finding]:
    """SL-006: Detect cloud provider credential references.

    Identifies patterns suggesting cloud provider credentials are baked into
    the configuration, such as references to credential files, hardcoded
    service account keys, or client secrets.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected cloud credential reference.
    """
    rule = get_rule("SL-006")
    findings: list[Finding] = []
    seen: set[str] = set()

    for location, text in _iter_all_texts(config):
        for label, pattern in _CLOUD_CREDENTIAL_PATTERNS:
            for match in pattern.finditer(text):
                matched_value = match.group(0)
                key = f"{label}:{location}:{matched_value[:40]}"
                if key in seen:
                    continue
                seen.add(key)
                # Redact any captured group that might be a secret value
                evidence = _redact_secret(matched_value)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=evidence,
                        detail=f"Cloud credential reference type: {label}",
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _iter_all_texts(config: AgentConfig) -> list[tuple[str, str]]:
    """Collect all text content from a config for scanning.

    Returns a deduplicated list of (location, text) pairs covering the system
    prompt, all structured string values, and the raw text.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of ``(location, text)`` tuples.
    """
    texts: list[tuple[str, str]] = []
    seen_texts: set[str] = set()

    def _add(loc: str, text: str) -> None:
        if text and text not in seen_texts:
            seen_texts.add(text)
            texts.append((loc, text))

    if config.system_prompt:
        _add("system_prompt", config.system_prompt)

    for location, value in config.get_all_string_values():
        _add(location, value)

    _add("raw_text", config.raw_text)

    return texts


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy (bits per character) of a string.

    Args:
        text: Input string to analyse.

    Returns:
        Shannon entropy in bits per character. Returns 0.0 for empty strings.
    """
    if not text:
        return 0.0

    length = len(text)
    frequency: dict[str, int] = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1

    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def _is_placeholder(value: str) -> bool:
    """Return True if the value looks like a safe placeholder, not a real secret.

    Args:
        value: String value to evaluate.

    Returns:
        ``True`` if the value is a recognised placeholder pattern.
    """
    for pattern in _NON_SECRET_PATTERNS:
        if pattern.match(value):
            return True
    for pattern in _PLACEHOLDER_VALUE_PATTERNS:
        if pattern.match(value):
            return True
    return False


def _matches_known_format(candidate: str) -> bool:
    """Return True if the candidate matches any known API key format.

    Used to avoid double-reporting a finding as both SL-001 and SL-002.

    Args:
        candidate: String to test against known patterns.

    Returns:
        ``True`` if the candidate matches a known credential pattern.
    """
    for _label, pattern in _KNOWN_SECRET_PATTERNS:
        if pattern.search(candidate):
            return True
    return False


def _is_credential_key(key: str) -> bool:
    """Return True if the key name suggests it holds a credential value.

    Args:
        key: Key name string (leaf key from a dotted path).

    Returns:
        ``True`` if the key matches any credential name pattern.
    """
    for pattern in _CREDENTIAL_KEY_PATTERNS:
        if pattern.match(key):
            return True
    return False


def _extract_leaf_key(location: str) -> str:
    """Extract the leaf key name from a dotted location path.

    For example, ``"agent.tools[0].api_key"`` → ``"api_key"``.

    Args:
        location: Dot-separated path string from AgentConfig.get_all_string_values().

    Returns:
        The leaf key name, or an empty string if it cannot be determined.
    """
    if not location:
        return ""
    # Strip array index suffixes like [0], [1], etc.
    cleaned = re.sub(r"\[\d+\]$", "", location)
    # Take the last dot-separated segment
    parts = cleaned.rsplit(".", 1)
    leaf = parts[-1] if parts else ""
    # Remove any remaining array index
    leaf = re.sub(r"\[\d+\]", "", leaf)
    return leaf.strip()


def _redact_secret(value: str) -> str:
    """Partially redact a secret value for safe display in findings.

    Shows the first 4 and last 4 characters with asterisks in the middle,
    unless the string is too short, in which case it is fully redacted.

    Args:
        value: The secret string to redact.

    Returns:
        A partially or fully redacted string safe for display.
    """
    length = len(value)
    if length <= 8:
        return "*" * length
    visible_chars = min(4, length // 4)
    prefix = value[:visible_chars]
    suffix = value[-visible_chars:]
    middle = "*" * min(8, length - visible_chars * 2)
    return f"{prefix}{middle}{suffix}"


def _redact_connection_string(value: str) -> str:
    """Redact the password portion of a database connection string URI.

    Replaces the password segment ``user:password@host`` with
    ``user:***REDACTED***@host``.

    Args:
        value: The connection string to redact.

    Returns:
        The connection string with the password portion redacted.
    """
    # Redact URI-style passwords: scheme://user:password@host
    redacted = re.sub(
        r"(://[^:@/]+:)([^@]+)(@)",
        r"\1***REDACTED***\3",
        value,
    )
    # Redact key=value style passwords
    redacted = re.sub(
        r"(?i)(password\s*=\s*['"]?)([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':,.<>?/\\]{3,})(['"]?)",
        r"\1***REDACTED***\3",
        redacted,
    )
    redacted = re.sub(
        r"(?i)(Password=)([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':,.<>?/\\]{3,})(;?)",
        r"\1***REDACTED***\3",
        redacted,
    )
    return redacted


def _should_skip_location_for_entropy(location: str) -> bool:
    """Return True if the location path should be skipped for entropy analysis.

    Long prose fields like descriptions and system prompts naturally have
    moderate entropy and should not be scanned for high-entropy secrets.

    Args:
        location: Dot-separated location path string.

    Returns:
        ``True`` if the location should be excluded from entropy checks.
    """
    location_lower = location.lower()
    return any(skip in location_lower for skip in _ENTROPY_SKIP_LOCATION_SUBSTRINGS)
