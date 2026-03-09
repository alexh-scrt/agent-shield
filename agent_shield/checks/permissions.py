"""Excessive permissions vulnerability checks for agent_shield.

This module implements detection rules for overly broad or insecure permission
scopes in agent configuration files and tool definitions. It checks for:

- Wildcard resource permissions (EP-001)
- Destructive action permissions without confirmation gates (EP-002)
- Overly broad OAuth or API scopes (EP-003)
- Filesystem access outside expected working directory (EP-004)
- Missing scope constraints on tool permissions (EP-005)
- Network egress permissions without an allowlist (EP-006)

Each check function accepts an :class:`~agent_shield.models.AgentConfig` and
returns a list of :class:`~agent_shield.models.Finding` objects.

Usage::

    from agent_shield.checks.permissions import check_permissions
    from agent_shield.loader import load_config
    from pathlib import Path

    config = load_config(Path("agent.json"))
    findings = check_permissions(config)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from agent_shield.models import AgentConfig, Finding
from agent_shield.rules import get_rule

# ---------------------------------------------------------------------------
# EP-001: Wildcard resource permission patterns
# ---------------------------------------------------------------------------

#: Keys that commonly hold permission / scope / resource specifications.
_PERMISSION_KEYS: tuple[str, ...] = (
    "permissions",
    "permission",
    "scopes",
    "scope",
    "access",
    "resources",
    "resource",
    "actions",
    "action",
    "grants",
    "grant",
    "roles",
    "role",
    "capabilities",
    "capability",
    "allowed",
    "allow",
    "rights",
    "privilege",
    "privileges",
)

#: Patterns that indicate wildcard / catch-all resource specifications.
_WILDCARD_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?<![A-Za-z0-9_])\*(?![A-Za-z0-9_])"),          # bare *
    re.compile(r"\*:\*"),                                          # *:*
    re.compile(r"\*\.\*"),                                         # *.*
    re.compile(r"all\s+resources?", re.IGNORECASE),                # all resources
    re.compile(r"(?:^|[^A-Za-z])any\s+resource", re.IGNORECASE),  # any resource
    re.compile(r"arn:\*"),                                         # AWS ARN wildcard
    re.compile(r"arn:aws:[a-z0-9*]+:\*"),                          # AWS ARN region wildcard
    re.compile(r"arn:aws:[a-z0-9*]+:[a-z0-9\-]*:\*"),             # AWS ARN account wildcard
    re.compile(r"projects/\*/", re.IGNORECASE),                    # GCP project wildcard
    re.compile(r"subscriptions/\*/", re.IGNORECASE),               # Azure subscription wildcard
    re.compile(r"//\*$"),                                          # trailing //
    re.compile(r"^\*$"),                                           # exactly "*"
]

# ---------------------------------------------------------------------------
# EP-002: Destructive action permission patterns
# ---------------------------------------------------------------------------

#: Keywords identifying destructive / irreversible operations.
_DESTRUCTIVE_ACTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bdelete\b", re.IGNORECASE),
    re.compile(r"\bdrop\b", re.IGNORECASE),
    re.compile(r"\bdestroy\b", re.IGNORECASE),
    re.compile(r"\bpurge\b", re.IGNORECASE),
    re.compile(r"\bwipe\b", re.IGNORECASE),
    re.compile(r"\bterminate\b", re.IGNORECASE),
    re.compile(r"\bremove\b", re.IGNORECASE),
    re.compile(r"\berase\b", re.IGNORECASE),
    re.compile(r"\btruncate\b", re.IGNORECASE),
    re.compile(r"\bformat\b", re.IGNORECASE),
    re.compile(r"\bdecommission\b", re.IGNORECASE),
    re.compile(r"\bkill\b", re.IGNORECASE),
    re.compile(r"\bshutdown\b", re.IGNORECASE),
    re.compile(r"\bdeactivate\b", re.IGNORECASE),
    re.compile(r"\bdisable\b", re.IGNORECASE),
    re.compile(r"\bforce[_\-]?delete\b", re.IGNORECASE),
    re.compile(r"\bhard[_\-]?delete\b", re.IGNORECASE),
    re.compile(r"\bpermanent[_\-]?delete\b", re.IGNORECASE),
    re.compile(r"\bobliterate\b", re.IGNORECASE),
    re.compile(r"\bclean(?:up)?\b", re.IGNORECASE),
]

#: Patterns that suggest a human-in-the-loop confirmation is in place.
_CONFIRMATION_GATE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"confirm", re.IGNORECASE),
    re.compile(r"approval", re.IGNORECASE),
    re.compile(r"approve", re.IGNORECASE),
    re.compile(r"human[_\-]?in[_\-]?the[_\-]?loop", re.IGNORECASE),
    re.compile(r"hitl", re.IGNORECASE),
    re.compile(r"review[_\-]?required", re.IGNORECASE),
    re.compile(r"manual[_\-]?approval", re.IGNORECASE),
    re.compile(r"require[sd]?[_\s]+(approval|confirmation|review)", re.IGNORECASE),
    re.compile(r"two[_\-]?(?:step|phase|factor)[_\-]?(?:auth|approval|confirm)", re.IGNORECASE),
    re.compile(r"user[_\s]+must[_\s]+confirm", re.IGNORECASE),
    re.compile(r"await[_\s]+(?:confirmation|approval|review)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# EP-003: Overly broad OAuth / API scope patterns
# ---------------------------------------------------------------------------

_BROAD_SCOPE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("read:all scope", re.compile(r"\bread:all\b", re.IGNORECASE)),
    ("write:all scope", re.compile(r"\bwrite:all\b", re.IGNORECASE)),
    ("admin scope", re.compile(r"\badmin\b", re.IGNORECASE)),
    ("superuser scope", re.compile(r"\bsuperuser\b", re.IGNORECASE)),
    ("root scope", re.compile(r"(?:^|\s|[""'\[,])root(?:$|\s|[""'\],])", re.IGNORECASE)),
    ("full_access scope", re.compile(r"\bfull[_\-]?access\b", re.IGNORECASE)),
    ("all:* scope", re.compile(r"\ball:\*\b", re.IGNORECASE)),
    ("*:all scope", re.compile(r"\*:all\b", re.IGNORECASE)),
    ("owner permission level", re.compile(r"\bowner\b", re.IGNORECASE)),
    ("global scope", re.compile(r"\bglobal\b", re.IGNORECASE)),
    ("unrestricted scope", re.compile(r"\bunrestricted\b", re.IGNORECASE)),
    ("unlimited scope", re.compile(r"\bunlimited\b", re.IGNORECASE)),
    # GitHub broad scopes
    ("GitHub repo scope (broad)", re.compile(r"[""']repo[""']", re.IGNORECASE)),
    ("GitHub admin:org scope", re.compile(r"\badmin:org\b", re.IGNORECASE)),
    ("GitHub delete_repo scope", re.compile(r"\bdelete_repo\b", re.IGNORECASE)),
    # Google broad scopes
    ("Google Cloud Platform full scope", re.compile(r"https://www\.googleapis\.com/auth/cloud-platform", re.IGNORECASE)),
    ("Google Drive full access scope", re.compile(r"https://www\.googleapis\.com/auth/drive(?!\.(readonly|file|metadata|appdata|scripts|install|activity))", re.IGNORECASE)),
    # AWS managed policies that are overly broad
    ("AWS AdministratorAccess policy", re.compile(r"AdministratorAccess", re.IGNORECASE)),
    ("AWS PowerUserAccess policy", re.compile(r"PowerUserAccess", re.IGNORECASE)),
    ("AWS IAM FullAccess policy", re.compile(r"IAMFullAccess", re.IGNORECASE)),
    # Catch-all admin/sudo patterns
    ("sudo permission", re.compile(r"\bsudo\b", re.IGNORECASE)),
    ("elevate/escalate privilege", re.compile(r"\b(?:elevate|escalate)[_\-]?privilege\b", re.IGNORECASE)),
    # OpenAI / Anthropic / LLM API full access patterns
    ("Full API access scope", re.compile(r"\bapi:full\b", re.IGNORECASE)),
    ("all_scopes permission", re.compile(r"\ball[_\-]?scopes?\b", re.IGNORECASE)),
]

# ---------------------------------------------------------------------------
# EP-004: Filesystem access outside expected working directory
# ---------------------------------------------------------------------------

#: Patterns matching paths that suggest broad filesystem access.
_FILESYSTEM_BROAD_PATH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Unix root path", re.compile(r"(?:^|['",\s])/(etc|var|usr|bin|sbin|lib|proc|sys|dev|tmp|boot|root|home)(?:/|$)", re.IGNORECASE)),
    ("Home directory reference", re.compile(r"~/?[A-Za-z0-9_./]*", re.IGNORECASE)),
    ("Windows system path", re.compile(r"[Cc]:\\(?:Windows|System32|Program Files|Users|ProgramData)", re.IGNORECASE)),
    ("Absolute Unix path in tool arg", re.compile(r"(?:^|['",\[\s])/(?:[A-Za-z0-9_\-.]+/){2,}", re.IGNORECASE)),
    ("Path traversal sequence", re.compile(r"\.\.[\\/]", re.IGNORECASE)),
    ("Sensitive file reference", re.compile(r"(?:/etc/passwd|/etc/shadow|/etc/sudoers|\.ssh/(?:id_rsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts)|\.aws/credentials|\.env(?:\.local)?)", re.IGNORECASE)),
    ("Network filesystem path", re.compile(r"//[A-Za-z0-9_\-.]+/[A-Za-z0-9_\-.]+", re.IGNORECASE)),
]

#: Keys within tool definitions that are likely to contain filesystem paths.
_FILESYSTEM_TOOL_KEYS: tuple[str, ...] = (
    "path",
    "file_path",
    "filepath",
    "directory",
    "dir",
    "folder",
    "root",
    "base_path",
    "base_dir",
    "working_dir",
    "working_directory",
    "home",
    "mount",
    "volume",
    "args",
    "arguments",
    "params",
    "parameters",
)

# ---------------------------------------------------------------------------
# EP-005: Missing scope constraints on tool permissions
# ---------------------------------------------------------------------------

#: Keys within tool/permission entries whose presence indicates scoping.
_SCOPE_CONSTRAINT_KEYS: tuple[str, ...] = (
    "resource",
    "resources",
    "scope",
    "scopes",
    "condition",
    "conditions",
    "constraint",
    "constraints",
    "target",
    "targets",
    "arn",
    "path",
    "filter",
    "filters",
    "policy",
    "limit",
    "limits",
    "allowed_paths",
    "allowed_hosts",
    "allowed_urls",
)

#: Keys that indicate an action/permission is declared without a resource scope.
_ACTION_KEYS: tuple[str, ...] = (
    "actions",
    "action",
    "permissions",
    "permission",
    "allow",
    "allowed",
    "grants",
    "grant",
    "methods",
    "method",
    "operations",
    "operation",
    "verbs",
    "verb",
    "access",
)

# ---------------------------------------------------------------------------
# EP-006: Network egress without allowlist
# ---------------------------------------------------------------------------

#: Keywords in tool names / descriptions indicating network egress capability.
_NETWORK_EGRESS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bhttp[_\-]?(?:request|call|fetch|get|post|put|delete|client)\b", re.IGNORECASE),
    re.compile(r"\bweb[_\-]?(?:request|fetch|scrape|scraper|hook)\b", re.IGNORECASE),
    re.compile(r"\bfetch[_\-]?(?:url|page|content|data)\b", re.IGNORECASE),
    re.compile(r"\bcurl\b", re.IGNORECASE),
    re.compile(r"\bwget\b", re.IGNORECASE),
    re.compile(r"\boutbound[_\-]?(?:request|http|network|connection)\b", re.IGNORECASE),
    re.compile(r"\bexternal[_\-]?(?:api|request|call|http)\b", re.IGNORECASE),
    re.compile(r"\bapi[_\-]?(?:request|call|client)\b", re.IGNORECASE),
    re.compile(r"\bsend[_\-]?(?:request|http|email|message)\b", re.IGNORECASE),
    re.compile(r"\bwebhook\b", re.IGNORECASE),
    re.compile(r"\bnetwork[_\-]?(?:access|egress|request|call)\b", re.IGNORECASE),
    re.compile(r"\btcp[_\-]?(?:connect|client|socket)\b", re.IGNORECASE),
    re.compile(r"\bsocket[_\-]?(?:connect|client)\b", re.IGNORECASE),
    re.compile(r"\bproxy\b", re.IGNORECASE),
    re.compile(r"\bdownload\b", re.IGNORECASE),
    re.compile(r"\bupload\b", re.IGNORECASE),
    re.compile(r"\binternet[_\-]?(?:access|connection|request)\b", re.IGNORECASE),
    # MCP server commands that imply network access
    re.compile(r"\bserver[_\-]?(?:fetch|http|browser|playwright|puppeteer)\b", re.IGNORECASE),
]

#: Patterns that suggest an allowlist is defined for network egress.
_NETWORK_ALLOWLIST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"allowed[_\-]?(?:hosts?|urls?|domains?|origins?|endpoints?|destinations?)", re.IGNORECASE),
    re.compile(r"(?:host|url|domain|origin|endpoint)[_\-]?allowlist", re.IGNORECASE),
    re.compile(r"(?:host|url|domain|origin|endpoint)[_\-]?whitelist", re.IGNORECASE),
    re.compile(r"permitted[_\-]?(?:hosts?|urls?|domains?|origins?|endpoints?)", re.IGNORECASE),
    re.compile(r"egress[_\-]?(?:allowlist|whitelist|filter|policy|rules?)", re.IGNORECASE),
    re.compile(r"url[_\-]?filter", re.IGNORECASE),
    re.compile(r"domain[_\-]?filter", re.IGNORECASE),
    re.compile(r"network[_\-]?policy", re.IGNORECASE),
    re.compile(r"outbound[_\-]?(?:allowlist|whitelist|filter|policy|rules?)", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_permissions(config: AgentConfig) -> list[Finding]:
    """Run all excessive permissions checks against an agent configuration.

    This is the main entry point for the permissions check module. It
    dispatches to all individual check functions and aggregates the results.

    Args:
        config: The normalised agent configuration to check.

    Returns:
        List of :class:`~agent_shield.models.Finding` objects, possibly empty.
    """
    findings: list[Finding] = []
    findings.extend(_check_wildcard_permissions(config))
    findings.extend(_check_destructive_permissions(config))
    findings.extend(_check_broad_oauth_scopes(config))
    findings.extend(_check_filesystem_access(config))
    findings.extend(_check_missing_scope_constraints(config))
    findings.extend(_check_network_egress_without_allowlist(config))
    return findings


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------


def _check_wildcard_permissions(config: AgentConfig) -> list[Finding]:
    """EP-001: Detect wildcard resource permissions.

    Searches permission-related fields in the configuration data for wildcard
    resource specifications that violate the principle of least privilege.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected wildcard permission.
    """
    rule = get_rule("EP-001")
    findings: list[Finding] = []
    seen: set[str] = set()

    # Scan structured data for wildcard permissions in permission-related keys
    _walk_permission_values(config.data, "", rule, config, seen, findings, _WILDCARD_PATTERNS)

    # Also check tool definitions specifically
    for idx, tool in enumerate(config.tools):
        tool_name = tool.get("name", f"tool[{idx}]")
        _walk_permission_values(
            tool, f"tools[{idx}]", rule, config, seen, findings, _WILDCARD_PATTERNS,
            permission_key_only=True,
        )

    # Check raw text for common IAM wildcard patterns
    for pattern in _WILDCARD_PATTERNS:
        for match in pattern.finditer(config.raw_text):
            evidence = _extract_context(config.raw_text, match.start(), match.end())
            key = f"raw_text:{evidence[:60]}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule=rule,
                    file_path=config.source_path,
                    location="raw_text",
                    evidence=evidence,
                    detail=f"Wildcard resource pattern matched: {pattern.pattern!r}",
                )
            )

    return findings


def _check_destructive_permissions(config: AgentConfig) -> list[Finding]:
    """EP-002: Detect destructive action permissions without confirmation gates.

    Identifies tool configurations that grant destructive operations (delete,
    destroy, purge, etc.) without any evident human-in-the-loop confirmation
    step or approval workflow.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected unguarded destructive permission.
    """
    rule = get_rule("EP-002")
    findings: list[Finding] = []
    seen: set[str] = set()

    # Determine if any confirmation gate exists in the overall config
    config_text = config.raw_text
    has_global_confirmation = _has_confirmation_gate(config_text)

    def _scan_text_for_destructive(
        text: str,
        location: str,
        local_confirmation: bool,
    ) -> None:
        if local_confirmation or has_global_confirmation:
            return
        for pattern in _DESTRUCTIVE_ACTION_PATTERNS:
            for match in pattern.finditer(text):
                evidence = _extract_context(text, match.start(), match.end())
                key = f"{location}:{evidence[:60].lower()}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=evidence,
                        detail=(
                            f"Destructive action '{match.group(0)}' detected without "
                            "an evident confirmation gate or approval workflow."
                        ),
                    )
                )

    # Check tool definitions
    for idx, tool in enumerate(config.tools):
        tool_name = tool.get("name", f"tool[{idx}]")
        location = f"tools[{idx}] ({tool_name})"
        tool_text = _tool_to_text(tool)
        local_confirmation = _has_confirmation_gate(tool_text)
        _scan_text_for_destructive(tool_text, location, local_confirmation)

    # Check permission-related sections of structured data
    for location, value in config.get_all_string_values():
        leaf_key = _get_leaf_key(location)
        if leaf_key.lower() in {k.lower() for k in _PERMISSION_KEYS}:
            _scan_text_for_destructive(value, location, _has_confirmation_gate(value))

    # Check system prompt for destructive instructions without confirmation
    if config.system_prompt:
        _scan_text_for_destructive(
            config.system_prompt,
            "system_prompt",
            _has_confirmation_gate(config.system_prompt),
        )

    return findings


def _check_broad_oauth_scopes(config: AgentConfig) -> list[Finding]:
    """EP-003: Detect overly broad OAuth or API permission scopes.

    Identifies permission scope values that grant far more access than typical
    agent workflows require, such as 'admin', 'write:all', 'full_access', etc.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected broad scope.
    """
    rule = get_rule("EP-003")
    findings: list[Finding] = []
    seen: set[str] = set()

    # Scan all string values and permission-related fields
    for location, value in config.get_all_string_values():
        leaf_key = _get_leaf_key(location)
        # Focus on permission-related locations, but also scan all short strings
        # that could be OAuth scope values
        is_permission_field = leaf_key.lower() in {k.lower() for k in _PERMISSION_KEYS}
        is_short_value = len(value.strip()) < 200  # likely a scope token, not prose

        if not is_permission_field and not is_short_value:
            continue

        for label, pattern in _BROAD_SCOPE_PATTERNS:
            for match in pattern.finditer(value):
                evidence = _extract_context(value, match.start(), match.end())
                key = f"{location}:{label}:{evidence[:40].lower()}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=evidence,
                        detail=f"Broad permission scope detected: {label}",
                    )
                )

    # Also scan tool permission lists in structured tool configs
    for idx, tool in enumerate(config.tools):
        tool_name = tool.get("name", f"tool[{idx}]")
        tool_text = _tool_to_text(tool)
        for label, pattern in _BROAD_SCOPE_PATTERNS:
            for match in pattern.finditer(tool_text):
                evidence = _extract_context(tool_text, match.start(), match.end())
                location = f"tools[{idx}] ({tool_name})"
                key = f"{location}:{label}:{evidence[:40].lower()}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=evidence,
                        detail=f"Broad permission scope detected in tool definition: {label}",
                    )
                )

    return findings


def _check_filesystem_access(config: AgentConfig) -> list[Finding]:
    """EP-004: Detect filesystem access outside expected working directory.

    Flags tool configurations and permission entries that grant or imply
    filesystem access to paths outside a bounded working directory, such as
    system directories, home directories, or absolute paths.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected broad filesystem access pattern.
    """
    rule = get_rule("EP-004")
    findings: list[Finding] = []
    seen: set[str] = set()

    # Check tool definitions — focus on path-like arguments
    for idx, tool in enumerate(config.tools):
        tool_name = tool.get("name", f"tool[{idx}]")
        location_prefix = f"tools[{idx}] ({tool_name})"

        # Flatten the tool dict to check all values
        for key, value in _flatten_dict(tool):
            if not isinstance(value, str) or not value.strip():
                continue
            leaf_key = _get_leaf_key(key)
            # Check filesystem-related keys and any string value that looks like a path
            if leaf_key.lower() not in {k.lower() for k in _FILESYSTEM_TOOL_KEYS} and not _looks_like_path(value):
                continue
            for label, pattern in _FILESYSTEM_BROAD_PATH_PATTERNS:
                for match in pattern.finditer(value):
                    evidence = _extract_context(value, match.start(), match.end())
                    full_location = f"{location_prefix}.{key}" if key else location_prefix
                    finding_key = f"{full_location}:{label}:{evidence[:40].lower()}"
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)
                    findings.append(
                        Finding(
                            rule=rule,
                            file_path=config.source_path,
                            location=full_location,
                            evidence=evidence,
                            detail=(
                                f"Broad filesystem path pattern detected ({label}). "
                                "Access should be restricted to an approved working directory."
                            ),
                        )
                    )

    # Also scan all string values in the full config
    for location, value in config.get_all_string_values():
        if not _looks_like_path(value) and not any(
            _get_leaf_key(location).lower() == k.lower() for k in _FILESYSTEM_TOOL_KEYS
        ):
            continue
        for label, pattern in _FILESYSTEM_BROAD_PATH_PATTERNS:
            for match in pattern.finditer(value):
                evidence = _extract_context(value, match.start(), match.end())
                finding_key = f"{location}:{label}:{evidence[:40].lower()}"
                if finding_key in seen:
                    continue
                seen.add(finding_key)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=evidence,
                        detail=(
                            f"Broad filesystem path pattern detected ({label}). "
                            "Access should be restricted to an approved working directory."
                        ),
                    )
                )

    return findings


def _check_missing_scope_constraints(config: AgentConfig) -> list[Finding]:
    """EP-005: Detect tool permissions without explicit scope constraints.

    Identifies tool or permission entries that declare an action/permission
    but do not specify an explicit resource scope, condition, or constraint.
    An unconstrained permission may grant broader access than intended.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each permission entry missing a scope.
    """
    rule = get_rule("EP-005")
    findings: list[Finding] = []
    seen: set[str] = set()

    # Check tool definitions
    for idx, tool in enumerate(config.tools):
        tool_name = tool.get("name", f"tool[{idx}]")
        location = f"tools[{idx}] ({tool_name})"

        _check_permission_entry_for_scope(
            entry=tool,
            location=location,
            rule=rule,
            config=config,
            seen=seen,
            findings=findings,
        )

    # Check top-level permission/scope sections in data
    if isinstance(config.data, dict):
        for perm_key in _PERMISSION_KEYS:
            perm_value = config.data.get(perm_key)
            if isinstance(perm_value, list):
                for item_idx, item in enumerate(perm_value):
                    if isinstance(item, dict):
                        _check_permission_entry_for_scope(
                            entry=item,
                            location=f"{perm_key}[{item_idx}]",
                            rule=rule,
                            config=config,
                            seen=seen,
                            findings=findings,
                        )
                    elif isinstance(item, str):
                        # Plain string permission without any structure
                        finding_key = f"{perm_key}[{item_idx}]:{item[:30]}"
                        if finding_key not in seen:
                            seen.add(finding_key)
                            findings.append(
                                Finding(
                                    rule=rule,
                                    file_path=config.source_path,
                                    location=f"{perm_key}[{item_idx}]",
                                    evidence=item[:80],
                                    detail=(
                                        f"Permission '{item}' is declared without any resource "
                                        "scope, condition, or constraint."
                                    ),
                                )
                            )
            elif isinstance(perm_value, dict):
                _check_permission_entry_for_scope(
                    entry=perm_value,
                    location=perm_key,
                    rule=rule,
                    config=config,
                    seen=seen,
                    findings=findings,
                )

    return findings


def _check_network_egress_without_allowlist(config: AgentConfig) -> list[Finding]:
    """EP-006: Detect network egress permissions without an allowlist.

    Identifies tool configurations that enable outbound HTTP/TCP connections
    without a defined allowlist of permitted destination hosts, URLs, or
    domains, which could enable data exfiltration or SSRF.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each network-capable tool without an allowlist.
    """
    rule = get_rule("EP-006")
    findings: list[Finding] = []
    seen: set[str] = set()

    # Check if a global egress allowlist is defined anywhere in the config
    global_allowlist = _has_egress_allowlist(config.raw_text)

    if global_allowlist:
        # A global allowlist is defined — no findings needed
        return findings

    # Check individual tool definitions for network egress capabilities
    for idx, tool in enumerate(config.tools):
        tool_name = tool.get("name", f"tool[{idx}]")
        tool_text = _tool_to_text(tool)
        location = f"tools[{idx}] ({tool_name})"

        # Check if this specific tool has a local allowlist
        tool_allowlist = _has_egress_allowlist(tool_text)
        if tool_allowlist:
            continue

        for pattern in _NETWORK_EGRESS_PATTERNS:
            match = pattern.search(tool_text)
            if match:
                evidence = _extract_context(tool_text, match.start(), match.end())
                key = f"{location}:{evidence[:40].lower()}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=evidence,
                        detail=(
                            f"Tool '{tool_name}' appears to have network egress capability "
                            "but no allowlist of permitted destinations is defined. "
                            "Unrestricted outbound access enables SSRF and data exfiltration."
                        ),
                    )
                )
                break  # One finding per tool for network egress is sufficient

    # Also check system prompt for instructions granting unrestricted network access
    if config.system_prompt and not _has_egress_allowlist(config.system_prompt):
        for pattern in _NETWORK_EGRESS_PATTERNS:
            match = pattern.search(config.system_prompt)
            if match:
                evidence = _extract_context(
                    config.system_prompt, match.start(), match.end()
                )
                key = f"system_prompt:{evidence[:40].lower()}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        Finding(
                            rule=rule,
                            file_path=config.source_path,
                            location="system_prompt",
                            evidence=evidence,
                            detail=(
                                "System prompt grants or implies network egress capability "
                                "without a defined allowlist of permitted destinations."
                            ),
                        )
                    )
                break

    return findings


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _walk_permission_values(
    data: Any,
    path: str,
    rule: Any,
    config: AgentConfig,
    seen: set[str],
    findings: list[Finding],
    patterns: list[re.Pattern[str]],
    permission_key_only: bool = False,
) -> None:
    """Recursively walk a data structure and scan permission-related values.

    Args:
        data: Current node to traverse.
        path: Dot-separated path accumulated so far.
        rule: The Rule to associate with any findings.
        config: Source AgentConfig (for file_path metadata).
        seen: Set of deduplicated evidence keys already reported.
        findings: Accumulator list for findings.
        patterns: List of compiled regex patterns to test against.
        permission_key_only: If True, only scan nodes whose key is a
            recognised permission key name.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            child_path = f"{path}.{key}" if path else key
            is_permission_key = key.lower() in {k.lower() for k in _PERMISSION_KEYS}

            if isinstance(value, str):
                if permission_key_only and not is_permission_key:
                    # Recurse but don't scan non-permission keys in this mode
                    pass
                else:
                    _scan_value_with_patterns(
                        value=value,
                        location=child_path,
                        rule=rule,
                        config=config,
                        seen=seen,
                        findings=findings,
                        patterns=patterns,
                    )
            elif isinstance(value, (dict, list)):
                _walk_permission_values(
                    value, child_path, rule, config, seen, findings, patterns,
                    permission_key_only=permission_key_only,
                )
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            child_path = f"{path}[{idx}]"
            if isinstance(item, str):
                _scan_value_with_patterns(
                    value=item,
                    location=child_path,
                    rule=rule,
                    config=config,
                    seen=seen,
                    findings=findings,
                    patterns=patterns,
                )
            elif isinstance(item, (dict, list)):
                _walk_permission_values(
                    item, child_path, rule, config, seen, findings, patterns,
                    permission_key_only=permission_key_only,
                )
    elif isinstance(data, str):
        _scan_value_with_patterns(
            value=data,
            location=path,
            rule=rule,
            config=config,
            seen=seen,
            findings=findings,
            patterns=patterns,
        )


def _scan_value_with_patterns(
    value: str,
    location: str,
    rule: Any,
    config: AgentConfig,
    seen: set[str],
    findings: list[Finding],
    patterns: list[re.Pattern[str]],
) -> None:
    """Scan a single string value against a list of patterns and record findings.

    Args:
        value: The string value to scan.
        location: Human-readable location path for reporting.
        rule: The Rule to associate with findings.
        config: Source AgentConfig.
        seen: Deduplication set.
        findings: Accumulator list.
        patterns: Compiled patterns to test.
    """
    for pattern in patterns:
        for match in pattern.finditer(value):
            evidence = _extract_context(value, match.start(), match.end())
            key = f"{location}:{evidence[:60].lower()}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule=rule,
                    file_path=config.source_path,
                    location=location,
                    evidence=evidence,
                    detail=f"Pattern matched: {pattern.pattern!r}",
                )
            )


def _check_permission_entry_for_scope(
    entry: dict[str, Any],
    location: str,
    rule: Any,
    config: AgentConfig,
    seen: set[str],
    findings: list[Finding],
) -> None:
    """Check a single permission/tool dict entry for missing scope constraints.

    A finding is generated when the entry has an action/permission key but
    no corresponding scope/resource/constraint key.

    Args:
        entry: Dictionary representing a permission or tool entry.
        location: Location path string for reporting.
        rule: The Rule to associate with findings.
        config: Source AgentConfig.
        seen: Deduplication set.
        findings: Accumulator list.
    """
    entry_keys_lower = {k.lower() for k in entry.keys()}

    # Determine if an action is declared
    has_action = any(k in entry_keys_lower for k in {a.lower() for a in _ACTION_KEYS})
    if not has_action:
        return

    # Determine if a scope/constraint is declared
    has_scope = any(k in entry_keys_lower for k in {s.lower() for s in _SCOPE_CONSTRAINT_KEYS})
    if has_scope:
        return

    # Build a summary of the action values for the evidence field
    action_values: list[str] = []
    for action_key in _ACTION_KEYS:
        for k, v in entry.items():
            if k.lower() == action_key.lower():
                if isinstance(v, str):
                    action_values.append(v)
                elif isinstance(v, list):
                    action_values.extend(str(item) for item in v if isinstance(item, str))

    evidence = ", ".join(action_values[:5]) or str(list(entry.keys())[:5])
    finding_key = f"{location}:{evidence[:40].lower()}"
    if finding_key in seen:
        return
    seen.add(finding_key)

    findings.append(
        Finding(
            rule=rule,
            file_path=config.source_path,
            location=location,
            evidence=evidence[:100],
            detail=(
                "Permission entry declares an action but has no explicit resource scope, "
                "condition, or constraint. The effective permission scope may be broader "
                "than intended."
            ),
        )
    )


def _has_confirmation_gate(text: str) -> bool:
    """Return True if the text contains evidence of a confirmation / approval gate.

    Args:
        text: Text to search for confirmation gate patterns.

    Returns:
        ``True`` if any confirmation gate pattern is found.
    """
    return any(pattern.search(text) for pattern in _CONFIRMATION_GATE_PATTERNS)


def _has_egress_allowlist(text: str) -> bool:
    """Return True if the text contains evidence of a network egress allowlist.

    Args:
        text: Text to search for allowlist patterns.

    Returns:
        ``True`` if any allowlist pattern is found.
    """
    return any(pattern.search(text) for pattern in _NETWORK_ALLOWLIST_PATTERNS)


def _tool_to_text(tool: dict[str, Any]) -> str:
    """Convert a tool definition dict to a flat text representation for scanning.

    Concatenates all string values found recursively in the tool dict.

    Args:
        tool: Tool definition dictionary.

    Returns:
        Concatenated string representation of the tool.
    """
    parts: list[str] = []

    def _collect(node: Any) -> None:
        if isinstance(node, str):
            parts.append(node)
        elif isinstance(node, dict):
            for k, v in node.items():
                parts.append(str(k))
                _collect(v)
        elif isinstance(node, list):
            for item in node:
                _collect(item)
        elif node is not None:
            parts.append(str(node))

    _collect(tool)
    return " ".join(parts)


def _flatten_dict(
    data: dict[str, Any],
    prefix: str = "",
) -> list[tuple[str, Any]]:
    """Flatten a nested dictionary into a list of (dot-path, value) tuples.

    Args:
        data: Dictionary to flatten.
        prefix: Path prefix accumulated so far.

    Returns:
        List of ``(path, value)`` tuples for all leaf values.
    """
    results: list[tuple[str, Any]] = []
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            results.extend(_flatten_dict(value, prefix=path))
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                item_path = f"{path}[{idx}]"
                if isinstance(item, dict):
                    results.extend(_flatten_dict(item, prefix=item_path))
                else:
                    results.append((item_path, item))
        else:
            results.append((path, value))
    return results


def _looks_like_path(value: str) -> bool:
    """Return True if a string value looks like a filesystem path.

    Args:
        value: String to test.

    Returns:
        ``True`` if the value resembles a filesystem path.
    """
    stripped = value.strip()
    if not stripped:
        return False
    # Absolute Unix paths
    if stripped.startswith("/") or stripped.startswith("~/"):
        return True
    # Relative paths with directory separators
    if re.search(r"(?:^|\s)\.{1,2}[\\/]", stripped):
        return True
    # Windows paths
    if re.match(r"[A-Za-z]:\\\\", stripped):
        return True
    # Paths containing multiple slashes (URL-like strings are excluded separately)
    if stripped.count("/") >= 2 and not stripped.startswith(("http://", "https://", "ftp://")):
        return True
    return False


def _get_leaf_key(location: str) -> str:
    """Extract the leaf key name from a dotted location path.

    For example, ``"agent.tools[0].permissions"`` → ``"permissions"``.

    Args:
        location: Dot-separated path string.

    Returns:
        The leaf key name, stripped of array index suffixes.
    """
    if not location:
        return ""
    # Strip trailing array index like [0]
    cleaned = re.sub(r"\[\d+\]$", "", location)
    parts = cleaned.rsplit(".", 1)
    leaf = parts[-1] if parts else ""
    # Remove any remaining array indices
    leaf = re.sub(r"\[\d+\]", "", leaf)
    return leaf.strip()


def _extract_context(text: str, start: int, end: int, max_len: int = 120) -> str:
    """Extract a context window around a regex match for use as evidence.

    Returns up to ``max_len`` characters centred around the matched region,
    with leading/trailing ellipsis when the text is truncated.

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
    if len(result) > max_len + 6:
        result = result[:max_len] + "..."
    return result
