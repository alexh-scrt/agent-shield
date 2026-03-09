"""Rule registry for agent_shield.

Defines all built-in detection rules as Rule dataclass instances, organised by
category. Each rule has a unique ID, severity level, human-readable title and
description, and concrete remediation advice.

Rule ID format: <CATEGORY_PREFIX>-<NNN>
  PI  - Prompt Injection
  SL  - Secret Leakage
  EP  - Excessive Permissions
  TS  - Tool Schema

Usage::

    from agent_shield.rules import RULES, get_rule, rules_by_category

    # All rules as a dict keyed by rule_id
    for rule_id, rule in RULES.items():
        print(rule.rule_id, rule.severity)

    # Look up a single rule
    rule = get_rule("PI-001")

    # All rules in a specific category
    pi_rules = rules_by_category("prompt_injection")
"""

from __future__ import annotations

from typing import Iterator

from agent_shield.models import Rule, Severity

# ---------------------------------------------------------------------------
# Prompt Injection rules  (PI-xxx)
# ---------------------------------------------------------------------------

_PI_RULES: list[Rule] = [
    Rule(
        rule_id="PI-001",
        severity=Severity.CRITICAL,
        title="Role Override Instruction Detected",
        description=(
            "The system prompt contains phrases that attempt to override the model's "
            "role, identity, or core instructions (e.g. 'ignore all previous "
            "instructions', 'disregard your system prompt', 'you are now DAN'). "
            "These are classic prompt injection vectors that can cause the model to "
            "abandon its intended behaviour and follow attacker-supplied instructions."
        ),
        remediation=(
            "Remove or sanitise any user-controlled content that is concatenated "
            "directly into the system prompt. Apply an allowlist of permitted "
            "instructions and validate all dynamic content before interpolation. "
            "Consider using a separate untrusted-input channel rather than embedding "
            "user data in the system prompt."
        ),
        category="prompt_injection",
    ),
    Rule(
        rule_id="PI-002",
        severity=Severity.HIGH,
        title="Instruction Smuggling Pattern Detected",
        description=(
            "The configuration contains patterns commonly used to smuggle hidden "
            "instructions into prompts, such as invisible Unicode characters, "
            "HTML/XML comment blocks, base64-encoded payloads, or whitespace "
            "padding designed to push content off-screen. Attackers use these "
            "techniques to inject instructions that appear invisible to human "
            "reviewers but are processed by the model."
        ),
        remediation=(
            "Strip or reject content containing invisible Unicode (e.g. zero-width "
            "spaces, soft hyphens), HTML/XML comments, and suspicious base64 blobs "
            "before they reach the prompt. Implement a content normalisation step "
            "that makes hidden characters visible during review."
        ),
        category="prompt_injection",
    ),
    Rule(
        rule_id="PI-003",
        severity=Severity.HIGH,
        title="Jailbreak Template Detected",
        description=(
            "The system prompt contains well-known jailbreak template phrases such as "
            "'DAN mode', 'Developer Mode', 'Do Anything Now', 'grandma exploit', or "
            "similar patterns that attempt to unlock unrestricted model behaviour. "
            "These templates are frequently shared in adversarial communities and can "
            "cause models to bypass safety guidelines."
        ),
        remediation=(
            "Audit the system prompt for jailbreak template language and remove it. "
            "If the prompt was sourced from a third party or user input, add "
            "pattern-based filtering before the prompt is sent to the model. "
            "Consider periodic automated scanning of prompt templates in your CI/CD "
            "pipeline."
        ),
        category="prompt_injection",
    ),
    Rule(
        rule_id="PI-004",
        severity=Severity.MEDIUM,
        title="Prompt Leakage Instruction Detected",
        description=(
            "The system prompt includes instructions that encourage or allow the model "
            "to reveal its own system prompt, internal instructions, or configuration "
            "to end users (e.g. 'if asked, share your instructions', "
            "'you may reveal your system prompt'). This can expose sensitive business "
            "logic or security controls."
        ),
        remediation=(
            "Remove instructions that permit the model to disclose its configuration. "
            "Explicitly instruct the model to decline requests for its system prompt "
            "and to treat all configuration content as confidential. Validate that no "
            "dynamic content can override this constraint."
        ),
        category="prompt_injection",
    ),
    Rule(
        rule_id="PI-005",
        severity=Severity.MEDIUM,
        title="Indirect Prompt Injection via External Data Reference",
        description=(
            "The configuration instructs the agent to fetch, read, or process content "
            "from external URLs or user-supplied files and incorporate that content "
            "directly into its context without sanitisation. This creates an indirect "
            "prompt injection risk where an attacker controls the external resource "
            "and can inject malicious instructions."
        ),
        remediation=(
            "Never concatenate raw external content directly into the model context. "
            "Summarise or extract structured data from external sources before use, "
            "and treat all externally sourced text as untrusted. Implement a "
            "content-security layer that validates external data before it enters the "
            "prompt pipeline."
        ),
        category="prompt_injection",
    ),
]

# ---------------------------------------------------------------------------
# Secret Leakage rules  (SL-xxx)
# ---------------------------------------------------------------------------

_SL_RULES: list[Rule] = [
    Rule(
        rule_id="SL-001",
        severity=Severity.CRITICAL,
        title="Hardcoded API Key or Secret Token Detected",
        description=(
            "A string matching the pattern of a well-known API key or secret token "
            "(e.g. OpenAI sk-…, AWS AKIA…, GitHub ghp_…, Anthropic sk-ant-…) was "
            "found hardcoded in the agent configuration. Embedding credentials in "
            "config files risks accidental exposure through version control, logs, or "
            "error messages."
        ),
        remediation=(
            "Remove the hardcoded credential immediately and rotate it. Store secrets "
            "in environment variables, a secrets manager (e.g. AWS Secrets Manager, "
            "HashiCorp Vault, GitHub Secrets), or an encrypted configuration backend. "
            "Add the config file to .gitignore and run a secrets scanner (e.g. "
            "truffleHog, gitleaks) as a pre-commit hook."
        ),
        category="secret_leakage",
    ),
    Rule(
        rule_id="SL-002",
        severity=Severity.HIGH,
        title="Generic High-Entropy Secret Detected",
        description=(
            "A high-entropy string consistent with a randomly generated password, "
            "token, or private key was found in the configuration. While not matching "
            "a known credential format, high-entropy strings in config files are "
            "strong indicators of embedded secrets."
        ),
        remediation=(
            "Review the flagged string and confirm whether it is a secret. If so, "
            "remove it from the config and relocate it to a secrets management "
            "solution. Reference the secret via an environment variable placeholder "
            "(e.g. ${MY_SECRET}) instead of a literal value."
        ),
        category="secret_leakage",
    ),
    Rule(
        rule_id="SL-003",
        severity=Severity.HIGH,
        title="Private Key Material Detected",
        description=(
            "PEM-encoded private key material (e.g. RSA, EC, or generic private keys "
            "beginning with '-----BEGIN … PRIVATE KEY-----') was detected in the "
            "configuration. Private keys embedded in config files are extremely high "
            "risk and are frequently leaked through repositories and container images."
        ),
        remediation=(
            "Remove the private key from the configuration immediately. Store private "
            "keys only in dedicated key management systems (e.g. AWS KMS, GCP Cloud "
            "KMS, HashiCorp Vault). Reference keys by identifier, not by value. "
            "Rotate any key that may have been exposed."
        ),
        category="secret_leakage",
    ),
    Rule(
        rule_id="SL-004",
        severity=Severity.HIGH,
        title="Database Connection String with Credentials Detected",
        description=(
            "A database connection string containing embedded credentials was found "
            "(e.g. postgresql://user:password@host/db, "
            "mysql://root:secret@localhost/mydb). Connection strings with credentials "
            "embedded in the URI are a common source of accidental secret exposure."
        ),
        remediation=(
            "Replace the inline credentials with references to environment variables "
            "or a secrets manager. Use connection pooling libraries that accept "
            "separate host/user/password parameters sourced from secure storage "
            "rather than a single credential-bearing URI."
        ),
        category="secret_leakage",
    ),
    Rule(
        rule_id="SL-005",
        severity=Severity.MEDIUM,
        title="Potential Password or Secret in Key-Value Pair",
        description=(
            "A configuration key whose name suggests it holds a credential (e.g. "
            "'password', 'passwd', 'secret', 'api_key', 'access_token', "
            "'client_secret') has a non-empty, non-placeholder value. This may "
            "indicate a hardcoded password or secret rather than an environment "
            "variable reference."
        ),
        remediation=(
            "Verify that no literal secret is stored in this field. Replace any "
            "hardcoded value with an environment variable reference such as "
            "${MY_PASSWORD} or a pointer to a secrets manager path. Treat all "
            "credential-named fields as sensitive regardless of their actual content."
        ),
        category="secret_leakage",
    ),
    Rule(
        rule_id="SL-006",
        severity=Severity.MEDIUM,
        title="Cloud Provider Credential Reference Detected",
        description=(
            "The configuration references cloud provider credential files or "
            "environment variables in a way that suggests credentials may be "
            "baked-in or improperly scoped (e.g. referencing ~/.aws/credentials, "
            "GOOGLE_APPLICATION_CREDENTIALS pointing to a file path, or Azure "
            "client secrets hardcoded in config)."
        ),
        remediation=(
            "Use instance metadata service (IMDS) or workload identity federation "
            "instead of file-based or environment-variable credentials where "
            "possible. Ensure credential files are never bundled into container "
            "images or committed to version control."
        ),
        category="secret_leakage",
    ),
]

# ---------------------------------------------------------------------------
# Excessive Permissions rules  (EP-xxx)
# ---------------------------------------------------------------------------

_EP_RULES: list[Rule] = [
    Rule(
        rule_id="EP-001",
        severity=Severity.HIGH,
        title="Wildcard Resource Permission Detected",
        description=(
            "A tool or permission scope uses a wildcard ('*') to grant access to all "
            "resources of a given type. Wildcard permissions violate the principle of "
            "least privilege and mean the agent can access resources far beyond what "
            "is needed for its intended task."
        ),
        remediation=(
            "Replace wildcard resource specifications with explicit, enumerated "
            "resource identifiers. Scope permissions to only the specific resources "
            "the agent actually requires. Apply attribute-based access control (ABAC) "
            "or resource tagging to enforce fine-grained boundaries."
        ),
        category="permissions",
    ),
    Rule(
        rule_id="EP-002",
        severity=Severity.HIGH,
        title="Destructive Action Permission Without Confirmation Gate",
        description=(
            "The agent is granted permission to perform destructive or irreversible "
            "actions (e.g. delete, drop, destroy, purge, wipe, terminate) without any "
            "indication of a human-in-the-loop confirmation step. Agents with "
            "unguarded destructive permissions pose significant data-loss and "
            "operational risk."
        ),
        remediation=(
            "Require explicit human confirmation before destructive actions are "
            "executed. Implement a two-step approval workflow or use separate "
            "read-only and write/delete permission sets. Log all destructive "
            "operations with full audit trails."
        ),
        category="permissions",
    ),
    Rule(
        rule_id="EP-003",
        severity=Severity.MEDIUM,
        title="Overly Broad OAuth or API Scope Detected",
        description=(
            "The agent requests broad OAuth scopes or API permission categories "
            "(e.g. 'read:all', 'write:all', 'admin', 'superuser', 'root', or "
            "platform-specific catch-all scopes) that provide far more access than "
            "typical agent workflows require."
        ),
        remediation=(
            "Audit the required operations and request only the minimum OAuth scopes "
            "needed. Use scope narrowing features provided by the API platform "
            "(e.g. GitHub fine-grained tokens, Google Cloud IAM conditions). "
            "Periodically review and prune unused scopes."
        ),
        category="permissions",
    ),
    Rule(
        rule_id="EP-004",
        severity=Severity.MEDIUM,
        title="Filesystem Access Outside Expected Working Directory",
        description=(
            "The tool configuration grants or implies filesystem access to paths "
            "outside the expected working directory or sandbox (e.g. absolute paths "
            "to system directories like /etc, /var, C:\\Windows, or home directory "
            "references like ~/). This increases the attack surface for path "
            "traversal and data exfiltration."
        ),
        remediation=(
            "Restrict filesystem tool access to a specific, bounded working directory. "
            "Use chroot jails, container volume mounts, or a virtual filesystem "
            "abstraction layer to enforce path boundaries. Validate and sanitise all "
            "file path arguments before execution."
        ),
        category="permissions",
    ),
    Rule(
        rule_id="EP-005",
        severity=Severity.LOW,
        title="Missing Scope Constraint on Tool Permission",
        description=(
            "A tool definition grants a permission action but does not specify an "
            "explicit resource scope, condition, or constraint. Without scope "
            "constraints, the effective permission may be broader than intended and "
            "could expand unexpectedly when new resources are added."
        ),
        remediation=(
            "Add explicit resource identifiers, conditions, or scope constraints to "
            "every permission entry. Document the intended scope in comments or "
            "metadata so future maintainers do not inadvertently broaden access."
        ),
        category="permissions",
    ),
    Rule(
        rule_id="EP-006",
        severity=Severity.HIGH,
        title="Network Egress Permission Without Allowlist",
        description=(
            "The agent or tool is granted network egress permissions (ability to make "
            "outbound HTTP/TCP connections) without a defined allowlist of permitted "
            "destinations. Unrestricted outbound access enables data exfiltration and "
            "SSRF attack chains."
        ),
        remediation=(
            "Implement an egress allowlist specifying permitted destination hosts, "
            "ports, and protocols. Use an outbound proxy with URL filtering to enforce "
            "the allowlist at runtime. Deny all outbound connections not explicitly "
            "permitted."
        ),
        category="permissions",
    ),
]

# ---------------------------------------------------------------------------
# Tool Schema rules  (TS-xxx)
# ---------------------------------------------------------------------------

_TS_RULES: list[Rule] = [
    Rule(
        rule_id="TS-001",
        severity=Severity.CRITICAL,
        title="Unrestricted Code Execution Tool Detected",
        description=(
            "A tool definition exposes an interface for executing arbitrary code, "
            "shell commands, or system calls (e.g. functions named exec, eval, shell, "
            "run_command, execute_code, subprocess) without any visible sandboxing or "
            "input validation constraints in the schema. This is one of the most "
            "dangerous patterns in agent tool configurations."
        ),
        remediation=(
            "Remove or strictly constrain code execution tools. If code execution is "
            "genuinely required, run it in an isolated, resource-limited sandbox "
            "(e.g. gVisor, Firecracker, a locked-down Docker container). Apply an "
            "allowlist of permitted operations, validate all inputs, and log every "
            "execution with full arguments."
        ),
        category="tool_schema",
    ),
    Rule(
        rule_id="TS-002",
        severity=Severity.HIGH,
        title="SSRF-Prone URL Parameter in Tool Schema",
        description=(
            "A tool schema accepts a URL or endpoint parameter with no format "
            "validation, allowlisting, or protocol restriction. If the agent can "
            "supply arbitrary URLs to this tool, an attacker who controls the "
            "agent's inputs (e.g. via prompt injection) can perform Server-Side "
            "Request Forgery (SSRF) attacks to reach internal services."
        ),
        remediation=(
            "Add a strict format validator or enum constraint to URL parameters, "
            "limiting them to approved origins and HTTPS only. Resolve the URL "
            "server-side and block private IP ranges (RFC 1918, loopback, link-local) "
            "before making any outbound request. Never forward raw user-supplied URLs "
            "without validation."
        ),
        category="tool_schema",
    ),
    Rule(
        rule_id="TS-003",
        severity=Severity.HIGH,
        title="Shell Injection Sink in Tool Parameter",
        description=(
            "A tool parameter name or description suggests that its value is "
            "interpolated directly into a shell command (e.g. parameters named "
            "'command', 'cmd', 'shell_args', 'script', 'query' passed to a shell "
            "executor). Without proper escaping, this enables shell injection attacks."
        ),
        remediation=(
            "Use parameterised APIs instead of string interpolation for shell "
            "commands. Pass arguments as arrays rather than concatenated strings. "
            "Apply a strict allowlist of permitted commands and arguments. "
            "Consider using a higher-level abstraction that never invokes a shell "
            "directly."
        ),
        category="tool_schema",
    ),
    Rule(
        rule_id="TS-004",
        severity=Severity.MEDIUM,
        title="Tool Schema Missing Input Validation Constraints",
        description=(
            "One or more tool parameters are defined without type constraints, "
            "format validators, enum restrictions, or length limits. Unconstrained "
            "parameters increase the risk of injection attacks, unexpected behaviour, "
            "and abuse through malformed inputs."
        ),
        remediation=(
            "Add JSON Schema validation keywords (type, format, enum, minLength, "
            "maxLength, pattern, minimum, maximum) to all tool parameters. Reject "
            "requests that violate the schema before the tool is invoked. Document "
            "the expected value ranges for each parameter."
        ),
        category="tool_schema",
    ),
    Rule(
        rule_id="TS-005",
        severity=Severity.MEDIUM,
        title="Sensitive Data Exfiltration Sink Detected",
        description=(
            "A tool definition includes functionality that could be used to exfiltrate "
            "sensitive data (e.g. tools that send emails, post to webhooks, write to "
            "external storage, or call messaging APIs) without any indication of "
            "output content controls or data-loss prevention measures."
        ),
        remediation=(
            "Implement output content scanning before data leaves the system boundary. "
            "Apply data-loss prevention (DLP) policies to restrict what categories of "
            "data can be sent via exfiltration-capable tools. Require human approval "
            "for outbound data transfers above a configured sensitivity threshold."
        ),
        category="tool_schema",
    ),
    Rule(
        rule_id="TS-006",
        severity=Severity.LOW,
        title="Tool Description Too Vague for Safe Invocation",
        description=(
            "A tool's description field is missing, empty, or contains fewer than "
            "10 characters. Vague descriptions make it harder for operators to audit "
            "the tool's purpose and may cause the model to invoke the tool in "
            "unintended ways due to ambiguity."
        ),
        remediation=(
            "Write a clear, specific description for every tool that explains what "
            "the tool does, what inputs it expects, and what side effects it may have. "
            "Good descriptions help both human reviewers and the model use the tool "
            "safely and correctly."
        ),
        category="tool_schema",
    ),
    Rule(
        rule_id="TS-007",
        severity=Severity.HIGH,
        title="Path Traversal Risk in File Tool Parameter",
        description=(
            "A tool that performs file read or write operations accepts a file path "
            "parameter without visible traversal prevention (e.g. no allowlist of "
            "directories, no rejection of '../' sequences). This allows an agent "
            "influenced by prompt injection to read or overwrite arbitrary files."
        ),
        remediation=(
            "Canonicalise and validate all file path inputs server-side. Reject paths "
            "containing '..' components or absolute paths outside an approved base "
            "directory. Use a virtual filesystem layer that maps logical names to "
            "physical paths without exposing the real filesystem structure."
        ),
        category="tool_schema",
    ),
]

# ---------------------------------------------------------------------------
# Master registry
# ---------------------------------------------------------------------------

#: Complete mapping of rule_id → Rule for all built-in rules.
RULES: dict[str, Rule] = {
    rule.rule_id: rule
    for rule in (
        *_PI_RULES,
        *_SL_RULES,
        *_EP_RULES,
        *_TS_RULES,
    )
}


def get_rule(rule_id: str) -> Rule:
    """Return the Rule with the given ID.

    Args:
        rule_id: The unique rule identifier (e.g. ``"PI-001"``).

    Returns:
        The matching :class:`~agent_shield.models.Rule` instance.

    Raises:
        KeyError: If no rule with the given ID exists in the registry.
    """
    try:
        return RULES[rule_id]
    except KeyError as exc:
        raise KeyError(f"No rule with ID {rule_id!r} found in registry.") from exc


def rules_by_category(category: str) -> list[Rule]:
    """Return all rules belonging to the specified category.

    Args:
        category: Category name to filter by (e.g. ``"prompt_injection"``,
            ``"secret_leakage"``, ``"permissions"``, ``"tool_schema"``).

    Returns:
        List of :class:`~agent_shield.models.Rule` objects in the category,
        ordered by rule ID.
    """
    return sorted(
        [rule for rule in RULES.values() if rule.category == category],
        key=lambda r: r.rule_id,
    )


def all_rule_ids() -> list[str]:
    """Return a sorted list of all registered rule IDs.

    Returns:
        Sorted list of rule ID strings.
    """
    return sorted(RULES.keys())


def iter_rules() -> Iterator[Rule]:
    """Iterate over all registered rules in rule-ID order.

    Yields:
        :class:`~agent_shield.models.Rule` instances.
    """
    for rule_id in sorted(RULES):
        yield RULES[rule_id]


#: Set of valid category names derived from the registered rules.
KNOWN_CATEGORIES: frozenset[str] = frozenset(
    rule.category for rule in RULES.values()
)
