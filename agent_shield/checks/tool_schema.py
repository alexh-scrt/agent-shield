"""Tool schema vulnerability checks for agent_shield.

This module implements detection rules for insecure patterns in tool and function
schema definitions within agent configuration files. It checks for:

- Unrestricted code execution tools (TS-001)
- SSRF-prone URL parameters in tool schemas (TS-002)
- Shell injection sinks in tool parameters (TS-003)
- Missing input validation constraints on tool parameters (TS-004)
- Sensitive data exfiltration sinks in tool definitions (TS-005)
- Vague or missing tool descriptions (TS-006)
- Path traversal risks in file tool parameters (TS-007)

Each check function accepts an :class:`~agent_shield.models.AgentConfig` and
returns a list of :class:`~agent_shield.models.Finding` objects.

Usage::

    from agent_shield.checks.tool_schema import check_tool_schema
    from agent_shield.loader import load_config
    from pathlib import Path

    config = load_config(Path("agent.json"))
    findings = check_tool_schema(config)
"""

from __future__ import annotations

import re
from typing import Any

from agent_shield.models import AgentConfig, Finding
from agent_shield.rules import get_rule

# ---------------------------------------------------------------------------
# TS-001: Unrestricted code execution tool patterns
# ---------------------------------------------------------------------------

#: Tool name / function name patterns indicating code / command execution.
_CODE_EXEC_NAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bexec(?:ute)?\b", re.IGNORECASE),
    re.compile(r"\beval(?:uate)?\b", re.IGNORECASE),
    re.compile(r"\bshell\b", re.IGNORECASE),
    re.compile(r"\brun[_\-]?(?:command|code|script|shell|cmd|bash|sh|zsh|python|node|ruby|perl)?\b", re.IGNORECASE),
    re.compile(r"\bexecute[_\-]?(?:command|code|script|shell|bash|sh|python|node)?\b", re.IGNORECASE),
    re.compile(r"\bsubprocess\b", re.IGNORECASE),
    re.compile(r"\bspawn\b", re.IGNORECASE),
    re.compile(r"\bpopen\b", re.IGNORECASE),
    re.compile(r"\bsystem[_\-]?(?:call|command|exec)?\b", re.IGNORECASE),
    re.compile(r"\bcode[_\-]?(?:exec(?:ute)?|run|interpret|eval)\b", re.IGNORECASE),
    re.compile(r"\binterpret[_\-]?(?:code|script|command)?\b", re.IGNORECASE),
    re.compile(r"\brepl\b", re.IGNORECASE),
    re.compile(r"\bcompile[_\-]?(?:and[_\-]?run|exec(?:ute)?)?\b", re.IGNORECASE),
    re.compile(r"\bbash[_\-]?(?:exec|run|command|script)?\b", re.IGNORECASE),
    re.compile(r"\bpython[_\-]?(?:exec|run|eval|repl)?\b", re.IGNORECASE),
    re.compile(r"\bnode[_\-]?(?:exec|run|eval|repl)?\b", re.IGNORECASE),
    re.compile(r"\bdynamic[_\-]?(?:code|exec(?:ution)?|eval(?:uation)?)\b", re.IGNORECASE),
    re.compile(r"\barbitrary[_\-]?(?:code|command|script)[_\-]?(?:exec(?:ution)?|run(?:ner)?)?\b", re.IGNORECASE),
    re.compile(r"\bcmd(?:[_\-]exec(?:ute)?)?\b", re.IGNORECASE),
    re.compile(r"\bterminal\b", re.IGNORECASE),
    re.compile(r"\bcommand[_\-]?(?:line|exec(?:ute)?|run(?:ner)?)?\b", re.IGNORECASE),
]

#: Description-level patterns indicating code execution capabilities.
_CODE_EXEC_DESCRIPTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"execut(?:es?|ing)\s+(?:arbitrary\s+)?(?:code|commands?|scripts?|shell)", re.IGNORECASE),
    re.compile(r"run(?:s|ning)?\s+(?:arbitrary\s+)?(?:code|commands?|scripts?|shell)", re.IGNORECASE),
    re.compile(r"(?:arbitrary|any)\s+(?:code|command|script)\s+(?:execution|evaluation)", re.IGNORECASE),
    re.compile(r"allows?\s+(?:running|executing)\s+(?:code|commands?|scripts?)", re.IGNORECASE),
    re.compile(r"(?:shell|bash|python|node)\s+(?:command|script|code)\s+execution", re.IGNORECASE),
    re.compile(r"eval(?:uate)?\s+(?:code|expression|script)", re.IGNORECASE),
    re.compile(r"interprets?\s+(?:and\s+executes?)?\s+(?:code|commands?|scripts?)", re.IGNORECASE),
]

#: Sandboxing / isolation keywords that reduce the risk of an exec tool.
_SANDBOX_KEYWORDS: list[re.Pattern[str]] = [
    re.compile(r"\bsandbox(?:ed)?\b", re.IGNORECASE),
    re.compile(r"\bisolat(?:ed|ion)\b", re.IGNORECASE),
    re.compile(r"\bcontainer(?:ised|ized)?\b", re.IGNORECASE),
    re.compile(r"\bgvisor\b", re.IGNORECASE),
    re.compile(r"\bfirecracker\b", re.IGNORECASE),
    re.compile(r"\brestrict(?:ed)?\s+(?:environment|mode|execution)\b", re.IGNORECASE),
    re.compile(r"\bchroot\b", re.IGNORECASE),
    re.compile(r"\bnamespace(?:d)?\b", re.IGNORECASE),
    re.compile(r"\bresource[_\-]?limit(?:ed|s)?\b", re.IGNORECASE),
    re.compile(r"\bread[_\-]?only\s+(?:file)?\s*system\b", re.IGNORECASE),
    re.compile(r"\ballowlist(?:ed)?\b", re.IGNORECASE),
    re.compile(r"\bwhitelist(?:ed)?\b", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# TS-002: SSRF-prone URL parameter patterns
# ---------------------------------------------------------------------------

#: Parameter names suggesting a URL / endpoint is accepted as input.
_URL_PARAM_NAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\burl\b", re.IGNORECASE),
    re.compile(r"\bendpoint\b", re.IGNORECASE),
    re.compile(r"\buri\b", re.IGNORECASE),
    re.compile(r"\bwebhook(?:[_\-]?url)?\b", re.IGNORECASE),
    re.compile(r"\bcallback(?:[_\-]?url)?\b", re.IGNORECASE),
    re.compile(r"\bredirect(?:[_\-]?url|[_\-]?to)?\b", re.IGNORECASE),
    re.compile(r"\bdestination(?:[_\-]?url)?\b", re.IGNORECASE),
    re.compile(r"\btarget(?:[_\-]?url|[_\-]?host)?\b", re.IGNORECASE),
    re.compile(r"\bhost(?:[_\-]?url)?\b", re.IGNORECASE),
    re.compile(r"\bbase[_\-]?url\b", re.IGNORECASE),
    re.compile(r"\bapi[_\-]?url\b", re.IGNORECASE),
    re.compile(r"\bremote[_\-]?url\b", re.IGNORECASE),
    re.compile(r"\bsource[_\-]?url\b", re.IGNORECASE),
    re.compile(r"\bfetch[_\-]?url\b", re.IGNORECASE),
    re.compile(r"\bimage[_\-]?url\b", re.IGNORECASE),
    re.compile(r"\bfile[_\-]?url\b", re.IGNORECASE),
    re.compile(r"\bproxy[_\-]?(?:url|target|to)?\b", re.IGNORECASE),
    re.compile(r"\bconnect(?:[_\-]?to)?\b", re.IGNORECASE),
    re.compile(r"\bserver(?:[_\-]?url)?\b", re.IGNORECASE),
    re.compile(r"\blink\b", re.IGNORECASE),
    re.compile(r"\bhref\b", re.IGNORECASE),
    re.compile(r"\bsrc\b", re.IGNORECASE),
]

#: JSON Schema format values and enum constraints that would make a URL param safe.
_URL_SAFETY_INDICATORS: list[re.Pattern[str]] = [
    re.compile(r"\benum\b", re.IGNORECASE),
    re.compile(r"\bconst\b", re.IGNORECASE),
    re.compile(r"\bpattern\b", re.IGNORECASE),
    re.compile(r"\ballowed[_\-]?(?:hosts?|urls?|domains?|origins?)\b", re.IGNORECASE),
    re.compile(r"\bformat\s*[=:]\s*['"]uri['"]\b", re.IGNORECASE),
    re.compile(r"\bhttps?[_\-]only\b", re.IGNORECASE),
    re.compile(r"\bscheme\s*=\s*https\b", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# TS-003: Shell injection sink patterns
# ---------------------------------------------------------------------------

#: Parameter names that are commonly passed directly to a shell.
_SHELL_SINK_PARAM_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bcmd\b", re.IGNORECASE),
    re.compile(r"\bcommand\b", re.IGNORECASE),
    re.compile(r"\bshell[_\-]?(?:cmd|command|args?|input|script)?\b", re.IGNORECASE),
    re.compile(r"\bargs?\b", re.IGNORECASE),
    re.compile(r"\barguments?\b", re.IGNORECASE),
    re.compile(r"\bscript(?:[_\-]?(?:body|content|source|text))?\b", re.IGNORECASE),
    re.compile(r"\bexec[_\-]?(?:args?|cmd|command|string)?\b", re.IGNORECASE),
    re.compile(r"\brun[_\-]?(?:args?|cmd|command|string)?\b", re.IGNORECASE),
    re.compile(r"\bsystem[_\-]?(?:call|cmd|command)?\b", re.IGNORECASE),
    re.compile(r"\binput[_\-]?(?:cmd|command|string)?\b", re.IGNORECASE),
    re.compile(r"\buser[_\-]?(?:cmd|command|input|script)?\b", re.IGNORECASE),
    re.compile(r"\braw[_\-]?(?:command|query|input)?\b", re.IGNORECASE),
    re.compile(r"\bquery\b", re.IGNORECASE),
    re.compile(r"\bexpression\b", re.IGNORECASE),
    re.compile(r"\bstatement\b", re.IGNORECASE),
    re.compile(r"\bsql\b", re.IGNORECASE),
    re.compile(r"\bcode[_\-]?(?:string|snippet|body|source)?\b", re.IGNORECASE),
]

#: Tool names that clearly indicate shell/command execution context.
_SHELL_TOOL_NAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bshell\b", re.IGNORECASE),
    re.compile(r"\bbash\b", re.IGNORECASE),
    re.compile(r"\bsh\b"),
    re.compile(r"\bzsh\b", re.IGNORECASE),
    re.compile(r"\bpowershell\b", re.IGNORECASE),
    re.compile(r"\bcmd(?:\.exe)?\b", re.IGNORECASE),
    re.compile(r"\bexec(?:ute)?\b", re.IGNORECASE),
    re.compile(r"\brun[_\-]command\b", re.IGNORECASE),
    re.compile(r"\bcommand[_\-]?(?:runner|executor|line)?\b", re.IGNORECASE),
    re.compile(r"\bos[_\-]?(?:exec|command|shell)?\b", re.IGNORECASE),
    re.compile(r"\bterminal\b", re.IGNORECASE),
    re.compile(r"\bprocess[_\-]?(?:run(?:ner)?|spawn|exec(?:ute)?)?\b", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# TS-004: Missing input validation constraints
# ---------------------------------------------------------------------------

#: JSON Schema keywords that constitute input validation.
_VALIDATION_CONSTRAINT_KEYWORDS: frozenset[str] = frozenset({
    "enum",
    "const",
    "pattern",
    "format",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "minProperties",
    "maxProperties",
    "multipleOf",
    "uniqueItems",
    "contains",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "if",
    "then",
    "else",
    "$ref",
})

#: Parameter types that require validation (strings and integers are most risky).
_RISKY_PARAM_TYPES: frozenset[str] = frozenset({"string", "integer", "number"})

#: Minimum number of unconstrained parameters to trigger a finding.
_MIN_UNCONSTRAINED_PARAMS = 1

# ---------------------------------------------------------------------------
# TS-005: Sensitive data exfiltration sink patterns
# ---------------------------------------------------------------------------

#: Tool name and description patterns indicating exfiltration-capable sinks.
_EXFIL_TOOL_NAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bsend[_\-]?(?:email|mail|message|sms|notification|data|file)?\b", re.IGNORECASE),
    re.compile(r"\bemail\b", re.IGNORECASE),
    re.compile(r"\bmail(?:er|gun|chimp|jet)?\b", re.IGNORECASE),
    re.compile(r"\bwebhook\b", re.IGNORECASE),
    re.compile(r"\bpost(?:[_\-]?(?:data|message|to|request))?\b", re.IGNORECASE),
    re.compile(r"\bupload(?:[_\-]?(?:file|data|to|s3|blob))?\b", re.IGNORECASE),
    re.compile(r"\bwrite[_\-]?(?:to[_\-]?(?:s3|gcs|blob|storage|disk|file))?\b", re.IGNORECASE),
    re.compile(r"\bslack(?:[_\-]?(?:message|notify|post|send))?\b", re.IGNORECASE),
    re.compile(r"\btwilio\b", re.IGNORECASE),
    re.compile(r"\bsms\b", re.IGNORECASE),
    re.compile(r"\bpush[_\-]?(?:notification|to|data)?\b", re.IGNORECASE),
    re.compile(r"\bnotif(?:y|ication)\b", re.IGNORECASE),
    re.compile(r"\btelemetry\b", re.IGNORECASE),
    re.compile(r"\blog(?:[_\-]?(?:to|event|data|upload|send|external))?\b", re.IGNORECASE),
    re.compile(r"\bexport(?:[_\-]?(?:data|to|file|csv|json))?\b", re.IGNORECASE),
    re.compile(r"\bftp(?:[_\-]?(?:upload|put|send))?\b", re.IGNORECASE),
    re.compile(r"\bs3[_\-]?(?:upload|put|write|push)?\b", re.IGNORECASE),
    re.compile(r"\bbucket[_\-]?(?:write|put|upload)?\b", re.IGNORECASE),
    re.compile(r"\bgcs[_\-]?(?:upload|write|put)?\b", re.IGNORECASE),
    re.compile(r"\bazure[_\-]?(?:blob|storage)[_\-]?(?:write|upload|put)?\b", re.IGNORECASE),
    re.compile(r"\bdiscord(?:[_\-]?(?:message|webhook|send|notify))?\b", re.IGNORECASE),
    re.compile(r"\btelegram(?:[_\-]?(?:message|send|bot))?\b", re.IGNORECASE),
    re.compile(r"\bpagerduty\b", re.IGNORECASE),
    re.compile(r"\bsendgrid\b", re.IGNORECASE),
    re.compile(r"\bdatadog[_\-]?(?:event|metric|log)?\b", re.IGNORECASE),
    re.compile(r"\bsplunk\b", re.IGNORECASE),
    re.compile(r"\bkafka[_\-]?(?:produce|publish|send)?\b", re.IGNORECASE),
    re.compile(r"\bpubsub\b", re.IGNORECASE),
    re.compile(r"\bsns[_\-]?(?:publish|send)?\b", re.IGNORECASE),
    re.compile(r"\bsqs[_\-]?(?:send|publish)?\b", re.IGNORECASE),
    re.compile(r"\bmessaging\b", re.IGNORECASE),
    re.compile(r"\boutbound[_\-]?(?:data|transfer|upload)?\b", re.IGNORECASE),
    re.compile(r"\btransfer(?:[_\-]?(?:file|data|to))?\b", re.IGNORECASE),
]

#: Description phrases indicating potential exfiltration capabilities.
_EXFIL_DESCRIPTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"send(?:s|ing)?\s+(?:data|content|information|messages?|files?|emails?)\s+(?:to|via|through)", re.IGNORECASE),
    re.compile(r"upload(?:s|ing)?\s+(?:data|content|files?|information)\s+(?:to|via|through)", re.IGNORECASE),
    re.compile(r"post(?:s|ing)?\s+(?:data|content|messages?|information)\s+(?:to|via|through)", re.IGNORECASE),
    re.compile(r"transmit(?:s|ting)?\s+(?:data|content|information)", re.IGNORECASE),
    re.compile(r"deliver(?:s|ing)?\s+(?:data|content|messages?|notifications?)", re.IGNORECASE),
    re.compile(r"(?:writes?|stores?)\s+(?:data|content|information)\s+(?:to|into)\s+(?:external|remote|cloud|s3|blob)", re.IGNORECASE),
    re.compile(r"notif(?:y|ies|ication)\s+(?:via|through|using)\s+(?:email|sms|slack|webhook|api)", re.IGNORECASE),
]

#: DLP / content control patterns that mitigate exfiltration risk.
_DLP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bdlp\b", re.IGNORECASE),
    re.compile(r"\bdata[_\-]?loss[_\-]?prevention\b", re.IGNORECASE),
    re.compile(r"\bcontent[_\-]?(?:scan|filter|inspect|check|control)\b", re.IGNORECASE),
    re.compile(r"\boutput[_\-]?(?:filter|validation|control|scan)\b", re.IGNORECASE),
    re.compile(r"\bsensitivity[_\-]?(?:check|filter|scan|label)\b", re.IGNORECASE),
    re.compile(r"\bpii[_\-]?(?:detect|filter|redact|scan)\b", re.IGNORECASE),
    re.compile(r"\bred(?:act|action)\b", re.IGNORECASE),
    re.compile(r"\bapproval[_\-]?(?:required|gate|workflow)\b", re.IGNORECASE),
    re.compile(r"\bhuman[_\-]?(?:review|approval|in[_\-]?the[_\-]?loop)\b", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# TS-006: Vague or missing tool descriptions
# ---------------------------------------------------------------------------

#: Minimum character count for a tool description to be considered adequate.
_MIN_DESCRIPTION_LENGTH = 10

# ---------------------------------------------------------------------------
# TS-007: Path traversal risk in file tool parameters
# ---------------------------------------------------------------------------

#: Tool name patterns indicating file operations.
_FILE_TOOL_NAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bfile[_\-]?(?:read|write|open|create|delete|list|get|put|copy|move|rename|download|upload)?\b", re.IGNORECASE),
    re.compile(r"\bread[_\-]?(?:file|document|path|disk)?\b", re.IGNORECASE),
    re.compile(r"\bwrite[_\-]?(?:file|document|path|disk)?\b", re.IGNORECASE),
    re.compile(r"\bopen[_\-]?(?:file|document|path)?\b", re.IGNORECASE),
    re.compile(r"\bcreate[_\-]?(?:file|document|dir(?:ectory)?)?\b", re.IGNORECASE),
    re.compile(r"\blist[_\-]?(?:files?|directory|dir|folder)?\b", re.IGNORECASE),
    re.compile(r"\bfilesystem\b", re.IGNORECASE),
    re.compile(r"\bfs[_\-]?(?:read|write|open|list|stat|delete)?\b", re.IGNORECASE),
    re.compile(r"\bdownload[_\-]?(?:file|document|asset)?\b", re.IGNORECASE),
    re.compile(r"\bftp\b", re.IGNORECASE),
    re.compile(r"\bsftp\b", re.IGNORECASE),
    re.compile(r"\bget[_\-]?(?:file|document|content|data)?\b", re.IGNORECASE),
    re.compile(r"\bput[_\-]?(?:file|document)?\b", re.IGNORECASE),
    re.compile(r"\bdelete[_\-]?(?:file|document|path)?\b", re.IGNORECASE),
    re.compile(r"\bcat\b"),
    re.compile(r"\bgrep\b"),
    re.compile(r"\bls\b"),
    re.compile(r"\bfind[_\-]?(?:file|document|in[_\-]?dir)?\b", re.IGNORECASE),
    re.compile(r"\bcopy[_\-]?(?:file|document)?\b", re.IGNORECASE),
    re.compile(r"\bmove[_\-]?(?:file|document)?\b", re.IGNORECASE),
]

#: File path parameter names.
_FILE_PATH_PARAM_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bpath\b", re.IGNORECASE),
    re.compile(r"\bfile(?:[_\-]?path)?\b", re.IGNORECASE),
    re.compile(r"\bfilepath\b", re.IGNORECASE),
    re.compile(r"\bfilename\b", re.IGNORECASE),
    re.compile(r"\bdirectory\b", re.IGNORECASE),
    re.compile(r"\bdir(?:ectory)?(?:[_\-]?path)?\b", re.IGNORECASE),
    re.compile(r"\bfolder\b", re.IGNORECASE),
    re.compile(r"\bdest(?:ination)?(?:[_\-]?path)?\b", re.IGNORECASE),
    re.compile(r"\bsource[_\-]?(?:path|file)?\b", re.IGNORECASE),
    re.compile(r"\binput[_\-]?(?:path|file)?\b", re.IGNORECASE),
    re.compile(r"\boutput[_\-]?(?:path|file)?\b", re.IGNORECASE),
    re.compile(r"\btarget[_\-]?(?:path|file)?\b", re.IGNORECASE),
    re.compile(r"\blocation\b", re.IGNORECASE),
    re.compile(r"\broot(?:[_\-]?dir)?\b", re.IGNORECASE),
    re.compile(r"\bbase[_\-]?(?:dir|path)?\b", re.IGNORECASE),
]

#: Path traversal prevention indicators in tool schemas.
_PATH_TRAVERSAL_PREVENTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:reject|strip|remove|prevent|block|disallow|forbid|validate).*?(?:traversal|\.\.|path)", re.IGNORECASE),
    re.compile(r"\bcanonical(?:ise|ize|isation|ization)?\b", re.IGNORECASE),
    re.compile(r"\bbase[_\-]?dir(?:ectory)?[_\-]?(?:check|enforce|restrict|bound|limit)", re.IGNORECASE),
    re.compile(r"\ballowed[_\-]?(?:paths?|directories|dirs?)\b", re.IGNORECASE),
    re.compile(r"\bpath[_\-]?(?:allowlist|whitelist|filter|validation|sanitiz)", re.IGNORECASE),
    re.compile(r"no(?:t)?\s+\.\.", re.IGNORECASE),
    re.compile(r"(?:chroot|jail|sandbox)", re.IGNORECASE),
    re.compile(r"\bresolve[_\-]?(?:and[_\-]?check|and[_\-]?validate|path)", re.IGNORECASE),
    re.compile(r"\bsafe[_\-]?path\b", re.IGNORECASE),
    re.compile(r"pattern.*?\.\*", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_tool_schema(config: AgentConfig) -> list[Finding]:
    """Run all tool schema vulnerability checks against an agent configuration.

    This is the main entry point for the tool schema check module. It
    dispatches to all individual check functions and aggregates the results.

    Args:
        config: The normalised agent configuration to check.

    Returns:
        List of :class:`~agent_shield.models.Finding` objects, possibly empty.
    """
    findings: list[Finding] = []
    findings.extend(_check_unrestricted_code_execution(config))
    findings.extend(_check_ssrf_prone_url_params(config))
    findings.extend(_check_shell_injection_sinks(config))
    findings.extend(_check_missing_input_validation(config))
    findings.extend(_check_exfiltration_sinks(config))
    findings.extend(_check_vague_descriptions(config))
    findings.extend(_check_path_traversal_risk(config))
    return findings


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------


def _check_unrestricted_code_execution(config: AgentConfig) -> list[Finding]:
    """TS-001: Detect unrestricted code / command execution tool definitions.

    Identifies tool definitions whose name or description suggests they provide
    code or shell execution capabilities without sandboxing constraints.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected execution tool.
    """
    rule = get_rule("TS-001")
    findings: list[Finding] = []
    seen: set[str] = set()

    for idx, tool in enumerate(config.tools):
        tool_name = str(tool.get("name", ""))
        tool_description = _get_description(tool)
        tool_text = _tool_to_text(tool)
        location = f"tools[{idx}] ({tool_name})"

        # Check if the tool has sandboxing indicators
        is_sandboxed = _has_sandbox_indicator(tool_text)

        # Check tool name against code execution patterns
        name_matched = False
        for pattern in _CODE_EXEC_NAME_PATTERNS:
            if pattern.search(tool_name):
                name_matched = True
                if not is_sandboxed:
                    finding_key = f"TS-001:name:{idx}:{pattern.pattern}"
                    if finding_key not in seen:
                        seen.add(finding_key)
                        findings.append(
                            Finding(
                                rule=rule,
                                file_path=config.source_path,
                                location=location,
                                evidence=f"tool name: {tool_name!r}",
                                detail=(
                                    f"Tool name '{tool_name}' matches a code/command execution "
                                    "pattern and no sandboxing indicators were found in the "
                                    "tool definition."
                                ),
                            )
                        )
                break  # One finding per tool for name match

        # Check description for execution language even if name didn't match
        for pattern in _CODE_EXEC_DESCRIPTION_PATTERNS:
            match = pattern.search(tool_description)
            if match:
                if not is_sandboxed:
                    finding_key = f"TS-001:desc:{idx}:{pattern.pattern}"
                    if finding_key not in seen:
                        seen.add(finding_key)
                        evidence = _extract_context(
                            tool_description, match.start(), match.end()
                        )
                        findings.append(
                            Finding(
                                rule=rule,
                                file_path=config.source_path,
                                location=location,
                                evidence=evidence,
                                detail=(
                                    "Tool description indicates code/command execution capability "
                                    "without sandboxing constraints."
                                ),
                            )
                        )
                break  # One finding per tool for description match

    return findings


def _check_ssrf_prone_url_params(config: AgentConfig) -> list[Finding]:
    """TS-002: Detect SSRF-prone URL parameters in tool schemas.

    Identifies tool parameters that accept a URL or endpoint value without
    format validation, allowlisting, or protocol restrictions.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected SSRF-prone parameter.
    """
    rule = get_rule("TS-002")
    findings: list[Finding] = []
    seen: set[str] = set()

    for idx, tool in enumerate(config.tools):
        tool_name = str(tool.get("name", ""))
        location_prefix = f"tools[{idx}] ({tool_name})"

        # Extract parameters from the tool schema
        params = _extract_parameters(tool)

        for param_name, param_schema in params.items():
            # Check if the parameter name suggests it's a URL
            is_url_param = any(
                pattern.search(param_name) for pattern in _URL_PARAM_NAME_PATTERNS
            )
            if not is_url_param:
                # Also check if description mentions URL
                param_desc = str(param_schema.get("description", ""))
                is_url_param = bool(
                    re.search(r"\b(?:url|uri|endpoint|webhook|link|href)\b", param_desc, re.IGNORECASE)
                )

            if not is_url_param:
                continue

            # Check if any safety constraints are present
            param_schema_text = _flatten_to_text(param_schema)
            has_safety = any(
                indicator.search(param_schema_text)
                for indicator in _URL_SAFETY_INDICATORS
            )

            if not has_safety:
                location = f"{location_prefix}.parameters.{param_name}"
                finding_key = f"TS-002:{idx}:{param_name}"
                if finding_key in seen:
                    continue
                seen.add(finding_key)
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=f"parameter: {param_name!r} (type: {param_schema.get('type', 'unspecified')!r})",
                        detail=(
                            f"Parameter '{param_name}' accepts a URL/endpoint value with no "
                            "format validator, enum constraint, or allowlist. This enables "
                            "SSRF attacks if user-controlled input reaches this parameter."
                        ),
                    )
                )

    return findings


def _check_shell_injection_sinks(config: AgentConfig) -> list[Finding]:
    """TS-003: Detect shell injection sinks in tool parameters.

    Identifies tool parameters whose names suggest they are passed directly to
    a shell command, enabling shell injection attacks when combined with
    unsanitised input.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected shell injection sink.
    """
    rule = get_rule("TS-003")
    findings: list[Finding] = []
    seen: set[str] = set()

    for idx, tool in enumerate(config.tools):
        tool_name = str(tool.get("name", ""))
        location_prefix = f"tools[{idx}] ({tool_name})"

        # Is the tool itself a shell executor?
        is_shell_tool = any(
            pattern.search(tool_name) for pattern in _SHELL_TOOL_NAME_PATTERNS
        )

        # Extract parameters from the tool schema
        params = _extract_parameters(tool)

        for param_name, param_schema in params.items():
            is_shell_sink = any(
                pattern.search(param_name) for pattern in _SHELL_SINK_PARAM_PATTERNS
            )

            if not is_shell_sink and not is_shell_tool:
                continue

            if not is_shell_sink:
                # The tool is a shell executor but parameter name isn't obviously a sink;
                # we still flag if the tool itself is shell-oriented.
                pass

            location = f"{location_prefix}.parameters.{param_name}"
            finding_key = f"TS-003:{idx}:{param_name}"
            if finding_key in seen:
                continue
            seen.add(finding_key)

            if is_shell_tool or is_shell_sink:
                param_desc = str(param_schema.get("description", ""))
                detail_parts = []
                if is_shell_tool:
                    detail_parts.append(
                        f"Tool '{tool_name}' is identified as a shell/command executor."
                    )
                if is_shell_sink:
                    detail_parts.append(
                        f"Parameter '{param_name}' name matches a shell injection sink pattern."
                    )
                detail_parts.append(
                    "Without parameterised invocation, user-supplied values in this "
                    "parameter may enable shell injection."
                )
                findings.append(
                    Finding(
                        rule=rule,
                        file_path=config.source_path,
                        location=location,
                        evidence=f"tool: {tool_name!r}, parameter: {param_name!r}",
                        detail=" ".join(detail_parts),
                    )
                )

    return findings


def _check_missing_input_validation(config: AgentConfig) -> list[Finding]:
    """TS-004: Detect tool parameters without input validation constraints.

    Identifies parameters in tool/function schemas that are defined without
    any type constraints, format validators, enum restrictions, or length
    limits, increasing the risk of injection and abuse.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each tool with unconstrained parameters.
    """
    rule = get_rule("TS-004")
    findings: list[Finding] = []
    seen: set[str] = set()

    for idx, tool in enumerate(config.tools):
        tool_name = str(tool.get("name", ""))
        location_prefix = f"tools[{idx}] ({tool_name})"

        params = _extract_parameters(tool)
        unconstrained: list[str] = []

        for param_name, param_schema in params.items():
            if not isinstance(param_schema, dict):
                unconstrained.append(param_name)
                continue

            param_type = param_schema.get("type", "")

            # Only flag risky types (strings/numbers) as needing validation
            if param_type and param_type not in _RISKY_PARAM_TYPES:
                continue

            # Check if any validation constraint is present
            schema_keys = set(param_schema.keys())
            has_constraint = bool(schema_keys & _VALIDATION_CONSTRAINT_KEYWORDS)

            if not has_constraint:
                unconstrained.append(param_name)

        if len(unconstrained) >= _MIN_UNCONSTRAINED_PARAMS:
            finding_key = f"TS-004:{idx}"
            if finding_key in seen:
                continue
            seen.add(finding_key)

            # Summarise the unconstrained params in evidence
            param_list = ", ".join(f"'{p}'" for p in unconstrained[:5])
            if len(unconstrained) > 5:
                param_list += f" (and {len(unconstrained) - 5} more)"

            findings.append(
                Finding(
                    rule=rule,
                    file_path=config.source_path,
                    location=location_prefix,
                    evidence=f"Unconstrained parameters: {param_list}",
                    detail=(
                        f"Tool '{tool_name}' has {len(unconstrained)} parameter(s) without "
                        "type constraints, format validators, enum restrictions, or length "
                        "limits. Add JSON Schema validation keywords to all parameters."
                    ),
                )
            )

    return findings


def _check_exfiltration_sinks(config: AgentConfig) -> list[Finding]:
    """TS-005: Detect sensitive data exfiltration sinks in tool definitions.

    Identifies tools that could be used to exfiltrate sensitive data (e.g.
    email, webhooks, cloud storage writes) without visible DLP controls or
    human approval requirements.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each detected exfiltration-capable tool.
    """
    rule = get_rule("TS-005")
    findings: list[Finding] = []
    seen: set[str] = set()

    for idx, tool in enumerate(config.tools):
        tool_name = str(tool.get("name", ""))
        tool_description = _get_description(tool)
        tool_text = _tool_to_text(tool)
        location = f"tools[{idx}] ({tool_name})"

        # Check if DLP / approval controls are present
        has_dlp = _has_dlp_control(tool_text)
        if has_dlp:
            continue

        # Check tool name for exfiltration capability indicators
        name_matched = False
        for pattern in _EXFIL_TOOL_NAME_PATTERNS:
            if pattern.search(tool_name):
                name_matched = True
                finding_key = f"TS-005:name:{idx}:{pattern.pattern[:30]}"
                if finding_key not in seen:
                    seen.add(finding_key)
                    findings.append(
                        Finding(
                            rule=rule,
                            file_path=config.source_path,
                            location=location,
                            evidence=f"tool name: {tool_name!r}",
                            detail=(
                                f"Tool '{tool_name}' appears capable of sending or exporting data "
                                "to an external destination without DLP controls or human approval "
                                "requirements. Implement output content scanning and consider "
                                "requiring human approval for sensitive data transfers."
                            ),
                        )
                    )
                break

        if not name_matched:
            # Check description for exfiltration language
            for pattern in _EXFIL_DESCRIPTION_PATTERNS:
                match = pattern.search(tool_description)
                if match:
                    finding_key = f"TS-005:desc:{idx}:{pattern.pattern[:30]}"
                    if finding_key not in seen:
                        seen.add(finding_key)
                        evidence = _extract_context(
                            tool_description, match.start(), match.end()
                        )
                        findings.append(
                            Finding(
                                rule=rule,
                                file_path=config.source_path,
                                location=location,
                                evidence=evidence,
                                detail=(
                                    "Tool description indicates data exfiltration capability "
                                    "without DLP controls or human approval requirements."
                                ),
                            )
                        )
                    break

    return findings


def _check_vague_descriptions(config: AgentConfig) -> list[Finding]:
    """TS-006: Detect tools with missing or vague descriptions.

    Identifies tool definitions where the description field is absent, empty,
    or contains fewer than 10 characters, making it difficult for operators
    to audit the tool's purpose and for the model to use it safely.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each tool with an inadequate description.
    """
    rule = get_rule("TS-006")
    findings: list[Finding] = []

    for idx, tool in enumerate(config.tools):
        tool_name = str(tool.get("name", f"tool[{idx}]"))
        location = f"tools[{idx}] ({tool_name})"

        description = _get_description(tool)
        description_stripped = description.strip()

        if len(description_stripped) < _MIN_DESCRIPTION_LENGTH:
            if description_stripped:
                evidence = f"description: {description_stripped!r} ({len(description_stripped)} chars)"
                detail = (
                    f"Tool '{tool_name}' has a very short description ({len(description_stripped)} chars). "
                    f"Descriptions should be at least {_MIN_DESCRIPTION_LENGTH} characters and clearly "
                    "explain what the tool does, its expected inputs, and any side effects."
                )
            else:
                evidence = f"tool name: {tool_name!r} — description field is missing or empty"
                detail = (
                    f"Tool '{tool_name}' has no description. A clear description is required for "
                    "safe and auditable tool usage."
                )

            findings.append(
                Finding(
                    rule=rule,
                    file_path=config.source_path,
                    location=location,
                    evidence=evidence,
                    detail=detail,
                )
            )

    return findings


def _check_path_traversal_risk(config: AgentConfig) -> list[Finding]:
    """TS-007: Detect path traversal risks in file-handling tool parameters.

    Identifies tools that perform file operations and accept a file path
    parameter without visible path traversal prevention mechanisms.

    Args:
        config: Normalised agent configuration.

    Returns:
        List of Finding objects for each at-risk file tool parameter.
    """
    rule = get_rule("TS-007")
    findings: list[Finding] = []
    seen: set[str] = set()

    for idx, tool in enumerate(config.tools):
        tool_name = str(tool.get("name", ""))
        tool_text = _tool_to_text(tool)
        location_prefix = f"tools[{idx}] ({tool_name})"

        # Determine if this is a file-handling tool
        is_file_tool = any(
            pattern.search(tool_name) for pattern in _FILE_TOOL_NAME_PATTERNS
        )

        if not is_file_tool:
            # Also check the description for file operation language
            tool_desc = _get_description(tool)
            is_file_tool = bool(
                re.search(
                    r"\b(?:file|path|directory|filesystem|disk|read|write|open|create|delete|list|move|copy|rename)\b",
                    tool_desc,
                    re.IGNORECASE,
                )
            )

        if not is_file_tool:
            continue

        # Check if path traversal prevention is present
        has_prevention = any(
            pattern.search(tool_text)
            for pattern in _PATH_TRAVERSAL_PREVENTION_PATTERNS
        )

        if has_prevention:
            continue

        # Extract parameters and look for file path parameters
        params = _extract_parameters(tool)
        path_params: list[str] = []

        for param_name, param_schema in params.items():
            is_path_param = any(
                pattern.search(param_name) for pattern in _FILE_PATH_PARAM_PATTERNS
            )
            if not is_path_param:
                # Check description of the parameter
                param_desc = str(param_schema.get("description", "")) if isinstance(param_schema, dict) else ""
                is_path_param = bool(
                    re.search(
                        r"\b(?:path|file|directory|folder|location)\b",
                        param_desc,
                        re.IGNORECASE,
                    )
                )
            if is_path_param:
                path_params.append(param_name)

        # If the tool is a file tool but has no explicit path params in schema,
        # still flag it if it has any params at all or no params schema.
        if not path_params and is_file_tool:
            # No explicit path params found in schema, but tool is file-related.
            # Check if the tool has args that could be paths.
            args_value = tool.get("args", tool.get("arguments", tool.get("parameters")))
            if args_value is None:
                # No parameters defined at all — still potentially risky.
                path_params = ["<unspecified>"]  # placeholder

        for param_name in path_params:
            finding_key = f"TS-007:{idx}:{param_name}"
            if finding_key in seen:
                continue
            seen.add(finding_key)
            findings.append(
                Finding(
                    rule=rule,
                    file_path=config.source_path,
                    location=(
                        f"{location_prefix}.parameters.{param_name}"
                        if param_name != "<unspecified>"
                        else location_prefix
                    ),
                    evidence=(
                        f"file tool: {tool_name!r}, path parameter: {param_name!r}"
                    ),
                    detail=(
                        f"Tool '{tool_name}' performs file operations and accepts a path "
                        f"parameter ('{param_name}') without visible path traversal "
                        "prevention. Canonicalise paths server-side, reject '../' sequences, "
                        "and restrict access to an approved base directory."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _get_description(tool: dict[str, Any]) -> str:
    """Extract the description string from a tool definition.

    Checks common key names used for tool descriptions in various schema
    formats (OpenAI function calling, MCP, custom).

    Args:
        tool: Tool definition dictionary.

    Returns:
        Description string, or empty string if not found.
    """
    for key in ("description", "desc", "summary", "help", "about", "info", "detail", "details"):
        value = tool.get(key)
        if isinstance(value, str):
            return value
    return ""


def _extract_parameters(
    tool: dict[str, Any],
) -> dict[str, Any]:
    """Extract the parameters dict from a tool definition.

    Handles multiple common schema formats:
    - OpenAI function calling: ``{"parameters": {"properties": {...}}}``
    - MCP format: ``{"inputSchema": {"properties": {...}}}``
    - Simple flat: ``{"params": {...}}``
    - Direct properties: ``{"properties": {...}}``

    Args:
        tool: Tool definition dictionary.

    Returns:
        Mapping of parameter name → parameter schema dict.
        Returns an empty dict if no parameters are found.
    """
    # Try standard locations for parameter properties
    candidates: list[dict[str, Any]] = []

    for key in ("parameters", "inputSchema", "input_schema", "schema", "params", "arguments", "args"):
        value = tool.get(key)
        if isinstance(value, dict):
            # Look for JSON Schema "properties" sub-key
            properties = value.get("properties")
            if isinstance(properties, dict):
                return properties
            # If the dict itself looks like a properties map (values are dicts with "type"),
            # treat it directly as the parameter map.
            if all(isinstance(v, dict) for v in value.values()):
                candidates.append(value)

    # Try a top-level "properties" key
    top_properties = tool.get("properties")
    if isinstance(top_properties, dict):
        return top_properties

    # Return the first candidate found
    if candidates:
        return candidates[0]

    return {}


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


def _flatten_to_text(data: Any) -> str:
    """Recursively flatten any data structure to a single text string.

    Args:
        data: Any Python object to convert to text.

    Returns:
        String representation of all leaf values concatenated with spaces.
    """
    parts: list[str] = []

    def _collect(node: Any) -> None:
        if isinstance(node, str):
            parts.append(node)
        elif isinstance(node, dict):
            for k, v in node.items():
                parts.append(str(k))
                _collect(v)
        elif isinstance(node, (list, tuple)):
            for item in node:
                _collect(item)
        elif node is not None:
            parts.append(str(node))

    _collect(data)
    return " ".join(parts)


def _has_sandbox_indicator(text: str) -> bool:
    """Return True if the text contains evidence of sandboxing or isolation.

    Args:
        text: Text to search for sandboxing indicators.

    Returns:
        ``True`` if any sandboxing indicator pattern is found.
    """
    return any(pattern.search(text) for pattern in _SANDBOX_KEYWORDS)


def _has_dlp_control(text: str) -> bool:
    """Return True if the text contains evidence of DLP or output control.

    Args:
        text: Text to search for DLP control patterns.

    Returns:
        ``True`` if any DLP indicator pattern is found.
    """
    return any(pattern.search(text) for pattern in _DLP_PATTERNS)


def _extract_context(text: str, start: int, end: int, max_len: int = 120) -> str:
    """Extract a context window around a regex match for use as evidence.

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
    if len(result) > max_len + 6:
        result = result[:max_len] + "..."
    return result
