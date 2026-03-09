"""Result reporter for agent_shield.

This module formats :class:`~agent_shield.models.ScanResult` objects into
human-readable terminal output using Rich, or machine-readable JSON suitable
for CI/CD pipeline integration.

Two output modes are supported:

- **Terminal report** (:func:`print_terminal_report`): Renders a colour-coded
  Rich table with per-severity finding counts, a full findings table, and a
  summary banner. Designed for interactive use.

- **JSON report** (:func:`print_json_report`): Serialises the full scan result
  to structured JSON and prints it to stdout. Designed for machine consumption
  in CI/CD pipelines.

Usage::

    from agent_shield.reporter import print_terminal_report, print_json_report
    from agent_shield.scanner import scan_file
    from pathlib import Path

    result = scan_file(Path("agent.json"))
    print_terminal_report(result)
    # or
    print_json_report(result)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from agent_shield.models import Finding, ScanResult, Severity

# ---------------------------------------------------------------------------
# Module-level console instances
# ---------------------------------------------------------------------------

#: Default Rich console for stdout output.
_console = Console()

#: Rich console targeting stderr (used for status messages).
_err_console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Severity display configuration
# ---------------------------------------------------------------------------

#: Maps Severity → Rich style string for table cells.
_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "dim",
}

#: Maps Severity → emoji prefix for severity labels.
_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

#: Maximum character width for evidence and detail columns in the table.
_MAX_EVIDENCE_WIDTH = 60
_MAX_DETAIL_WIDTH = 70
_MAX_LOCATION_WIDTH = 50


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def print_terminal_report(
    result: ScanResult,
    console: Console | None = None,
    show_remediation: bool = False,
    min_severity: Severity = Severity.INFO,
) -> None:
    """Render a colour-coded terminal report of scan results using Rich.

    Prints a header panel, a per-severity summary, a findings table (sorted
    by severity descending), and a final status banner to the given console.

    Args:
        result: The :class:`~agent_shield.models.ScanResult` to display.
        console: Optional :class:`rich.console.Console` to write to.
            Defaults to the module-level stdout console.
        show_remediation: If ``True``, include a remediation column in the
            findings table. Defaults to ``False`` to keep the table compact.
        min_severity: Only display findings at or above this severity level.
            Defaults to :attr:`~agent_shield.models.Severity.INFO` (all).
    """
    con = console or _console

    _print_header(con, result)
    _print_summary_table(con, result)

    findings_to_show = [
        f for f in result.sorted_findings() if f.severity >= min_severity
    ]

    if findings_to_show:
        _print_findings_table(con, findings_to_show, show_remediation=show_remediation)
    else:
        con.print()
        con.print("  [dim]No findings to display at the selected severity level.[/dim]")
        con.print()

    _print_status_banner(con, result)


def print_json_report(
    result: ScanResult,
    console: Console | None = None,
    indent: int = 2,
    min_severity: Severity = Severity.INFO,
) -> None:
    """Print the scan result as structured JSON to stdout.

    The JSON output is designed for machine consumption in CI/CD pipelines.
    It includes a summary block, a list of all findings (sorted by severity),
    the list of scanned files, and any loader errors.

    Args:
        result: The :class:`~agent_shield.models.ScanResult` to serialise.
        console: Optional :class:`rich.console.Console` to write to.
            Defaults to the module-level stdout console with no markup.
        indent: JSON indentation level. Defaults to 2.
        min_severity: Only include findings at or above this severity level
            in the JSON output.
    """
    con = console or Console(highlight=False, markup=False)

    # Filter findings if a minimum severity is requested
    if min_severity != Severity.INFO:
        filtered_findings = [
            f for f in result.sorted_findings() if f.severity >= min_severity
        ]
        # Build a filtered copy of the dict representation
        output = _build_json_output(result, filtered_findings, min_severity)
    else:
        output = result.to_dict()

    con.print(json.dumps(output, indent=indent))


def format_json_report(
    result: ScanResult,
    indent: int = 2,
    min_severity: Severity = Severity.INFO,
) -> str:
    """Serialise a scan result to a JSON string without printing it.

    Useful when the caller wants to write the JSON to a file or process it
    further before output.

    Args:
        result: The :class:`~agent_shield.models.ScanResult` to serialise.
        indent: JSON indentation level. Defaults to 2.
        min_severity: Only include findings at or above this severity level.

    Returns:
        Pretty-printed JSON string.
    """
    if min_severity != Severity.INFO:
        filtered_findings = [
            f for f in result.sorted_findings() if f.severity >= min_severity
        ]
        output = _build_json_output(result, filtered_findings, min_severity)
    else:
        output = result.to_dict()
    return json.dumps(output, indent=indent)


# ---------------------------------------------------------------------------
# Internal rendering helpers
# ---------------------------------------------------------------------------


def _print_header(con: Console, result: ScanResult) -> None:
    """Print the scan report header panel.

    Shows the tool name, version, and a summary of scanned files and errors.

    Args:
        con: Rich console to write to.
        result: The scan result providing file and error counts.
    """
    from agent_shield import __version__

    file_count = len(result.scanned_files)
    error_count = len(result.errors)

    lines: list[str] = [
        f"[bold cyan]agent_shield[/bold cyan] [dim]v{__version__}[/dim]",
        f"[dim]Scanned [bold]{file_count}[/bold] file(s)"
        + (f", [bold red]{error_count}[/bold red] error(s)" if error_count else "")
        + "[/dim]",
    ]

    if result.scanned_files:
        for p in result.scanned_files[:5]:
            lines.append(f"[dim]  • {p}[/dim]")
        if file_count > 5:
            lines.append(f"[dim]  … and {file_count - 5} more[/dim]")

    if result.errors:
        lines.append("[bold red]Errors:[/bold red]")
        for path_str, err_msg in result.errors.items():
            lines.append(f"[red]  • {path_str}: {err_msg}[/red]")

    header_text = "\n".join(lines)
    con.print()
    con.print(
        Panel(
            header_text,
            title="[bold cyan] Security Scan Report [/bold cyan]",
            border_style="cyan",
            expand=False,
            padding=(0, 2),
        )
    )
    con.print()


def _print_summary_table(con: Console, result: ScanResult) -> None:
    """Print a compact per-severity finding count table.

    Args:
        con: Rich console to write to.
        result: The scan result to summarise.
    """
    table = Table(
        title="Finding Summary",
        box=box.ROUNDED,
        title_style="bold",
        show_header=True,
        header_style="bold",
        expand=False,
        min_width=40,
    )
    table.add_column("Severity", style="", min_width=12)
    table.add_column("Count", justify="right", min_width=8)

    total = result.finding_count
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = len(result.findings_by_severity(sev))
        emoji = _SEVERITY_EMOJI[sev]
        style = _SEVERITY_STYLES[sev]
        count_str = str(count) if count > 0 else "[dim]0[/dim]"
        label = Text(f"{emoji} {sev.value}", style=style if count > 0 else "dim")
        table.add_row(label, count_str)

    table.add_section()
    table.add_row(
        Text("TOTAL", style="bold"),
        Text(str(total), style="bold"),
    )

    con.print(table)
    con.print()


def _print_findings_table(
    con: Console,
    findings: list[Finding],
    show_remediation: bool = False,
) -> None:
    """Print the full findings table.

    Each row represents one finding, with columns for severity, rule ID,
    title, file location, evidence snippet, and optionally remediation advice.

    Args:
        con: Rich console to write to.
        findings: Sorted list of findings to display.
        show_remediation: Whether to include a remediation column.
    """
    table = Table(
        title=f"Findings ({len(findings)})",
        box=box.ROUNDED,
        title_style="bold",
        show_header=True,
        header_style="bold dim",
        expand=True,
        show_lines=True,
    )

    table.add_column("Severity", min_width=10, no_wrap=True)
    table.add_column("Rule ID", min_width=8, no_wrap=True)
    table.add_column("Title", min_width=20)
    table.add_column("Location", min_width=15, max_width=_MAX_LOCATION_WIDTH)
    table.add_column("Evidence", min_width=20, max_width=_MAX_EVIDENCE_WIDTH)

    if show_remediation:
        table.add_column("Remediation", min_width=30, max_width=_MAX_DETAIL_WIDTH)

    for finding in findings:
        sev = finding.severity
        style = _SEVERITY_STYLES[sev]
        emoji = _SEVERITY_EMOJI[sev]

        severity_cell = Text(f"{emoji} {sev.value}", style=style)
        rule_id_cell = Text(finding.rule_id, style="bold")
        title_cell = Text(finding.rule.title)
        location_cell = Text(
            _truncate(str(finding.location), _MAX_LOCATION_WIDTH),
            style="dim",
        )
        evidence_cell = Text(
            _truncate(finding.evidence, _MAX_EVIDENCE_WIDTH),
            style="italic",
        )

        row: list[Any] = [
            severity_cell,
            rule_id_cell,
            title_cell,
            location_cell,
            evidence_cell,
        ]

        if show_remediation:
            remediation_cell = Text(
                _truncate(finding.rule.remediation, _MAX_DETAIL_WIDTH),
                style="dim",
            )
            row.append(remediation_cell)

        table.add_row(*row)

    con.print(table)
    con.print()


def _print_status_banner(con: Console, result: ScanResult) -> None:
    """Print the final status banner indicating pass/fail.

    Displays a green PASS banner if no HIGH or CRITICAL findings were found,
    or a red FAIL banner if the result contains actionable issues.

    Args:
        con: Rich console to write to.
        result: The scan result to evaluate.
    """
    total = result.finding_count
    file_count = len(result.scanned_files)

    if total == 0:
        status_style = "bold green"
        icon = "✅"
        status_text = "PASS — No findings detected."
        detail = f"Scanned {file_count} file(s) with zero security issues."
        border = "green"
    elif result.has_high_or_critical:
        status_style = "bold red"
        icon = "❌"
        status_text = "FAIL — HIGH or CRITICAL findings detected."
        high_count = len(result.findings_by_severity(Severity.HIGH))
        critical_count = len(result.findings_by_severity(Severity.CRITICAL))
        parts: list[str] = []
        if critical_count:
            parts.append(f"{critical_count} CRITICAL")
        if high_count:
            parts.append(f"{high_count} HIGH")
        detail = (
            f"{total} total finding(s) including {', '.join(parts)}. "
            "Remediate HIGH/CRITICAL issues before deployment."
        )
        border = "red"
    else:
        status_style = "bold yellow"
        icon = "⚠️ "
        status_text = "WARN — Lower-severity findings detected."
        detail = (
            f"{total} finding(s) found (none HIGH or CRITICAL). "
            "Review and remediate at your discretion."
        )
        border = "yellow"

    banner_text = f"{icon}  [{status_style}]{status_text}[/{status_style}]\n[dim]{detail}[/dim]"
    con.print(
        Panel(
            banner_text,
            border_style=border,
            expand=False,
            padding=(0, 2),
        )
    )
    con.print()


def _build_json_output(
    result: ScanResult,
    filtered_findings: list[Finding],
    min_severity: Severity,
) -> dict[str, Any]:
    """Build a JSON-serialisable dict from a ScanResult with filtered findings.

    Used when a minimum severity filter is applied to the JSON output to avoid
    re-serialising findings that were filtered out.

    Args:
        result: The original scan result.
        filtered_findings: Pre-filtered and sorted list of findings to include.
        min_severity: The minimum severity used for filtering (recorded in output).

    Returns:
        A dict suitable for ``json.dumps``.
    """
    severity_counts: dict[str, int] = {}
    for sev in Severity:
        severity_counts[sev.value] = sum(
            1 for f in filtered_findings if f.severity == sev
        )

    return {
        "summary": {
            "total_findings": len(filtered_findings),
            "scanned_files": len(result.scanned_files),
            "errors": len(result.errors),
            "has_high_or_critical": any(
                f.severity in (Severity.HIGH, Severity.CRITICAL)
                for f in filtered_findings
            ),
            "severity_counts": severity_counts,
            "min_severity_filter": min_severity.value,
        },
        "findings": [f.to_dict() for f in filtered_findings],
        "scanned_files": [str(p) for p in result.scanned_files],
        "errors": result.errors,
    }


def _truncate(text: str, max_len: int, suffix: str = "…") -> str:
    """Truncate a string to at most ``max_len`` characters.

    If the string is longer than ``max_len``, it is cut and a suffix (default
    ``…``) is appended. Newlines are replaced with spaces for table display.

    Args:
        text: The string to truncate.
        max_len: Maximum number of characters to allow.
        suffix: String to append when truncation occurs.

    Returns:
        The (possibly truncated) string with newlines normalised.
    """
    # Normalise whitespace for table display
    normalised = text.replace("\n", " ").replace("\r", " ").strip()
    if len(normalised) <= max_len:
        return normalised
    return normalised[: max_len - len(suffix)] + suffix
