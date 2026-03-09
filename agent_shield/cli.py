"""Typer-based CLI entry point for agent_shield.

This module defines the ``agent-shield`` command-line interface. It handles:

- File and directory input (single path or recursive directory scan)
- Output format selection (human-readable Rich terminal report or ``--json``
  machine-readable JSON for CI/CD integration)
- Severity filtering via ``--min-severity`` to suppress lower-priority findings
- ``--show-remediation`` flag to include remediation advice in terminal output
- Non-zero exit codes when HIGH or CRITICAL findings are detected, enabling
  pipeline failure gates
- ``--recursive`` flag for directory scans
- ``--list-rules`` sub-command to display all registered detection rules

Exit codes:
    0  — No findings at or above the blocking threshold (HIGH by default)
    1  — HIGH or CRITICAL findings detected (CI/CD failure gate)
    2  — Usage error (bad arguments, missing file, etc.)

Usage examples::

    # Scan a single file, human-readable output
    agent-shield scan agent.json

    # Scan a directory recursively, output JSON
    agent-shield scan ./configs --recursive --json

    # Filter to HIGH+ findings only
    agent-shield scan agent.yaml --min-severity HIGH

    # Show remediation advice in terminal
    agent-shield scan agent.json --show-remediation

    # List all built-in rules
    agent-shield list-rules

    # List rules for a specific category
    agent-shield list-rules --category prompt_injection
"""

from __future__ import annotations

import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

from agent_shield import __version__
from agent_shield.models import Severity
from agent_shield.reporter import print_json_report, print_terminal_report
from agent_shield.rules import KNOWN_CATEGORIES, RULES, iter_rules, rules_by_category
from agent_shield.scanner import Scanner

# ---------------------------------------------------------------------------
# Typer application
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="agent-shield",
    help=(
        "agent_shield — Security scanner for AI agent configurations.\n\n"
        "Detects prompt injection vectors, secret leakage, excessive permissions,\n"
        "and insecure tool schemas in JSON, YAML, and plain-text agent configs."
    ),
    add_completion=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

# ---------------------------------------------------------------------------
# Shared console instances
# ---------------------------------------------------------------------------

_console = Console()
_err_console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Severity enum for CLI argument (mirrors models.Severity but Typer-friendly)
# ---------------------------------------------------------------------------


class SeverityChoice(str, Enum):
    """CLI-facing severity choices that map to :class:`~agent_shield.models.Severity`."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def to_severity(self) -> Severity:
        """Convert this CLI choice to the internal Severity enum value.

        Returns:
            The corresponding :class:`~agent_shield.models.Severity` member.
        """
        return Severity(self.value)


# ---------------------------------------------------------------------------
# Version callback
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:  # pragma: no cover
    """Print the version string and exit."""
    if value:
        typer.echo(f"agent-shield {__version__}")
        raise typer.Exit(code=0)


# ---------------------------------------------------------------------------
# ``scan`` command
# ---------------------------------------------------------------------------


@app.command(name="scan", help="Scan one or more agent configuration files or a directory.")
def scan_command(
    target: Path = typer.Argument(
        ...,
        help=(
            "Path to a configuration file (JSON, YAML, or plain text) or a directory "
            "containing configuration files to scan."
        ),
        show_default=False,
        metavar="TARGET",
    ),
    recursive: bool = typer.Option(
        False,
        "--recursive",
        "-r",
        help="Recursively scan subdirectories when TARGET is a directory.",
        show_default=True,
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        "-j",
        help=(
            "Output results as machine-readable JSON instead of the terminal report. "
            "Useful for CI/CD pipeline integration."
        ),
        show_default=True,
    ),
    min_severity: SeverityChoice = typer.Option(
        SeverityChoice.INFO,
        "--min-severity",
        "-s",
        help=(
            "Only report findings at or above this severity level. "
            "Choices: CRITICAL, HIGH, MEDIUM, LOW, INFO."
        ),
        show_default=True,
        case_sensitive=False,
    ),
    show_remediation: bool = typer.Option(
        False,
        "--show-remediation",
        help=(
            "Include remediation advice column in the terminal report. "
            "Has no effect when --json is used."
        ),
        show_default=True,
    ),
    fail_on: SeverityChoice = typer.Option(
        SeverityChoice.HIGH,
        "--fail-on",
        help=(
            "Exit with code 1 if any finding meets or exceeds this severity. "
            "Defaults to HIGH (i.e. exit 1 on HIGH or CRITICAL findings). "
            "Set to CRITICAL to only fail on critical issues."
        ),
        show_default=True,
        case_sensitive=False,
    ),
    version: Optional[bool] = typer.Option(  # noqa: UP007
        None,
        "--version",
        "-V",
        help="Print version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Scan agent configuration files or directories for security vulnerabilities.

    TARGET can be a path to a single configuration file or a directory.  When
    TARGET is a directory, all ``.json``, ``.yaml``, ``.yml``, ``.txt``, and
    ``.md`` files are scanned. Use ``--recursive`` to include subdirectories.

    Exit codes:

    \b
      0  No findings at or above the --fail-on severity threshold
      1  Findings at or above the --fail-on threshold were detected
      2  Usage or I/O error (file not found, unreadable, etc.)
    """
    target = target.resolve()
    min_sev: Severity = min_severity.to_severity()
    fail_sev: Severity = fail_on.to_severity()

    # -----------------------------------------------------------------------
    # Validate the target path
    # -----------------------------------------------------------------------
    if not target.exists():
        _err_console.print(
            f"[bold red]Error:[/bold red] Target path does not exist: {target}"
        )
        raise typer.Exit(code=2)

    # -----------------------------------------------------------------------
    # Build scanner and run the scan
    # -----------------------------------------------------------------------
    scanner = Scanner(min_severity=min_sev)

    if target.is_file():
        result = scanner.scan_file(target)
    elif target.is_dir():
        result = scanner.scan_directory(target, recursive=recursive)
    else:
        _err_console.print(
            f"[bold red]Error:[/bold red] Target is neither a file nor a directory: {target}"
        )
        raise typer.Exit(code=2)

    # -----------------------------------------------------------------------
    # Emit results
    # -----------------------------------------------------------------------
    if output_json:
        print_json_report(result, console=Console(highlight=False, markup=False), min_severity=min_sev)
    else:
        print_terminal_report(
            result,
            console=_console,
            show_remediation=show_remediation,
            min_severity=min_sev,
        )

    # -----------------------------------------------------------------------
    # Determine exit code
    # -----------------------------------------------------------------------
    # Check if any findings meet or exceed the fail-on threshold
    findings_at_threshold = result.findings_at_or_above(fail_sev)
    if findings_at_threshold:
        raise typer.Exit(code=1)

    # Also exit with code 2 if there were loader errors (partial scan)
    if result.errors and not result.scanned_files:
        # All targets failed to load — treat as a hard error
        raise typer.Exit(code=2)

    raise typer.Exit(code=0)


# ---------------------------------------------------------------------------
# ``list-rules`` command
# ---------------------------------------------------------------------------


@app.command(
    name="list-rules",
    help="Display all built-in detection rules registered in the rule registry.",
)
def list_rules_command(
    category: Optional[str] = typer.Option(  # noqa: UP007
        None,
        "--category",
        "-c",
        help=(
            f"Filter rules by category. "
            f"Available categories: {', '.join(sorted(KNOWN_CATEGORIES))}."
        ),
        show_default=False,
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output rules as machine-readable JSON.",
        show_default=True,
    ),
    severity_filter: Optional[SeverityChoice] = typer.Option(  # noqa: UP007
        None,
        "--severity",
        "-s",
        help="Filter rules to a specific severity level.",
        show_default=False,
        case_sensitive=False,
    ),
) -> None:
    """List all registered security detection rules.

    Optionally filter by category or severity. Use ``--json`` to get
    machine-readable output suitable for scripting.
    """
    import json as _json

    # -----------------------------------------------------------------------
    # Validate category argument
    # -----------------------------------------------------------------------
    if category is not None and category not in KNOWN_CATEGORIES:
        _err_console.print(
            f"[bold red]Error:[/bold red] Unknown category '{category}'.\n"
            f"Available categories: {', '.join(sorted(KNOWN_CATEGORIES))}"
        )
        raise typer.Exit(code=2)

    # -----------------------------------------------------------------------
    # Gather matching rules
    # -----------------------------------------------------------------------
    if category is not None:
        rules = rules_by_category(category)
    else:
        rules = list(iter_rules())

    # Apply severity filter if requested
    if severity_filter is not None:
        target_sev = severity_filter.to_severity()
        rules = [r for r in rules if r.severity == target_sev]

    if not rules:
        if output_json:
            Console(highlight=False, markup=False).print(_json.dumps([], indent=2))
        else:
            _console.print("[dim]No rules match the specified filters.[/dim]")
        raise typer.Exit(code=0)

    # -----------------------------------------------------------------------
    # Emit results
    # -----------------------------------------------------------------------
    if output_json:
        output = [rule.to_dict() for rule in rules]
        Console(highlight=False, markup=False).print(_json.dumps(output, indent=2))
    else:
        _print_rules_table(rules)

    raise typer.Exit(code=0)


# ---------------------------------------------------------------------------
# ``version`` command
# ---------------------------------------------------------------------------


@app.command(name="version", help="Print the agent-shield version and exit.")
def version_command() -> None:
    """Print the installed agent-shield version string."""
    _console.print(f"agent-shield [bold cyan]{__version__}[/bold cyan]")
    raise typer.Exit(code=0)


# ---------------------------------------------------------------------------
# Internal rendering helpers
# ---------------------------------------------------------------------------


#: Severity colour mapping for the rules table.
_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "dim",
}

#: Severity emoji for the rules table.
_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def _print_rules_table(rules: list) -> None:  # type: ignore[type-arg]
    """Render the list of rules as a Rich terminal table.

    Args:
        rules: List of :class:`~agent_shield.models.Rule` objects to display.
    """
    table = Table(
        title=f"Registered Detection Rules ({len(rules)})",
        box=box.ROUNDED,
        title_style="bold",
        show_header=True,
        header_style="bold dim",
        expand=True,
        show_lines=True,
    )

    table.add_column("Rule ID", min_width=8, no_wrap=True)
    table.add_column("Severity", min_width=10, no_wrap=True)
    table.add_column("Category", min_width=15, no_wrap=True)
    table.add_column("Title", min_width=25)
    table.add_column("Description", min_width=40, max_width=80)

    for rule in rules:
        sev = rule.severity
        style = _SEVERITY_STYLES.get(sev, "")
        emoji = _SEVERITY_EMOJI.get(sev, "")

        severity_cell = Text(f"{emoji} {sev.value}", style=style)
        rule_id_cell = Text(rule.rule_id, style="bold")
        category_cell = Text(rule.category, style="dim")
        title_cell = Text(rule.title)
        # Truncate long descriptions for the table
        desc_truncated = _cli_truncate(rule.description, 180)
        desc_cell = Text(desc_truncated, style="dim")

        table.add_row(
            rule_id_cell,
            severity_cell,
            category_cell,
            title_cell,
            desc_cell,
        )

    _console.print()
    _console.print(table)
    _console.print(
        f"\n[dim]Total: {len(rules)} rule(s). "
        f"Categories: {', '.join(sorted(KNOWN_CATEGORIES))}[/dim]\n"
    )


def _cli_truncate(text: str, max_len: int, suffix: str = "…") -> str:
    """Truncate a string for display in the CLI rules table.

    Normalises whitespace and trims to ``max_len`` characters.

    Args:
        text: Input string to truncate.
        max_len: Maximum allowed character length.
        suffix: Suffix to append when truncation occurs.

    Returns:
        Truncated (or unchanged) string with normalised whitespace.
    """
    normalised = " ".join(text.split())
    if len(normalised) <= max_len:
        return normalised
    return normalised[: max_len - len(suffix)] + suffix


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    app()
