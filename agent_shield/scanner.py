"""Scanner orchestration for agent_shield.

This module provides the core scanning pipeline that loads agent configuration
files and dispatches them through all registered security check functions,
aggregating the results into a :class:`~agent_shield.models.ScanResult`.

The scanner is intentionally decoupled from both the CLI and the reporter so
that it can be used programmatically in CI/CD pipelines, test suites, or other
integration contexts.

Usage::

    from pathlib import Path
    from agent_shield.scanner import Scanner

    scanner = Scanner()
    result = scanner.scan_file(Path("agent.json"))
    print(f"Found {result.finding_count} issues.")

    # Scan an entire directory
    result = scanner.scan_directory(Path("./configs"), recursive=True)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from agent_shield.checks.permissions import check_permissions
from agent_shield.checks.prompt_injection import check_prompt_injection
from agent_shield.checks.secret_leakage import check_secret_leakage
from agent_shield.checks.tool_schema import check_tool_schema
from agent_shield.loader import load_config, load_directory
from agent_shield.models import AgentConfig, Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type alias for check functions
# ---------------------------------------------------------------------------

#: Callable signature that all check functions must implement.
CheckFunction = Callable[[AgentConfig], list[Finding]]

# ---------------------------------------------------------------------------
# Default check registry
# ---------------------------------------------------------------------------

#: Ordered list of all built-in check functions.
#: The order determines the order findings are collected (not their final sort order).
DEFAULT_CHECKS: list[CheckFunction] = [
    check_prompt_injection,
    check_secret_leakage,
    check_permissions,
    check_tool_schema,
]


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------


class Scanner:
    """Orchestrates security checks against agent configuration files.

    The Scanner maintains a registry of check functions and dispatches each
    loaded :class:`~agent_shield.models.AgentConfig` through all of them,
    collecting :class:`~agent_shield.models.Finding` objects and aggregating
    them into a :class:`~agent_shield.models.ScanResult`.

    Attributes:
        checks: Ordered list of check functions to run against each config.
        min_severity: Minimum :class:`~agent_shield.models.Severity` level
            for findings to be included in the result. Findings below this
            threshold are silently discarded.
    """

    def __init__(
        self,
        checks: list[CheckFunction] | None = None,
        min_severity: Severity = Severity.INFO,
    ) -> None:
        """Initialise the Scanner.

        Args:
            checks: Optional list of check functions to use. Defaults to
                :data:`DEFAULT_CHECKS` (all built-in checks).
            min_severity: Only include findings at or above this severity.
                Defaults to :attr:`~agent_shield.models.Severity.INFO` (all).
        """
        self.checks: list[CheckFunction] = checks if checks is not None else list(DEFAULT_CHECKS)
        self.min_severity: Severity = min_severity

    # ------------------------------------------------------------------
    # Public scanning methods
    # ------------------------------------------------------------------

    def scan_file(self, path: Path) -> ScanResult:
        """Scan a single agent configuration file.

        Loads the file using :func:`~agent_shield.loader.load_config`, runs
        all registered check functions, and returns the aggregated result.

        Args:
            path: Path to the configuration file to scan.

        Returns:
            A :class:`~agent_shield.models.ScanResult` containing all findings
            and metadata about the scan.
        """
        result = ScanResult()
        path = Path(path).resolve()

        try:
            config = load_config(path)
        except FileNotFoundError as exc:
            logger.error("File not found: %s — %s", path, exc)
            result.errors[str(path)] = f"File not found: {exc}"
            return result
        except Exception as exc:
            logger.error("Failed to load %s: %s", path, exc)
            result.errors[str(path)] = str(exc)
            return result

        result.scanned_files.append(path)
        findings = self._run_checks(config)
        result.findings.extend(findings)
        return result

    def scan_files(self, paths: list[Path]) -> ScanResult:
        """Scan multiple agent configuration files.

        Loads and scans each file in sequence, merging all findings and
        metadata into a single :class:`~agent_shield.models.ScanResult`.

        Args:
            paths: List of file paths to scan.

        Returns:
            A merged :class:`~agent_shield.models.ScanResult` for all files.
        """
        merged = ScanResult()
        for path in paths:
            partial = self.scan_file(path)
            merged.findings.extend(partial.findings)
            merged.scanned_files.extend(partial.scanned_files)
            merged.errors.update(partial.errors)
        return merged

    def scan_directory(
        self,
        directory: Path,
        recursive: bool = False,
    ) -> ScanResult:
        """Scan all recognised agent configuration files in a directory.

        Discovers files using :func:`~agent_shield.loader.load_directory` and
        runs all registered check functions against each one.

        Args:
            directory: Path to the directory to scan.
            recursive: If ``True``, scan subdirectories recursively.
                Defaults to ``False``.

        Returns:
            A :class:`~agent_shield.models.ScanResult` aggregating findings
            from all scanned files.
        """
        result = ScanResult()
        directory = Path(directory).resolve()

        try:
            configs = load_directory(directory, recursive=recursive)
        except NotADirectoryError as exc:
            logger.error("Not a directory: %s — %s", directory, exc)
            result.errors[str(directory)] = str(exc)
            return result
        except Exception as exc:
            logger.error("Failed to load directory %s: %s", directory, exc)
            result.errors[str(directory)] = str(exc)
            return result

        if not configs:
            logger.info("No recognised configuration files found in %s", directory)
            return result

        for config in configs:
            result.scanned_files.append(config.source_path)
            try:
                findings = self._run_checks(config)
                result.findings.extend(findings)
            except Exception as exc:  # pragma: no cover — defensive belt-and-suspenders
                logger.error(
                    "Unexpected error scanning %s: %s",
                    config.source_path,
                    exc,
                )
                result.errors[str(config.source_path)] = str(exc)

        return result

    def scan_config(self, config: AgentConfig) -> ScanResult:
        """Scan an already-loaded :class:`~agent_shield.models.AgentConfig`.

        This method is useful when the caller has already loaded and possibly
        pre-processed the configuration, bypassing the file loader entirely.

        Args:
            config: A pre-loaded :class:`~agent_shield.models.AgentConfig`.

        Returns:
            A :class:`~agent_shield.models.ScanResult` for the provided config.
        """
        result = ScanResult()
        result.scanned_files.append(config.source_path)
        findings = self._run_checks(config)
        result.findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # Check dispatch
    # ------------------------------------------------------------------

    def _run_checks(self, config: AgentConfig) -> list[Finding]:
        """Dispatch all registered checks against a single AgentConfig.

        Iterates through :attr:`checks`, calls each with the config, collects
        all :class:`~agent_shield.models.Finding` objects, and applies the
        :attr:`min_severity` filter before returning.

        Args:
            config: The normalised agent configuration to check.

        Returns:
            Filtered list of :class:`~agent_shield.models.Finding` objects.
        """
        all_findings: list[Finding] = []

        for check_fn in self.checks:
            check_name = getattr(check_fn, "__name__", repr(check_fn))
            try:
                findings = check_fn(config)
                logger.debug(
                    "%s returned %d finding(s) for %s",
                    check_name,
                    len(findings),
                    config.source_path,
                )
                all_findings.extend(findings)
            except Exception as exc:  # pragma: no cover — individual check safety net
                logger.warning(
                    "Check %s raised an unexpected error for %s: %s",
                    check_name,
                    config.source_path,
                    exc,
                    exc_info=True,
                )

        # Apply minimum severity filter
        if self.min_severity != Severity.INFO:
            all_findings = [
                f for f in all_findings if f.severity >= self.min_severity
            ]

        return all_findings

    # ------------------------------------------------------------------
    # Registry helpers
    # ------------------------------------------------------------------

    def register_check(self, check_fn: CheckFunction) -> None:
        """Add a custom check function to the scanner's registry.

        The function will be called with every :class:`~agent_shield.models.AgentConfig`
        that the scanner processes, after all existing checks.

        Args:
            check_fn: A callable accepting an :class:`~agent_shield.models.AgentConfig`
                and returning a list of :class:`~agent_shield.models.Finding` objects.
        """
        self.checks.append(check_fn)

    def unregister_check(self, check_fn: CheckFunction) -> bool:
        """Remove a check function from the scanner's registry.

        Args:
            check_fn: The check function to remove.

        Returns:
            ``True`` if the function was found and removed, ``False`` otherwise.
        """
        try:
            self.checks.remove(check_fn)
            return True
        except ValueError:
            return False


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------


def scan_file(
    path: Path,
    min_severity: Severity = Severity.INFO,
) -> ScanResult:
    """Convenience function to scan a single file with default settings.

    Creates a :class:`Scanner` with the default check registry and runs it
    against the specified file.

    Args:
        path: Path to the configuration file to scan.
        min_severity: Minimum severity for findings to include.

    Returns:
        :class:`~agent_shield.models.ScanResult` for the file.
    """
    scanner = Scanner(min_severity=min_severity)
    return scanner.scan_file(path)


def scan_directory(
    directory: Path,
    recursive: bool = False,
    min_severity: Severity = Severity.INFO,
) -> ScanResult:
    """Convenience function to scan a directory with default settings.

    Creates a :class:`Scanner` with the default check registry and runs it
    against the specified directory.

    Args:
        directory: Path to the directory to scan.
        recursive: If ``True``, scan subdirectories recursively.
        min_severity: Minimum severity for findings to include.

    Returns:
        :class:`~agent_shield.models.ScanResult` for all scanned files.
    """
    scanner = Scanner(min_severity=min_severity)
    return scanner.scan_directory(directory, recursive=recursive)
