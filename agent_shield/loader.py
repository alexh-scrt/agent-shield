"""Agent configuration loader for agent_shield.

This module is responsible for reading agent configuration files from disk and
normalising them into :class:`~agent_shield.models.AgentConfig` objects that
the scanner and check functions can work with uniformly, regardless of the
original file format.

Supported formats:
- **JSON** (``.json``) — parsed with the stdlib ``json`` module.
- **YAML** (``.yaml``, ``.yml``) — parsed with PyYAML.
- **Plain text** (``.txt``, ``.md``, ``.prompt``, or any unknown extension) —
  treated as a raw system prompt string.

The loader also performs light normalisation to extract common fields that
check functions frequently need:

- ``system_prompt``: extracted from well-known keys such as
  ``system_prompt``, ``system``, ``prompt``, ``instructions``.
- ``tools``: extracted from well-known keys such as ``tools``,
  ``functions``, ``actions``, ``capabilities``.
- ``metadata``: top-level scalar fields not otherwise categorised.

Usage::

    from agent_shield.loader import load_config, load_directory

    config = load_config(Path("agent.json"))
    configs = load_directory(Path("./configs"))
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from agent_shield.models import AgentConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: File extensions treated as JSON.
_JSON_EXTENSIONS: frozenset[str] = frozenset({".json"})

#: File extensions treated as YAML.
_YAML_EXTENSIONS: frozenset[str] = frozenset({".yaml", ".yml"})

#: File extensions treated as plain text (system prompt).
_TEXT_EXTENSIONS: frozenset[str] = frozenset({".txt", ".md", ".prompt", ".text"})

#: Maximum file size to attempt loading (10 MB guard).
_MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024

#: Keys checked (in order) when searching for a system prompt in parsed data.
_SYSTEM_PROMPT_KEYS: tuple[str, ...] = (
    "system_prompt",
    "system",
    "systemPrompt",
    "instructions",
    "prompt",
    "user_prompt",
    "userPrompt",
    "initial_prompt",
    "initialPrompt",
    "context",
)

#: Keys checked (in order) when searching for tool/function definitions.
_TOOLS_KEYS: tuple[str, ...] = (
    "tools",
    "functions",
    "actions",
    "capabilities",
    "plugins",
    "integrations",
    "mcp_servers",
    "mcpServers",
    "toolDefinitions",
    "tool_definitions",
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_config(path: Path) -> AgentConfig:
    """Load and normalise a single agent configuration file.

    Detects the file format from the file extension, parses the content, and
    returns a normalised :class:`~agent_shield.models.AgentConfig`.

    Args:
        path: Path to the configuration file to load.

    Returns:
        A populated :class:`~agent_shield.models.AgentConfig` instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file exceeds the maximum allowed size.
        json.JSONDecodeError: If a ``.json`` file contains invalid JSON.
        yaml.YAMLError: If a ``.yaml`` / ``.yml`` file contains invalid YAML.
        OSError: If the file cannot be read due to permission or I/O errors.
    """
    path = Path(path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {path}")

    file_size = path.stat().st_size
    if file_size > _MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"File {path} is too large ({file_size} bytes). "
            f"Maximum allowed size is {_MAX_FILE_SIZE_BYTES} bytes."
        )

    raw_text = path.read_text(encoding="utf-8", errors="replace")
    extension = path.suffix.lower()

    if extension in _JSON_EXTENSIONS:
        return _load_json(path, raw_text)
    elif extension in _YAML_EXTENSIONS:
        return _load_yaml(path, raw_text)
    else:
        # Treat everything else as plain text (system prompt)
        return _load_text(path, raw_text)


def load_directory(
    directory: Path,
    recursive: bool = False,
) -> list[AgentConfig]:
    """Load all recognised agent configuration files from a directory.

    Scans the directory for files with supported extensions (``.json``,
    ``.yaml``, ``.yml``, ``.txt``, ``.md``, ``.prompt``) and loads each one.
    Files that fail to load are logged as warnings and skipped.

    Args:
        directory: Path to the directory to scan.
        recursive: If ``True``, scan subdirectories recursively.
            Defaults to ``False``.

    Returns:
        List of successfully loaded :class:`~agent_shield.models.AgentConfig`
        objects. May be empty if no recognised files were found.

    Raises:
        NotADirectoryError: If ``directory`` does not point to a directory.
    """
    directory = Path(directory).resolve()

    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    supported_extensions = _JSON_EXTENSIONS | _YAML_EXTENSIONS | _TEXT_EXTENSIONS
    glob_pattern = "**/*" if recursive else "*"

    configs: list[AgentConfig] = []
    for file_path in sorted(directory.glob(glob_pattern)):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in supported_extensions:
            continue
        try:
            config = load_config(file_path)
            configs.append(config)
            logger.debug("Loaded config: %s", file_path)
        except (json.JSONDecodeError, yaml.YAMLError) as exc:
            logger.warning("Failed to parse %s: %s", file_path, exc)
        except (OSError, ValueError) as exc:
            logger.warning("Failed to load %s: %s", file_path, exc)

    return configs


def detect_format(path: Path) -> str:
    """Detect the configuration format from a file's extension.

    Args:
        path: Path whose extension determines the format.

    Returns:
        One of ``"json"``, ``"yaml"``, or ``"text"``.
    """
    ext = Path(path).suffix.lower()
    if ext in _JSON_EXTENSIONS:
        return "json"
    if ext in _YAML_EXTENSIONS:
        return "yaml"
    return "text"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_json(path: Path, raw_text: str) -> AgentConfig:
    """Parse a JSON config file and return a normalised AgentConfig.

    Args:
        path: Source file path (used for metadata and error messages).
        raw_text: Raw UTF-8 text content of the file.

    Returns:
        Normalised :class:`~agent_shield.models.AgentConfig`.

    Raises:
        json.JSONDecodeError: On invalid JSON syntax.
    """
    try:
        data: Any = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise json.JSONDecodeError(
            f"Invalid JSON in {path}: {exc.msg}",
            exc.doc,
            exc.pos,
        ) from exc

    return _build_config(path=path, raw_text=raw_text, fmt="json", data=data)


def _load_yaml(path: Path, raw_text: str) -> AgentConfig:
    """Parse a YAML config file and return a normalised AgentConfig.

    Args:
        path: Source file path (used for metadata and error messages).
        raw_text: Raw UTF-8 text content of the file.

    Returns:
        Normalised :class:`~agent_shield.models.AgentConfig`.

    Raises:
        yaml.YAMLError: On invalid YAML syntax.
    """
    try:
        data: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise yaml.YAMLError(f"Invalid YAML in {path}: {exc}") from exc

    # yaml.safe_load returns None for an empty file
    if data is None:
        data = {}

    return _build_config(path=path, raw_text=raw_text, fmt="yaml", data=data)


def _load_text(path: Path, raw_text: str) -> AgentConfig:
    """Treat a plain-text file as a raw system prompt.

    Args:
        path: Source file path.
        raw_text: Raw text content treated as the system prompt.

    Returns:
        Normalised :class:`~agent_shield.models.AgentConfig` with
        ``system_prompt`` set to the file contents.
    """
    return AgentConfig(
        source_path=path,
        raw_text=raw_text,
        format="text",
        data={},
        system_prompt=raw_text.strip(),
        tools=[],
        metadata={"filename": path.name},
    )


def _build_config(
    path: Path,
    raw_text: str,
    fmt: str,
    data: Any,
) -> AgentConfig:
    """Build a normalised AgentConfig from parsed structured data.

    Extracts the system prompt, tool list, and metadata from the parsed data
    dictionary (or list) using well-known key names.

    Args:
        path: Source file path.
        raw_text: Original raw text of the file.
        fmt: Format string (``"json"`` or ``"yaml"``).
        data: Parsed Python object (dict, list, or scalar).

    Returns:
        Populated :class:`~agent_shield.models.AgentConfig`.
    """
    # Normalise top-level data to a dict for uniform processing
    if isinstance(data, list):
        # Some configs (e.g. OpenAI function arrays) are bare lists of tools
        data_dict: dict[str, Any] = {"tools": data}
    elif isinstance(data, dict):
        data_dict = data
    else:
        # Scalar at top level — treat entire file as a text prompt
        return AgentConfig(
            source_path=path,
            raw_text=raw_text,
            format=fmt,
            data={},
            system_prompt=str(data).strip(),
            tools=[],
            metadata={},
        )

    system_prompt = _extract_system_prompt(data_dict)
    tools = _extract_tools(data_dict)
    metadata = _extract_metadata(data_dict)

    return AgentConfig(
        source_path=path,
        raw_text=raw_text,
        format=fmt,
        data=data_dict,
        system_prompt=system_prompt,
        tools=tools,
        metadata=metadata,
    )


def _extract_system_prompt(data: dict[str, Any]) -> str:
    """Extract the system prompt string from a parsed config dict.

    Checks a prioritised list of well-known key names. Returns the first
    non-empty string value found, or an empty string if none is found.

    Args:
        data: Parsed top-level config dictionary.

    Returns:
        System prompt string, or ``""`` if not found.
    """
    for key in _SYSTEM_PROMPT_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    # Check one level deeper — some configs nest under "agent" or "config"
    for outer_key in ("agent", "config", "settings", "llm", "model"):
        nested = data.get(outer_key)
        if isinstance(nested, dict):
            for key in _SYSTEM_PROMPT_KEYS:
                value = nested.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()

    return ""


def _extract_tools(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract tool/function definition list from a parsed config dict.

    Checks a prioritised list of well-known key names. Returns the first
    non-empty list found, filtering out any non-dict items.

    Also handles MCP-style configs where tools are nested under server entries.

    Args:
        data: Parsed top-level config dictionary.

    Returns:
        List of tool definition dicts, possibly empty.
    """
    # Direct top-level keys
    for key in _TOOLS_KEYS:
        value = data.get(key)
        if isinstance(value, list) and value:
            tools = [item for item in value if isinstance(item, dict)]
            if tools:
                return tools
            # If it's a list but not of dicts, keep looking

    # MCP-style: mcpServers is a dict of server_name → server_config
    for mcp_key in ("mcpServers", "mcp_servers"):
        mcp_value = data.get(mcp_key)
        if isinstance(mcp_value, dict):
            return _flatten_mcp_servers(mcp_value)

    # Check one level deeper under common wrapper keys
    for outer_key in ("agent", "config", "settings"):
        nested = data.get(outer_key)
        if isinstance(nested, dict):
            for key in _TOOLS_KEYS:
                value = nested.get(key)
                if isinstance(value, list):
                    tools = [item for item in value if isinstance(item, dict)]
                    if tools:
                        return tools

    return []


def _flatten_mcp_servers(mcp_servers: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert an MCP servers dict into a flat list of tool-like dicts.

    MCP configs typically look like::

        {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "permissions": ["read", "write", "delete"]
                }
            }
        }

    Each server entry is converted to a dict with a ``"name"`` key added.

    Args:
        mcp_servers: The value of the ``mcpServers`` / ``mcp_servers`` key.

    Returns:
        List of normalised tool dicts.
    """
    tools: list[dict[str, Any]] = []
    for server_name, server_config in mcp_servers.items():
        if isinstance(server_config, dict):
            tool_entry: dict[str, Any] = {"name": server_name, **server_config}
            tools.append(tool_entry)
        else:
            tools.append({"name": server_name, "config": server_config})
    return tools


def _extract_metadata(data: dict[str, Any]) -> dict[str, Any]:
    """Extract top-level scalar metadata fields from a parsed config dict.

    Collects all top-level key-value pairs whose values are scalars (str, int,
    float, bool) and that are not themselves the system prompt or tools list.
    This gives check functions easy access to fields like ``name``, ``version``,
    ``model``, ``temperature``, etc.

    Args:
        data: Parsed top-level config dictionary.

    Returns:
        Dict of scalar metadata fields.
    """
    # Keys to skip because they are handled by dedicated extractors
    skip_keys: frozenset[str] = frozenset(_SYSTEM_PROMPT_KEYS) | frozenset(
        _TOOLS_KEYS
    ) | frozenset(
        ("mcpServers", "mcp_servers", "agent", "config", "settings", "llm", "model")
    )

    metadata: dict[str, Any] = {}
    for key, value in data.items():
        if key in skip_keys:
            continue
        if isinstance(value, (str, int, float, bool)):
            metadata[key] = value
        elif isinstance(value, dict):
            # Include nested dicts under common metadata keys
            if key in ("permissions", "scopes", "access", "auth", "security"):
                metadata[key] = value

    return metadata
