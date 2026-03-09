"""Unit tests for agent_shield.loader — config file loader."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
import yaml

from agent_shield.loader import (
    _extract_metadata,
    _extract_system_prompt,
    _extract_tools,
    _flatten_mcp_servers,
    detect_format,
    load_config,
    load_directory,
)
from agent_shield.models import AgentConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_file(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a temp file and return its path."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# detect_format
# ---------------------------------------------------------------------------


class TestDetectFormat:
    """Tests for detect_format()."""

    def test_json_extension(self) -> None:
        assert detect_format(Path("agent.json")) == "json"

    def test_yaml_extension(self) -> None:
        assert detect_format(Path("agent.yaml")) == "yaml"

    def test_yml_extension(self) -> None:
        assert detect_format(Path("agent.yml")) == "yaml"

    def test_txt_extension(self) -> None:
        assert detect_format(Path("prompt.txt")) == "text"

    def test_md_extension(self) -> None:
        assert detect_format(Path("README.md")) == "text"

    def test_prompt_extension(self) -> None:
        assert detect_format(Path("system.prompt")) == "text"

    def test_unknown_extension_defaults_to_text(self) -> None:
        assert detect_format(Path("config.xyz")) == "text"


# ---------------------------------------------------------------------------
# load_config — JSON
# ---------------------------------------------------------------------------


class TestLoadConfigJson:
    """Tests for loading JSON config files."""

    def test_basic_json_loading(self, tmp_path: Path) -> None:
        """A minimal JSON config loads without errors."""
        p = write_file(tmp_path, "agent.json", json.dumps({"name": "test_agent"}))
        config = load_config(p)
        assert isinstance(config, AgentConfig)
        assert config.format == "json"
        assert config.source_path == p

    def test_system_prompt_extracted(self, tmp_path: Path) -> None:
        """system_prompt key is extracted correctly."""
        data = {"system_prompt": "You are a helpful assistant."}
        p = write_file(tmp_path, "agent.json", json.dumps(data))
        config = load_config(p)
        assert config.system_prompt == "You are a helpful assistant."

    def test_system_key_fallback(self, tmp_path: Path) -> None:
        """'system' key is used as fallback for system_prompt."""
        data = {"system": "You are a coding assistant."}
        p = write_file(tmp_path, "agent.json", json.dumps(data))
        config = load_config(p)
        assert config.system_prompt == "You are a coding assistant."

    def test_tools_extracted(self, tmp_path: Path) -> None:
        """tools list is extracted correctly."""
        data = {
            "tools": [
                {"name": "search", "description": "Search the web"},
                {"name": "calculator", "description": "Do maths"},
            ]
        }
        p = write_file(tmp_path, "agent.json", json.dumps(data))
        config = load_config(p)
        assert len(config.tools) == 2
        assert config.tools[0]["name"] == "search"

    def test_functions_key_fallback(self, tmp_path: Path) -> None:
        """'functions' key is used as fallback for tools."""
        data = {
            "functions": [
                {"name": "get_weather", "description": "Get weather data"}
            ]
        }
        p = write_file(tmp_path, "agent.json", json.dumps(data))
        config = load_config(p)
        assert len(config.tools) == 1
        assert config.tools[0]["name"] == "get_weather"

    def test_bare_list_of_tools(self, tmp_path: Path) -> None:
        """A top-level JSON array is treated as a list of tools."""
        data = [
            {"name": "tool_a", "description": "Does A"},
            {"name": "tool_b", "description": "Does B"},
        ]
        p = write_file(tmp_path, "tools.json", json.dumps(data))
        config = load_config(p)
        assert len(config.tools) == 2

    def test_mcp_servers_extracted(self, tmp_path: Path) -> None:
        """MCP-style mcpServers dict is flattened into tool list."""
        data = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    "permissions": ["read", "write", "delete"],
                }
            }
        }
        p = write_file(tmp_path, "mcp.json", json.dumps(data))
        config = load_config(p)
        assert len(config.tools) == 1
        assert config.tools[0]["name"] == "filesystem"
        assert config.tools[0]["command"] == "npx"

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        """Invalid JSON raises json.JSONDecodeError."""
        p = write_file(tmp_path, "bad.json", "{not valid json}")
        with pytest.raises(json.JSONDecodeError):
            load_config(p)

    def test_raw_text_preserved(self, tmp_path: Path) -> None:
        """raw_text attribute holds the original file content."""
        content = json.dumps({"name": "test"})
        p = write_file(tmp_path, "agent.json", content)
        config = load_config(p)
        assert config.raw_text == content

    def test_metadata_extracted(self, tmp_path: Path) -> None:
        """Top-level scalar fields appear in metadata."""
        data = {
            "name": "my_agent",
            "version": "1.0",
            "temperature": 0.7,
            "system_prompt": "You are helpful.",
        }
        p = write_file(tmp_path, "agent.json", json.dumps(data))
        config = load_config(p)
        assert config.metadata.get("name") == "my_agent"
        assert config.metadata.get("version") == "1.0"
        # system_prompt should not appear in metadata
        assert "system_prompt" not in config.metadata


# ---------------------------------------------------------------------------
# load_config — YAML
# ---------------------------------------------------------------------------


class TestLoadConfigYaml:
    """Tests for loading YAML config files."""

    def test_basic_yaml_loading(self, tmp_path: Path) -> None:
        """A minimal YAML config loads without errors."""
        content = textwrap.dedent("""
            name: test_agent
            version: "1.0"
        """)
        p = write_file(tmp_path, "agent.yaml", content)
        config = load_config(p)
        assert isinstance(config, AgentConfig)
        assert config.format == "yaml"

    def test_system_prompt_extracted_yaml(self, tmp_path: Path) -> None:
        """system_prompt is extracted from YAML."""
        content = textwrap.dedent("""
            system_prompt: |
              You are a helpful YAML assistant.
        """)
        p = write_file(tmp_path, "agent.yaml", content)
        config = load_config(p)
        assert "helpful YAML assistant" in config.system_prompt

    def test_tools_extracted_yaml(self, tmp_path: Path) -> None:
        """tools list is extracted from YAML."""
        content = textwrap.dedent("""
            tools:
              - name: search
                description: Search the web
              - name: calculator
                description: Do maths
        """)
        p = write_file(tmp_path, "agent.yaml", content)
        config = load_config(p)
        assert len(config.tools) == 2

    def test_empty_yaml_file(self, tmp_path: Path) -> None:
        """An empty YAML file loads as empty config."""
        p = write_file(tmp_path, "empty.yaml", "")
        config = load_config(p)
        assert config.format == "yaml"
        assert config.system_prompt == ""
        assert config.tools == []

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        """Invalid YAML raises yaml.YAMLError."""
        p = write_file(tmp_path, "bad.yaml", "key: [unclosed")
        with pytest.raises(yaml.YAMLError):
            load_config(p)

    def test_yml_extension_works(self, tmp_path: Path) -> None:
        """Files with .yml extension are also loaded as YAML."""
        p = write_file(tmp_path, "agent.yml", "name: my_agent\n")
        config = load_config(p)
        assert config.format == "yaml"


# ---------------------------------------------------------------------------
# load_config — plain text
# ---------------------------------------------------------------------------


class TestLoadConfigText:
    """Tests for loading plain-text config files."""

    def test_txt_file_loaded_as_system_prompt(self, tmp_path: Path) -> None:
        """A .txt file is loaded as a plain-text system prompt."""
        content = "You are a helpful assistant. Always answer politely."
        p = write_file(tmp_path, "system.txt", content)
        config = load_config(p)
        assert config.format == "text"
        assert config.system_prompt == content
        assert config.tools == []
        assert config.data == {}

    def test_md_file_loaded_as_system_prompt(self, tmp_path: Path) -> None:
        """A .md file is loaded as a plain-text system prompt."""
        content = "# System Prompt\n\nBe helpful and concise."
        p = write_file(tmp_path, "prompt.md", content)
        config = load_config(p)
        assert config.format == "text"
        assert "helpful and concise" in config.system_prompt

    def test_prompt_extension_loaded_as_text(self, tmp_path: Path) -> None:
        """A .prompt file is loaded as a plain-text system prompt."""
        content = "You are an expert Python developer."
        p = write_file(tmp_path, "system.prompt", content)
        config = load_config(p)
        assert config.format == "text"
        assert config.system_prompt == content

    def test_text_raw_text_matches_content(self, tmp_path: Path) -> None:
        """raw_text holds the full original content."""
        content = "You are helpful.\n\nAlways be polite."
        p = write_file(tmp_path, "system.txt", content)
        config = load_config(p)
        assert config.raw_text == content


# ---------------------------------------------------------------------------
# load_config — error cases
# ---------------------------------------------------------------------------


class TestLoadConfigErrors:
    """Tests for error handling in load_config()."""

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        """FileNotFoundError is raised for non-existent files."""
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.json")

    def test_directory_path_raises(self, tmp_path: Path) -> None:
        """ValueError is raised if path points to a directory."""
        with pytest.raises(ValueError):
            load_config(tmp_path)


# ---------------------------------------------------------------------------
# load_directory
# ---------------------------------------------------------------------------


class TestLoadDirectory:
    """Tests for load_directory()."""

    def test_loads_json_and_yaml(self, tmp_path: Path) -> None:
        """JSON and YAML files in a directory are both loaded."""
        write_file(tmp_path, "a.json", json.dumps({"name": "agent_a"}))
        write_file(tmp_path, "b.yaml", "name: agent_b\n")
        configs = load_directory(tmp_path)
        assert len(configs) == 2

    def test_loads_text_files(self, tmp_path: Path) -> None:
        """Text files (.txt) are loaded from the directory."""
        write_file(tmp_path, "prompt.txt", "You are helpful.")
        configs = load_directory(tmp_path)
        assert len(configs) == 1
        assert configs[0].format == "text"

    def test_ignores_unsupported_extensions(self, tmp_path: Path) -> None:
        """Files with unsupported extensions are ignored."""
        write_file(tmp_path, "script.py", "print('hello')")
        write_file(tmp_path, "data.csv", "a,b,c")
        write_file(tmp_path, "config.json", json.dumps({"name": "agent"}))
        configs = load_directory(tmp_path)
        assert len(configs) == 1  # only the JSON file

    def test_bad_json_skipped_not_raised(self, tmp_path: Path) -> None:
        """Invalid JSON files are skipped with a warning, not raising."""
        write_file(tmp_path, "bad.json", "{not valid json}")
        write_file(tmp_path, "good.json", json.dumps({"name": "ok"}))
        configs = load_directory(tmp_path)
        assert len(configs) == 1
        assert configs[0].metadata.get("name") == "ok"

    def test_non_directory_raises(self, tmp_path: Path) -> None:
        """NotADirectoryError is raised if path is not a directory."""
        p = write_file(tmp_path, "file.json", "{}")
        with pytest.raises(NotADirectoryError):
            load_directory(p)

    def test_recursive_option(self, tmp_path: Path) -> None:
        """recursive=True loads files in subdirectories."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        write_file(subdir, "nested.json", json.dumps({"name": "nested_agent"}))
        write_file(tmp_path, "top.json", json.dumps({"name": "top_agent"}))

        configs_non_recursive = load_directory(tmp_path, recursive=False)
        configs_recursive = load_directory(tmp_path, recursive=True)

        assert len(configs_non_recursive) == 1
        assert len(configs_recursive) == 2

    def test_empty_directory_returns_empty_list(self, tmp_path: Path) -> None:
        """An empty directory returns an empty list."""
        configs = load_directory(tmp_path)
        assert configs == []


# ---------------------------------------------------------------------------
# Internal helper unit tests
# ---------------------------------------------------------------------------


class TestExtractSystemPrompt:
    """Unit tests for _extract_system_prompt()."""

    def test_system_prompt_key(self) -> None:
        assert _extract_system_prompt({"system_prompt": "Hello"}) == "Hello"

    def test_system_key_fallback(self) -> None:
        assert _extract_system_prompt({"system": "Hello"}) == "Hello"

    def test_prompt_key_fallback(self) -> None:
        assert _extract_system_prompt({"prompt": "Hello"}) == "Hello"

    def test_instructions_key_fallback(self) -> None:
        assert _extract_system_prompt({"instructions": "Hello"}) == "Hello"

    def test_priority_order(self) -> None:
        """system_prompt takes priority over system."""
        data = {"system_prompt": "First", "system": "Second"}
        assert _extract_system_prompt(data) == "First"

    def test_returns_empty_string_if_not_found(self) -> None:
        assert _extract_system_prompt({"name": "agent"}) == ""

    def test_nested_agent_key(self) -> None:
        """system_prompt nested under 'agent' key is found."""
        data = {"agent": {"system_prompt": "Nested prompt"}}
        assert _extract_system_prompt(data) == "Nested prompt"


class TestExtractTools:
    """Unit tests for _extract_tools()."""

    def test_tools_key(self) -> None:
        data = {"tools": [{"name": "t1"}, {"name": "t2"}]}
        tools = _extract_tools(data)
        assert len(tools) == 2

    def test_functions_key(self) -> None:
        data = {"functions": [{"name": "f1"}]}
        tools = _extract_tools(data)
        assert len(tools) == 1
        assert tools[0]["name"] == "f1"

    def test_non_dict_items_filtered_out(self) -> None:
        data = {"tools": [{"name": "t1"}, "not_a_dict", 42]}
        tools = _extract_tools(data)
        assert len(tools) == 1

    def test_returns_empty_if_no_tools(self) -> None:
        data = {"name": "agent", "system_prompt": "Hello"}
        assert _extract_tools(data) == []


class TestFlattenMcpServers:
    """Unit tests for _flatten_mcp_servers()."""

    def test_single_server(self) -> None:
        servers = {"filesystem": {"command": "npx", "args": ["--flag"]}}
        tools = _flatten_mcp_servers(servers)
        assert len(tools) == 1
        assert tools[0]["name"] == "filesystem"
        assert tools[0]["command"] == "npx"

    def test_multiple_servers(self) -> None:
        servers = {
            "server_a": {"command": "a"},
            "server_b": {"command": "b"},
        }
        tools = _flatten_mcp_servers(servers)
        assert len(tools) == 2
        names = {t["name"] for t in tools}
        assert names == {"server_a", "server_b"}

    def test_non_dict_server_config(self) -> None:
        """A server config that is not a dict is still wrapped."""
        servers = {"odd_server": "some_string"}
        tools = _flatten_mcp_servers(servers)
        assert len(tools) == 1
        assert tools[0]["name"] == "odd_server"
        assert tools[0]["config"] == "some_string"


class TestExtractMetadata:
    """Unit tests for _extract_metadata()."""

    def test_extracts_scalar_fields(self) -> None:
        data = {"name": "agent", "version": "1.0", "temperature": 0.7}
        meta = _extract_metadata(data)
        assert meta["name"] == "agent"
        assert meta["version"] == "1.0"
        assert meta["temperature"] == 0.7

    def test_skips_system_prompt_keys(self) -> None:
        data = {"system_prompt": "Hello", "name": "agent"}
        meta = _extract_metadata(data)
        assert "system_prompt" not in meta
        assert "name" in meta

    def test_skips_tools_keys(self) -> None:
        data = {"tools": [{"name": "t1"}], "version": "2.0"}
        meta = _extract_metadata(data)
        assert "tools" not in meta
        assert "version" in meta

    def test_includes_permissions_dict(self) -> None:
        data = {"permissions": {"read": True, "write": False}, "name": "agent"}
        meta = _extract_metadata(data)
        assert "permissions" in meta
        assert meta["permissions"]["read"] is True
