"""PREP-016 tests: AI-file filename pattern matching."""

from __future__ import annotations

from pathlib import Path

from preprocessing import detect_ai_file


# ── Exact filename matches — byte-for-byte parity with labeling ──


def test_detect_skill_md() -> None:
    assert detect_ai_file(Path("SKILL.md")) == "skill_definition"
    assert detect_ai_file(Path("agents/coder/SKILL.md")) == "skill_definition"


def test_detect_agents_md() -> None:
    assert detect_ai_file(Path("AGENTS.md")) == "agent_config"


def test_detect_claude_md() -> None:
    assert detect_ai_file(Path("CLAUDE.md")) == "system_prompt"
    assert detect_ai_file(Path("src/module/CLAUDE.md")) == "system_prompt"


def test_detect_cursor_rules() -> None:
    assert detect_ai_file(Path(".cursorrules")) == "system_prompt"
    assert detect_ai_file(Path(".cursorrc")) == "system_prompt"


def test_detect_cline_rules() -> None:
    """Cline AI assistant rules — same role as ``.cursorrules``.

    Phase-C corpus inspection found that ``.clinerules`` was a real
    common pattern missed by the original PREP-016 list. Pattern
    matches both bare ``.clinerules`` and prefixed variants like
    ``trivy-vscode-ext.clinerules`` shipped inside extensions.
    """
    assert detect_ai_file(Path(".clinerules")) == "system_prompt"
    assert detect_ai_file(Path("trivy-vscode-ext.clinerules")) == "system_prompt"
    assert detect_ai_file(Path(".vscode/extensions/foo.clinerules")) == "system_prompt"


def test_clinerules_does_not_match_unrelated_suffixes() -> None:
    """FPR guard: filenames that just happen to end with the substring
    ``rules`` (e.g. ``firewall_rules``, ``yaml_rules``) must NOT match.
    """
    assert detect_ai_file(Path("firewall_rules.json")) is None
    assert detect_ai_file(Path("yaml_rules.yaml")) is None
    assert detect_ai_file(Path("clinerules_demo.py")) is None  # not a clinerules file


def test_detect_system_prompt() -> None:
    assert detect_ai_file(Path("system_prompt.txt")) == "system_prompt"
    assert detect_ai_file(Path("system_prompt.md")) == "system_prompt"


def test_detect_plugin_json() -> None:
    assert detect_ai_file(Path("plugin.json")) == "plugin_manifest"
    assert detect_ai_file(Path("ai-plugin.json")) == "plugin_manifest"


def test_detect_mcp_json() -> None:
    assert detect_ai_file(Path("mcp.json")) == "mcp_config"


def test_detect_openapi() -> None:
    assert detect_ai_file(Path("openapi.yaml")) == "api_schema"
    assert detect_ai_file(Path("openapi.json")) == "api_schema"


def test_detect_copilot_instructions() -> None:
    # Nested-path exact match — backslashes on Windows, forward slashes
    # on Unix, both should work.
    assert detect_ai_file(Path(".github/copilot-instructions.md")) == "system_prompt"


# ── Regex-glob matches ──


def test_detect_agent_config_glob() -> None:
    assert detect_ai_file(Path("agent_config.yaml")) == "agent_config"
    assert detect_ai_file(Path("agent-config.json")) == "agent_config"
    assert detect_ai_file(Path("agent_config.toml")) == "agent_config"
    assert detect_ai_file(Path(".claude/agents/coder.md")) == "agent_config"
    assert detect_ai_file(Path("agents/triager.yaml")) == "agent_config"


def test_detect_prompt_template_glob() -> None:
    assert detect_ai_file(Path("prompt_template.j2")) == "system_prompt"
    assert detect_ai_file(Path("prompt-template.md")) == "system_prompt"


def test_detect_mcp_prefix_glob() -> None:
    assert detect_ai_file(Path("mcp-server.json")) == "mcp_config"
    assert detect_ai_file(Path("mcp_tools.yaml")) == "mcp_config"


def test_detect_tools_glob() -> None:
    assert detect_ai_file(Path("tools.json")) == "tool_definition"
    assert detect_ai_file(Path("tool.yaml")) == "tool_definition"
    assert detect_ai_file(Path("function_call.json")) == "tool_definition"
    assert detect_ai_file(Path("functioncall.yaml")) == "tool_definition"


# ── Negative cases — should NOT match ──


def test_non_ai_files_not_detected() -> None:
    assert detect_ai_file(Path("main.py")) is None
    assert detect_ai_file(Path("README.md")) is None
    assert detect_ai_file(Path("package.json")) is None
    assert detect_ai_file(Path("requirements.txt")) is None
    assert detect_ai_file(Path("Dockerfile")) is None
    assert detect_ai_file(Path("src/utils.go")) is None


def test_case_insensitive_globs() -> None:
    # Regex globs use re.IGNORECASE, so AGENT_CONFIG.YAML also matches.
    assert detect_ai_file(Path("AGENT_CONFIG.YAML")) == "agent_config"
    assert detect_ai_file(Path("Tools.JSON")) == "tool_definition"


def test_windows_separators_handled() -> None:
    # Path strings with backslashes work too (Windows).
    assert detect_ai_file(".claude\\agents\\coder.md") == "agent_config"
    assert detect_ai_file(".github\\copilot-instructions.md") == "system_prompt"


# ── Str paths, not just Path objects ──


def test_accepts_str_input() -> None:
    # The helper accepts str | Path — same contract as other
    # preprocessing detectors.
    assert detect_ai_file("SKILL.md") == "skill_definition"
    assert detect_ai_file("foo/bar/plugin.json") == "plugin_manifest"
