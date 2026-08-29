"""What the model is even allowed to see.

The Agent SDK ships Bash, Write, Edit and the web tools by default, so this
project's first job is subtraction. A bare-name entry in `disallowed_tools`
removes the tool definition from the request entirely — the model cannot call it,
cannot be argued into calling it, and cannot see that it exists.

Removing `Bash` is the single most load-bearing line in the project. With a shell
available, every kubectl guardrail is decoration, because the agent could simply
shell out.
"""

from __future__ import annotations

import pytest

from agent.audit import AuditLog
from agent.options import (
    READ_ONLY_TOOLS,
    WRITE_TOOLS,
    build_options,
)


@pytest.fixture
def opts(tmp_path):
    return build_options(audit_log=AuditLog(tmp_path / "a.jsonl"), project_root=tmp_path)


@pytest.fixture
def write_opts(tmp_path):
    return build_options(
        audit_log=AuditLog(tmp_path / "a.jsonl"), project_root=tmp_path, allow_writes=True
    )


# --------------------------------------------------------------------------
# Capability removal
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool",
    ["Bash", "BashOutput", "KillShell", "Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch"],
)
def test_dangerous_builtins_are_removed_by_bare_name(opts, tool):
    """Bare names strip the definition; a scoped rule like Bash(rm *) would leave
    the tool available and only filter calls, which is not what we want here."""
    assert tool in opts.disallowed_tools
    assert not any(entry.startswith(f"{tool}(") for entry in opts.disallowed_tools)


def test_bash_is_removed_even_with_writes_enabled(write_opts):
    assert "Bash" in write_opts.disallowed_tools


# --------------------------------------------------------------------------
# Write tools are absent unless asked for
# --------------------------------------------------------------------------


def test_write_tools_are_not_registered_by_default(opts):
    for tool in WRITE_TOOLS:
        assert tool not in opts.allowed_tools


def test_read_only_tools_are_auto_approved(opts):
    for tool in READ_ONLY_TOOLS:
        assert tool in opts.allowed_tools


def test_dont_ask_mode_is_used_when_read_only(opts):
    """Anything not pre-approved is denied outright rather than prompting — there
    is nothing a human could usefully approve in a diagnose-only session."""
    assert opts.permission_mode == "dontAsk"


def test_write_mode_prompts_rather_than_denying(write_opts):
    assert write_opts.permission_mode == "default"
    assert write_opts.can_use_tool is not None


def test_write_tools_are_never_auto_approved(write_opts):
    """An allow rule would bypass can_use_tool entirely and silently skip the
    approval prompt. Write tools must fall through to the callback."""
    for tool in WRITE_TOOLS:
        assert tool not in write_opts.allowed_tools


# --------------------------------------------------------------------------
# Hook registration
# --------------------------------------------------------------------------


def test_the_guardrail_hook_is_registered_without_a_matcher(opts):
    """A matcher would scope it to named tools; the policy must see everything."""
    matchers = opts.hooks["PreToolUse"]
    assert matchers
    assert all(getattr(m, "matcher", None) in (None, "", "*") for m in matchers)
    assert all(m.hooks for m in matchers)


def test_the_hook_is_registered_in_both_modes(opts, write_opts):
    assert opts.hooks["PreToolUse"]
    assert write_opts.hooks["PreToolUse"]


# --------------------------------------------------------------------------
# Configuration determinism
# --------------------------------------------------------------------------


def test_only_project_settings_are_loaded(opts):
    """Excluding "user" and "local" keeps a developer's personal ~/.claude out of
    the agent's configuration, so a run is reproducible."""
    assert opts.setting_sources == ["project"]


def test_model_and_effort_are_pinned(opts):
    assert opts.model == "claude-opus-5"
    assert opts.effort in ("high", "xhigh")
    assert opts.thinking == {"type": "adaptive"}


def test_runaway_limits_are_set(opts):
    assert opts.max_turns and opts.max_turns > 0
    assert opts.max_budget_usd and opts.max_budget_usd > 0


def test_the_specialist_subagent_is_read_only(opts):
    specialist = opts.agents["kubernetes-specialist"]
    assert "Bash" in (specialist.disallowedTools or [])
    for tool in WRITE_TOOLS:
        assert tool not in (specialist.tools or [])


def test_cwd_is_the_project_root(opts, tmp_path):
    assert str(opts.cwd) == str(tmp_path)
