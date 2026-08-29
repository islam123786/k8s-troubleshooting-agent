"""The unbypassable choke point at the SDK layer.

The Agent SDK evaluates permissions in a fixed order:

    hooks -> deny rules -> ask rules -> permission mode -> allow rules -> can_use_tool

Hooks run *first*, and a hook `deny` holds even in `bypassPermissions` mode. That
makes `PreToolUse` the only place a check is guaranteed to run on every single
tool call — including calls made inside the subagent, and including tools that an
`allowed_tools` entry would otherwise auto-approve without ever consulting
`can_use_tool`.

So the policy is enforced here, and `can_use_tool` is left to do only what it is
good at: asking a human.
"""

from __future__ import annotations

import json

import pytest

from agent.audit import AuditLog
from agent.hooks import make_guardrail_hook
from agent.policy import Verdict


@pytest.fixture
def log(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def hook(log):
    return make_guardrail_hook(audit_log=log)


def entries(log):
    return [json.loads(line) for line in log.path.read_text().splitlines() if line.strip()]


def call(tool_name, tool_input=None, **extra):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input or {},
        **extra,
    }


# --------------------------------------------------------------------------
# Deny shape
# --------------------------------------------------------------------------


async def test_denied_call_returns_the_documented_deny_shape(hook):
    out = await hook(call("Bash", {"command": "kubectl delete ns kube-system"}), None, None)
    decision = out["hookSpecificOutput"]
    assert decision["hookEventName"] == "PreToolUse"
    assert decision["permissionDecision"] == "deny"
    assert decision["permissionDecisionReason"]


async def test_deny_reason_is_the_policy_reason(hook):
    out = await hook(
        call("mcp__k8s__kubectl_write", {"args": ["delete", "namespace", "chaos"]}), None, None
    )
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "delete_resource" in reason or "namespace" in reason.lower()


async def test_hook_event_name_is_echoed_from_the_input(hook):
    """The SDK matches the returned block against the event that fired it."""
    payload = call("Bash", {"command": "ls"})
    payload["hook_event_name"] = "PreToolUse"
    out = await hook(payload, None, None)
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"


# --------------------------------------------------------------------------
# Allowing
# --------------------------------------------------------------------------


async def test_permitted_call_returns_an_empty_object(hook):
    """An empty dict means 'no opinion' — the call continues down the normal
    permission flow. Returning an explicit allow would be wrong: it would signal
    a decision the hook is not the right layer to make."""
    out = await hook(
        call("mcp__k8s__kubectl_read", {"args": ["get", "pods", "-n", "chaos"]}), None, None
    )
    assert out == {}


async def test_mutations_are_not_denied_here_but_passed_on_to_the_approval_gate(hook):
    out = await hook(
        call(
            "mcp__k8s__kubectl_write",
            {"args": ["scale", "deploy", "web", "--replicas=2", "-n", "chaos"]},
        ),
        None,
        None,
    )
    assert out == {}


# --------------------------------------------------------------------------
# Auditing
# --------------------------------------------------------------------------


async def test_every_call_is_audited_before_it_runs(hook, log):
    await hook(call("mcp__k8s__kubectl_read", {"args": ["get", "pods", "-n", "chaos"]}), None, None)
    (row,) = entries(log)
    assert row["event"] == "attempt"
    assert row["verdict"] == Verdict.READ.value


async def test_denials_are_audited_too(hook, log):
    await hook(call("Bash", {"command": "rm -rf /"}), None, None)
    (row,) = entries(log)
    assert row["verdict"] == Verdict.DENY.value
    assert row["tool_name"] == "Bash"


async def test_subagent_calls_are_attributed(hook, log):
    """PreToolUse carries agent_id when it fires inside a subagent, and the hook
    fires there too — which is what puts the specialist under the same policy."""
    await hook(
        call(
            "mcp__k8s__kubectl_read",
            {"args": ["get", "pods", "-n", "chaos"]},
            agent_id="kubernetes-specialist",
        ),
        "toolu_123",
        None,
    )
    (row,) = entries(log)
    assert row["agent_id"] == "kubernetes-specialist"
    assert row["tool_use_id"] == "toolu_123"


# --------------------------------------------------------------------------
# Failing closed
# --------------------------------------------------------------------------


async def test_an_unrecognised_tool_is_denied(hook):
    out = await hook(call("SomeFutureTool", {"anything": 1}), None, None)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


async def test_a_malformed_payload_is_denied_not_crashed(hook):
    """A hook that raises would surface as an error, and an error is not a denial."""
    for payload in ({}, {"tool_name": None}, {"hook_event_name": "PreToolUse"}):
        out = await hook(payload, None, None)
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


async def test_an_internal_error_denies_rather_than_allowing(log, monkeypatch):
    """If classification itself breaks, the safe answer is no."""
    import agent.hooks as hooks_module

    def exploding(*args, **kwargs):
        raise RuntimeError("classifier is broken")

    monkeypatch.setattr(hooks_module, "classify", exploding)
    hook = make_guardrail_hook(audit_log=log)
    out = await hook(call("mcp__k8s__kubectl_read", {"args": ["get", "pods"]}), None, None)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


async def test_an_audit_failure_does_not_let_a_denial_through(log, monkeypatch):
    def exploding(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(log, "attempt", exploding)
    hook = make_guardrail_hook(audit_log=log)
    out = await hook(call("Bash", {"command": "ls"}), None, None)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


async def test_writable_namespaces_are_honoured(log):
    hook = make_guardrail_hook(audit_log=log, writable_namespaces=frozenset({"staging"}))
    args = {"args": ["scale", "deploy", "web", "--replicas=2", "-n", "staging"]}
    assert await hook(call("mcp__k8s__kubectl_write", args), None, None) == {}

    strict = make_guardrail_hook(audit_log=log)
    out = await strict(call("mcp__k8s__kubectl_write", args), None, None)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
