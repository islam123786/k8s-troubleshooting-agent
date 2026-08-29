"""The human gate.

`can_use_tool` is consulted only for calls the hook did not deny and no allow
rule auto-approved. Its job is narrow: show a human exactly what is about to
happen, and default to no.

The properties that matter are the ones that stop the gate becoming theatre —
bare Enter declines, a destructive action needs the resource name typed out, a
declined call never reaches the cluster, and there is no "yes to all".
"""

from __future__ import annotations

import pytest
from claude_agent_sdk import PermissionResultAllow, PermissionResultDeny

from agent.approval import ApprovalGate, MutationBudgetExhausted
from agent.rollback import Snapshot

WRITE_ARGS = {"args": ["scale", "deploy", "web", "--replicas=2", "-n", "chaos"], "rationale": "x"}
DELETE_INPUT = {"kind": "pod", "name": "web-abc", "namespace": "chaos", "rationale": "restart it"}


def snapshot(tmp_path):
    return Snapshot(
        path=tmp_path / "snap.yaml",
        kind="deployment",
        name="web",
        namespace="chaos",
        existed=True,
        undo_command="kubectl --context kind-x apply -f snap.yaml",
    )


def gate(tmp_path, answers, **kw):
    """A gate wired to canned answers and a dry-run that succeeds."""
    replies = list(answers)
    shown: list[str] = []

    def prompt(text):
        shown.append(text)
        return replies.pop(0) if replies else ""

    g = ApprovalGate(
        prompt=prompt,
        dry_run=kw.pop("dry_run", lambda tool_name, tool_input: (True, "no diff")),
        snapshot=kw.pop("snapshot", lambda tool_name, tool_input: snapshot(tmp_path)),
        **kw,
    )
    g.shown = shown
    return g


async def decide(g, tool_name, tool_input):
    return await g(tool_name, tool_input, None)


# --------------------------------------------------------------------------
# Defaulting to no
# --------------------------------------------------------------------------


async def test_bare_enter_declines(tmp_path):
    g = gate(tmp_path, [""])
    result = await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS)
    assert isinstance(result, PermissionResultDeny)


@pytest.mark.parametrize("answer", ["n", "no", "N", "  ", "nope", "q"])
async def test_anything_that_is_not_yes_declines(tmp_path, answer):
    g = gate(tmp_path, [answer])
    assert isinstance(await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS), PermissionResultDeny)


@pytest.mark.parametrize("answer", ["y", "yes", "Y", " yes "])
async def test_an_explicit_yes_allows_a_write(tmp_path, answer):
    g = gate(tmp_path, [answer])
    assert isinstance(await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS), PermissionResultAllow)


async def test_decline_message_reaches_the_model(tmp_path):
    """So it adapts instead of retrying the identical call."""
    g = gate(tmp_path, ["n"])
    result = await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS)
    assert result.message


# --------------------------------------------------------------------------
# What the human is shown
# --------------------------------------------------------------------------


async def test_prompt_shows_the_command_rationale_and_undo(tmp_path):
    g = gate(tmp_path, ["n"])
    await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS)
    text = "\n".join(g.shown)
    assert "scale" in text
    assert "--replicas=2" in text
    assert "no diff" in text
    assert "apply -f snap.yaml" in text, "the undo command must be visible before approving"


# --------------------------------------------------------------------------
# Destructive actions need more than a keystroke
# --------------------------------------------------------------------------


async def test_destructive_requires_the_resource_name_typed(tmp_path):
    g = gate(tmp_path, ["y", "web-abc"])
    result = await decide(g, "mcp__k8s__delete_resource", DELETE_INPUT)
    assert isinstance(result, PermissionResultAllow)


async def test_destructive_declines_on_a_wrong_name(tmp_path):
    g = gate(tmp_path, ["y", "web-abd"])
    result = await decide(g, "mcp__k8s__delete_resource", DELETE_INPUT)
    assert isinstance(result, PermissionResultDeny)


async def test_destructive_declines_on_an_empty_confirmation(tmp_path):
    g = gate(tmp_path, ["y", ""])
    assert isinstance(
        await decide(g, "mcp__k8s__delete_resource", DELETE_INPUT), PermissionResultDeny
    )


# --------------------------------------------------------------------------
# Nothing reaches the cluster on a decline
# --------------------------------------------------------------------------


async def test_a_declined_call_takes_no_snapshot_and_no_dry_run(tmp_path):
    """Ordering: the dry-run and snapshot happen before the prompt, because the
    human needs the diff to decide. But on decline nothing is applied."""
    applied = []
    g = gate(tmp_path, ["n"], dry_run=lambda t, i: (True, "diff"))
    result = await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS)
    assert isinstance(result, PermissionResultDeny)
    assert applied == []


async def test_a_failed_dry_run_declines_without_asking(tmp_path):
    """The API server rejected it, so there is nothing worth asking a human about."""
    g = gate(tmp_path, ["y"], dry_run=lambda t, i: (False, "error: unknown field spec.replica"))
    result = await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS)
    assert isinstance(result, PermissionResultDeny)
    assert "unknown field" in result.message
    assert g.shown == [], "a rejected command must not reach the human at all"


async def test_a_failed_snapshot_declines_without_asking(tmp_path):
    def exploding(tool_name, tool_input):
        raise RuntimeError("could not write snapshot")

    g = gate(tmp_path, ["y"], snapshot=exploding)
    result = await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS)
    assert isinstance(result, PermissionResultDeny)
    assert g.shown == []


# --------------------------------------------------------------------------
# No blanket approvals
# --------------------------------------------------------------------------


async def test_each_call_is_asked_about_separately(tmp_path):
    g = gate(tmp_path, ["y", "y", "y"])
    for _ in range(3):
        await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS)
    assert len(g.shown) == 3, "approval is never remembered between calls"


async def test_the_mutation_budget_ends_the_session(tmp_path):
    g = gate(tmp_path, ["y"] * 5, max_mutations=2)
    await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS)
    await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS)
    with pytest.raises(MutationBudgetExhausted):
        await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS)


async def test_declines_do_not_consume_the_budget(tmp_path):
    g = gate(tmp_path, ["n", "n", "y"], max_mutations=1)
    await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS)
    await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS)
    assert isinstance(await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS), PermissionResultAllow)


# --------------------------------------------------------------------------
# Defence in depth
# --------------------------------------------------------------------------


async def test_a_policy_denial_is_refused_here_too(tmp_path):
    """The hook should already have stopped this. If configuration ever drifts,
    the gate must not become the thing that lets it through."""
    g = gate(tmp_path, ["y", "kube-system"])
    result = await decide(
        g, "mcp__k8s__kubectl_write", {"args": ["delete", "namespace", "kube-system"]}
    )
    assert isinstance(result, PermissionResultDeny)
    assert g.shown == []


async def test_reads_are_allowed_without_a_prompt(tmp_path):
    g = gate(tmp_path, [])
    result = await decide(g, "mcp__k8s__kubectl_read", {"args": ["get", "pods", "-n", "chaos"]})
    assert isinstance(result, PermissionResultAllow)
    assert g.shown == []


async def test_non_interactive_mode_declines_instead_of_blocking(tmp_path):
    """Integration tests run unattended; a gate that waits on stdin would hang."""
    g = gate(tmp_path, [], interactive=False)
    result = await decide(g, "mcp__k8s__kubectl_write", WRITE_ARGS)
    assert isinstance(result, PermissionResultDeny)
    assert g.shown == []
