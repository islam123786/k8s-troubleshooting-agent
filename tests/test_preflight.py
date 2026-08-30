"""Dry run and snapshot — what happens between the model asking and the human deciding.

The snapshot has to name the *right* resource. A snapshot of the wrong object
produces an undo command that points somewhere else, which is worse than having
no undo command at all: it looks like a safety net and isn't one.
"""

from __future__ import annotations

import pytest

from agent.policy import PINNED_CONTEXT
from agent.preflight import _target, make_snapshotter


def ok_runner(argv, stdin, timeout):
    return 0, "kind: Deployment\nmetadata:\n  name: web\n", ""


# --------------------------------------------------------------------------
# Identifying the target
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool_input", "expected"),
    [
        # The structured tools carry it explicitly.
        (
            {"kind": "pod", "name": "web-abc", "namespace": "chaos"},
            ("pod", "web-abc", "chaos"),
        ),
        # One-word verbs.
        (
            {"args": ["scale", "deploy", "web", "--replicas=2", "-n", "chaos"]},
            ("deploy", "web", "chaos"),
        ),
        (
            {"args": ["patch", "-n", "chaos", "deployment", "web", "-p", "{}"]},
            ("deployment", "web", "chaos"),
        ),
        # Two-word verbs: the subcommand is not the kind. These used to resolve to
        # kind "restart"/"undo"/"image", so the snapshot always failed and the two
        # commonest Kubernetes fixes could never be approved.
        (
            {"args": ["rollout", "restart", "deployment", "web", "-n", "chaos"]},
            ("deployment", "web", "chaos"),
        ),
        (
            {"args": ["rollout", "undo", "deploy/web", "-n", "chaos"]},
            ("deploy", "web", "chaos"),
        ),
        (
            {"args": ["set", "image", "deployment/web", "app=nginx:1.2", "-n", "chaos"]},
            ("deployment", "web", "chaos"),
        ),
    ],
)
def test_target_is_identified(tool_input, expected):
    assert _target(tool_input) == expected


def test_the_attached_namespace_form_is_understood():
    """policy._namespace_values accepts -nchaos, so preflight must too — otherwise
    the call is approved for `chaos` while the snapshot reads namespace "", which
    kubectl resolves to the context default. That snapshots a *different live
    object* and prints an undo command pointing at it."""
    assert _target({"args": ["scale", "deploy", "web", "--replicas=2", "-nchaos"]}) == (
        "deploy",
        "web",
        "chaos",
    )


def test_apply_manifest_target_comes_from_the_manifest():
    """apply_manifest carries no argv. This returned None, so the gate denied every
    call with 'could not capture a rollback snapshot' — the tool was unusable."""
    assert _target(
        {
            "manifest": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
            "namespace": "chaos",
        }
    ) == ("deployment", "web", "chaos")


def test_an_unidentifiable_target_is_none():
    assert _target({"args": ["get"]}) is None
    assert _target({}) is None


# --------------------------------------------------------------------------
# The snapshotter refuses rather than guessing
# --------------------------------------------------------------------------


def test_an_empty_namespace_is_refused(tmp_path):
    """kubectl resolves `-n ""` to the context default, silently snapshotting the
    wrong object. Better to abandon the mutation."""
    snapshot = make_snapshotter(root=tmp_path)
    with pytest.raises(RuntimeError):
        snapshot("mcp__k8s__kubectl_write", {"args": ["scale", "deploy", "web", "--replicas=2"]})


def test_an_unidentifiable_target_is_refused(tmp_path):
    snapshot = make_snapshotter(root=tmp_path)
    with pytest.raises(RuntimeError):
        snapshot("mcp__k8s__kubectl_write", {"args": ["get"]})


def test_the_undo_command_is_shell_safe(tmp_path):
    """The undo command is copy-pasted by a human, so a path with a space in it
    must not silently become two arguments."""
    import shlex

    from agent import rollback

    spaced = tmp_path / "dir with space"
    snap = rollback.capture("deployment", "web", "chaos", root=spaced, runner=ok_runner)
    tokens = shlex.split(snap.undo_command)
    assert str(snap.path) in tokens, "the snapshot path must survive shell splitting intact"
    assert PINNED_CONTEXT in tokens
