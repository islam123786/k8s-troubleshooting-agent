"""Working out which resource a command acts on.

Two callers depend on this and they must never disagree:

* `approval._target_name` picks the word a human types to confirm a destructive
  action. Get it wrong and the prompt asks for the wrong word — which, as the
  review found, *rejects* the operator who types the real resource name and
  *accepts* the one who parrots the prompt.
* `preflight._target` picks what to snapshot. Get it wrong and the undo command
  points at a different live object, which is worse than having no undo command.

Both bugs came from the same shortcut: "the first token that doesn't start with
a dash". That treats a subcommand (`rollout undo`), a flag value (`-n chaos`)
and a resource name as the same thing.
"""

from __future__ import annotations

import pytest

from agent.targets import positionals, target_from_args, target_from_manifest

# --------------------------------------------------------------------------
# Flag values are not positionals
# --------------------------------------------------------------------------


def test_flag_values_are_not_mistaken_for_positionals():
    assert positionals(["patch", "-n", "chaos", "deployment", "web", "-p", "{}"]) == [
        "patch",
        "deployment",
        "web",
    ]


def test_attached_and_equals_flag_forms():
    assert positionals(["scale", "deploy", "web", "--replicas=2", "-nchaos"]) == [
        "scale",
        "deploy",
        "web",
    ]


def test_everything_after_the_terminator_is_ignored():
    assert positionals(["logs", "web", "--", "sh", "-c", "x"]) == ["logs", "web"]


# --------------------------------------------------------------------------
# The cases the review found broken
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        # One-word verbs
        (["scale", "deploy", "web", "--replicas=2", "-n", "chaos"], ("deploy", "web")),
        (["scale", "--replicas", "2", "deployment", "web", "-n", "chaos"], ("deployment", "web")),
        (["patch", "-n", "chaos", "deployment", "web", "-p", "{}"], ("deployment", "web")),
        (["label", "pod", "web-abc", "tier=fe", "-n", "chaos"], ("pod", "web-abc")),
        (["delete", "pod/web-abc", "-n", "chaos"], ("pod", "web-abc")),
        # Two-word verbs — the subcommand is not the kind
        (["rollout", "restart", "deployment", "web", "-n", "chaos"], ("deployment", "web")),
        (["rollout", "undo", "deploy/web", "-n", "chaos"], ("deploy", "web")),
        (["set", "image", "deployment/web", "app=nginx:1.2", "-n", "chaos"], ("deployment", "web")),
        # Node-scoped: a bare name with no kind
        (["cordon", "kind-worker"], ("node", "kind-worker")),
        (["drain", "kind-worker"], ("node", "kind-worker")),
    ],
)
def test_target_from_args(args, expected):
    assert target_from_args(args) == expected


def test_a_command_with_no_identifiable_target_returns_none():
    assert target_from_args(["get"]) is None
    assert target_from_args([]) is None
    assert target_from_args(["rollout", "restart"]) is None


# --------------------------------------------------------------------------
# apply_manifest — the tool that could never be approved
# --------------------------------------------------------------------------


def test_target_from_manifest():
    """apply_manifest passes a manifest and no argv, so the argv parser returned
    None and the gate denied every call. The tool was unusable."""
    manifest = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"
    assert target_from_manifest(manifest) == ("deployment", "web")


def test_manifest_without_a_name_returns_none():
    assert target_from_manifest("kind: Deployment\n") is None
    assert target_from_manifest("") is None
    assert target_from_manifest("not: valid: yaml: [") is None


def test_multi_document_manifest_uses_the_first_named_document():
    manifest = (
        "kind: ConfigMap\nmetadata:\n  name: cfg\n---\nkind: Deployment\nmetadata:\n  name: web\n"
    )
    assert target_from_manifest(manifest) == ("configmap", "cfg")
