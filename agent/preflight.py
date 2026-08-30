"""What runs between the model asking for a change and a human being asked to approve it.

Two steps, both of which must succeed or the change is abandoned:

* **Dry run.** The mutation is sent to the API server with `--dry-run=server`
  first. A change the server would reject never reaches a human, because there is
  nothing useful to approve — and a malformed fix is caught by Kubernetes rather
  than by the cluster.
* **Snapshot.** The prior state is captured to disk and an undo command is
  generated, so the approval prompt can show what putting it back would take.
"""

from __future__ import annotations

from agent import kubectl, rollback
from agent.kubectl import DeniedError
from agent.policy import (
    APPLY_MANIFEST_TOOL,
    DELETE_RESOURCE_TOOL,
    INTERNAL_APPLY_TOOL,
    INTERNAL_DELETE_TOOL,
    KUBECTL_WRITE_TOOL,
    _namespace_values,
)
from agent.targets import target_from_args, target_from_manifest

DRY_RUN_FLAG = "--dry-run=server"


def _namespace(tool_input: dict) -> str:
    """The namespace a mutation targets.

    Delegates the argv parsing to `policy._namespace_values` so preflight and the
    classifier can never disagree about which namespace a command names — the
    class of bug where one is fixed and the other is not.
    """
    declared = tool_input.get("namespace")
    if isinstance(declared, str) and declared:
        return declared
    values = [v for v in _namespace_values([str(a) for a in (tool_input.get("args") or [])]) if v]
    return values[-1] if values else ""


def _target(tool_input: dict) -> tuple[str, str, str] | None:
    """(kind, name, namespace) for the resource a mutation touches, if identifiable."""
    namespace = _namespace(tool_input)

    if tool_input.get("kind") and tool_input.get("name"):
        return str(tool_input["kind"]), str(tool_input["name"]), namespace

    if tool_input.get("manifest"):
        found = target_from_manifest(str(tool_input["manifest"]))
        return (found[0], found[1], namespace) if found else None

    found = target_from_args([str(a) for a in (tool_input.get("args") or [])])
    return (found[0], found[1], namespace) if found else None


def make_dry_run(*, writable_namespaces: frozenset[str] | None = None):
    """Validate a pending mutation against the API server without applying it."""

    def dry_run(tool_name: str, tool_input: dict) -> tuple[bool, str]:
        namespace = str(tool_input.get("namespace") or "")

        if tool_name == APPLY_MANIFEST_TOOL:
            args = ["apply", "-f", "-", "-n", namespace, DRY_RUN_FLAG]
            internal, stdin = INTERNAL_APPLY_TOOL, str(tool_input.get("manifest") or "")
        elif tool_name == DELETE_RESOURCE_TOOL:
            args = [
                "delete",
                str(tool_input.get("kind") or ""),
                str(tool_input.get("name") or ""),
                "-n",
                namespace,
                DRY_RUN_FLAG,
            ]
            internal, stdin = INTERNAL_DELETE_TOOL, None
        else:
            args = [str(a) for a in (tool_input.get("args") or [])] + [DRY_RUN_FLAG]
            internal, stdin = KUBECTL_WRITE_TOOL, None

        try:
            result = kubectl.run(
                args,
                tool_name=internal,
                stdin=stdin,
                writable_namespaces=writable_namespaces,
            )
        except DeniedError as denied:
            return False, denied.decision.reason

        detail = (result.stdout or result.stderr or "").strip() or "(server accepted, no output)"
        return result.ok, detail

    return dry_run


def make_snapshotter(
    *, root=rollback.DEFAULT_ROLLBACK_ROOT, writable_namespaces: frozenset[str] | None = None
):
    """Capture prior state so the change can be undone."""

    def snapshot(tool_name: str, tool_input: dict):
        target = _target(tool_input)
        if target is None:
            raise RuntimeError(
                "Could not identify which resource this change targets, so no rollback "
                "snapshot could be taken."
            )
        kind, name, namespace = target
        if not namespace:
            raise RuntimeError(
                f"Could not determine the namespace for {kind}/{name}. kubectl would "
                f"resolve an empty namespace to the context default and snapshot a "
                f"different object, so the change is abandoned instead."
            )
        return rollback.capture(
            kind, name, namespace, root=root, writable_namespaces=writable_namespaces
        )

    return snapshot
