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
)

DRY_RUN_FLAG = "--dry-run=server"


def _target(tool_input: dict) -> tuple[str, str, str] | None:
    """(kind, name, namespace) for the resource a mutation touches, if identifiable."""
    if tool_input.get("kind") and tool_input.get("name"):
        return (
            str(tool_input["kind"]),
            str(tool_input["name"]),
            str(tool_input.get("namespace") or ""),
        )

    args = [str(a) for a in (tool_input.get("args") or [])]
    namespace = ""
    for i, arg in enumerate(args):
        if arg in ("-n", "--namespace") and i + 1 < len(args):
            namespace = args[i + 1]
        elif arg.startswith("--namespace="):
            namespace = arg.split("=", 1)[1]

    positional = [a for a in args[1:] if not a.startswith("-")]
    if len(positional) >= 2:
        kind, name = positional[0], positional[1]
        if "/" in kind:
            kind, name = kind.split("/", 1)
        return kind, name, namespace
    if len(positional) == 1 and "/" in positional[0]:
        kind, name = positional[0].split("/", 1)
        return kind, name, namespace
    return None


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
        return rollback.capture(
            kind, name, namespace, root=root, writable_namespaces=writable_namespaces
        )

    return snapshot
