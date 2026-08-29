"""Capture a resource's current state before anything changes it.

The ordering is the point: `capture()` runs *before* the mutation, and if it
cannot establish the prior state — the read failed, the file could not be
written — it raises rather than returning, and the caller abandons the mutation.
An agent that changes a broken cluster with no undo path is how troubleshooting
becomes an outage.

**Snapshots are written unredacted**, because a redacted snapshot cannot restore
anything. The mitigations are that they are `chmod 0600`, that `Secret` is absent
from `policy.APPLICABLE_KINDS` so the agent cannot apply one in the first place,
and that only the snapshot's *path* is ever returned to the model or written to
the audit log — never its contents.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from agent import kubectl
from agent.policy import KUBECTL_READ_TOOL, PINNED_CONTEXT

DEFAULT_ROLLBACK_ROOT = Path(".agent-memory") / "rollback"

# Anything outside this becomes an underscore, so a resource name can never
# traverse out of the snapshot directory or collide with a path separator.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


class SnapshotError(Exception):
    """The prior state could not be established, so the mutation must not proceed."""


@dataclass(frozen=True)
class Snapshot:
    path: Path
    kind: str
    name: str
    namespace: str
    existed: bool
    undo_command: str
    # There is deliberately no `content` field. The manifest body stays on disk;
    # exposing it here would put a live manifest into the model's context and,
    # via the tool result, into the audit log.


def _slug(value: str) -> str:
    """Make an arbitrary Kubernetes name safe to embed in a filename."""
    cleaned = _UNSAFE.sub("_", value).strip("._") or "unnamed"
    return cleaned[:60]


def capture(
    kind: str,
    name: str,
    namespace: str,
    *,
    root: str | os.PathLike[str] = DEFAULT_ROLLBACK_ROOT,
    runner=None,
    writable_namespaces: frozenset[str] | None = None,
) -> Snapshot:
    """Snapshot `kind/name` in `namespace` and return how to put it back.

    Raises `SnapshotError` if the current state cannot be read or stored. Policy
    denials propagate as `kubectl.DeniedError`.
    """
    result = kubectl.run(
        ["get", kind, name, "-n", namespace, "-o", "yaml"],
        tool_name=KUBECTL_READ_TOOL,
        runner=runner,
        writable_namespaces=writable_namespaces,
    )

    existed = result.ok
    if not existed and "notfound" not in result.stderr.lower().replace(" ", ""):
        # Some other failure — a timeout, a connection refusal, an RBAC error.
        # We do not know the prior state, so we do not proceed.
        raise SnapshotError(
            f"Could not read the current state of {kind}/{name} in {namespace}: "
            f"{result.stderr.strip() or result.stdout.strip() or 'unknown error'}"
        )

    root = Path(root)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    filename = f"{stamp}-{_slug(kind)}-{_slug(name)}-{uuid.uuid4().hex[:8]}.yaml"
    path = root / filename

    body = (
        result.stdout
        if existed
        else f"# {kind}/{name} did not exist in namespace {namespace} at {stamp}.\n"
    )

    try:
        root.mkdir(parents=True, exist_ok=True)
        # Create with 0600 from the outset rather than chmod-ing afterwards, so
        # the contents are never briefly world-readable.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(body)
    except OSError as exc:
        raise SnapshotError(f"Could not write a rollback snapshot to {path}: {exc}") from exc

    if existed:
        undo = f"kubectl --context {PINNED_CONTEXT} apply -n {namespace} -f {path}"
    else:
        undo = f"kubectl --context {PINNED_CONTEXT} delete {kind} {name} -n {namespace}"

    return Snapshot(
        path=path,
        kind=kind,
        name=name,
        namespace=namespace,
        existed=existed,
        undo_command=undo,
    )
