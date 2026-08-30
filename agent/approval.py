"""The human gate — `can_use_tool`.

By the time a call arrives here the `PreToolUse` hook has already classified it
and refused anything on the deny list. This layer does the one thing a hook
cannot: show a person what is about to happen and wait for them to say yes.

Three deliberate choices:

* **Default no.** Bare Enter declines. So does anything that is not an explicit
  yes. The failure mode of an approval prompt is a tired human hitting return.
* **No blanket approvals.** There is no "yes to all" and no remembering. Approval
  fatigue is the usual way a gate like this stops meaning anything; the answer is
  fewer prompts — read-only by default, a namespace fence — not cheaper ones.
* **Dry-run and snapshot before asking.** The human needs the server-validated
  diff and the undo command in front of them to decide. If either step fails, the
  call is declined without troubling anyone: there is nothing useful to approve.

The gate is also a second line of defence. It re-classifies rather than trusting
that the hook ran, so configuration drift cannot turn this into the layer that
lets something through.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from claude_agent_sdk import PermissionResultAllow, PermissionResultDeny

from agent.audit import AuditLog
from agent.policy import (
    DELETE_RESOURCE_TOOL,
    Verdict,
    classify,
)
from agent.targets import target_from_args, target_from_manifest

# (ok, human-readable detail) — a server-side dry run of the pending mutation.
DryRun = Callable[[str, dict], tuple[bool, str]]
Snapshotter = Callable[[str, dict], Any]

YES = {"y", "yes"}


class MutationBudgetExhausted(Exception):
    """Retained for callers outside the SDK permission path.

    The gate itself no longer raises this: the SDK wraps `can_use_tool` in a
    blanket `except Exception` and turns anything raised into an opaque control
    protocol error, so the session carried on instead of stopping. The supported
    way to end a turn from here is `PermissionResultDeny(interrupt=True)`.
    """


def _describe(tool_name: str, tool_input: dict) -> str:
    if "args" in tool_input:
        return "kubectl " + " ".join(str(a) for a in tool_input.get("args", []))
    if tool_name == DELETE_RESOURCE_TOOL:
        return (
            f"delete {tool_input.get('kind')}/{tool_input.get('name')} "
            f"in namespace {tool_input.get('namespace')}"
        )
    return f"{tool_name} {tool_input}"


def _target_name(tool_input: dict) -> str | None:
    """The token a human must retype to confirm a destructive action.

    This used to take "the first token that doesn't start with a dash", which for
    `rollout undo deploy/web` yields `undo` — so the prompt asked for the verb.
    An operator who knew the cluster and typed the real name was refused, while
    one who echoed the prompt was approved. It now shares one parser with
    preflight, so the word you confirm is the resource that gets snapshotted.
    """
    if tool_input.get("name"):
        return str(tool_input["name"])
    if tool_input.get("manifest"):
        found = target_from_manifest(str(tool_input["manifest"]))
        return found[1] if found else None
    found = target_from_args([str(a) for a in (tool_input.get("args") or [])])
    return found[1] if found else None


@dataclass(kw_only=True)
class ApprovalGate:
    # dry_run and snapshot are REQUIRED, deliberately. A gate without them still
    # prompts and still looks like a safety mechanism, while applying an
    # unvalidated change with no undo path. Making them mandatory turns invariant
    # 10 into a construction error instead of a code path nobody walks.
    dry_run: DryRun
    snapshot: Snapshotter
    prompt: Callable[[str], str] = input
    writable_namespaces: frozenset[str] | None = None
    audit_log: AuditLog | None = None
    max_mutations: int = 10
    interactive: bool = True
    mutations_applied: int = field(default=0, init=True)
    budget_exhausted: bool = field(default=False, init=False)

    def _record(self, context: Any, status: str, **fields) -> None:
        """Close out the audit entry the hook opened for this same tool call."""
        if self.audit_log is None:
            return
        self.audit_log.outcome_for(getattr(context, "tool_use_id", None), status=status, **fields)

    async def __call__(self, tool_name: str, tool_input: dict, context: Any):
        tool_input = tool_input or {}
        decision = classify(tool_name, tool_input, writable_namespaces=self.writable_namespaces)

        # Defence in depth: the hook should have caught this already.
        if decision.verdict is Verdict.DENY:
            self._record(context, "denied", detail=decision.reason)
            return PermissionResultDeny(message=f"Refused by policy: {decision.reason}")

        if decision.verdict is Verdict.READ:
            return PermissionResultAllow(updated_input=tool_input)

        if self.mutations_applied >= self.max_mutations:
            self.budget_exhausted = True
            self._record(context, "budget_exhausted")
            return PermissionResultDeny(
                message=(
                    f"This session has already applied {self.mutations_applied} changes "
                    f"(limit {self.max_mutations}). Stopping rather than asking again."
                ),
                interrupt=True,
            )

        if not self.interactive:
            self._record(context, "declined", detail="non-interactive session")
            return PermissionResultDeny(
                message=(
                    "Running non-interactively, so no one can approve this. "
                    "Re-run with a terminal attached, or use propose_fix to write the "
                    "change out for review instead."
                )
            )

        # Validate against the API server before asking a human to judge it.
        try:
            ok, detail = self.dry_run(tool_name, tool_input)
        except Exception as exc:  # noqa: BLE001 - an unverifiable change is not approvable
            self._record(context, "dry_run_failed", detail=str(exc))
            return PermissionResultDeny(message=f"Dry run failed: {exc}")
        if not ok:
            self._record(context, "rejected_by_server", detail=detail)
            return PermissionResultDeny(
                message=f"The API server rejected this change, so it was not applied: {detail}"
            )

        # No undo path, no mutation.
        try:
            snap = self.snapshot(tool_name, tool_input)
        except Exception as exc:  # noqa: BLE001 - see module docstring
            self._record(context, "snapshot_failed", detail=str(exc))
            return PermissionResultDeny(
                message=f"Could not capture a rollback snapshot, so nothing was changed: {exc}"
            )
        undo = getattr(snap, "undo_command", "(no rollback captured)")

        answer = self.prompt(
            self._render(tool_name, tool_input, decision.reason, detail, undo)
        ).strip()

        if answer.lower() not in YES:
            self._record(context, "declined", rollback_path=str(getattr(snap, "path", "")) or None)
            return PermissionResultDeny(message="User declined this change.")

        if decision.verdict is Verdict.DESTRUCTIVE:
            expected = _target_name(tool_input)
            if not expected:
                # Fail closed rather than prompting for a name we could not work out.
                self._record(context, "declined", detail="target not identifiable")
                return PermissionResultDeny(
                    message=(
                        "Could not determine which resource this would destroy, so it "
                        "was not applied."
                    )
                )
            typed = self.prompt(
                f"This is destructive. Type the resource name ({expected}) to confirm: "
            ).strip()
            if typed != expected:
                self._record(context, "declined", detail="name not confirmed")
                return PermissionResultDeny(message="Destructive action not confirmed.")

        self.mutations_applied += 1
        self._record(context, "applied", rollback_path=str(getattr(snap, "path", "")) or None)
        return PermissionResultAllow(updated_input=tool_input)

    def _render(self, tool_name: str, tool_input: dict, reason: str, diff: str, undo: str) -> str:
        rationale = tool_input.get("rationale") or "(none given)"
        return (
            "\n"
            "──────────────────────────────────────────────────────────\n"
            f"  {_describe(tool_name, tool_input)}\n"
            "──────────────────────────────────────────────────────────\n"
            f"  What it does : {reason}\n"
            f"  Why          : {rationale}\n"
            f"  Server diff  : {diff}\n"
            f"  Undo with    : {undo}\n"
            f"  Applied so far: {self.mutations_applied}/{self.max_mutations}\n"
            "\n"
            "  Apply this change? [y/N] "
        )
