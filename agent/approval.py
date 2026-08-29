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

from agent.policy import (
    DELETE_RESOURCE_TOOL,
    Verdict,
    classify,
)

# (ok, human-readable detail) — a server-side dry run of the pending mutation.
DryRun = Callable[[str, dict], tuple[bool, str]]
Snapshotter = Callable[[str, dict], Any]

YES = {"y", "yes"}


class MutationBudgetExhausted(Exception):
    """The session has changed as much as it is allowed to. Stop rather than ask again."""


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
    """The token a human must retype to confirm a destructive action."""
    if tool_input.get("name"):
        return str(tool_input["name"])
    args = tool_input.get("args") or []
    for token in args[1:]:
        if isinstance(token, str) and not token.startswith("-"):
            return token.split("/")[-1]
    return None


@dataclass
class ApprovalGate:
    prompt: Callable[[str], str] = input
    dry_run: DryRun | None = None
    snapshot: Snapshotter | None = None
    writable_namespaces: frozenset[str] | None = None
    max_mutations: int = 10
    interactive: bool = True
    mutations_applied: int = field(default=0, init=True)

    async def __call__(self, tool_name: str, tool_input: dict, context: Any):
        tool_input = tool_input or {}
        decision = classify(tool_name, tool_input, writable_namespaces=self.writable_namespaces)

        # Defence in depth: the hook should have caught this already.
        if decision.verdict is Verdict.DENY:
            return PermissionResultDeny(message=f"Refused by policy: {decision.reason}")

        if decision.verdict is Verdict.READ:
            return PermissionResultAllow(updated_input=tool_input)

        if self.mutations_applied >= self.max_mutations:
            raise MutationBudgetExhausted(
                f"This session has already applied {self.mutations_applied} changes "
                f"(limit {self.max_mutations}). Stopping rather than asking again."
            )

        if not self.interactive:
            return PermissionResultDeny(
                message=(
                    "Running non-interactively, so no one can approve this. "
                    "Re-run with a terminal attached, or use propose_fix to write the "
                    "change out for review instead."
                )
            )

        # Validate against the API server before asking a human to judge it.
        if self.dry_run is not None:
            try:
                ok, detail = self.dry_run(tool_name, tool_input)
            except Exception as exc:  # noqa: BLE001 - an unverifiable change is not approvable
                return PermissionResultDeny(message=f"Dry run failed: {exc}")
            if not ok:
                return PermissionResultDeny(
                    message=f"The API server rejected this change, so it was not applied: {detail}"
                )
        else:
            detail = "(no dry run performed)"

        # No undo path, no mutation.
        undo = "(no rollback captured)"
        if self.snapshot is not None:
            try:
                snap = self.snapshot(tool_name, tool_input)
            except Exception as exc:  # noqa: BLE001 - see module docstring
                return PermissionResultDeny(
                    message=f"Could not capture a rollback snapshot, so nothing was changed: {exc}"
                )
            undo = getattr(snap, "undo_command", undo)

        answer = self.prompt(
            self._render(tool_name, tool_input, decision.reason, detail, undo)
        ).strip()

        if answer.lower() not in YES:
            return PermissionResultDeny(message="User declined this change.")

        if decision.verdict is Verdict.DESTRUCTIVE:
            expected = _target_name(tool_input)
            typed = self.prompt(
                f"This is destructive. Type the resource name ({expected}) to confirm: "
            ).strip()
            if not typed or typed != expected:
                return PermissionResultDeny(message="Destructive action not confirmed.")

        self.mutations_applied += 1
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
