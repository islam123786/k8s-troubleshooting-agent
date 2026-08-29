"""SDK hooks: where the policy is actually enforced.

The Agent SDK evaluates permissions in a documented order —

    hooks -> deny rules -> ask rules -> permission mode -> allow rules -> can_use_tool

— and two properties of that order shape this module.

First, hooks run *before* everything else and a hook `deny` holds even in
`bypassPermissions` mode, so `PreToolUse` is the one layer guaranteed to see
every tool call. It fires inside subagents too, which is what puts the
`kubernetes-specialist` under the same policy as the main session.

Second, and less obviously: **a tool auto-approved by an `allowed_tools` entry
never reaches `can_use_tool`**. Any check placed only in the approval callback is
silently skipped for those tools. So the policy lives here, and `can_use_tool` is
left to do the one thing a hook cannot — ask a human.

Registered without a matcher, so it fires for every tool rather than a named
subset.
"""

from __future__ import annotations

import sys
from collections.abc import Awaitable, Callable
from typing import Any

from agent.audit import AuditLog
from agent.policy import Verdict, classify

HookResult = dict[str, Any]


def _deny(event_name: str, reason: str) -> HookResult:
    return {
        "hookSpecificOutput": {
            "hookEventName": event_name or "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def make_guardrail_hook(
    *,
    audit_log: AuditLog,
    writable_namespaces: frozenset[str] | None = None,
) -> Callable[[dict, str | None, Any], Awaitable[HookResult]]:
    """Build the PreToolUse callback.

    Returns `{}` for anything it does not deny — "no opinion", letting the call
    continue down the normal permission flow — rather than an explicit `allow`,
    which would assert a decision this layer is not the right place to make.
    """

    async def guardrail_hook(input_data: dict, tool_use_id: str | None, context: Any) -> HookResult:
        event_name = "PreToolUse"
        try:
            event_name = (input_data or {}).get("hook_event_name") or "PreToolUse"
            tool_name = (input_data or {}).get("tool_name")
            tool_input = (input_data or {}).get("tool_input") or {}

            if not isinstance(tool_name, str) or not tool_name:
                return _deny(event_name, "Tool call carried no usable tool name.")

            decision = classify(tool_name, tool_input, writable_namespaces=writable_namespaces)
        except Exception as exc:  # noqa: BLE001 - a broken classifier must not mean "allow"
            return _deny(
                event_name,
                f"Refused: the guardrail could not classify this call ({exc.__class__.__name__}). "
                f"An unclassifiable call is denied rather than assumed safe.",
            )

        try:
            audit_log.attempt(
                tool_name=tool_name,
                tool_input=tool_input,
                decision=decision,
                agent_id=(input_data or {}).get("agent_id"),
                tool_use_id=tool_use_id,
            )
        except Exception as exc:  # noqa: BLE001 - losing the log must not change the verdict
            # The audit log is how these decisions stay checkable afterwards, so a
            # failure is worth surfacing — but not worth changing the verdict over,
            # and not worth ending a troubleshooting session for.
            print(f"[audit] could not record tool attempt: {exc}", file=sys.stderr)

        if decision.verdict is Verdict.DENY:
            return _deny(event_name, decision.reason)

        return {}

    return guardrail_hook
