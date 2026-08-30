"""Append-only record of every tool call the agent attempted.

This is the layer that makes the other guardrails checkable rather than merely
claimed. Two design choices carry most of the weight:

  * The `attempt` entry is written **before** the tool runs, so an action that
    hangs, times out, or takes the process down with it still leaves a trace.
    A log written after the fact would systematically lose the events most worth
    investigating.
  * Denials and declines are recorded with the same weight as successes. "The
    agent tried to delete kube-system and was refused" is the single most useful
    line this file can contain.

The log outlives the session, so entries go through the same secret redaction as
the model's context.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from agent.policy import Decision
from agent.redact import redact

DEFAULT_AUDIT_PATH = Path(".agent-memory") / "audit.jsonl"


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _scrub(value: object) -> object:
    """Recursively redact every string in a structure.

    Redaction must be applied to the *leaves*, not to the serialised whole: a
    manifest arrives as a string field, and once JSON-encoded its newlines become
    `\\n` escapes, at which point it no longer parses as YAML and a Secret inside
    it would sail straight through.
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {str(key): _scrub(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub(item) for item in value]
    return value


def _sanitise(value: object) -> object:
    """Make a tool_input JSON-safe and secret-free."""
    scrubbed = _scrub(value)
    try:
        json.dumps(scrubbed, sort_keys=True)
    except (TypeError, ValueError):
        return {"unserialisable": repr(value)[:500]}
    return scrubbed


class AuditLog:
    def __init__(self, path: str | os.PathLike[str] = DEFAULT_AUDIT_PATH):
        self.path = Path(path)
        # The hook records the attempt; the approval gate learns the verdict several
        # layers later. All they share is the tool_use_id, so that is the join key.
        self._by_tool_use: dict[str, str] = {}

    def _write(self, entry: dict) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
        except OSError:
            # An unwritable audit log is a real problem, but taking down a
            # troubleshooting session mid-diagnosis is a worse one.
            pass

    def attempt(
        self,
        *,
        tool_name: str,
        tool_input: dict,
        decision: Decision,
        agent_id: str | None = None,
        tool_use_id: str | None = None,
    ) -> str:
        """Record an attempt before it executes. Returns the id to pass to `outcome`."""
        event_id = uuid.uuid4().hex
        if tool_use_id:
            self._by_tool_use[tool_use_id] = event_id
        self._write(
            {
                "event": "attempt",
                "id": event_id,
                "ts": _now(),
                "tool_name": tool_name,
                "tool_input": _sanitise(tool_input),
                "verdict": str(decision.verdict),
                "reason": decision.reason,
                "agent_id": agent_id,
                "tool_use_id": tool_use_id,
            }
        )
        return event_id

    def event_id_for(self, tool_use_id: str | None) -> str | None:
        """The attempt id previously recorded for this tool call, if any."""
        return self._by_tool_use.get(tool_use_id) if tool_use_id else None

    def outcome_for(self, tool_use_id: str | None, **kwargs) -> None:
        """Record an outcome against whichever attempt this tool call produced.

        Silently does nothing for a call we never saw an attempt for — a missing
        outcome row is a gap in the record, not a reason to interrupt the session.
        """
        event_id = self.event_id_for(tool_use_id)
        if event_id:
            self.outcome(event_id, **kwargs)

    def outcome(
        self,
        event_id: str,
        *,
        status: str,
        returncode: int | None = None,
        rollback_path: str | None = None,
        detail: str | None = None,
    ) -> None:
        """Record what became of an attempt: applied, denied, declined, failed, timed_out."""
        self._write(
            {
                "event": "outcome",
                "id": event_id,
                "ts": _now(),
                "status": status,
                "returncode": returncode,
                "rollback_path": rollback_path,
                "detail": redact(detail) if detail else None,
            }
        )
