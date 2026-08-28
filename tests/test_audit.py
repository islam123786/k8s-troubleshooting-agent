"""The audit log is what makes every other guardrail verifiable after the fact.

Two properties matter more than the rest:

  * **Written before execution.** An action that hangs, crashes the process, or
    is killed must still leave a record. A log written afterwards would lose
    precisely the events worth investigating.
  * **Never leaks a secret.** It is a file on disk that outlives the session, so
    it goes through the same redaction as the model's context.
"""

from __future__ import annotations

import json

import pytest

from agent.audit import AuditLog
from agent.policy import Decision, Verdict


@pytest.fixture
def log(tmp_path):
    return AuditLog(tmp_path / "nested" / "audit.jsonl")


def read_lines(log) -> list[dict]:
    return [json.loads(line) for line in log.path.read_text().splitlines() if line.strip()]


def test_parent_directory_is_created(log):
    log.attempt(
        tool_name="mcp__k8s__kubectl_read",
        tool_input={"args": ["get", "pods"]},
        decision=Decision(Verdict.READ, "fine"),
    )
    assert log.path.is_file()


def test_each_entry_is_one_json_line(log):
    for _ in range(3):
        log.attempt(tool_name="T", tool_input={}, decision=Decision(Verdict.READ, "fine"))
    entries = read_lines(log)
    assert len(entries) == 3
    assert all(isinstance(e, dict) for e in entries)


def test_entry_records_the_decision(log):
    log.attempt(
        tool_name="mcp__k8s__kubectl_write",
        tool_input={"args": ["delete", "namespace", "chaos"]},
        decision=Decision(Verdict.DENY, "namespaces are never deletable"),
    )
    (entry,) = read_lines(log)
    assert entry["tool_name"] == "mcp__k8s__kubectl_write"
    assert entry["verdict"] == "DENY"
    assert "never deletable" in entry["reason"]
    assert entry["event"] == "attempt"
    assert entry["tool_input"] == {"args": ["delete", "namespace", "chaos"]}


def test_timestamps_are_utc_iso8601(log):
    log.attempt(tool_name="T", tool_input={}, decision=Decision(Verdict.READ, "fine"))
    (entry,) = read_lines(log)
    assert entry["ts"].endswith("Z") or "+00:00" in entry["ts"]


def test_appends_rather_than_truncates(log):
    log.attempt(tool_name="first", tool_input={}, decision=Decision(Verdict.READ, "fine"))
    reopened = AuditLog(log.path)
    reopened.attempt(tool_name="second", tool_input={}, decision=Decision(Verdict.READ, "fine"))
    names = [e["tool_name"] for e in read_lines(log)]
    assert names == ["first", "second"]


def test_attempt_returns_a_unique_id(log):
    a = log.attempt(tool_name="T", tool_input={}, decision=Decision(Verdict.READ, "fine"))
    b = log.attempt(tool_name="T", tool_input={}, decision=Decision(Verdict.READ, "fine"))
    assert a and b and a != b


def test_outcome_links_back_to_the_attempt(log):
    event_id = log.attempt(
        tool_name="mcp__k8s__kubectl_write",
        tool_input={"args": ["scale", "deploy", "web", "--replicas=2", "-n", "chaos"]},
        decision=Decision(Verdict.WRITE, "scales a deployment"),
    )
    log.outcome(event_id, status="applied", returncode=0, rollback_path="/tmp/rb.yaml")

    attempt, outcome = read_lines(log)
    assert outcome["event"] == "outcome"
    assert outcome["id"] == attempt["id"] == event_id
    assert outcome["status"] == "applied"
    assert outcome["returncode"] == 0
    assert outcome["rollback_path"] == "/tmp/rb.yaml"


def test_declines_and_denials_are_recorded_not_dropped(log):
    """The interesting entries are the ones where nothing happened."""
    for status in ("denied", "declined", "timed_out"):
        event_id = log.attempt(tool_name="T", tool_input={}, decision=Decision(Verdict.DENY, "no"))
        log.outcome(event_id, status=status)
    statuses = [e.get("status") for e in read_lines(log) if e["event"] == "outcome"]
    assert statuses == ["denied", "declined", "timed_out"]


def test_secrets_are_redacted_before_being_written(log):
    log.attempt(
        tool_name="mcp__k8s__apply_manifest",
        tool_input={"manifest": "kind: Secret\ndata:\n  password: aHVudGVyMg==\n"},
        decision=Decision(Verdict.WRITE, "applies a secret"),
    )
    raw = log.path.read_text()
    assert "aHVudGVyMg==" not in raw
    assert "hunter2" not in raw


def test_unserialisable_input_does_not_lose_the_entry(log):
    """A weird tool_input must not cost us the audit record."""
    log.attempt(
        tool_name="T",
        tool_input={"obj": object()},
        decision=Decision(Verdict.READ, "fine"),
    )
    (entry,) = read_lines(log)
    assert entry["tool_name"] == "T"


def test_agent_id_is_recorded_when_present(log):
    """PreToolUse carries agent_id inside a subagent; attributing the call matters."""
    log.attempt(
        tool_name="T",
        tool_input={},
        decision=Decision(Verdict.READ, "fine"),
        agent_id="kubernetes-specialist",
    )
    (entry,) = read_lines(log)
    assert entry["agent_id"] == "kubernetes-specialist"


def test_write_failure_is_swallowed_not_raised(tmp_path):
    """Losing the log is bad; crashing the agent mid-troubleshoot is worse."""
    blocked = tmp_path / "file-in-the-way"
    blocked.write_text("not a directory")
    log = AuditLog(blocked / "audit.jsonl")
    log.attempt(tool_name="T", tool_input={}, decision=Decision(Verdict.READ, "fine"))
