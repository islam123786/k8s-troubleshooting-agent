"""The browser front end.

A UI changes who can drive the agent, so the thing worth testing is that it does
not quietly change *what* the agent may do. The web app builds its session from
the same `build_options` / `build_server` the CLI uses, so every guardrail comes
along; these tests exist to prove that stays true.

The one deliberate difference is that the UI is read-only, full stop. The
approval gate is a blocking stdin prompt, and a half-built browser equivalent —
one that renders a prompt but cannot actually hold the mutation open while a
person reads it — would be worse than not offering writes at all.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent.web import ALLOW_WRITES, build_app


@pytest.fixture
def client(tmp_path):
    return TestClient(build_app(project_root=tmp_path))


def test_the_page_is_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Kubernetes" in response.text


def test_the_page_needs_no_external_network(client):
    """Offline-first: a troubleshooting tool should not need a CDN to render."""
    body = client.get("/").text
    for marker in ("http://", "https://"):
        assert marker not in body.replace("http://localhost", ""), "no external assets"


def test_health_reports_what_the_session_can_do(client):
    payload = client.get("/api/health").json()
    assert payload["read_only"] is True
    assert payload["context"] == "kind-k8s-troubleshooting-agent"
    assert "writable_namespaces" in payload


def test_the_ui_never_enables_writes():
    """Not a preference — a constant, so enabling writes is a code change with a
    failing test attached rather than a flag someone flips in passing."""
    assert ALLOW_WRITES is False


def test_the_session_is_built_read_only(tmp_path):
    from agent.web import _session_options

    options = _session_options(tmp_path)
    assert options.permission_mode == "dontAsk"
    assert options.can_use_tool is None
    for write_tool in (
        "mcp__k8s__kubectl_write",
        "mcp__k8s__apply_manifest",
        "mcp__k8s__delete_resource",
    ):
        assert write_tool not in options.allowed_tools


def test_the_session_keeps_the_shell_removed(tmp_path):
    from agent.web import _session_options

    options = _session_options(tmp_path)
    for tool in ("Bash", "Write", "Edit"):
        assert tool in options.disallowed_tools


def test_an_empty_question_is_rejected(client):
    assert client.get("/api/ask", params={"q": "  "}).status_code == 400


def test_findings_endpoint_reports_emptiness_rather_than_failing(client):
    assert "No findings" in client.get("/api/findings").json()["text"]


def test_audit_endpoint_is_empty_before_anything_runs(client):
    assert client.get("/api/audit").json()["entries"] == []


def test_audit_entries_are_redacted(tmp_path):
    """The audit view renders in a browser, so it goes through the same scrubbing
    as everything else."""
    from agent.audit import AuditLog
    from agent.policy import Decision, Verdict

    log = AuditLog(tmp_path / ".agent-memory" / "audit.jsonl")
    log.attempt(
        tool_name="mcp__k8s__apply_manifest",
        tool_input={"manifest": "kind: Secret\ndata:\n  p: aHVudGVyMg==\n"},
        decision=Decision(Verdict.WRITE, "applies"),
    )
    entries = TestClient(build_app(project_root=tmp_path)).get("/api/audit").json()["entries"]
    assert entries
    assert "aHVudGVyMg==" not in str(entries)
