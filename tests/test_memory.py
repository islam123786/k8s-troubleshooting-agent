"""Findings and proposals — the session's durable output."""

from __future__ import annotations

import stat

import pytest

from agent.memory import Journal


@pytest.fixture
def journal(tmp_path):
    return Journal(root=tmp_path, session="20260829T120000")


def test_findings_accumulate_in_one_file(journal):
    journal.record_finding(summary="first", root_cause="a")
    journal.record_finding(summary="second", root_cause="b")
    text = journal.findings_path.read_text()
    assert "first" in text and "second" in text
    assert text.count("## ") == 2


def test_a_finding_records_whether_anything_was_applied(journal):
    journal.record_finding(summary="x", applied=False)
    assert "**Applied:** no" in journal.findings_path.read_text()


def test_an_applied_finding_carries_its_undo_command(journal):
    journal.record_finding(summary="x", applied=True, rollback_command="kubectl apply -f snap.yaml")
    text = journal.findings_path.read_text()
    assert "**Applied:** yes" in text
    assert "snap.yaml" in text


def test_secrets_never_reach_the_journal(journal):
    journal.record_finding(summary="kind: Secret\ndata:\n  p: aHVudGVyMg==\n")
    assert "aHVudGVyMg==" not in journal.findings_path.read_text()


def test_a_proposal_is_written_but_nothing_is_applied(journal):
    path = journal.propose_fix(
        diagnosis="probe port wrong", manifest="kind: Deployment\n", rationale="8080 vs 80"
    )
    body = path.read_text()
    assert "NOT APPLIED" in body
    assert "kind: Deployment" in body
    assert "probe port wrong" in body


def test_a_proposal_tells_the_human_how_to_apply_it(journal):
    path = journal.propose_fix(diagnosis="d", manifest="kind: Pod\n", rationale="r")
    assert "kubectl --context kind-k8s-troubleshooting-agent apply -f" in path.read_text()


def test_proposals_are_owner_readable_only(journal):
    path = journal.propose_fix(diagnosis="d", manifest="kind: Pod\n", rationale="r")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_hostile_diagnosis_cannot_escape_the_proposals_directory(journal):
    path = journal.propose_fix(
        diagnosis="../../../etc/passwd", manifest="kind: Pod\n", rationale="r"
    )
    assert path.parent.resolve() == journal.proposals_dir.resolve()


def test_reading_findings_before_any_exist_is_safe(journal):
    assert "No findings" in journal.read_findings()
