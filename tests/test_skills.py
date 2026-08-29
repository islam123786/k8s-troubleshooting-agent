"""The authored skills and the specialist definition.

These are loaded natively by the SDK from `.claude/`, so the checks here are
about the contract that loading depends on: valid frontmatter, a name matching
the directory, and a description good enough to trigger on.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKILLS = sorted((ROOT / ".claude" / "skills").glob("*/SKILL.md"))
SPECIALIST = ROOT / ".claude" / "agents" / "kubernetes-specialist.md"

EXPECTED = {
    "k8s-crashloop",
    "k8s-image-pull",
    "k8s-oom-and-limits",
    "k8s-probes",
    "k8s-pending-scheduling",
    "k8s-storage-pvc",
    "k8s-networking-dns",
}


def frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---"), f"{path} has no frontmatter"
    block = text.split("---", 2)[1]
    return dict(re.findall(r"^(\w+):\s*(.+)$", block, re.MULTILINE))


def test_every_planned_skill_exists():
    assert {p.parent.name for p in SKILLS} == EXPECTED


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_skill_name_matches_its_directory(path):
    """The SDK addresses a skill by name; a mismatch makes it unloadable."""
    assert frontmatter(path)["name"] == path.parent.name


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_skill_description_is_substantial(path):
    """The description is the whole basis for the model deciding to load it."""
    description = frontmatter(path)["description"]
    assert len(description) > 40
    assert "diagnose" in description.lower() or "use when" in description.lower()


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_skill_documents_how_to_verify_a_fix(path):
    """A playbook that stops at the fix invites declaring victory too early."""
    assert "## Verify" in path.read_text()


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_skill_cross_references_resolve(path):
    """A [[link]] to a skill that does not exist is a dead end mid-diagnosis."""
    for referenced in re.findall(r"\[\[([a-z0-9-]+)\]\]", path.read_text()):
        assert referenced in EXPECTED, f"{path.parent.name} links to unknown {referenced}"


def test_the_specialist_is_declared_read_only():
    meta = frontmatter(SPECIALIST)
    assert meta["name"] == "kubernetes-specialist"
    assert "mcp__k8s__kubectl_read" in meta["tools"]
    for write_tool in ("kubectl_write", "apply_manifest", "delete_resource"):
        assert write_tool not in meta["tools"]


def test_the_specialist_is_told_that_cluster_output_is_untrusted():
    body = SPECIALIST.read_text().lower()
    assert "untrusted" in body
    assert "never followed" in body or "not instructions" in body
