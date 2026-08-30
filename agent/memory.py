"""Session memory: findings the agent reached, and fixes it proposed.

Two kinds of file, both under `.agent-memory/`:

* **Findings** accumulate into one Markdown journal per session — what was wrong,
  the evidence, and whether anything was applied.
* **Proposals** are standalone manifests written by `propose_fix`. They are what
  makes the default read-only mode genuinely useful: you get the complete change
  as a reviewable file, and applying it stays a human act.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from agent.redact import redact

DEFAULT_MEMORY_ROOT = Path(".agent-memory")

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")

# Tool-call parameter markup that has, in practice, leaked into argument values
# when a model sends fields the schema does not declare. Stripped so the journal
# never renders scaffolding as if it were the diagnosis.
_MARKUP = re.compile(r"</?(parameter|root_cause|evidence|fix|title|summary)\b[^>]*>")


def _slug(value: str, fallback: str = "item") -> str:
    cleaned = _UNSAFE.sub("-", value).strip("-.") or fallback
    return cleaned[:50].lower()


def _clean(value: object) -> str:
    return _MARKUP.sub("", str(value or "")).strip()


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Journal:
    root: Path = DEFAULT_MEMORY_ROOT
    session: str = ""

    def __post_init__(self):
        self.root = Path(self.root)
        self.session = self.session or datetime.now(UTC).strftime("%Y%m%dT%H%M%S")

    @property
    def findings_path(self) -> Path:
        return self.root / f"session-{self.session}.md"

    @property
    def proposals_dir(self) -> Path:
        return self.root / "proposals"

    def record_finding(
        self,
        *,
        title: str = "",
        summary: str = "",
        root_cause: str = "",
        evidence: str = "",
        fix: str = "",
        resource: str = "",
        namespace: str = "",
        applied: bool = False,
        rollback_command: str = "",
    ) -> Path:
        """Append one finding.

        The field list mirrors the shape a diagnosis actually takes, which the
        first live run established: a title, the resource it concerns, the root
        cause, the evidence for it, and the fix. An earlier version declared only
        summary/root_cause/fix, so a model sending `title` and `resource` had the
        title silently dropped and the extra fields leak into the text.

        Every field is optional: a partial finding is worth more than a rejected
        one, and the model should never have to fight the schema mid-diagnosis.
        """
        path = self.findings_path
        path.parent.mkdir(parents=True, exist_ok=True)

        if not path.exists():
            path.write_text(f"# Troubleshooting session {self.session}\n", encoding="utf-8")

        heading = _clean(title) or _clean(summary) or "finding"
        where = " / ".join(x for x in (_clean(resource), _clean(namespace)) if x)

        block = [f"\n## {_now()} — {redact(heading)}\n"]
        if where:
            block.append(f"**Resource:** {redact(where)}\n")
        if root_cause:
            block.append(f"**Root cause:** {redact(_clean(root_cause))}\n")
        if evidence:
            block.append(f"**Evidence:** {redact(_clean(evidence))}\n")
        if fix:
            block.append(f"**Fix:** {redact(_clean(fix))}\n")
        block.append(f"**Applied:** {'yes' if applied else 'no'}\n")
        if rollback_command:
            block.append(f"**Undo:** `{rollback_command}`\n")

        with path.open("a", encoding="utf-8") as handle:
            handle.write("".join(block))
        return path

    def propose_fix(self, *, diagnosis: str, manifest: str, rationale: str) -> Path:
        """Write a fix out for review. Nothing is applied."""
        self.proposals_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        path = self.proposals_dir / f"{stamp}-{_slug(diagnosis, 'fix')}.yaml"

        header = (
            f"# Proposed fix — NOT APPLIED\n"
            f"# Diagnosis: {diagnosis}\n"
            f"# Rationale: {rationale}\n"
            f"# Written:   {_now()}\n"
            f"#\n"
            f"# Review this, then apply it yourself if you agree:\n"
            f"#   kubectl --context kind-k8s-troubleshooting-agent apply -f {path}\n"
            f"\n"
        )
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(header + redact(manifest))
        return path

    def read_findings(self) -> str:
        try:
            return self.findings_path.read_text(encoding="utf-8")
        except OSError:
            return "No findings recorded yet."
