"""Assembly of `ClaudeAgentOptions` — the tool surface the model actually gets.

The Agent SDK ships a capable default toolset: Bash, Write, Edit, the web tools.
For this agent that is the wrong starting point, so the first job here is
subtraction. A bare-name entry in `disallowed_tools` removes the tool definition
from the request altogether, which is stronger than guarding it: the model cannot
call what it cannot see.

Removing `Bash` is the load-bearing decision. With a shell in the toolset, every
kubectl guardrail elsewhere in this project is decoration.

Two SDK subtleties shape the rest:

* `allowed_tools` auto-approves, and **an auto-approved tool never reaches
  `can_use_tool`**. So read-only tools go in it and write tools never do.
* In `dontAsk` mode anything not pre-approved is denied outright instead of
  prompting. That is exactly right for a diagnose-only session, where there is
  nothing a human could usefully approve.
"""

from __future__ import annotations

from pathlib import Path

from claude_agent_sdk import AgentDefinition, ClaudeAgentOptions, HookMatcher

from agent.approval import ApprovalGate
from agent.audit import AuditLog
from agent.hooks import make_guardrail_hook

MODEL = "claude-opus-5"

# Diagnosis is long-horizon agentic work, which is where effort actually pays.
EFFORT = "high"

MAX_TURNS = 60
MAX_BUDGET_USD = 5.0

# Removed from the request entirely. Bash first: it would otherwise be a complete
# bypass of the kubectl choke point.
DISALLOWED_TOOLS = [
    "Bash",
    "BashOutput",
    "KillShell",
    "Write",
    "Edit",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
]

# Auto-approved. Safe to run unattended and far too frequent to prompt on.
READ_ONLY_TOOLS = [
    "mcp__k8s__kubectl_read",
    "mcp__k8s__propose_fix",
    "mcp__k8s__record_finding",
    "Read",
    "Glob",
    "Grep",
    "Skill",
    "Task",
]

# Registered only with --allow-writes, and never placed in allowed_tools: an
# allow rule would skip the approval callback without a word.
WRITE_TOOLS = [
    "mcp__k8s__kubectl_write",
    "mcp__k8s__apply_manifest",
    "mcp__k8s__delete_resource",
]

SPECIALIST_PROMPT_PATH = Path(".claude") / "agents" / "kubernetes-specialist.md"

_FALLBACK_SPECIALIST_PROMPT = """\
You are a Kubernetes troubleshooting specialist. You are read-only: you observe and
reason, and you never change the cluster. Work from evidence — describe what you
observed, what it rules in and out, and what single next observation would most
cheaply distinguish the remaining hypotheses. State your confidence and say plainly
when the evidence does not support a conclusion.
"""


def _specialist_prompt(project_root: Path) -> str:
    path = project_root / SPECIALIST_PROMPT_PATH
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return _FALLBACK_SPECIALIST_PROMPT


def build_options(
    *,
    audit_log: AuditLog,
    project_root: Path | str = ".",
    allow_writes: bool = False,
    writable_namespaces: frozenset[str] | None = None,
    approval_gate: ApprovalGate | None = None,
    system_prompt: str | None = None,
) -> ClaudeAgentOptions:
    project_root = Path(project_root)

    guardrail = make_guardrail_hook(audit_log=audit_log, writable_namespaces=writable_namespaces)

    # Writes never exist without a gate. Leaving can_use_tool unset here would put
    # the session in "default" mode with nothing to answer the prompt, which is a
    # far more dangerous state than simply refusing to enable writes.
    if allow_writes and approval_gate is None:
        approval_gate = ApprovalGate(writable_namespaces=writable_namespaces)

    specialist = AgentDefinition(
        description=(
            "Deep root-cause analysis for a Kubernetes failure. Read-only: it "
            "investigates and explains, and cannot change anything."
        ),
        prompt=_specialist_prompt(project_root),
        tools=["mcp__k8s__kubectl_read", "Skill", "Read", "Grep", "Glob"],
        disallowedTools=DISALLOWED_TOOLS,
        model=MODEL,
    )

    return ClaudeAgentOptions(
        model=MODEL,
        effort=EFFORT,
        thinking={"type": "adaptive"},
        max_turns=MAX_TURNS,
        max_budget_usd=MAX_BUDGET_USD,
        cwd=str(project_root),
        system_prompt=system_prompt,
        # Only project settings: a developer's personal ~/.claude must not leak
        # into the agent's configuration, so every run is reproducible.
        setting_sources=["project"],
        disallowed_tools=DISALLOWED_TOOLS,
        allowed_tools=list(READ_ONLY_TOOLS),
        # dontAsk: in a read-only session there is nothing a human could usefully
        # approve, so an unlisted tool is denied rather than turned into a prompt.
        permission_mode="default" if allow_writes else "dontAsk",
        can_use_tool=approval_gate if allow_writes else None,
        # No matcher — the policy must see every tool call, including the ones
        # made inside the specialist subagent.
        hooks={"PreToolUse": [HookMatcher(hooks=[guardrail])]},
        agents={"kubernetes-specialist": specialist},
    )
