# Kubernetes Troubleshooting Agent

A guardrailed troubleshooting agent for a local kind cluster, built on the Claude
Agent SDK. It diagnoses cluster problems, explains root causes, and proposes
fixes. It never changes anything without explicit human approval.

## The one thing to understand first

This agent is handed a broken system and asked to reason about it. That is
exactly the situation where a confident wrong action does real damage, so
**containment is the primary requirement and troubleshooting is built on top of
it**. When a change would make the agent more capable but less contained, the
containment wins unless someone decides otherwise explicitly.

## Invariants

These are load-bearing. Each is enforced by a test; if you change one, the test
should change first and the reason should be in the commit message.

1. **The agent has no shell.** `Bash`, `Write`, `Edit`, `NotebookEdit` and the web
   tools are in `disallowed_tools` by bare name, which strips them from the
   request entirely. With a shell available every other guardrail here is
   decoration. — `agent/options.py`, `tests/test_options.py`

2. **One module spawns processes.** Only `agent/kubectl.py`. Enforced structurally
   by an AST scan over `agent/*.py`, not by convention. — `tests/test_no_subprocess_bypass.py`

3. **The context is pinned to a constant.** `--context kind-k8s-troubleshooting-agent`
   is injected on every invocation and never read from ambient kubeconfig, so a
   stray `kubectl config use-context prod` cannot redirect the agent.

4. **Policy is fail-closed.** An unrecognised verb, flag, kind or tool classifies
   as `DENY`. Where a check must enumerate, it enumerates what is *allowed*.
   `APPLICABLE_KINDS` is an allowlist specifically because cluster-scoped kinds
   arrive from CRDs and cannot be enumerated. — `agent/policy.py`

5. **The policy runs in a `PreToolUse` hook, not in `can_use_tool`.** SDK hooks
   run before every other permission step and hold even in `bypassPermissions`.
   Critically, **a tool auto-approved by an `allowed_tools` entry never reaches
   `can_use_tool`** — a check placed only there is silently skipped. — `agent/hooks.py`

6. **Mutations are fenced to one namespace** (default `chaos`). Control-plane
   namespaces are readable but never writable, even if someone passes
   `--writable-ns kube-system`.

7. **One named resource per mutation.** `--all`, `-A`, `-l`, `--selector` and
   `--field-selector` are refused on any mutating command.

8. **A command naming two different namespaces is refused as ambiguous.** kubectl
   resolves repeated flags last-wins; rather than track pflag's precedence rules
   forever, ambiguity is a denial.

9. **`apply` and `delete` are unreachable from free-form argv.** They carry
   validation only the structured tools perform, so they execute through internal
   tool names that are never registered with the SDK.

10. **Dry run, then snapshot, then ask.** No mutation reaches the cluster without
    passing `--dry-run=server` and having its prior state captured with a
    generated undo command. If either fails, the change is abandoned without
    troubling a human. `dry_run` and `snapshot` are *required* arguments to
    `ApprovalGate`, so a gate without them is a `TypeError` rather than a code
    path — an earlier version defaulted them to `None` and prompted anyway.

11. **Secrets never leave the cluster.** `redact()` runs over all output before it
    reaches context, transcript, journal or audit log. ConfigMaps are deliberately
    *not* redacted — a wrong ConfigMap value is a common defect and hiding it
    would defeat the agent.

12. **Output formats are an allowlist** (`-o yaml|json|wide|name`). A projecting
    format such as `-o jsonpath={.data.password}` returns a bare value with no
    surrounding document, so redaction has nothing to identify it by — a Secret
    would walk out through the auto-approved read tool. No amount of redaction
    fixes this; only refusing the format does. — `agent/policy.py`

13. **One parser decides what a command acts on.** `agent/targets.py` is shared by
    the approval gate (which word must be typed to confirm) and preflight (which
    resource is snapshotted). They must never disagree: if they do, you confirm
    one object and snapshot another.

14. **Cluster output is untrusted data.** Pod logs, events and annotations are
    written by workloads. They are wrapped in `<untrusted-output>` and the system
    prompt says instructions inside them are never followed — but the real defence
    is structural: in read-only mode the mutating tools do not exist to be reached.

## Working on this project

### Everything runs through uv

Never bare `python` or `pip`.

```bash
uv sync
uv run pytest                    # unit suite: no Docker, no API key, <1s
uv run pytest -m integration     # needs a cluster and an API key; costs money
uv run ruff check . && uv run ruff format .
```

### The loop

**RED → GREEN → COMMIT → REVIEW.** Write the test first and watch it fail for the
right reason; make it pass; commit test and implementation together so the step is
one reviewable diff; then run a background `/code-review` on that diff and fold
the findings in before building on top.

Review effort scales with blast radius:

| Modules | Effort |
|---|---|
| `policy`, `kubectl`, `hooks`, `approval`, `options`, `redact` | `max` |
| `rollback`, `audit`, `mcp_server`, `preflight` | `high` |
| `memory`, `cli`, skills, chaos scripts | `medium` |

This is not ceremony. Review of the first two steps found two real fence escapes
that 130 passing tests had not caught.

### Beware the vacuous test

Twice already a test passed by asserting against nothing — a `set()` that was
always empty, and a fail-closed branch that was never reached. When a test
guards something important, prove it can fail: inject the violation and watch it
go red, or assert the shape of the data before asserting on its contents.

### The safety code is where the bugs were

Review of steps 3-7 found six defects that 389 passing tests had not caught, and
**three of them were in code written specifically to be safe**: the destructive
confirmation prompt asked for the wrong word (and so rejected the operator who
knew the right one), the snapshot step named the wrong resource, and the fallback
`ApprovalGate` added so writes could not exist ungated was itself ungated.

The pattern is that a guardrail is written once, reasoned about carefully, and
then never exercised — the tests alongside it assert the shape it was built with
rather than the behaviour it promises. When you add a guard, write the test that
proves the guard *stops something*, from the outside.

### Do not put a deny list in `.claude/settings.json`

Claude Code reads that file too. A deny list for `Bash`/`Write`/`Edit` intended to
constrain the agent's SDK sessions disarms anyone developing this repo — it
happened here, mid-project, and only became visible after a session restart. It
also buys nothing: `options.py` sets `disallowed_tools` explicitly on every
session it builds, and `tests/test_options.py` enforces that. A test now checks
the deny list cannot come back.

### The API key lives in `.env`

Gitignored, `chmod 600`, loaded by `agent/env.py` (nothing reads `.env`
automatically). Never in `.env.example` — that file is committed, and a live key
was pasted into it once. A test checks no tracked file contains anything shaped
like a real key.

## Layout

```
agent/
  policy.py      classify(tool_name, tool_input) -> READ|WRITE|DESTRUCTIVE|DENY. Pure.
  kubectl.py     The only process-spawning module. Context pinning, argv-only.
  hooks.py       PreToolUse enforcement — fires on every call, subagents included.
  approval.py    can_use_tool. Defaults to no.
  preflight.py   Dry run and snapshot, both before the human is asked.
  rollback.py    Prior-state capture and undo-command generation.
  redact.py      Secret scrubbing.
  audit.py       Append-only JSONL, written before execution.
  mcp_server.py  The typed tool surface; the agent's whole route to the cluster.
  memory.py      Findings journal and fix proposals.
  targets.py     Which resource a command acts on. Shared by approval and preflight.
  env.py         Loads .env, since nothing reads it automatically.
  options.py     ClaudeAgentOptions assembly.
  cli.py         The chat REPL.
.claude/
  skills/        Seven failure-family playbooks, loaded natively by the SDK.
  agents/        kubernetes-specialist (read-only).
chaos/scenarios/ 12 scenarios; expect.yaml is the test contract.
scripts/         setup-cluster.sh, teardown-cluster.sh, chaos.sh
```

## Conventions

- **Skills** follow symptoms → diagnostic sequence → decision tree → fix patterns →
  `## Verify`. Cross-link with `[[skill-name]]`; a test checks the links resolve.
  Every skill must be exercised by at least one chaos scenario.
- **Chaos scenarios** are a directory with `broken.yaml` and `expect.yaml`. They
  must stay inside the `chaos` namespace — a test enforces it — so `heal-all` is
  always a clean teardown and the sandbox matches the agent's writable fence.
- **`propose_fix` is a real deliverable**, not a fallback. Read-only mode is
  expected to be the common case, and a reviewed manifest on disk is the output.
- **Don't add a tool that takes a command string.** Every tool wraps a fixed argv
  shape. A free-form command tool would reintroduce the shell by the back door.
