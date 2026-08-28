# Kubernetes Troubleshooting Agent

A guardrailed troubleshooting agent for a local [kind](https://kind.sigs.k8s.io/) cluster,
built on the [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk).

It inspects the cluster, works out *why* something is broken, explains the root cause in plain
English, and proposes a fix. It never changes anything without your explicit approval.

## Design stance

The agent is handed a broken system and asked to reason about it. That is precisely the
situation where a confident wrong action does real damage, so containment comes first:

- **No shell.** `Bash`, `Write`, and `Edit` are removed from the model's context entirely.
  `kubectl` is reachable only through a small typed MCP tool surface.
- **Read-only by default.** Writes require launching with `--allow-writes`, and each one is
  still gated individually.
- **Pinned to the kind cluster.** The kubectl context is a hardcoded constant, so a stray
  `kubectl config use-context prod` cannot redirect the agent.
- **Fail-closed policy.** An unrecognised verb or flag is denied, not assumed safe.

See `CLAUDE.md` for the full set of invariants.

## Quick start

```bash
uv sync
./scripts/setup-cluster.sh          # needs Docker running
./scripts/chaos.sh break crashloop  # break something on purpose
export ANTHROPIC_API_KEY=sk-ant-...
uv run python -m agent.cli
```

## Development

```bash
uv run pytest                  # unit suite: no Docker, no API key
uv run pytest -m integration   # full scenario sweep: needs cluster + API key
uv run ruff check .
```
