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

The invariants are enforced in `agent/policy.py` (classification) and
`agent/kubectl.py` (the single process-spawning choke point), and pinned down by
`tests/test_policy.py` and `tests/test_no_subprocess_bypass.py`.

## Running it

### 1. Prerequisites

| Needs | Why | Check |
|---|---|---|
| Docker, running | kind runs its nodes as containers | `docker info` |
| [kind](https://kind.sigs.k8s.io/) | creates the cluster | `kind version` |
| `kubectl` | the agent's only route to the cluster | `kubectl version --client` |
| [uv](https://docs.astral.sh/uv/) | manages the venv and the Python interpreter | `uv --version` |
| Claude Code CLI | the Agent SDK runs on it | `claude --version` |
| An Anthropic API key with credit | | see step 3 |

Python is pinned to 3.12 via `.python-version`; uv installs it if you don't have it.

### 2. Install

```bash
uv sync
```

Everything afterwards runs through `uv run`. Never bare `python` or `pip` — the whole point
is that your interpreter and the tests' interpreter are the same one.

### 3. Provide the API key

```bash
cp .env.example .env
$EDITOR .env            # ANTHROPIC_API_KEY=sk-ant-...
chmod 600 .env
```

`.env` is gitignored and loaded by `agent/env.py`. **Never put a real key in `.env.example`** —
that file is committed, and a test fails the build if a key-shaped string ever appears in a
tracked file.

An exported `ANTHROPIC_API_KEY` takes precedence over the file, so a deliberate `export` in
your shell always wins over a stale `.env`.

### 4. Create the cluster

```bash
./scripts/setup-cluster.sh
```

Creates a 3-node kind cluster named `k8s-troubleshooting-agent`, waits for the nodes, creates
the `chaos` namespace, and installs metrics-server (which `kubectl top` needs). It is
idempotent — re-running against an existing cluster just verifies it.

### 5. Break something on purpose

```bash
./scripts/chaos.sh list             # the 12 scenarios
./scripts/chaos.sh break crashloop
./scripts/chaos.sh status           # confirm it is genuinely broken
```

| Family | Scenarios |
|---|---|
| Pod-level | `crashloop` · `image-pull` · `oom-killed` · `bad-probe` |
| Scheduling | `pending-resources` · `bad-node-selector` · `pvc-no-storageclass` · `quota-exhausted` |
| Networking | `svc-selector-mismatch` · `wrong-target-port` · `netpol-block` · `dns-broken` |

Everything lives in the `chaos` namespace, which is also the only namespace the agent may
modify — so `./scripts/chaos.sh heal-all` is always a clean teardown.

`dns-broken` is the exception: it scales CoreDNS in `kube-system`, deliberately out of the
agent's reach. The agent should diagnose it correctly and then refuse to fix it.

### 6. Talk to it

Either a terminal chat or a browser UI — both run the same session with the same
guardrails.

**Browser:**

```bash
uv run python -m agent.web      # then open http://127.0.0.1:8765
```

Streams the agent's reasoning and every kubectl call as it happens, with buttons
for the findings journal and the audit log. Read-only, always: the approval gate
is a blocking prompt that has to hold a mutation open while a person reads a diff,
and a browser version that renders a prompt without actually holding the call
would look like a gate without being one. Writes stay in the CLI.

**Terminal:**

```bash
uv run python -m agent.cli
```

```
> what is wrong in the chaos namespace?
```

**Read-only by default.** The mutating tools are not registered at all, so the agent
investigates and then writes the fix out for you to review rather than applying it.

| Flag | Effect |
|---|---|
| `--allow-writes` | Registers the mutating tools. Each change still needs approval. |
| `--writable-ns NS` | Namespace a mutation may target. Repeatable. Default `chaos`. |
| `--max-mutations N` | Ends the session after N applied changes. Default 10. |

In-session commands: `/skills` `/findings` `/audit` `/reset` `/quit`

### 7. What it leaves behind

Everything lands in `.agent-memory/` (gitignored):

| Path | Contents |
|---|---|
| `session-<ts>.md` | Findings — root cause, evidence, fix |
| `proposals/*.yaml` | Fixes written out for review. **The main output in read-only mode.** |
| `audit.jsonl` | Every tool call attempted, with its verdict — including denials |
| `rollback/*.yaml` | Prior state captured before any mutation, `chmod 0600` |

### 8. Approving a change

With `--allow-writes`, every mutation is dry-run against the API server and snapshotted
*before* you are asked. If either step fails the change is abandoned without prompting you.
The prompt shows the exact command, the server's diff, the rationale, and the undo command.

Bare Enter declines. Destructive actions additionally require typing the resource name.
There is no "yes to all".

### 9. Clean up

```bash
./scripts/chaos.sh heal-all
./scripts/teardown-cluster.sh
```

## Development

```bash
uv run pytest                    # unit suite: no Docker, no API key, <2s
uv run pytest -m integration     # live: needs cluster + API key, costs money
uv run ruff check . && uv run ruff format .
```

The integration suite runs the agent for real against each broken scenario and asserts the
diagnosis names the right root cause. It runs read-only, so it applies nothing.

See `CLAUDE.md` for the invariants, the test that enforces each, and the conventions for
adding a skill or a chaos scenario.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Docker is not running` | Start Docker Desktop; kind needs it. |
| `Credit balance is too low` | The API key has no credit. |
| Integration tests silently skip | No cluster, or no key. They skip rather than fail by design. |
| `context "kind-k8s-troubleshooting-agent" does not exist` | Run `./scripts/setup-cluster.sh`. |
| Agent says it cannot apply a fix | Expected without `--allow-writes` — look in `.agent-memory/proposals/`. |
| Agent refuses to fix `dns-broken` | Also expected. CoreDNS is in `kube-system`, outside the fence. |
