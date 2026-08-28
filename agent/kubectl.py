"""The single choke point: the only module in this project that spawns a process.

Two invariants live here, and `tests/test_no_subprocess_bypass.py` enforces the
structural claim that nothing else can sidestep them:

  1. **Context pinning.** `--context kind-k8s-troubleshooting-agent` is injected
     on every invocation from a hardcoded constant. The agent's target cluster is
     therefore not a function of ambient kubeconfig state, so a developer running
     `kubectl config use-context prod` in another terminal cannot redirect it.

  2. **Policy first.** `policy.classify` runs before anything is spawned. A DENY
     raises `DeniedError` and never reaches the operating system.

Commands are always built as an argv list with `shell=False`, so a pod name
containing shell metacharacters is inert data rather than a command.
"""

from __future__ import annotations

import subprocess  # noqa: S404 - this is the one module permitted to spawn processes
from collections.abc import Callable
from dataclasses import dataclass

from agent.policy import (
    KUBECTL_READ_TOOL,
    PINNED_CONTEXT,
    Decision,
    Verdict,
    classify,
)

KUBECTL_BIN = "kubectl"

# Kubernetes output can be enormous (a full `get -o yaml` of a large deployment).
# Truncating protects the model's context window rather than the cluster.
MAX_OUTPUT_CHARS = 20_000

DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_TIMEOUT_SECONDS = 120.0

# (returncode, stdout, stderr)
Runner = Callable[[list[str], "str | None", float], tuple[int, str, str]]


class DeniedError(Exception):
    """Raised when policy refuses a command. Nothing was spawned."""

    def __init__(self, decision: Decision):
        super().__init__(decision.reason)
        self.decision = decision


@dataclass(frozen=True)
class Result:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    dropped = len(text) - MAX_OUTPUT_CHARS
    return text[:MAX_OUTPUT_CHARS] + f"\n... [truncated {dropped} more characters]"


def _strip_context_flags(args: list[str]) -> list[str]:
    """Remove any caller-supplied --context so the injected one is unambiguous.

    Policy has already established that a present --context names the pinned
    cluster, so dropping it changes nothing except avoiding a duplicated flag.
    """
    cleaned: list[str] = []
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg == "--context":
            # Value form: --context <value>
            if i + 1 < len(args) and not args[i + 1].startswith("-"):
                skip_next = True
            continue
        if arg.startswith("--context="):
            continue
        cleaned.append(arg)
    return cleaned


def _default_runner(argv: list[str], stdin: str | None, timeout: float) -> tuple[int, str, str]:
    completed = subprocess.run(  # noqa: S603 - argv list, shell=False, fixed binary
        argv,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def run(
    args: list[str],
    *,
    tool_name: str = KUBECTL_READ_TOOL,
    stdin: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    writable_namespaces: frozenset[str] | None = None,
    runner: Runner | None = None,
) -> Result:
    """Run one kubectl command against the pinned cluster.

    Raises `DeniedError` if policy refuses. A non-zero exit is *not* an error:
    `Error from server (NotFound)` is frequently the diagnosis, so it is returned
    as data for the model to reason about.
    """
    decision = classify(tool_name, {"args": args}, writable_namespaces=writable_namespaces)
    if decision.verdict is Verdict.DENY:
        raise DeniedError(decision)

    runner = runner or _default_runner
    timeout = min(max(timeout, 0.1), MAX_TIMEOUT_SECONDS)

    argv = [KUBECTL_BIN, "--context", PINNED_CONTEXT, *_strip_context_flags(list(args))]

    try:
        returncode, stdout, stderr = runner(argv, stdin, timeout)
    except subprocess.TimeoutExpired:
        return Result(
            argv=argv,
            returncode=124,
            stdout="",
            stderr=f"kubectl timed out after {timeout:.0f}s.",
            timed_out=True,
        )
    except FileNotFoundError:
        return Result(
            argv=argv,
            returncode=127,
            stdout="",
            stderr="kubectl was not found on PATH.",
        )

    return Result(
        argv=argv,
        returncode=returncode,
        stdout=_truncate(stdout or ""),
        stderr=_truncate(stderr or ""),
    )
