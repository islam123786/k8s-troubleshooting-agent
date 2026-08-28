"""The choke point.

`kubectl.run` is the only place in the project that spawns a process. Every
guardrail in the design rests on two properties proved here:

  1. the pinned context is injected on *every* invocation, so the agent cannot
     be redirected at a real cluster by ambient kubeconfig state; and
  2. the policy classifier runs *before* anything is spawned, so a DENY never
     reaches the operating system.
"""

from __future__ import annotations

import subprocess

import pytest

from agent import kubectl
from agent.kubectl import DeniedError, Result
from agent.policy import PINNED_CONTEXT, Verdict

READ = "mcp__k8s__kubectl_read"
WRITE = "mcp__k8s__kubectl_write"


# --------------------------------------------------------------------------
# Context pinning
# --------------------------------------------------------------------------


def test_pinned_context_is_injected(runner):
    kubectl.run(["get", "pods", "-n", "chaos"], tool_name=READ, runner=runner)
    argv = runner.last_argv
    assert argv[0] == "kubectl"
    assert "--context" in argv
    assert argv[argv.index("--context") + 1] == PINNED_CONTEXT


@pytest.mark.parametrize(
    "args",
    [
        ["get", "pods", "-n", "chaos"],
        ["describe", "pod", "web", "-n", "chaos"],
        ["logs", "web", "-n", "chaos"],
        ["events", "-n", "chaos"],
    ],
)
def test_every_invocation_is_pinned(args, runner):
    kubectl.run(args, tool_name=READ, runner=runner)
    assert runner.last_argv.count("--context") == 1
    assert PINNED_CONTEXT in runner.last_argv


def test_caller_supplied_pinned_context_is_not_duplicated(runner):
    """Policy permits a redundant --context if it names the pinned cluster.
    kubectl must not then see the flag twice."""
    kubectl.run(
        ["get", "pods", "-n", "chaos", "--context", PINNED_CONTEXT], tool_name=READ, runner=runner
    )
    assert runner.last_argv.count("--context") == 1

    kubectl.run(
        ["get", "pods", "-n", "chaos", f"--context={PINNED_CONTEXT}"], tool_name=READ, runner=runner
    )
    argv = runner.last_argv
    assert argv.count("--context") == 1
    assert not any(a.startswith("--context=") for a in argv)


def test_context_is_a_constant_not_read_from_environment(monkeypatch, runner):
    """A stray `kubectl config use-context prod` on the developer's machine, or a
    KUBECONFIG pointing somewhere else, must not change where the agent points."""
    monkeypatch.setenv("KUBECONFIG", "/tmp/somewhere-else.yaml")
    monkeypatch.setenv("KUBE_CONTEXT", "production")
    kubectl.run(["get", "pods", "-n", "chaos"], tool_name=READ, runner=runner)
    argv = runner.last_argv
    assert argv[argv.index("--context") + 1] == PINNED_CONTEXT


# --------------------------------------------------------------------------
# Policy runs first
# --------------------------------------------------------------------------


def test_denied_command_never_spawns(runner):
    with pytest.raises(DeniedError):
        kubectl.run(["delete", "namespace", "chaos"], tool_name=WRITE, runner=runner)
    assert not runner.called, "policy DENY must be decided before anything is spawned"


def test_denied_error_carries_the_decision(runner):
    with pytest.raises(DeniedError) as excinfo:
        kubectl.run(["exec", "web", "--", "sh"], tool_name=WRITE, runner=runner)
    assert excinfo.value.decision.verdict is Verdict.DENY
    assert excinfo.value.decision.reason
    assert str(excinfo.value)


def test_foreign_context_is_refused_before_spawning(runner):
    with pytest.raises(DeniedError):
        kubectl.run(["get", "pods", "--context", "prod"], tool_name=READ, runner=runner)
    assert not runner.called


def test_writable_namespaces_are_threaded_through_to_policy(runner):
    args = ["scale", "deployment", "web", "--replicas=2", "-n", "staging"]
    with pytest.raises(DeniedError):
        kubectl.run(args, tool_name=WRITE, runner=runner)

    kubectl.run(args, tool_name=WRITE, runner=runner, writable_namespaces=frozenset({"staging"}))
    assert runner.called


def test_read_tool_cannot_mutate(runner):
    with pytest.raises(DeniedError):
        kubectl.run(["delete", "pod", "web", "-n", "chaos"], tool_name=READ, runner=runner)
    assert not runner.called


# --------------------------------------------------------------------------
# Argv construction
# --------------------------------------------------------------------------


def test_arguments_are_passed_as_a_list_never_a_string(runner):
    kubectl.run(["get", "pods", "-n", "chaos"], tool_name=READ, runner=runner)
    argv = runner.last_argv
    assert isinstance(argv, list)
    assert all(isinstance(a, str) for a in argv)


def test_shell_metacharacters_stay_inert_in_a_single_argument(runner):
    """argv-only execution means this is a literal pod name, not a command."""
    evil = "web; rm -rf /"
    kubectl.run(["logs", evil, "-n", "chaos"], tool_name=READ, runner=runner)
    assert evil in runner.last_argv


def test_caller_args_are_not_mutated(runner):
    args = ["get", "pods", "-n", "chaos"]
    snapshot = list(args)
    kubectl.run(args, tool_name=READ, runner=runner)
    assert args == snapshot


# --------------------------------------------------------------------------
# Result handling
# --------------------------------------------------------------------------


def test_result_carries_streams_and_exit_code(runner):
    runner.returncode = 1
    runner.stdout = "some output"
    runner.stderr = "some error"
    result = kubectl.run(["get", "pods", "-n", "chaos"], tool_name=READ, runner=runner)
    assert isinstance(result, Result)
    assert result.returncode == 1
    assert result.stdout == "some output"
    assert result.stderr == "some error"
    assert result.ok is False
    assert result.timed_out is False


def test_nonzero_exit_is_returned_not_raised(runner):
    """A failing kubectl is diagnostic signal — 'NotFound' is often the answer.
    Only a policy denial is exceptional."""
    runner.returncode = 1
    runner.stderr = 'Error from server (NotFound): pods "web" not found'
    result = kubectl.run(["get", "pod", "web", "-n", "chaos"], tool_name=READ, runner=runner)
    assert result.returncode == 1
    assert "NotFound" in result.stderr


def test_oversized_output_is_truncated(runner):
    runner.stdout = "x" * (kubectl.MAX_OUTPUT_CHARS + 5000)
    result = kubectl.run(["get", "pods", "-n", "chaos"], tool_name=READ, runner=runner)
    assert len(result.stdout) <= kubectl.MAX_OUTPUT_CHARS + 200
    assert "truncated" in result.stdout.lower()


def test_timeout_is_reported_not_raised(runner):
    runner.raises = subprocess.TimeoutExpired(cmd=["kubectl"], timeout=1.0)
    result = kubectl.run(["get", "pods", "-n", "chaos"], tool_name=READ, runner=runner)
    assert result.timed_out is True
    assert result.ok is False
    assert "timed out" in result.stderr.lower()


def test_missing_binary_is_reported_clearly(runner):
    runner.raises = FileNotFoundError("kubectl")
    result = kubectl.run(["get", "pods", "-n", "chaos"], tool_name=READ, runner=runner)
    assert result.ok is False
    assert "kubectl" in result.stderr.lower()


def test_stdin_is_forwarded_for_apply(runner):
    kubectl.run(
        ["apply", "-f", "-", "-n", "chaos"],
        tool_name=WRITE,
        runner=runner,
        stdin="kind: Pod\n",
    )
    assert runner.calls[-1]["stdin"] == "kind: Pod\n"


def test_timeout_is_bounded(runner):
    kubectl.run(["get", "pods", "-n", "chaos"], tool_name=READ, runner=runner)
    assert 0 < runner.calls[-1]["timeout"] <= kubectl.MAX_TIMEOUT_SECONDS
