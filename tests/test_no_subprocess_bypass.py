"""Structural guarantee: exactly one module may spawn a process.

Every kubectl guardrail — context pinning, the policy classifier, the namespace
fence — lives inside `agent/kubectl.py`. All of it is worthless if some other
module can reach `subprocess` directly, and that is an easy mistake to make
months from now while adding an unrelated feature.

So this is a test rather than a code-review convention. If a second module ever
grows a subprocess call, the suite fails and names it.
"""

from __future__ import annotations

import ast
import pathlib

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent / "agent"

# The one module allowed to spawn processes.
CHOKE_POINT = "kubectl.py"

SPAWNING_MODULES = {"subprocess", "os", "pty", "asyncio.subprocess", "multiprocessing", "shutil"}

SPAWNING_CALLS = {
    "system",
    "popen",
    "spawn",
    "spawnl",
    "spawnv",
    "spawnve",
    "execv",
    "execve",
    "execvp",
    "fork",
    "forkpty",
    "create_subprocess_exec",
    "create_subprocess_shell",
}


def _python_files():
    return sorted(p for p in AGENT_DIR.rglob("*.py"))


def test_only_the_choke_point_imports_subprocess():
    offenders = []
    for path in _python_files():
        if path.name == CHOKE_POINT:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in {"subprocess", "pty", "multiprocessing"}:
                        offenders.append(f"{path.name}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root in {"subprocess", "pty", "multiprocessing"}:
                    offenders.append(f"{path.name}: from {node.module} import ...")

    assert not offenders, "Only agent/kubectl.py may spawn processes. Found: " + "; ".join(
        offenders
    )


def test_no_module_calls_os_level_spawn_helpers():
    offenders = []
    for path in _python_files():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = None
            if isinstance(func, ast.Attribute):
                name = func.attr
            elif isinstance(func, ast.Name):
                name = func.id
            if name in SPAWNING_CALLS:
                offenders.append(f"{path.name}:{node.lineno} calls {name}()")

    assert not offenders, "Process-spawning helpers are forbidden: " + "; ".join(offenders)


def test_shell_true_is_never_passed_anywhere():
    """shell=True would reintroduce the injection surface argv-only execution removes."""
    offenders = []
    for path in _python_files():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg == "shell":
                    is_false = isinstance(kw.value, ast.Constant) and kw.value.value is False
                    if not is_false:
                        offenders.append(f"{path.name}:{node.lineno}")

    assert not offenders, "shell=True (or a non-literal shell=) found at: " + "; ".join(offenders)


def test_the_choke_point_actually_exists():
    """Guards against the suite passing vacuously if the file is renamed."""
    assert (AGENT_DIR / CHOKE_POINT).is_file()
    assert len(_python_files()) > 1
