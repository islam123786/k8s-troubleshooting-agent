"""Shared test doubles.

Nothing in the unit suite may spawn a real process or touch a real cluster, so
`kubectl.run` takes an injectable runner and these fakes stand in for it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from agent.env import load_project_env

# Integration tests skip themselves when ANTHROPIC_API_KEY is unset, so the .env
# has to be loaded before collection decides — otherwise they silently skip while
# a perfectly good key sits in the file.
load_project_env(Path(__file__).resolve().parent.parent)


@dataclass
class FakeRunner:
    """Records the argv it was handed and replays a canned result.

    The recording is the point: most of `test_kubectl.py` is an assertion about
    the exact argv that would have reached the operating system.
    """

    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    raises: BaseException | None = None
    calls: list[dict] = field(default_factory=list)

    def __call__(self, argv: list[str], stdin: str | None, timeout: float):
        self.calls.append({"argv": list(argv), "stdin": stdin, "timeout": timeout})
        if self.raises is not None:
            raise self.raises
        return self.returncode, self.stdout, self.stderr

    @property
    def called(self) -> bool:
        return bool(self.calls)

    @property
    def last_argv(self) -> list[str]:
        assert self.calls, "runner was never called"
        return self.calls[-1]["argv"]


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()
