"""Loading the API key, and keeping it out of git.

A `.env` file that nothing reads is the worst of both worlds: it looks like
configuration, and the agent fails with "no API key" while the file sits there
looking correct. So the loading is tested, not assumed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from agent.env import load_project_env

ROOT = Path(__file__).resolve().parent.parent


def test_env_file_is_loaded_into_the_environment(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-from-file\n")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    load_project_env(tmp_path)
    import os

    assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-from-file"


def test_an_already_exported_key_wins(tmp_path, monkeypatch):
    """An explicit export is a deliberate override — a stale .env must not win."""
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-from-file\n")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-exported")
    load_project_env(tmp_path)
    import os

    assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-exported"


def test_a_missing_env_file_is_not_an_error(tmp_path):
    load_project_env(tmp_path)


def test_dotenv_is_gitignored():
    """The near-miss with .env.example is the reason this is a test."""
    result = subprocess.run(  # noqa: S603
        ["git", "check-ignore", ".env"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, ".env must be gitignored — it holds a live credential"


def test_no_real_key_is_tracked_by_git():
    """.env.example is committed. A real key must never live in it.

    The needle is assembled at runtime so this file does not match itself — which
    it did on the first run, reporting the guard as the leak.
    """
    needle = "sk-ant" + "-api"
    tracked = subprocess.run(  # noqa: S603
        ["git", "ls-files"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert ".env" not in tracked
    for path in tracked:
        if path.endswith((".py", ".md", ".toml", ".yaml", ".yml", ".sh", ".example", ".json")):
            body = (ROOT / path).read_text(errors="ignore")
            assert needle not in body, f"a real-looking API key is committed in {path}"
