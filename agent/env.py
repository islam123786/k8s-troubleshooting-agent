"""Load the project's `.env` so the SDK can find the API key.

The Agent SDK reads `ANTHROPIC_API_KEY` from the process environment. A `.env`
file is the natural place to keep it — it is gitignored, unlike `.env.example` —
but nothing reads it automatically, which makes for a confusing failure: the file
looks right and the agent reports no API key.

An already-exported variable always wins, so a deliberate `export` in the shell
overrides a stale file rather than being silently replaced by it.
"""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


def load_project_env(project_root: Path | str = ".") -> None:
    """Load `<project_root>/.env` if present. Never overrides an exported value."""
    load_dotenv(Path(project_root) / ".env", override=False)
