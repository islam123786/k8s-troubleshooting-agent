"""A minimal browser front end for the troubleshooting agent.

    uv run python -m agent.web        # then open http://127.0.0.1:8765

Built on Starlette and uvicorn, both of which arrive as transitive dependencies
of the Agent SDK — so the UI adds no new packages.

**The UI is read-only, deliberately.** The approval gate is a blocking stdin
prompt: it must hold the mutation open while a person reads a diff and types a
resource name. A browser equivalent that renders a prompt but cannot actually
hold the call open would look like an approval gate without being one, and that
is worse than not offering writes at all. So the web session runs exactly like
`agent.cli` with no `--allow-writes`: the mutating tools are never registered,
and the agent delivers fixes through `propose_fix` for you to apply yourself.

Everything else — the policy hook, the pinned context, redaction, the audit log —
comes from the same `build_options` / `build_server` the CLI uses, so there is one
security model rather than two.
"""

from __future__ import annotations

import json
from pathlib import Path

from claude_agent_sdk import (
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
    query,
)
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.routing import Route

from agent.audit import AuditLog
from agent.cli import SYSTEM_PROMPT
from agent.env import load_project_env
from agent.mcp_server import build_server
from agent.memory import Journal
from agent.options import build_options
from agent.policy import DEFAULT_WRITABLE_NAMESPACES, PINNED_CONTEXT
from agent.redact import redact

# Not a setting. Writes need an approval round-trip this UI does not implement;
# see the module docstring. `tests/test_web.py` fails if this is flipped.
ALLOW_WRITES = False

HOST = "127.0.0.1"
PORT = 8765

STATIC = Path(__file__).parent / "static"


def _memory_root(project_root: Path) -> Path:
    return Path(project_root) / ".agent-memory"


def _session_options(project_root: Path):
    """The same session the CLI builds, minus writes."""
    memory_root = _memory_root(project_root)
    return build_options(
        audit_log=AuditLog(memory_root / "audit.jsonl"),
        project_root=project_root,
        allow_writes=ALLOW_WRITES,
        system_prompt=SYSTEM_PROMPT,
        mcp_server=build_server(journal=Journal(root=memory_root), allow_writes=ALLOW_WRITES),
    )


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _describe_tool(block: ToolUseBlock) -> str:
    """A one-line rendering of what the agent is about to do."""
    args = block.input or {}
    if isinstance(args, dict) and args.get("args"):
        return "kubectl " + " ".join(str(a) for a in args["args"])
    if isinstance(args, dict) and args.get("title"):
        return str(args["title"])
    name = block.name.rsplit("__", 1)[-1]
    return name.replace("_", " ")


def build_app(project_root: Path | str = ".") -> Starlette:
    project_root = Path(project_root).resolve()
    load_project_env(project_root)

    async def index(_: Request) -> HTMLResponse:
        return HTMLResponse((STATIC / "index.html").read_text(encoding="utf-8"))

    async def health(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "context": PINNED_CONTEXT,
                "read_only": not ALLOW_WRITES,
                "writable_namespaces": sorted(DEFAULT_WRITABLE_NAMESPACES),
            }
        )

    async def findings(_: Request) -> JSONResponse:
        journal = Journal(root=_memory_root(project_root))
        return JSONResponse({"text": journal.read_findings()})

    async def audit(_: Request) -> JSONResponse:
        path = _memory_root(project_root) / "audit.jsonl"
        entries = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    entries.append(json.loads(redact(line)))
        except (OSError, json.JSONDecodeError):
            pass
        return JSONResponse({"entries": entries[-100:]})

    async def ask(request: Request):
        question = (request.query_params.get("q") or "").strip()
        if not question:
            return JSONResponse({"error": "empty question"}, status_code=400)

        async def stream():
            try:
                async for message in query(prompt=question, options=_session_options(project_root)):
                    if isinstance(message, AssistantMessage):
                        for block in message.content:
                            if isinstance(block, TextBlock):
                                yield _sse("text", {"text": block.text})
                            elif isinstance(block, ThinkingBlock):
                                yield _sse("thinking", {"text": ""})
                            elif isinstance(block, ToolUseBlock):
                                yield _sse(
                                    "tool",
                                    {
                                        "name": block.name.rsplit("__", 1)[-1],
                                        "detail": _describe_tool(block),
                                    },
                                )
                    elif isinstance(message, ResultMessage):
                        yield _sse(
                            "done",
                            {
                                "turns": message.num_turns,
                                "cost_usd": message.total_cost_usd,
                                "is_error": message.is_error,
                            },
                        )
            except Exception as exc:  # noqa: BLE001 - the browser needs to hear about it
                yield _sse("error", {"message": f"{exc.__class__.__name__}: {exc}"})

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return Starlette(
        routes=[
            Route("/", index),
            Route("/api/health", health),
            Route("/api/ask", ask),
            Route("/api/findings", findings),
            Route("/api/audit", audit),
        ]
    )


def main() -> int:
    import uvicorn

    print(f"Kubernetes troubleshooting agent — http://{HOST}:{PORT}")
    print(f"  cluster : {PINNED_CONTEXT}")
    print("  mode    : diagnose only (read-only)")
    uvicorn.run(build_app("."), host=HOST, port=PORT, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
