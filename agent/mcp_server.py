"""The in-process MCP server — the agent's entire route to the cluster.

`Bash` is removed from the toolset, so these tools are the only way the model can
observe or change anything. Each one is a thin, typed wrapper that hands a fixed
argv shape to `kubectl.run`; none of them accepts a command string.

Two things happen to every piece of cluster output before the model sees it:

* **Redaction.** Secret values are replaced with a length placeholder.
* **Delimiting.** Output is wrapped in `<untrusted-output>` tags. Pod logs, event
  messages and annotations are written by workloads, not by the operator, so text
  inside them that appears to issue instructions is data to be reported, never
  followed. The delimiters are a labelling aid; the actual protection is
  structural — in read-only mode the mutating tools are not registered at all, so
  a successful injection has nothing to reach for.
"""

from __future__ import annotations

from typing import Any

from claude_agent_sdk import create_sdk_mcp_server, tool

from agent import kubectl
from agent.approval import ApprovalGate
from agent.kubectl import DeniedError
from agent.memory import Journal
from agent.policy import (
    APPLY_MANIFEST_TOOL,
    DELETE_RESOURCE_TOOL,
    INTERNAL_APPLY_TOOL,
    INTERNAL_DELETE_TOOL,
    KUBECTL_READ_TOOL,
    KUBECTL_WRITE_TOOL,
)
from agent.redact import redact

SERVER_NAME = "k8s"


def _text(body: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": body}]}


def _wrap(result: kubectl.Result) -> str:
    """Render a kubectl result as clearly-labelled untrusted data."""
    parts = [f"$ {' '.join(result.argv)}", f"exit status: {result.returncode}"]
    if result.stdout.strip():
        parts.append('<untrusted-output stream="stdout">')
        parts.append(redact(result.stdout))
        parts.append("</untrusted-output>")
    if result.stderr.strip():
        parts.append('<untrusted-output stream="stderr">')
        parts.append(redact(result.stderr))
        parts.append("</untrusted-output>")
    if not result.stdout.strip() and not result.stderr.strip():
        parts.append("(no output)")
    return "\n".join(parts)


def build_tools(
    *,
    journal: Journal,
    writable_namespaces: frozenset[str] | None = None,
    allow_writes: bool = False,
):
    """The tools the model will be given.

    Kept separate from `build_server` so the composition — specifically, that
    nothing mutating appears unless `allow_writes` — is directly assertable
    without reaching into the SDK's private registries.
    """

    def _run(args: list[str], tool_name: str, stdin: str | None = None) -> str:
        try:
            result = kubectl.run(
                args,
                tool_name=tool_name,
                stdin=stdin,
                writable_namespaces=writable_namespaces,
            )
        except DeniedError as denied:
            return f"Refused by policy: {denied.decision.reason}"
        return _wrap(result)

    @tool(
        "kubectl_read",
        "Run a read-only kubectl command against the cluster. Pass the command as a "
        "list of arguments without the leading 'kubectl', e.g. "
        "['describe', 'pod', 'web-abc', '-n', 'chaos']. Read verbs only: get, "
        "describe, logs, events, top, explain, api-resources, version, cluster-info, "
        "diff, and 'auth can-i'.",
        {"args": list},
    )
    async def kubectl_read(args: dict[str, Any]) -> dict[str, Any]:
        return _text(_run(list(args.get("args") or []), KUBECTL_READ_TOOL))

    @tool(
        "record_finding",
        "Record a diagnosis in the session journal. Use this once you can explain "
        "the causal chain from a configuration fact to the observed behaviour. "
        "Every field is optional — record what you have rather than withholding a "
        "partial finding.",
        {
            "title": str,
            "resource": str,
            "namespace": str,
            "root_cause": str,
            "evidence": str,
            "fix": str,
        },
    )
    async def record_finding(args: dict[str, Any]) -> dict[str, Any]:
        path = journal.record_finding(
            title=str(args.get("title") or ""),
            summary=str(args.get("summary") or ""),
            resource=str(args.get("resource") or ""),
            namespace=str(args.get("namespace") or ""),
            root_cause=str(args.get("root_cause") or ""),
            evidence=str(args.get("evidence") or ""),
            fix=str(args.get("fix") or ""),
            applied=False,
        )
        return _text(f"Recorded in {path}")

    @tool(
        "propose_fix",
        "Write a complete fix out to a file for a human to review and apply. This "
        "changes nothing in the cluster. Use it whenever you know the fix but are "
        "not permitted to apply it, or the change deserves review first.",
        {"diagnosis": str, "manifest": str, "rationale": str},
    )
    async def propose_fix(args: dict[str, Any]) -> dict[str, Any]:
        path = journal.propose_fix(
            diagnosis=str(args.get("diagnosis") or ""),
            manifest=str(args.get("manifest") or ""),
            rationale=str(args.get("rationale") or ""),
        )
        return _text(
            f"Wrote a proposed fix to {path}. Nothing has been applied. "
            f"Tell the user the path and what the change does."
        )

    tools = [kubectl_read, record_finding, propose_fix]

    if allow_writes:

        @tool(
            "kubectl_write",
            "Run a mutating kubectl command. Requires approval. Verbs: patch, scale, "
            "set, label, annotate, 'rollout restart', cordon, uncordon. To apply a "
            "manifest use apply_manifest; to delete use delete_resource.",
            {"args": list, "rationale": str},
        )
        async def kubectl_write(args: dict[str, Any]) -> dict[str, Any]:
            return _text(_run(list(args.get("args") or []), KUBECTL_WRITE_TOOL))

        @tool(
            "apply_manifest",
            "Apply a Kubernetes manifest. Requires approval. The manifest is "
            "validated server-side first and the prior state is snapshotted so the "
            "change can be undone.",
            {"manifest": str, "namespace": str, "rationale": str},
        )
        async def apply_manifest(args: dict[str, Any]) -> dict[str, Any]:
            namespace = str(args.get("namespace") or "")
            manifest = str(args.get("manifest") or "")
            return _text(
                _run(["apply", "-f", "-", "-n", namespace], INTERNAL_APPLY_TOOL, stdin=manifest)
            )

        @tool(
            "delete_resource",
            "Delete one named pod, deployment, replicaset or job. Requires approval "
            "and a typed confirmation of the resource name.",
            {"kind": str, "name": str, "namespace": str, "rationale": str},
        )
        async def delete_resource(args: dict[str, Any]) -> dict[str, Any]:
            return _text(
                _run(
                    [
                        "delete",
                        str(args.get("kind") or ""),
                        str(args.get("name") or ""),
                        "-n",
                        str(args.get("namespace") or ""),
                    ],
                    INTERNAL_DELETE_TOOL,
                )
            )

        tools += [kubectl_write, apply_manifest, delete_resource]

    return tools


def build_server(
    *,
    journal: Journal,
    writable_namespaces: frozenset[str] | None = None,
    allow_writes: bool = False,
    approval_gate: ApprovalGate | None = None,
):
    """Build the MCP server. Mutating tools are omitted entirely unless allowed."""
    return create_sdk_mcp_server(
        name=SERVER_NAME,
        version="1.0.0",
        tools=build_tools(
            journal=journal,
            writable_namespaces=writable_namespaces,
            allow_writes=allow_writes,
        ),
    )


# Names the SDK will expose these under, for allowed_tools / disallowed_tools.
READ_TOOL_NAMES = (KUBECTL_READ_TOOL, "mcp__k8s__record_finding", "mcp__k8s__propose_fix")
WRITE_TOOL_NAMES = (KUBECTL_WRITE_TOOL, APPLY_MANIFEST_TOOL, DELETE_RESOURCE_TOOL)
