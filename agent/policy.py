"""Classification of every tool call the agent attempts.

This module is the security model. It is a pure function of its arguments — no
I/O, no clock, no environment — so the whole policy can be exercised without
Docker, a cluster, or an API key.

The governing rule is **fail-closed**: a verb, flag, or resource kind that is not
explicitly recognised classifies as DENY. A denylist can be outflanked by
something nobody thought of; an allowlist cannot.

`hooks.guardrail_hook` calls this on every tool invocation, including calls made
inside the subagent. Because SDK hooks run before all rules and permission modes,
a DENY here holds regardless of how the rest of the session is configured.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

import yaml

# The one cluster this agent may ever talk to. kubectl.py injects this; policy
# rejects any attempt to name a different one.
PINNED_CONTEXT = "kind-k8s-troubleshooting-agent"

# Mutations are fenced to these namespaces. Overridable at launch via --writable-ns,
# but never by the model.
DEFAULT_WRITABLE_NAMESPACES = frozenset({"chaos"})

# Never writable, even if someone passes --writable-ns kube-system. A misconfigured
# flag must not be able to unlock the control plane.
PROTECTED_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})


class Verdict(StrEnum):
    READ = "READ"
    WRITE = "WRITE"
    DESTRUCTIVE = "DESTRUCTIVE"
    DENY = "DENY"


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str


# --------------------------------------------------------------------------
# Tool routing
# --------------------------------------------------------------------------

KUBECTL_READ_TOOL = "mcp__k8s__kubectl_read"
KUBECTL_WRITE_TOOL = "mcp__k8s__kubectl_write"
APPLY_MANIFEST_TOOL = "mcp__k8s__apply_manifest"
DELETE_RESOURCE_TOOL = "mcp__k8s__delete_resource"

# Built-ins that cannot touch the cluster or the filesystem destructively.
HARMLESS_TOOLS = frozenset({"Read", "Glob", "Grep", "Skill", "Task", "TodoWrite"})

# Our own tools that only write to .agent-memory/, never to the cluster.
LOCAL_ONLY_TOOLS = frozenset({"mcp__k8s__propose_fix", "mcp__k8s__record_finding"})


# --------------------------------------------------------------------------
# kubectl vocabulary
# --------------------------------------------------------------------------

READ_VERBS = frozenset(
    {
        "get",
        "describe",
        "logs",
        "events",
        "top",
        "explain",
        "api-resources",
        "api-versions",
        "version",
        "cluster-info",
        "diff",
    }
)

WRITE_VERBS = frozenset({"apply", "patch", "scale", "set", "label", "annotate"})

DESTRUCTIVE_VERBS = frozenset({"evict", "drain"})

# Cluster-scoped mutations where requiring -n would be meaningless.
NODE_SCOPED_VERBS = frozenset({"cordon", "uncordon", "drain"})

# Only these may be deleted. Everything else — namespaces, volumes, CRDs, RBAC —
# is either data loss or cluster-wide, and is refused at any approval level.
DELETABLE_KINDS = frozenset(
    {
        "pod",
        "pods",
        "po",
        "deployment",
        "deployments",
        "deploy",
        "replicaset",
        "replicasets",
        "rs",
        "job",
        "jobs",
    }
)

# Redirect the client at another cluster, or escalate who it claims to be.
# Refused even on reads: these are not observation, they are relocation.
DENIED_CONNECTION_FLAGS = frozenset(
    {
        "--kubeconfig",
        "--server",
        "--token",
        "--as",
        "--as-group",
        "--as-uid",
        "--insecure-skip-tls-verify",
        "--client-certificate",
        "--client-key",
        "--certificate-authority",
        "--username",
        "--password",
        "--user",
        "--cluster",
        "--tls-server-name",
    }
)

# Turn one mutation into an unbounded number of them.
MASS_MUTATION_FLAGS = frozenset({"--all", "-A", "--all-namespaces", "-l", "--selector"})

# Skip graceful teardown or orphan children.
DANGEROUS_MUTATION_FLAGS = frozenset({"--force", "--grace-period", "--cascade", "--now", "--wait"})

CLUSTER_SCOPED_KINDS = frozenset(
    {
        "namespace",
        "clusterrole",
        "clusterrolebinding",
        "customresourcedefinition",
        "persistentvolume",
        "storageclass",
        "node",
        "apiservice",
        "mutatingwebhookconfiguration",
        "validatingwebhookconfiguration",
        "priorityclass",
        "ingressclass",
        "runtimeclass",
        "csidriver",
        "csinode",
        "volumeattachment",
    }
)


def _deny(reason: str) -> Decision:
    return Decision(Verdict.DENY, reason)


def _flag_name(token: str) -> str:
    """`--namespace=chaos` -> `--namespace`. Non-flags return unchanged."""
    return token.split("=", 1)[0]


def _flag_value(args: list[str], index: int) -> str | None:
    """Value of the flag at `index`, whether written `--x=v` or `--x v`."""
    token = args[index]
    if "=" in token:
        return token.split("=", 1)[1]
    if index + 1 < len(args) and not args[index + 1].startswith("-"):
        return args[index + 1]
    return None


def _find_namespace(args: list[str]) -> str | None:
    for i, token in enumerate(args):
        if _flag_name(token) in ("-n", "--namespace"):
            return _flag_value(args, i)
    return None


def _check_namespace(ns: str | None, writable: frozenset[str]) -> Decision | None:
    """None means the namespace is acceptable for mutation."""
    if ns is None:
        return _deny(
            "Mutations must name a namespace explicitly with -n. An omitted namespace "
            "silently resolves to the context default, and guessing which namespace to "
            "change is not a risk worth taking."
        )
    if ns in PROTECTED_NAMESPACES:
        return _deny(
            f"Namespace '{ns}' holds control-plane components and is never writable, "
            f"regardless of configuration. Diagnose it read-only instead."
        )
    if ns not in writable:
        return _deny(
            f"Namespace '{ns}' is outside the writable fence {sorted(writable)}. "
            f"It can be read but not changed."
        )
    return None


# --------------------------------------------------------------------------
# argv classification
# --------------------------------------------------------------------------


def _classify_argv(args: list[str], writable: frozenset[str]) -> Decision:
    if not args:
        return _deny("No command given.")
    if not all(isinstance(a, str) for a in args):
        return _deny("Every element of args must be a string.")
    if args[0] == "kubectl":
        return _deny("args must not repeat the binary name; kubectl is prepended by the caller.")
    if args[0].startswith("-"):
        return _deny("The first element of args must be a kubectl verb, not a flag.")

    # Connection and impersonation flags are refused on reads too.
    for i, token in enumerate(args):
        name = _flag_name(token)
        if name in DENIED_CONNECTION_FLAGS:
            return _deny(
                f"Flag '{name}' redirects or escalates the client connection. "
                f"This agent is pinned to context '{PINNED_CONTEXT}'."
            )
        if name == "--context":
            value = _flag_value(args, i)
            if value != PINNED_CONTEXT:
                return _deny(
                    f"Refusing context '{value}'. This agent may only talk to '{PINNED_CONTEXT}'."
                )

    verb = args[0]
    rest = args[1:]

    if verb == "auth":
        if rest[:1] == ["can-i"]:
            return Decision(Verdict.READ, "Permission check; reads no data and changes nothing.")
        return _deny("Only `auth can-i` is permitted; other auth subcommands can mutate RBAC.")

    if verb == "rollout":
        sub = rest[0] if rest else None
        if sub in ("status", "history"):
            decision = Decision(Verdict.READ, f"`rollout {sub}` only reports state.")
        elif sub == "restart":
            decision = Decision(Verdict.WRITE, "`rollout restart` recreates pods in place.")
        elif sub == "undo":
            decision = Decision(
                Verdict.DESTRUCTIVE, "`rollout undo` discards the current revision."
            )
        else:
            return _deny(f"Unrecognised rollout subcommand: {sub!r}.")
        if decision.verdict is Verdict.READ:
            return decision
        return _check_mutation(args, decision, writable, verb)

    if verb in READ_VERBS:
        return Decision(Verdict.READ, f"`{verb}` observes cluster state without changing it.")

    if verb == "delete":
        return _classify_delete(args, rest, writable)

    if verb in WRITE_VERBS:
        return _check_mutation(
            args,
            Decision(Verdict.WRITE, f"`{verb}` modifies an existing resource."),
            writable,
            verb,
        )

    if verb in NODE_SCOPED_VERBS or verb in DESTRUCTIVE_VERBS:
        level = Verdict.DESTRUCTIVE if verb in DESTRUCTIVE_VERBS else Verdict.WRITE
        return _check_mutation(
            args, Decision(level, f"`{verb}` changes node scheduling state."), writable, verb
        )

    return _deny(
        f"Verb '{verb}' is not on the allowlist. Unrecognised commands are refused rather "
        f"than assumed safe."
    )


def _classify_delete(args: list[str], rest: list[str], writable: frozenset[str]) -> Decision:
    if not rest:
        return _deny("`delete` needs a resource kind and name.")

    target = rest[0]
    if "/" in target:
        kind, _, name = target.partition("/")
    else:
        kind = target
        name = rest[1] if len(rest) > 1 and not rest[1].startswith("-") else ""

    kind = kind.lower()

    if kind not in DELETABLE_KINDS:
        return _deny(
            f"Deleting a resource of kind '{kind}' is never permitted — only pods, "
            f"deployments, replicasets and jobs may be deleted. Anything else risks data "
            f"loss or cluster-wide effect."
        )
    if not name:
        return _deny("`delete` must name exactly one resource. Deleting by kind alone is refused.")

    return _check_mutation(
        args,
        Decision(Verdict.DESTRUCTIVE, f"Deletes {kind}/{name}."),
        writable,
        "delete",
    )


def _check_mutation(
    args: list[str], decision: Decision, writable: frozenset[str], verb: str
) -> Decision:
    """Scope and fence checks applied to every mutating command."""
    for token in args:
        name = _flag_name(token)
        if name in MASS_MUTATION_FLAGS:
            return _deny(
                f"Flag '{name}' turns this into a bulk mutation. Exactly one named "
                f"resource per call."
            )
        if name in DANGEROUS_MUTATION_FLAGS:
            return _deny(
                f"Flag '{name}' bypasses graceful teardown or orphans dependents, which "
                f"is how a fix becomes an outage."
            )

    if verb not in NODE_SCOPED_VERBS:
        problem = _check_namespace(_find_namespace(args), writable)
        if problem is not None:
            return problem

    return decision


# --------------------------------------------------------------------------
# Structured tools
# --------------------------------------------------------------------------


def _classify_apply(tool_input: dict, writable: frozenset[str]) -> Decision:
    manifest = tool_input.get("manifest")
    rationale = tool_input.get("rationale")
    namespace = tool_input.get("namespace")

    if not isinstance(manifest, str) or not manifest.strip():
        return _deny("A non-empty manifest is required.")
    if not isinstance(rationale, str) or not rationale.strip():
        return _deny(
            "A rationale is required. It is shown in the approval prompt and recorded "
            "in the audit log."
        )
    if not isinstance(namespace, str):
        return _deny("An explicit target namespace is required.")

    problem = _check_namespace(namespace, writable)
    if problem is not None:
        return problem

    try:
        docs = list(yaml.safe_load_all(manifest))
    except yaml.YAMLError as exc:
        return _deny(f"Manifest is not valid YAML: {exc}")

    seen = False
    for doc in docs:
        if doc is None:
            continue
        seen = True
        if not isinstance(doc, dict):
            return _deny("Each manifest document must be a mapping.")

        kind = doc.get("kind")
        if not isinstance(kind, str) or not kind.strip():
            return _deny("Each manifest document must declare a kind.")
        if kind.lower() in CLUSTER_SCOPED_KINDS:
            return _deny(
                f"Kind '{kind}' is cluster-scoped and cannot be confined by the namespace "
                f"fence, so applying it is refused."
            )

        metadata = doc.get("metadata") or {}
        if isinstance(metadata, dict):
            embedded = metadata.get("namespace")
            if embedded is not None and embedded != namespace:
                return _deny(
                    f"Manifest declares metadata.namespace '{embedded}' but the call "
                    f"targets '{namespace}'. An embedded namespace would escape the fence."
                )

    if not seen:
        return _deny("Manifest contains no documents.")

    return Decision(Verdict.WRITE, f"Applies {len(docs)} document(s) to namespace '{namespace}'.")


def _classify_delete_resource(tool_input: dict, writable: frozenset[str]) -> Decision:
    kind = tool_input.get("kind")
    name = tool_input.get("name")
    namespace = tool_input.get("namespace")
    rationale = tool_input.get("rationale")

    if not isinstance(kind, str) or kind.lower() not in DELETABLE_KINDS:
        return _deny(
            f"Deleting a resource of kind '{kind}' is never permitted — only pods, "
            f"deployments, replicasets and jobs may be deleted."
        )
    if not isinstance(name, str) or not name.strip():
        return _deny("A resource name is required.")
    if not isinstance(rationale, str) or not rationale.strip():
        return _deny("A rationale is required for a destructive action.")
    if not isinstance(namespace, str):
        return _deny("An explicit target namespace is required.")

    problem = _check_namespace(namespace, writable)
    if problem is not None:
        return problem

    return Decision(Verdict.DESTRUCTIVE, f"Deletes {kind}/{name} in namespace '{namespace}'.")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def classify(
    tool_name: str,
    tool_input: dict,
    *,
    writable_namespaces: frozenset[str] | None = None,
) -> Decision:
    """Classify one tool call. Never raises; an unclassifiable call is DENY."""
    writable = (
        DEFAULT_WRITABLE_NAMESPACES
        if writable_namespaces is None
        else frozenset(writable_namespaces)
    )
    tool_input = tool_input or {}

    if tool_name in HARMLESS_TOOLS:
        return Decision(Verdict.READ, f"`{tool_name}` cannot reach the cluster.")

    if tool_name in LOCAL_ONLY_TOOLS:
        return Decision(Verdict.READ, f"`{tool_name}` writes only to local session state.")

    if tool_name in (KUBECTL_READ_TOOL, KUBECTL_WRITE_TOOL):
        args = tool_input.get("args")
        if not isinstance(args, list):
            return _deny("args must be a list of strings.")
        decision = _classify_argv(args, writable)
        # The read tool must never become a mutation path, whatever it was handed.
        if tool_name == KUBECTL_READ_TOOL and decision.verdict not in (Verdict.READ, Verdict.DENY):
            return _deny(
                f"`kubectl_read` was given a mutating command ({args[0]!r}). Mutations must "
                f"go through the gated write tools."
            )
        return decision

    if tool_name == APPLY_MANIFEST_TOOL:
        return _classify_apply(tool_input, writable)

    if tool_name == DELETE_RESOURCE_TOOL:
        return _classify_delete_resource(tool_input, writable)

    return _deny(
        f"Tool '{tool_name}' is not on the allowlist. Unrecognised tools are refused rather "
        f"than assumed safe."
    )
