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

# Execution paths used by the structured tools *after* they have validated their
# input. These are never registered as MCP tools, so the model cannot name them;
# they exist so `apply` and `delete` remain unreachable from free-form argv.
INTERNAL_APPLY_TOOL = "internal__apply"
INTERNAL_DELETE_TOOL = "internal__delete"

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
MASS_MUTATION_FLAGS = frozenset(
    {"--all", "-A", "--all-namespaces", "-l", "--selector", "--field-selector"}
)

# Output formats that return a whole document, which redact() can parse and scrub.
# An allowlist, because the danger is the opposite of a recognisable shape: a
# projecting format (`-o jsonpath={.data.password}`) returns a bare value with no
# surrounding document, so redaction has nothing to identify it by and a Secret
# walks out through the auto-approved read tool.
ALLOWED_OUTPUT_FORMATS = frozenset({"yaml", "json", "wide", "name", ""})

# Renders arbitrary projections; same problem as the formats above.
DENIED_TEMPLATE_FLAGS = frozenset({"--template", "--template-file"})

# Skip graceful teardown or orphan children.
DANGEROUS_MUTATION_FLAGS = frozenset({"--force", "--grace-period", "--cascade", "--now", "--wait"})

# Kinds the agent may apply. An allowlist rather than a denylist of cluster-scoped
# kinds, because cluster-scoped kinds arrive from CRDs and cannot be enumerated —
# so the namespace fence provably could not contain whatever a denylist missed.
# Secret is deliberately absent: applying one would put its value into a rollback
# snapshot on disk.
APPLICABLE_KINDS = frozenset(
    {
        "pod",
        "deployment",
        "replicaset",
        "statefulset",
        "daemonset",
        "job",
        "cronjob",
        "service",
        "endpoints",
        "ingress",
        "networkpolicy",
        "configmap",
        "persistentvolumeclaim",
        "resourcequota",
        "limitrange",
        "horizontalpodautoscaler",
        "poddisruptionbudget",
        "serviceaccount",
        "role",
        "rolebinding",
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


def _namespace_values(args: list[str]) -> list[str | None]:
    """Every namespace this command names, in order.

    Handles `-n x`, `-nx`, `--namespace x` and `--namespace=x`, and stops at the
    `--` terminator. Returning all of them (rather than the first) is what lets
    the caller notice a command that names two different namespaces.
    """
    values: list[str | None] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            break
        name, sep, inline = arg.partition("=")
        if name == "--namespace":
            if sep:
                values.append(inline)
            elif i + 1 < len(args) and not args[i + 1].startswith("-"):
                values.append(args[i + 1])
                i += 1
            else:
                values.append(None)
        elif arg.startswith("-n") and not arg.startswith("--"):
            if len(arg) > 2:
                values.append(arg[2:])  # attached form: -nchaos
            elif i + 1 < len(args) and not args[i + 1].startswith("-"):
                values.append(args[i + 1])
                i += 1
            else:
                values.append(None)
        i += 1
    return values


def _check_output_format(args: list[str]) -> Decision | None:
    """Refuse output formats that project a bare value out of a document."""
    for i, arg in enumerate(args):
        name = _flag_name(arg)
        if name in DENIED_TEMPLATE_FLAGS:
            return _deny(
                f"Flag '{name}' renders an arbitrary projection, which redaction cannot "
                f"recognise as Secret material. Use -o yaml or -o json."
            )
        if name not in ("-o", "--output"):
            continue
        value = (_flag_value(args, i) or "").split("=", 1)[0]
        if value not in ALLOWED_OUTPUT_FORMATS:
            return _deny(
                f"Output format '{value}' returns a bare projected value rather than a "
                f"document, so secret redaction cannot see what it is. Permitted: "
                f"{sorted(f for f in ALLOWED_OUTPUT_FORMATS if f)}."
            )
    return None


def _check_namespace_args(args: list[str], writable: frozenset[str]) -> Decision | None:
    values = _namespace_values(args)
    if len({v for v in values}) > 1:
        return _deny(
            f"Command names more than one namespace ({sorted(str(v) for v in set(values))}). "
            f"kubectl resolves a repeated flag last-wins, so this is refused as ambiguous "
            f"rather than guessed at."
        )
    return _check_namespace(values[0] if values else None, writable)


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


def _check_deletable(kind: str) -> Decision | None:
    """One place that decides, and explains, which kinds may be deleted."""
    if kind.lower() not in DELETABLE_KINDS:
        return _deny(
            f"Deleting a resource of kind '{kind}' is never permitted. Only "
            f"pods, deployments, replicasets and jobs may be deleted; anything else "
            f"risks data loss or a cluster-wide effect."
        )
    return None


def _classify_argv(
    args: list[str], writable: frozenset[str], *, allow_apply_delete: bool
) -> Decision:
    if not args:
        return _deny("No command given.")
    if not all(isinstance(a, str) for a in args):
        return _deny("Every element of args must be a string.")
    if args[0] == "kubectl":
        return _deny("args must not repeat the binary name; kubectl is prepended by the caller.")
    if args[0].startswith("-"):
        return _deny("The first element of args must be a kubectl verb, not a flag.")

    # Connection and impersonation flags are refused on reads too.
    for i, arg in enumerate(args):
        name = _flag_name(arg)
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

    problem = _check_output_format(args)
    if problem is not None:
        return problem

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
        if not allow_apply_delete:
            return _deny(
                "`delete` must go through the delete_resource tool, which requires a "
                "rationale, a named target and a typed confirmation. Free-form argv "
                "would make all of that optional."
            )
        return _classify_delete(args, rest, writable)

    if verb == "apply" and not allow_apply_delete:
        return _deny(
            "`apply` must go through the apply_manifest tool, which validates the "
            "manifest kind, rejects an embedded metadata.namespace that would escape "
            "the fence, and requires a rationale."
        )

    if verb in WRITE_VERBS:
        return _check_mutation(
            args,
            Decision(Verdict.WRITE, f"`{verb}` modifies an existing resource."),
            writable,
            verb,
        )

    # These are separated rather than merged: the reason string is shown to the
    # human in the approval prompt, so an eviction must not be described as a
    # change to node scheduling.
    if verb == "evict":
        return _check_mutation(
            args,
            Decision(Verdict.DESTRUCTIVE, "`evict` removes a running pod from its node."),
            writable,
            verb,
        )

    if verb == "drain":
        return _check_mutation(
            args,
            Decision(Verdict.DESTRUCTIVE, "`drain` evicts every pod from the node."),
            writable,
            verb,
        )

    if verb in NODE_SCOPED_VERBS:
        return _check_mutation(
            args,
            Decision(Verdict.WRITE, f"`{verb}` changes node scheduling state."),
            writable,
            verb,
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

    problem = _check_deletable(kind)
    if problem is not None:
        return problem
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
        problem = _check_namespace_args(args, writable)
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
        if kind.lower() not in APPLICABLE_KINDS:
            return _deny(
                f"Kind '{kind}' is not on the applicable allowlist. Cluster-scoped kinds "
                f"arrive from CRDs and cannot be enumerated, so only kinds known to be "
                f"namespaced and known to be needed may be applied."
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

    if not isinstance(kind, str):
        return _deny("A resource kind is required.")
    problem = _check_deletable(kind)
    if problem is not None:
        return problem
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

    if tool_name in (
        KUBECTL_READ_TOOL,
        KUBECTL_WRITE_TOOL,
        INTERNAL_APPLY_TOOL,
        INTERNAL_DELETE_TOOL,
    ):
        args = tool_input.get("args")
        if not isinstance(args, list):
            return _deny("args must be a list of strings.")
        decision = _classify_argv(
            args,
            writable,
            allow_apply_delete=tool_name in (INTERNAL_APPLY_TOOL, INTERNAL_DELETE_TOOL),
        )
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
