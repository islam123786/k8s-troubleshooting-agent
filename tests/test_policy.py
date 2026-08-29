"""The security model.

`policy.classify` is a pure function over (tool_name, tool_input). Everything the
agent is or is not allowed to do is decided here, so this is the file to read first
and the file to distrust most.

The governing property is **fail-closed**: anything not explicitly recognised is
DENY. Most of the tests below exist to prove that a thing we never thought about
lands in DENY rather than sliding into READ or WRITE.
"""

import pytest

from agent.policy import (
    DEFAULT_WRITABLE_NAMESPACES,
    INTERNAL_APPLY_TOOL,
    INTERNAL_DELETE_TOOL,
    PINNED_CONTEXT,
    Verdict,
    classify,
)

K_READ = "mcp__k8s__kubectl_read"
K_WRITE = "mcp__k8s__kubectl_write"
K_APPLY = "mcp__k8s__apply_manifest"
K_DELETE = "mcp__k8s__delete_resource"


def verdict(tool_name, tool_input, **kw):
    return classify(tool_name, tool_input, **kw).verdict


def read(*args):
    return verdict(K_READ, {"args": list(args)})


def write(*args):
    return verdict(K_WRITE, {"args": list(args)})


def do_delete(*args):
    """The internal execution path the delete_resource tool uses once it has validated."""
    return verdict(INTERNAL_DELETE_TOOL, {"args": list(args)})


def do_apply(*args):
    return verdict(INTERNAL_APPLY_TOOL, {"args": list(args)})


# --------------------------------------------------------------------------
# Non-kubectl tools
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool",
    ["Bash", "BashOutput", "KillShell", "Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch"],
)
def test_capability_removed_tools_are_denied(tool):
    """These are stripped via disallowed_tools, but the hook denies them anyway.

    Defence in depth: if the options are ever misconfigured, the choke point still
    holds. A regression in options.py must not silently become a shell.
    """
    assert verdict(tool, {"command": "kubectl get pods"}) is Verdict.DENY


@pytest.mark.parametrize("tool", ["Read", "Glob", "Grep", "Skill", "Task", "TodoWrite"])
def test_harmless_builtin_tools_are_read(tool):
    assert verdict(tool, {}) is Verdict.READ


def test_unknown_tool_is_denied():
    """Fail-closed: a tool nobody has classified is not assumed safe."""
    assert verdict("SomeFutureTool", {}) is Verdict.DENY
    assert verdict("mcp__other_server__do_thing", {}) is Verdict.DENY


# --------------------------------------------------------------------------
# Read verbs
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ("get", "pods", "-n", "chaos"),
        ("describe", "pod", "web-abc", "-n", "chaos"),
        ("logs", "web-abc", "-n", "chaos", "--previous"),
        ("events", "-n", "chaos"),
        ("top", "pod", "-n", "chaos"),
        ("explain", "pod.spec.containers"),
        ("api-resources",),
        ("version",),
        ("cluster-info",),
        ("get", "pods", "-A"),  # -A is fine for reads, only mutations forbid it
        ("get", "secret", "db", "-n", "chaos", "-o", "yaml"),
        ("auth", "can-i", "delete", "pods", "-n", "chaos"),
        ("diff", "-f", "-"),
    ],
)
def test_read_verbs(args):
    assert read(*args) is Verdict.READ


def test_read_of_protected_namespace_is_allowed():
    """The fence blocks mutation, not observation. Diagnosing dns-broken needs this."""
    assert read("get", "pods", "-n", "kube-system") is Verdict.READ
    assert read("describe", "deployment", "coredns", "-n", "kube-system") is Verdict.READ


def test_auth_subcommands_other_than_can_i_are_denied():
    assert read("auth", "reconcile", "-f", "rbac.yaml") is Verdict.DENY


# --------------------------------------------------------------------------
# Write and destructive verbs
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ("patch", "deployment", "web", "-n", "chaos", "-p", "{}"),
        ("scale", "deployment", "web", "--replicas=2", "-n", "chaos"),
        ("set", "image", "deployment/web", "web=nginx:1.25", "-n", "chaos"),
        ("label", "pod", "web-abc", "tier=fe", "-n", "chaos"),
        ("annotate", "pod", "web-abc", "note=x", "-n", "chaos"),
        ("rollout", "restart", "deployment/web", "-n", "chaos"),
        ("cordon", "kind-worker"),
        ("uncordon", "kind-worker"),
    ],
)
def test_write_verbs(args):
    assert write(*args) is Verdict.WRITE


@pytest.mark.parametrize(
    "args",
    [
        ("rollout", "undo", "deployment/web", "-n", "chaos"),
        ("drain", "kind-worker"),
        ("evict", "pod", "web-abc", "-n", "chaos"),
    ],
)
def test_destructive_verbs(args):
    assert write(*args) is Verdict.DESTRUCTIVE


@pytest.mark.parametrize(
    "args",
    [
        ("delete", "pod", "web-abc", "-n", "chaos"),
        ("delete", "deployment", "web", "-n", "chaos"),
        ("delete", "rs", "web-123", "-n", "chaos"),
        ("delete", "job", "migrate", "-n", "chaos"),
    ],
)
def test_delete_via_the_internal_execution_path(args):
    assert do_delete(*args) is Verdict.DESTRUCTIVE


def test_apply_via_the_internal_execution_path():
    assert do_apply("apply", "-f", "-", "-n", "chaos") is Verdict.WRITE


def test_rollout_status_and_history_are_reads():
    assert read("rollout", "status", "deployment/web", "-n", "chaos") is Verdict.READ
    assert read("rollout", "history", "deployment/web", "-n", "chaos") is Verdict.READ


# --------------------------------------------------------------------------
# Verbs that are never allowed
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ("exec", "-it", "web-abc", "--", "sh"),
        ("cp", "web-abc:/etc/passwd", "/tmp/x"),
        ("port-forward", "svc/web", "8080:80"),
        ("proxy",),
        ("edit", "deployment", "web", "-n", "chaos"),
        ("replace", "-f", "d.yaml"),
        ("attach", "web-abc"),
        ("debug", "web-abc", "--image=busybox"),
        ("run", "shell", "--image=busybox"),
        ("taint", "node", "kind-worker", "k=v:NoSchedule"),
        ("certificate", "approve", "csr-1"),
        ("config", "use-context", "prod"),
        ("create", "deployment", "web", "--image=nginx"),
        ("expose", "deployment", "web", "--port=80"),
        ("wait", "--for=delete", "pod/web-abc"),
    ],
)
def test_denied_verbs(args):
    assert write(*args) is Verdict.DENY


def test_unknown_verb_is_denied():
    assert write("frobnicate", "thing") is Verdict.DENY
    assert read("frobnicate", "thing") is Verdict.DENY


def test_empty_args_denied():
    assert verdict(K_READ, {"args": []}) is Verdict.DENY
    assert verdict(K_READ, {}) is Verdict.DENY


def test_args_must_not_respell_the_binary():
    """kubectl.py prepends the binary. An args list starting with `kubectl` means
    something has gone wrong upstream, and a doubled binary must never be guessed at."""
    assert read("kubectl", "get", "pods") is Verdict.DENY


def test_non_string_args_denied():
    assert verdict(K_READ, {"args": ["get", {"nested": "obj"}]}) is Verdict.DENY
    assert verdict(K_READ, {"args": "get pods"}) is Verdict.DENY


# --------------------------------------------------------------------------
# Context pinning
# --------------------------------------------------------------------------


def test_foreign_context_is_denied():
    assert read("get", "pods", "--context", "prod") is Verdict.DENY
    assert read("get", "pods", "--context=prod") is Verdict.DENY


def test_pinned_context_is_permitted_but_redundant():
    """kubectl.py injects it; a model that also passes it is not an attack."""
    assert read("get", "pods", "--context", PINNED_CONTEXT) is Verdict.READ
    assert read("get", "pods", f"--context={PINNED_CONTEXT}") is Verdict.READ


@pytest.mark.parametrize(
    "flag",
    [
        "--kubeconfig=/tmp/other.yaml",
        "--server=https://10.0.0.1",
        "--token=abc",
        "--as=system:admin",
        "--as-group=system:masters",
        "--insecure-skip-tls-verify",
        "--client-certificate=/tmp/c.pem",
        "--username=admin",
        "--password=hunter2",
    ],
)
def test_connection_and_impersonation_flags_denied(flag):
    """Even on a read. These redirect or escalate rather than observe."""
    assert read("get", "pods", flag) is Verdict.DENY


# --------------------------------------------------------------------------
# Scope-widening flags on mutations
# --------------------------------------------------------------------------


@pytest.mark.parametrize("flag", ["--all", "-A", "--all-namespaces", "-l", "--selector"])
def test_mass_mutation_flags_denied(flag):
    assert do_delete("delete", "pod", flag, "app=web", "-n", "chaos") is Verdict.DENY
    assert write("label", "pod", flag, "app=web", "x=y", "-n", "chaos") is Verdict.DENY


@pytest.mark.parametrize(
    "flag", ["--force", "--grace-period=0", "--cascade=orphan", "--now", "--wait=false"]
)
def test_dangerous_deletion_flags_denied(flag):
    assert do_delete("delete", "pod", "web-abc", flag, "-n", "chaos") is Verdict.DENY


def test_selector_denied_even_when_it_looks_scoped():
    assert do_delete("delete", "pod", "--selector=app=web", "-n", "chaos") is Verdict.DENY


# --------------------------------------------------------------------------
# Namespace fence
# --------------------------------------------------------------------------


def test_mutation_outside_writable_namespace_denied():
    assert write("scale", "deployment", "web", "--replicas=0", "-n", "default") is Verdict.DENY
    assert write("apply", "-f", "-", "-n", "kube-system") is Verdict.DENY


def test_mutation_without_explicit_namespace_denied():
    """An omitted -n silently means the current context's default namespace.
    Ambiguity plus mutation is not a combination worth resolving by guessing."""
    assert write("scale", "deployment", "web", "--replicas=2") is Verdict.DENY


def test_writable_namespace_is_configurable():
    args = {"args": ["scale", "deployment", "web", "--replicas=2", "-n", "staging"]}
    assert classify(K_WRITE, args).verdict is Verdict.DENY
    assert (
        classify(K_WRITE, args, writable_namespaces=frozenset({"staging"})).verdict is Verdict.WRITE
    )


def test_default_writable_namespaces_is_just_chaos():
    assert DEFAULT_WRITABLE_NAMESPACES == frozenset({"chaos"})


@pytest.mark.parametrize("ns", ["kube-system", "kube-public", "kube-node-lease"])
def test_protected_namespaces_never_writable_even_if_configured(ns):
    """A misconfigured --writable-ns must not be able to unlock the control plane."""
    args = {"args": ["scale", "deployment", "coredns", "--replicas=1", "-n", ns]}
    assert classify(K_WRITE, args, writable_namespaces=frozenset({ns})).verdict is Verdict.DENY


def test_namespace_long_form_and_equals_form_both_parsed():
    ok = ["scale", "deployment", "web", "--replicas=2"]
    assert write(*ok, "--namespace", "chaos") is Verdict.WRITE
    assert write(*ok, "--namespace=chaos") is Verdict.WRITE
    assert write(*ok, "--namespace=default") is Verdict.DENY


def test_node_scoped_mutations_do_not_require_a_namespace():
    """cordon/uncordon/drain are cluster-scoped; requiring -n would be nonsense."""
    assert write("cordon", "kind-worker") is Verdict.WRITE
    assert write("drain", "kind-worker") is Verdict.DESTRUCTIVE


# --------------------------------------------------------------------------
# Deletion kind allowlist
# --------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["pod", "pods", "po", "deployment", "deploy", "rs", "job"])
def test_deletable_kinds(kind):
    assert do_delete("delete", kind, "thing", "-n", "chaos") is Verdict.DESTRUCTIVE


@pytest.mark.parametrize(
    "kind",
    [
        "namespace",
        "ns",
        "pvc",
        "persistentvolumeclaim",
        "pv",
        "persistentvolume",
        "storageclass",
        "sc",
        "crd",
        "customresourcedefinition",
        "node",
        "clusterrole",
        "clusterrolebinding",
        "secret",
        "serviceaccount",
    ],
)
def test_undeletable_kinds(kind):
    """Data loss or cluster-wide effect. Not promptable, at any approval level."""
    assert do_delete("delete", kind, "thing", "-n", "chaos") is Verdict.DENY


def test_delete_namespace_denied_even_for_the_writable_one():
    assert do_delete("delete", "namespace", "chaos") is Verdict.DENY
    assert do_delete("delete", "ns", "chaos", "-n", "chaos") is Verdict.DENY


def test_delete_by_slash_form_is_parsed():
    assert do_delete("delete", "pod/web-abc", "-n", "chaos") is Verdict.DESTRUCTIVE
    assert do_delete("delete", "ns/chaos") is Verdict.DENY


def test_delete_requires_a_named_target():
    assert do_delete("delete", "pod", "-n", "chaos") is Verdict.DENY


# --------------------------------------------------------------------------
# The structured (non-argv) tools
# --------------------------------------------------------------------------


def test_apply_manifest_requires_rationale_and_namespace():
    good = {"manifest": "kind: Pod\n", "namespace": "chaos", "rationale": "fix the probe port"}
    assert verdict(K_APPLY, good) is Verdict.WRITE

    assert verdict(K_APPLY, {**good, "rationale": ""}) is Verdict.DENY
    assert verdict(K_APPLY, {**good, "namespace": "default"}) is Verdict.DENY
    assert verdict(K_APPLY, {"manifest": "kind: Pod\n"}) is Verdict.DENY


def test_apply_manifest_rejects_empty_manifest():
    assert verdict(K_APPLY, {"manifest": "  ", "namespace": "chaos", "rationale": "x"}) is (
        Verdict.DENY
    )


def test_apply_manifest_rejects_namespaced_kinds_it_cannot_fence():
    """A manifest may carry its own metadata.namespace, which would escape the fence."""
    escaping = {
        "manifest": "kind: Pod\nmetadata:\n  namespace: kube-system\n",
        "namespace": "chaos",
        "rationale": "x",
    }
    assert verdict(K_APPLY, escaping) is Verdict.DENY


def test_apply_manifest_rejects_cluster_scoped_kinds():
    for kind in ("Namespace", "ClusterRole", "CustomResourceDefinition", "PersistentVolume"):
        m = {"manifest": f"kind: {kind}\n", "namespace": "chaos", "rationale": "x"}
        assert verdict(K_APPLY, m) is Verdict.DENY, kind


def test_delete_resource_tool():
    good = {"kind": "pod", "name": "web-abc", "namespace": "chaos", "rationale": "restart it"}
    assert verdict(K_DELETE, good) is Verdict.DESTRUCTIVE

    assert verdict(K_DELETE, {**good, "kind": "namespace"}) is Verdict.DENY
    assert verdict(K_DELETE, {**good, "namespace": "kube-system"}) is Verdict.DENY
    assert verdict(K_DELETE, {**good, "name": ""}) is Verdict.DENY
    assert verdict(K_DELETE, {**good, "rationale": " "}) is Verdict.DENY


def test_read_only_tools_are_never_gated():
    assert verdict("mcp__k8s__propose_fix", {"diagnosis": "x", "manifest": "y"}) is Verdict.READ
    assert verdict("mcp__k8s__record_finding", {"summary": "x"}) is Verdict.READ


# --------------------------------------------------------------------------
# Every decision carries a reason
# --------------------------------------------------------------------------


def test_denials_explain_themselves():
    """The reason is fed back to the model as permissionDecisionReason, so it can
    adapt instead of retrying the same call."""
    d = classify(INTERNAL_DELETE_TOOL, {"args": ["delete", "namespace", "chaos"]})
    assert d.verdict is Verdict.DENY
    assert d.reason
    assert "namespace" in d.reason.lower()


def test_every_verdict_has_a_nonempty_reason():
    for tool, ti in [
        (K_READ, {"args": ["get", "pods", "-n", "chaos"]}),
        (K_WRITE, {"args": ["scale", "deploy", "web", "--replicas=1", "-n", "chaos"]}),
        (INTERNAL_DELETE_TOOL, {"args": ["delete", "pod", "web", "-n", "chaos"]}),
        (K_WRITE, {"args": ["exec", "web", "--", "sh"]}),
    ]:
        assert classify(tool, ti).reason.strip()


def test_classify_is_pure_and_does_not_mutate_input():
    ti = {"args": ["get", "pods", "-n", "chaos"]}
    snapshot = {"args": list(ti["args"])}
    classify(K_READ, ti)
    assert ti == snapshot


# --------------------------------------------------------------------------
# Regressions found in review of step 1
# --------------------------------------------------------------------------


def test_repeated_namespace_flags_are_refused_as_ambiguous():
    """kubectl/pflag resolves a repeated flag last-wins. A first-wins parser would
    check `chaos`, pass the fence, and then let kubectl act on `kube-system`.

    Rather than racing pflag's precedence rules forever, a command that names two
    different namespaces is simply refused."""
    assert do_delete("delete", "pod", "web", "-n", "chaos", "-n", "kube-system") is Verdict.DENY
    assert (
        write("scale", "deploy", "web", "--replicas=2", "--namespace=chaos", "--namespace=default")
        is Verdict.DENY
    )
    assert do_apply("apply", "-f", "-", "-n", "kube-system", "-n", "chaos") is Verdict.DENY


def test_repeating_the_same_namespace_is_harmless():
    assert write("scale", "deploy", "web", "--replicas=2", "-n", "chaos", "-n", "chaos") is (
        Verdict.WRITE
    )


def test_attached_short_namespace_form_is_parsed():
    """pflag accepts -nchaos as well as -n chaos."""
    assert write("scale", "deploy", "web", "--replicas=2", "-nchaos") is Verdict.WRITE
    assert write("scale", "deploy", "web", "--replicas=2", "-nkube-system") is Verdict.DENY


def test_free_form_argv_cannot_apply_or_delete():
    """apply and delete carry validation that only the structured tools perform:
    cluster-scoped kind checks, embedded-namespace checks, a mandatory rationale.
    Letting the free-form argv tool reach them would make all of that optional."""
    assert write("apply", "-f", "/tmp/anything.yaml", "-n", "chaos") is Verdict.DENY
    assert write("apply", "-f", "-", "-n", "chaos") is Verdict.DENY
    assert write("delete", "pod", "web-abc", "-n", "chaos") is Verdict.DENY


def test_internal_execution_paths_may_apply_and_delete():
    """The structured tools have already validated; they execute through an internal
    tool name the model cannot invoke because it is never registered with the SDK."""
    from agent.policy import INTERNAL_APPLY_TOOL, INTERNAL_DELETE_TOOL

    assert verdict(INTERNAL_APPLY_TOOL, {"args": ["apply", "-f", "-", "-n", "chaos"]}) is (
        Verdict.WRITE
    )
    assert (
        verdict(INTERNAL_DELETE_TOOL, {"args": ["delete", "pod", "web", "-n", "chaos"]})
        is Verdict.DESTRUCTIVE
    )
    assert verdict(INTERNAL_APPLY_TOOL, {"args": ["apply", "-f", "-", "-n", "kube-system"]}) is (
        Verdict.DENY
    )


def test_applicable_kinds_are_an_allowlist_not_a_denylist():
    """Cluster-scoped kinds arrive from CRDs, so they cannot be enumerated. Only
    kinds known to be namespaced and known to be needed may be applied."""
    for kind in ("ClusterIssuer", "PodSecurityPolicy", "Namespace", "ClusterRole"):
        m = {"manifest": f"kind: {kind}\n", "namespace": "chaos", "rationale": "x"}
        assert verdict(K_APPLY, m) is Verdict.DENY, kind


@pytest.mark.parametrize(
    "kind",
    [
        "Deployment",
        "Pod",
        "Service",
        "ConfigMap",
        "PersistentVolumeClaim",
        "NetworkPolicy",
        "ResourceQuota",
        "StatefulSet",
        "Job",
    ],
)
def test_kinds_the_chaos_scenarios_need_are_applicable(kind):
    m = {"manifest": f"kind: {kind}\n", "namespace": "chaos", "rationale": "fix it"}
    assert verdict(K_APPLY, m) is Verdict.WRITE


def test_secrets_are_not_applicable():
    """Applying a Secret would put its value into a rollback snapshot on disk."""
    m = {"manifest": "kind: Secret\ndata:\n  k: dg==\n", "namespace": "chaos", "rationale": "x"}
    assert verdict(K_APPLY, m) is Verdict.DENY


def test_field_selector_is_a_bulk_selector():
    assert (
        write("label", "pod", "web", "x=y", "--field-selector=status.phase=Running", "-n", "chaos")
        is Verdict.DENY
    )


def test_evict_reason_describes_eviction_not_node_scheduling():
    """The reason is shown to the human in the approval prompt and to the model as
    permissionDecisionReason, so it has to describe what actually happens."""
    d = classify(K_WRITE, {"args": ["evict", "pod", "web", "-n", "chaos"]})
    assert d.verdict is Verdict.DESTRUCTIVE
    assert "node scheduling" not in d.reason.lower()
