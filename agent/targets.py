"""Which resource is this command about?

Two callers need this answer and must never disagree about it: the approval gate,
which asks a human to retype the resource name before a destructive action, and
preflight, which snapshots that resource so the change can be undone.

They previously each guessed with "the first token that doesn't start with a
dash", which conflates three different things — a subcommand (`rollout undo`), a
flag's value (`-n chaos`), and an actual resource name. That produced a
confirmation prompt asking for the word `undo`, and snapshots of the wrong
object. One parser, used by both, is the fix.
"""

from __future__ import annotations

import yaml

# Flags whose *next* token is a value rather than a positional argument. Only the
# separated form needs listing; `--flag=value` is self-delimiting.
VALUE_TAKING_FLAGS = frozenset(
    {
        "-n",
        "--namespace",
        "-o",
        "--output",
        "-f",
        "--filename",
        "-p",
        "--patch",
        "-l",
        "--selector",
        "-c",
        "--container",
        "--field-selector",
        "--replicas",
        "--context",
        "--type",
        "--image",
        "--template",
        "--timeout",
        "--grace-period",
        "--cascade",
        "--since",
        "--tail",
        "--kubeconfig",
        "--overwrite",
        "--record",
        "--to-revision",
    }
)

# Verbs whose second word is a subcommand, not a resource kind.
TWO_WORD_VERBS = frozenset({"rollout", "set", "auth", "config", "create", "top"})

# Verbs that name a node directly, with no kind token.
NODE_VERBS = frozenset({"cordon", "uncordon", "drain"})


def positionals(args: list[str]) -> list[str]:
    """Tokens that are genuinely positional, with flag values consumed.

    Stops at the `--` terminator, since everything past it belongs to the
    container's command rather than to kubectl.
    """
    out: list[str] = []
    i = 0
    while i < len(args):
        arg = str(args[i])
        if arg == "--":
            break
        if arg.startswith("-"):
            name = arg.split("=", 1)[0]
            if "=" not in arg and name in VALUE_TAKING_FLAGS and i + 1 < len(args):
                i += 2  # this flag swallows the next token
                continue
            i += 1
            continue
        out.append(arg)
        i += 1
    return out


def _split(token: str) -> tuple[str, str] | None:
    if "/" in token:
        kind, _, name = token.partition("/")
        return (kind.lower(), name) if kind and name else None
    return None


def target_from_args(args: list[str]) -> tuple[str, str] | None:
    """(kind, name) for the resource an argv acts on, or None if not identifiable."""
    if not args:
        return None

    words = positionals(args)
    if not words:
        return None

    verb = words[0].lower()

    if verb in NODE_VERBS:
        return ("node", words[1]) if len(words) > 1 else None

    rest = words[2:] if verb in TWO_WORD_VERBS else words[1:]
    if not rest:
        return None

    slashed = _split(rest[0])
    if slashed is not None:
        return slashed
    if len(rest) >= 2:
        return rest[0].lower(), rest[1]
    return None


def target_from_manifest(manifest: str) -> tuple[str, str] | None:
    """(kind, name) for the first named document in a manifest.

    `apply_manifest` carries no argv, so without this it had no identifiable
    target, preflight could not snapshot anything, and the approval gate denied
    every call — the tool was unreachable.
    """
    if not manifest or not manifest.strip():
        return None
    try:
        documents = list(yaml.safe_load_all(manifest))
    except yaml.YAMLError:
        return None

    for document in documents:
        if not isinstance(document, dict):
            continue
        kind = document.get("kind")
        name = (document.get("metadata") or {}).get("name")
        if isinstance(kind, str) and isinstance(name, str) and kind and name:
            return kind.lower(), name
    return None
