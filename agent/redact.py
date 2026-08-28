"""Strip Secret values out of kubectl output before anything else sees them.

The agent needs a Secret's *shape* — does it exist, which keys does it have, what
type is it — because a mismatch between a referenced key and an actual key is a
common root cause. It never needs the value, so the value is removed at the
boundary and never reaches the model, the transcript, or the audit log.

ConfigMaps are deliberately left intact. A wrong key or malformed value in a
ConfigMap is itself a frequent defect, and redacting it would hide the answer the
agent is looking for.

Fail-closed: if the payload looks like a Secret but cannot be parsed, the whole
text is replaced rather than returned in the hope that no value was missed.
"""

from __future__ import annotations

import base64
import binascii
import json

import yaml

SECRET_KIND = "secret"  # noqa: S105 - a Kubernetes resource kind, not a credential
REDACTED_DOCUMENT = "<redacted: unparseable Secret payload withheld>"

# Fields whose values are secret material.
SECRET_FIELDS = ("data", "stringData")


def _decoded_length(value: object, *, base64_encoded: bool) -> int:
    if not isinstance(value, str):
        return 0
    if base64_encoded:
        try:
            return len(base64.b64decode(value, validate=True))
        except (binascii.Error, ValueError):
            # Malformed base64 is still a value we must not print.
            return len(value.encode())
    return len(value.encode())


def _placeholder(value: object, *, base64_encoded: bool) -> str:
    return f"<redacted:{_decoded_length(value, base64_encoded=base64_encoded)} bytes>"


def _is_redacted(value: object) -> bool:
    return isinstance(value, str) and value.startswith("<redacted:")


def _redact_node(node: object) -> object:
    """Walk any parsed structure and blank Secret payloads in place."""
    if isinstance(node, list):
        return [_redact_node(item) for item in node]

    if not isinstance(node, dict):
        return node

    kind = node.get("kind")
    if isinstance(kind, str) and kind.lower() == SECRET_KIND:
        result = dict(node)
        for field in SECRET_FIELDS:
            payload = result.get(field)
            if isinstance(payload, dict):
                result[field] = {
                    key: value
                    if _is_redacted(value)
                    else _placeholder(value, base64_encoded=(field == "data"))
                    for key, value in payload.items()
                }
        return {key: _redact_node(value) for key, value in result.items()}

    return {key: _redact_node(value) for key, value in node.items()}


def _looks_like_a_secret(text: str) -> bool:
    lowered = text.lower()
    return (
        "kind: secret" in lowered or '"kind": "secret"' in lowered or '"kind":"secret"' in lowered
    )


def redact(text: str | None) -> str:
    """Return `text` with any Secret values replaced by a length placeholder."""
    if not text:
        return ""

    # JSON first: kubectl -o json round-trips cleanly and preserves key order.
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            pass
        else:
            return json.dumps(_redact_node(parsed), indent=2)

    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        # Fail closed: something Secret-shaped that we cannot parse is withheld
        # entirely rather than returned on the assumption we found every value.
        return REDACTED_DOCUMENT if _looks_like_a_secret(text) else text

    if not any(isinstance(doc, (dict, list)) for doc in documents):
        # Plain table output (`kubectl get pods`) parses as a scalar or None.
        return text

    if not _looks_like_a_secret(text):
        # Nothing to do, and re-serialising would needlessly reformat the output.
        return text

    redacted = [_redact_node(doc) for doc in documents if doc is not None]
    return yaml.safe_dump_all(redacted, default_flow_style=False, sort_keys=False)
