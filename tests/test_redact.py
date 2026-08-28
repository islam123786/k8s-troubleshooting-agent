"""Secret values must never enter the model's context, the transcript, or the audit log.

The agent legitimately needs to reason about Secrets — whether one exists, what
keys it has, what type it is — because "the Deployment references key `password`
but the Secret only has `pass`" is a real and common root cause. None of that
requires the *value*, so the value never leaves the cluster.

ConfigMaps are deliberately NOT redacted: a wrong key or a malformed value in a
ConfigMap is itself a frequent defect, and blanking it would hide the answer.
"""

from __future__ import annotations

import json

from agent.redact import redact

SECRET_YAML = """\
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: chaos
type: Opaque
data:
  username: YWRtaW4=
  password: aHVudGVyMg==
"""


def test_secret_values_are_removed():
    out = redact(SECRET_YAML)
    assert "aHVudGVyMg==" not in out
    assert "hunter2" not in out
    assert "YWRtaW4=" not in out


def test_secret_keys_and_identity_survive():
    """The shape is the diagnostic signal; only the payload is dangerous."""
    out = redact(SECRET_YAML)
    assert "username" in out
    assert "password" in out
    assert "db-credentials" in out
    assert "Opaque" in out


def test_redaction_reports_decoded_length():
    """Length is occasionally the clue — an empty secret is a real defect."""
    out = redact(SECRET_YAML)
    assert "<redacted:7 bytes>" in out  # hunter2
    assert "<redacted:5 bytes>" in out  # admin


def test_string_data_is_redacted_too():
    out = redact("kind: Secret\nstringData:\n  token: plaintext-value\n")
    assert "plaintext-value" not in out
    assert "token" in out


def test_json_output_is_redacted():
    doc = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "db", "namespace": "chaos"},
        "data": {"password": "aHVudGVyMg=="},
    }
    out = redact(json.dumps(doc))
    assert "aHVudGVyMg==" not in out
    assert "password" in out


def test_secrets_inside_a_list_are_redacted():
    listing = """\
apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Secret
  metadata:
    name: a
  data:
    k: aHVudGVyMg==
- apiVersion: v1
  kind: ConfigMap
  metadata:
    name: b
  data:
    setting: visible-value
"""
    out = redact(listing)
    assert "aHVudGVyMg==" not in out
    assert "visible-value" in out, "ConfigMap data must survive"


def test_configmaps_are_not_redacted():
    """A wrong ConfigMap key is a common root cause. Hiding it defeats the agent."""
    cm = "kind: ConfigMap\ndata:\n  LOG_LEVEL: debug\n  PORT: '8080'\n"
    out = redact(cm)
    assert "debug" in out
    assert "8080" in out


def test_ordinary_output_passes_through_unchanged():
    plain = (
        "NAME   READY   STATUS             RESTARTS   AGE\n"
        "web-0  0/1     CrashLoopBackOff   5          2m\n"
    )
    assert redact(plain) == plain


def test_multi_document_output():
    out = redact(SECRET_YAML + "---\n" + "kind: ConfigMap\ndata:\n  a: keepme\n")
    assert "aHVudGVyMg==" not in out
    assert "keepme" in out


def test_unparseable_secret_output_fails_closed():
    """If we cannot parse it but it smells like a Secret, blank the whole thing
    rather than risk leaking a value we failed to locate."""
    mangled = "kind: Secret\ndata:\n  password: aHVudGVyMg==\n\t\tbroken: [unclosed\n"
    out = redact(mangled)
    assert "aHVudGVyMg==" not in out


def test_unparseable_non_secret_output_is_left_alone():
    mangled = "some: [unclosed\n\tgarbage\n"
    assert redact(mangled) == mangled


def test_redaction_is_idempotent():
    once = redact(SECRET_YAML)
    assert redact(once) == once


def test_empty_and_none_safe():
    assert redact("") == ""
    assert redact(None) == ""


def test_non_base64_data_value_still_redacted():
    """Malformed base64 is still a value we must not print."""
    out = redact("kind: Secret\ndata:\n  k: not!valid!base64\n")
    assert "not!valid!base64" not in out
