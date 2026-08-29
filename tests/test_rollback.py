"""Every mutation must be reversible with one copy-paste, or it does not happen.

The ordering is the whole point: the snapshot is captured *before* the mutation,
and if the snapshot cannot be written the mutation is abandoned. An agent that
changes a broken cluster without an undo path is how troubleshooting turns into
an outage.

Note on redaction: snapshot files are written unredacted, because a redacted
snapshot cannot restore anything. They are chmod 0600 and only their *path* is
ever surfaced to the model or the audit log — never their contents.
"""

from __future__ import annotations

import stat

import pytest

from agent.kubectl import DeniedError
from agent.policy import PINNED_CONTEXT
from agent.rollback import SnapshotError, capture

LIVE_YAML = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"


def ok_runner(stdout=LIVE_YAML):
    def _run(argv, stdin, timeout):
        return 0, stdout, ""

    return _run


def notfound_runner(argv, stdin, timeout):
    return 1, "", 'Error from server (NotFound): deployments.apps "web" not found'


def broken_runner(argv, stdin, timeout):
    return 1, "", "Error from server (Timeout): the server was unable to return a response"


# --------------------------------------------------------------------------
# Capturing an existing resource
# --------------------------------------------------------------------------


def test_snapshot_file_is_written(tmp_path):
    snap = capture("deployment", "web", "chaos", root=tmp_path, runner=ok_runner())
    assert snap.path.is_file()
    assert snap.path.read_text() == LIVE_YAML
    assert snap.existed is True


def test_snapshot_filename_identifies_the_resource(tmp_path):
    snap = capture("deployment", "web", "chaos", root=tmp_path, runner=ok_runner())
    assert "deployment" in snap.path.name
    assert "web" in snap.path.name
    assert snap.path.suffix == ".yaml"


def test_undo_command_restores_from_the_snapshot(tmp_path):
    snap = capture("deployment", "web", "chaos", root=tmp_path, runner=ok_runner())
    assert "apply" in snap.undo_command
    assert str(snap.path) in snap.undo_command
    assert PINNED_CONTEXT in snap.undo_command


def test_snapshots_are_owner_readable_only(tmp_path):
    """A live manifest can contain a Secret, so it must not be world-readable."""
    snap = capture("deployment", "web", "chaos", root=tmp_path, runner=ok_runner())
    mode = stat.S_IMODE(snap.path.stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {mode:o}"


def test_snapshot_content_is_not_exposed_on_the_result(tmp_path):
    """Only the path travels back to the model; the payload stays on disk."""
    snap = capture("deployment", "web", "chaos", root=tmp_path, runner=ok_runner())
    assert not hasattr(snap, "content")
    assert LIVE_YAML not in repr(snap)


# --------------------------------------------------------------------------
# Capturing something that does not exist yet
# --------------------------------------------------------------------------


def test_absent_resource_is_recorded_as_absent(tmp_path):
    snap = capture("deployment", "web", "chaos", root=tmp_path, runner=notfound_runner)
    assert snap.existed is False


def test_undo_for_an_absent_resource_is_a_delete(tmp_path):
    """If it did not exist and we are about to create it, undo means remove it."""
    snap = capture("deployment", "web", "chaos", root=tmp_path, runner=notfound_runner)
    assert "delete" in snap.undo_command
    assert "deployment" in snap.undo_command
    assert "web" in snap.undo_command
    assert "chaos" in snap.undo_command


# --------------------------------------------------------------------------
# Failing closed
# --------------------------------------------------------------------------


def test_unexpected_kubectl_failure_aborts(tmp_path):
    """An ambiguous read means we do not know the prior state, so we do not proceed."""
    with pytest.raises(SnapshotError):
        capture("deployment", "web", "chaos", root=tmp_path, runner=broken_runner)


def test_unwritable_destination_aborts(tmp_path):
    blocked = tmp_path / "in-the-way"
    blocked.write_text("not a directory")
    with pytest.raises(SnapshotError):
        capture("deployment", "web", "chaos", root=blocked, runner=ok_runner())


def test_a_resource_name_cannot_smuggle_a_flag(tmp_path):
    """capture() interpolates kind/name/namespace into an argv it builds itself, so
    a name that looks like a flag must not become one. Policy sees the assembled
    command and refuses it."""
    with pytest.raises(DeniedError):
        capture("deployment", "--context=prod", "chaos", root=tmp_path, runner=ok_runner())

    with pytest.raises(DeniedError):
        capture("deployment", "--kubeconfig=/tmp/x", "chaos", root=tmp_path, runner=ok_runner())


def test_reading_a_protected_namespace_is_allowed(tmp_path):
    """The fence blocks mutation, not observation — snapshotting CoreDNS to
    diagnose dns-broken is legitimate."""
    snap = capture("deployment", "coredns", "kube-system", root=tmp_path, runner=ok_runner())
    assert snap.existed is True


# --------------------------------------------------------------------------
# Path handling
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["../../../etc/passwd", "web/../../escape", "..", "a/b/c", "with space", "UPPER"],
)
def test_resource_names_cannot_escape_the_snapshot_directory(tmp_path, name):
    snap = capture("deployment", name, "chaos", root=tmp_path, runner=ok_runner())
    assert tmp_path.resolve() in snap.path.resolve().parents
    assert snap.path.parent.resolve() == tmp_path.resolve()


def test_repeated_snapshots_do_not_collide(tmp_path):
    a = capture("deployment", "web", "chaos", root=tmp_path, runner=ok_runner())
    b = capture("deployment", "web", "chaos", root=tmp_path, runner=ok_runner())
    assert a.path != b.path
    assert a.path.is_file() and b.path.is_file()


def test_snapshot_reads_the_right_resource(tmp_path):
    seen = {}

    def recording(argv, stdin, timeout):
        seen["argv"] = argv
        return 0, LIVE_YAML, ""

    capture("deployment", "web", "chaos", root=tmp_path, runner=recording)
    argv = seen["argv"]
    assert "get" in argv
    assert "deployment" in argv
    assert "web" in argv
    assert "chaos" in argv
    assert "-o" in argv and "yaml" in argv
    assert PINNED_CONTEXT in argv
