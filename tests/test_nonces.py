"""MYB-2.3 AC #5: nonce persistence — data dir only, 0600, append-only, opaque names."""

import stat

import pytest

from mybench import nonces, paths
from mybench.commitments import generate_nonce


def mode_of(p):
    return stat.S_IMODE(p.stat().st_mode)


def test_round_trip_in_order():
    written = [generate_nonce() for _ in range(5)]
    for i, n in enumerate(written):
        assert nonces.append_nonce("11111111-2222-3333-4444-555555555555", n) == i
    assert nonces.load_nonces("11111111-2222-3333-4444-555555555555") == written


def test_files_live_under_nonces_dir_mode_0600():
    nonces.append_nonce("abc-123", generate_nonce())
    f = nonces.session_nonce_file("abc-123")
    assert f.parent == paths.nonces_dir()
    assert mode_of(f) == 0o600
    assert mode_of(f.parent) == 0o700


def test_new_nonce_file_and_parent_are_fsynced(monkeypatch):
    events = []
    real_file = nonces._fsync_file
    real_parent = nonces._fsync_parent

    def fsync_file(fd):
        events.append("file")
        real_file(fd)

    def fsync_parent(directory):
        events.append("parent")
        real_parent(directory)

    monkeypatch.setattr(nonces, "_fsync_file", fsync_file)
    monkeypatch.setattr(nonces, "_fsync_parent", fsync_parent)
    nonces.append_nonce("durable-session", generate_nonce())
    assert events == ["file", "parent"]

    events.clear()
    nonces.append_nonce("durable-session", generate_nonce())
    assert events == ["file"]  # parent entry already durable; every append still fsyncs A2


def test_missing_session_loads_empty():
    assert nonces.load_nonces("never-written") == []


def test_rejects_path_or_content_derived_session_ids():
    for bad in ("../evil", "a/b", "", "x" * 65, "name.jsonl", "~home", "sp ace"):
        with pytest.raises(nonces.NonceStoreError):
            nonces.session_nonce_file(bad)


def test_rejects_wrong_nonce_size():
    with pytest.raises(nonces.NonceStoreError):
        nonces.append_nonce("abc", b"short")


def test_gap_or_reorder_detected_on_load():
    nonces.append_nonce("abc", generate_nonce())
    f = nonces.session_nonce_file("abc")
    f.write_text(f.read_text().replace('"i": 0', '"i": 3'))
    with pytest.raises(nonces.NonceStoreError, match="gap/reorder"):
        nonces.load_nonces("abc")


def test_loose_perms_on_nonce_file_fail_loudly():
    nonces.append_nonce("abc", generate_nonce())
    f = nonces.session_nonce_file("abc")
    f.chmod(0o644)
    with pytest.raises(paths.InsecurePermissionsError):
        nonces.load_nonces("abc")


def test_nonce_bytes_never_under_repo_tree():
    # Belt-and-braces alongside the suite-wide conftest guard: writing via the
    # store keeps everything under the (test-isolated) data dir.
    n = generate_nonce()
    nonces.append_nonce("abc", n)
    from tests.conftest import REPO_ROOT

    assert paths.nonces_dir().resolve().is_relative_to(REPO_ROOT) is False
