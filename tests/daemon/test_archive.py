"""MYB-12.1: synthetic-only A9 retention archive and privacy coverage."""

import json
import logging
import stat
from pathlib import Path

import pytest

from mybench import archive as archive_store
from mybench import commitments as c
from mybench import nonces, paths
from mybench.anchor.batch import build_batch, canonical_bytes
from mybench.daemon import capture
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures


@pytest.fixture
def fx(tmp_path):
    return generate_fixtures(tmp_path / "fx")


@pytest.fixture
def config(fx):
    return capture.DaemonConfig(
        watches=(
            capture.WatchSpec(fx.root / "claude" / "projects", "claude-code"),
            capture.WatchSpec(fx.root / "codex" / "sessions", "codex"),
        )
    )


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def watch_for(config, session_file):
    return next(w for w in config.watches if session_file.is_relative_to(w.path))


def sid(config, session_file):
    watch = watch_for(config, session_file)
    return capture.session_id_for(session_file, watch, paths.ensure_session_scope_key())


def archive_path(config, session_file):
    watch = watch_for(config, session_file)
    return paths.archive_session_path(watch.source, sid(config, session_file))


def committed_bytes(session_file):
    return b"".join(item + b"\n" for item in capture._complete_lines(session_file.read_bytes()))


def latest_session_rows(daemon):
    latest = {}
    for row in daemon.ledger.rows():
        if row["type"] == "session":
            latest[row["session_id"]] = row
    return latest


def assert_archive_matches_ledger(daemon, config, session_file):
    archived = archive_path(config, session_file).read_bytes()
    items = capture._complete_lines(archived)
    session_id = sid(config, session_file)
    known = nonces.load_nonces(session_id)
    leaves = [c.leaf_commitment(nonce, item) for nonce, item in zip(known, items)]
    row = latest_session_rows(daemon)[session_id]
    assert len(items) == row["item_count"]
    assert c.session_root(leaves).hex() == row["session_root"]


def test_every_committed_session_is_archived_and_verified_0600(fx, config):
    daemon = capture.Daemon(config)
    assert daemon.scan_once() == len(fx.sessions)

    data_dir = paths.data_dir().resolve()
    repo_root = Path(__file__).resolve().parents[2]
    assert repo_root not in data_dir.parents
    for directory in (data_dir, paths.archive_dir(), *map(paths.archive_source_dir, paths.ARCHIVE_SOURCES[:2])):
        assert directory.is_dir()
        assert mode_of(directory) == 0o700

    for session_file in fx.sessions:
        archived = archive_path(config, session_file)
        assert archived.resolve().is_relative_to(data_dir)
        assert repo_root not in archived.resolve().parents
        assert mode_of(archived) == 0o600
        assert archived.read_bytes() == committed_bytes(session_file)
        assert_archive_matches_ledger(daemon, config, session_file)

    stats = archive_store.archive_stats()
    assert stats.session_files == len(fx.sessions)
    assert stats.total_bytes == sum(len(committed_bytes(s)) for s in fx.sessions)
    assert stats.free_bytes > 0


def test_rescan_is_idempotent_and_growth_extends_same_file(fx, config):
    daemon = capture.Daemon(config)
    daemon.scan_once()
    target = fx.sessions[0]
    archived = archive_path(config, target)
    before = archived.read_bytes()
    inode = archived.stat().st_ino
    mtime = archived.stat().st_mtime_ns

    assert daemon.scan_once() == 0
    assert archived.read_bytes() == before
    assert archived.stat().st_ino == inode
    assert archived.stat().st_mtime_ns == mtime

    with target.open("ab") as source:
        source.write(json.dumps({"synthetic": "archive-growth"}).encode() + b"\n")
    assert daemon.scan_once() == 1
    after = archived.read_bytes()
    assert after.startswith(before)
    assert after == committed_bytes(target)
    assert archived.stat().st_ino == inode
    assert_archive_matches_ledger(daemon, config, target)

    assert daemon.scan_once() == 0
    assert archived.read_bytes() == after
    assert archived.stat().st_ino == inode


def test_exact_newline_bytes_and_partial_tail_are_preserved_only_after_commit(tmp_path):
    watch_dir = tmp_path / "synthetic-watch"
    watch_dir.mkdir()
    session_file = watch_dir / "opaque-session.jsonl"
    session_file.write_bytes(b"first\r\n\nthird\npartial")
    config = capture.DaemonConfig(
        watches=(capture.WatchSpec(watch_dir, "synthetic"),)
    )
    daemon = capture.Daemon(config)

    assert daemon.scan_once() == 1
    archived = archive_path(config, session_file)
    assert archived.read_bytes() == b"first\r\n\nthird\n"
    assert latest_session_rows(daemon)[sid(config, session_file)]["item_count"] == 3

    with session_file.open("ab") as source:
        source.write(b"-complete\n")
    assert daemon.scan_once() == 1
    assert archived.read_bytes() == b"first\r\n\nthird\npartial-complete\n"
    assert_archive_matches_ledger(daemon, config, session_file)


def test_shrunken_live_source_never_truncates_verified_archive(fx, config, caplog):
    daemon = capture.Daemon(config)
    daemon.scan_once()
    target = fx.sessions[0]
    archived = archive_path(config, target)
    before = archived.read_bytes()
    inode = archived.stat().st_ino
    target.write_bytes(target.read_bytes().splitlines(keepends=True)[0])

    with caplog.at_level(logging.INFO, logger="mybench.daemon"):
        assert daemon.scan_once() == 0
    assert archived.read_bytes() == before
    assert archived.stat().st_ino == inode
    assert "event=source_shrunk" in caplog.text
    assert "archive_covered=3" in caplog.text


def test_archive_failure_never_blocks_capture_and_noop_rescan_retries(
    fx, config, monkeypatch, caplog
):
    real_archive = archive_store.archive_session

    def fail_archive(**_kwargs):
        raise OSError("synthetic private path and content must not reach logs")

    monkeypatch.setattr(archive_store, "archive_session", fail_archive)
    daemon = capture.Daemon(config)
    with caplog.at_level(logging.INFO, logger="mybench.daemon"):
        assert daemon.scan_once() == len(fx.sessions)

    assert daemon.ledger.verify_chain() == 1 + len(fx.sessions)
    assert "archive_failed=3" in caplog.text
    assert "synthetic private path" not in caplog.text
    assert not list(paths.archive_dir().glob("*/*"))

    caplog.clear()
    monkeypatch.setattr(archive_store, "archive_session", real_archive)
    with caplog.at_level(logging.INFO, logger="mybench.daemon"):
        assert daemon.scan_once() == 0  # no duplicate rows; A9 is retried independently
    assert "archive_covered=3" in caplog.text
    assert "archive_failed=0" in caplog.text
    for session_file in fx.sessions:
        assert_archive_matches_ledger(daemon, config, session_file)


def test_readback_must_match_existing_ledger_commitment(fx, config, caplog):
    daemon = capture.Daemon(config)
    daemon.scan_once()
    target = fx.sessions[0]
    source_lines = capture._complete_lines(target.read_bytes())
    source_lines[0] = b'{"synthetic":"post-commit mutation"}'
    mutated = b"".join(line + b"\n" for line in source_lines)
    target.write_bytes(mutated)
    archived = archive_path(config, target)
    archived.write_bytes(mutated)

    before_rows = daemon.ledger.verify_chain()
    with caplog.at_level(logging.INFO, logger="mybench.daemon"):
        assert daemon.scan_once() == 0
    assert daemon.ledger.verify_chain() == before_rows
    assert archived.read_bytes() == mutated  # verifier never rewrites a divergent archive
    assert "event=archive_error type=ArchiveError" in caplog.text
    assert "post-commit mutation" not in caplog.text


def test_archive_fsyncs_new_file_and_parent_directory(monkeypatch):
    items = [b'{"synthetic":"fsync-a"}', b'{"synthetic":"fsync-b"}']
    known = [bytes([1]) * 32, bytes([2]) * 32]
    root = c.session_root(
        [c.leaf_commitment(nonce, item) for nonce, item in zip(known, items)]
    ).hex()
    real_fsync = archive_store.os.fsync
    fsynced = []

    def tracked_fsync(fd):
        fsynced.append("dir" if stat.S_ISDIR(archive_store.os.fstat(fd).st_mode) else "file")
        real_fsync(fd)

    monkeypatch.setattr(archive_store.os, "fsync", tracked_fsync)
    result = archive_store.archive_session(
        source="synthetic",
        session_id="synthetic-fsync-session",
        source_items=items,
        nonces=known,
        expected_item_count=len(items),
        expected_session_root=root,
    )
    assert result.items_verified == len(items)
    assert "file" in fsynced
    assert "dir" in fsynced


@pytest.mark.parametrize(
    ("source", "session_id"),
    [
        ("../codex", "opaque-session"),
        ("codex", "../escape"),
        ("codex", "/absolute"),
        ("codex", "contains.dot"),
        ("codex", "x" * 65),
    ],
)
def test_archive_address_rejects_traversal_and_nonopaque_ids(source, session_id):
    with pytest.raises(paths.PathsError):
        paths.archive_session_path(source, session_id)


def test_default_real_watch_config_remains_forbidden_in_archive_tests():
    with pytest.raises(capture.ConfigError, match="test mode"):
        capture.default_config()
    assert not list(paths.archive_dir().glob("*/*"))


def test_canaries_paths_and_archive_addresses_do_not_reach_a3_logs_or_anchor_staging(
    fx, config, tmp_path
):
    logfile = tmp_path / "daemon.log"
    handler = logging.FileHandler(logfile)
    logger = logging.getLogger("mybench.daemon")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        daemon = capture.Daemon(config)
        daemon.scan_once()
    finally:
        logger.removeHandler(handler)
        handler.close()

    anchor_artifact = paths.anchors_dir() / "synthetic-anchor-candidate.json"
    anchor_artifact.write_bytes(canonical_bytes(build_batch(daemon.ledger)))
    used_nonces = [
        nonce
        for nonce_file in paths.nonces_dir().glob("*.jsonl")
        for nonce in nonces.load_nonces(nonce_file.stem)
    ]
    source_paths = [str(session_file).encode() for session_file in fx.sessions]
    archive_addresses = [str(archive_path(config, session_file)).encode() for session_file in fx.sessions]
    canaries = fx.all_canaries() + used_nonces + source_paths + archive_addresses

    assert assert_no_canaries([daemon.ledger.path, logfile, anchor_artifact], canaries) == 3
    assert "archive_covered=3" in logfile.read_text()
    assert "committed_sessions=3" in logfile.read_text()


def test_archive_surface_leak_scanner_fires_when_canary_is_planted(fx, tmp_path):
    planted = tmp_path / "planted.log"
    planted.write_bytes(b"prefix:" + fx.content_canaries[0].encode() + b":suffix")
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], fx.all_canaries())
