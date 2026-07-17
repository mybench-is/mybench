"""MYB-3.7: enrollment point + since-enrollment reconciliation sweep.

The post-commit hook binds HEAD only, so it never fires for rebase/merge
commits, commits made on another machine, or GitHub server-side squash/
rebase-merge (a new hash born on GitHub, pulled later). ``enroll`` stamps the
enrollment point (HEAD at opt-in) in the data dir; ``reconcile`` walks
``git rev-list <enroll_commit>..HEAD`` and binds every SINCE-ENROLLMENT commit
that lacks a binding row. Pre-enrollment history is NOT swept.

Uses synthetic tmp git repos; XDG_DATA_HOME is isolated per test by the
suite-wide ``_isolated_data_dir`` fixture (tests/conftest.py), so these never
touch the real data dir (invariant #2/#3).
"""

import json
import os
import subprocess

import pytest

from mybench import paths
from mybench.hooks import binding
from mybench.hooks.__main__ import main as hooks_cli
from mybench.ledger import Ledger


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    )


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "throwaway"
    r.mkdir()
    git(r, "init", "-q")
    git(r, "config", "user.email", "synthetic@example.invalid")
    git(r, "config", "user.name", "Synthetic Committer")
    return r


def commit(repo, message="synthetic commit", filename="synthetic.txt"):
    (repo / filename).write_bytes(b"synthetic content\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def mark_only(repo):
    """Create the opt-in marker WITHOUT stamping an enrollment record."""
    (repo / ".mybench").mkdir(exist_ok=True)
    (repo / ".mybench" / "commit-binding-enabled").touch()


def enroll_disarmed(repo):
    """Enroll, then remove the live post-commit hook so subsequent commits are
    NOT auto-bound — the exact situation reconcile exists for (rebase, merge,
    off-machine, and GitHub server-side squash-merge all bypass post-commit).
    Lets each test drive reconcile deterministically against unbound commits."""
    record = binding.enroll(str(repo))
    (repo / ".git" / "hooks" / "post-commit").unlink()
    return record


def bound_hashes(repo):
    repo_id = binding.repo_identity(repo.resolve())
    return {
        row["commit_hash"]
        for row in Ledger().rows()
        if row["type"] == "binding" and row["repo_id"] == repo_id
    }


# --- enroll(): stamps the enrollment point, first-write-wins ---------------------------


def test_enroll_writes_record_with_current_head_and_installs_hook(repo):
    head = commit(repo, filename="a.txt")
    record = binding.enroll(str(repo))

    assert record["enroll_commit"] == head
    assert record["repo_id"] == binding.repo_identity(repo.resolve())
    assert (repo / ".mybench" / "commit-binding-enabled").is_file()
    assert (repo / ".git" / "hooks" / "post-commit").is_file()

    path = paths.enrollment_path(record["repo_id"])
    assert path.is_file()
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert json.loads(path.read_text()) == record


def test_enroll_is_idempotent_and_never_moves_the_point(repo):
    first_head = commit(repo, filename="a.txt")
    rec1 = binding.enroll(str(repo))
    assert rec1["enroll_commit"] == first_head

    commit(repo, filename="b.txt")  # HEAD advances
    rec2 = binding.enroll(str(repo))  # re-enroll must NOT re-stamp
    assert rec2 == rec1
    assert rec2["enroll_commit"] == first_head


# --- enrollment point: tracked vs untracked marker ------------------------------------


def test_enroll_tracked_marker_anchors_at_marker_commit_parent(repo):
    """A repo whose marker was committed in the past (dogfooded mybench) genuinely
    enrolled back then — anchor at the marker-add commit's parent so its live
    history (merge/squash commits post-commit missed) is swept, not mislabeled."""
    commit(repo, filename="pre0.txt")
    pre1 = commit(repo, filename="pre1.txt")  # this is marker_add~1

    # Commit the marker itself — now it is TRACKED history.
    (repo / ".mybench").mkdir(exist_ok=True)
    (repo / ".mybench" / "commit-binding-enabled").touch()
    git(repo, "add", ".mybench/commit-binding-enabled")
    git(repo, "commit", "-q", "-m", "enable commit-binding")
    marker_add = git(repo, "rev-parse", "HEAD").stdout.strip()

    after1 = commit(repo, filename="after1.txt")
    after2 = commit(repo, filename="after2.txt")

    record = binding.enroll(str(repo))
    assert record["enroll_commit"] == pre1  # == marker_add~1

    (repo / ".git" / "hooks" / "post-commit").unlink()  # drive reconcile deterministically
    assert binding.reconcile(repo) == 3
    assert bound_hashes(repo) == {marker_add, after1, after2}  # marker commit + everything after


def test_enroll_untracked_marker_anchors_at_head(repo):
    """A local-only marker (never git-added, e.g. in .git/info/exclude — typer/
    typer-curriculum) means the repo really is enrolling now: bind from HEAD on."""
    head = commit(repo, filename="base.txt")
    record = binding.enroll(str(repo))  # enroll touches the marker; it stays untracked
    assert record["enroll_commit"] == head

    (repo / ".git" / "hooks" / "post-commit").unlink()
    assert binding.reconcile(repo) == 0  # nothing after enrollment yet

    later = commit(repo, filename="later.txt")
    assert binding.reconcile(repo) == 1
    assert bound_hashes(repo) == {later}


# --- reconcile(): SINCE-ENROLLMENT window only ----------------------------------------


def test_reconcile_binds_only_post_enrollment_commits(repo):
    commit(repo, filename="pre1.txt")
    at_enroll = commit(repo, filename="pre2.txt")
    enroll_disarmed(repo)  # enrollment point = at_enroll

    c1 = commit(repo, filename="post1.txt")
    c2 = commit(repo, filename="post2.txt")

    assert binding.reconcile(repo) == 2
    assert bound_hashes(repo) == {c1, c2}  # pre-enrollment history untouched
    assert at_enroll not in bound_hashes(repo)

    assert binding.reconcile(repo) == 0  # idempotent
    assert bound_hashes(repo) == {c1, c2}


def test_historical_reconcile_backfills_only_pre_enrollment_as_imported(repo):
    pre1 = commit(repo, filename="pre1.txt")
    at_enroll = commit(repo, filename="at-enroll.txt")
    enroll_disarmed(repo)
    post1 = commit(repo, filename="post1.txt")
    post2 = commit(repo, filename="post2.txt")

    assert binding.reconcile(repo, historical=True, dry_run=True) == 2
    assert not Ledger().path.exists()
    assert binding.reconcile(repo, historical=True) == 2
    rows = Ledger().rows()
    imported = [row for row in rows if row["type"] == "binding"]
    assert {row["commit_hash"] for row in imported} == {pre1, at_enroll}
    assert all(row["schema_version"] == "3" for row in imported)
    assert all(row["provenance"] == "IMPORTED" for row in imported)
    assert all(
        set(row)
        == {
            "schema_version",
            "i",
            "type",
            "ts",
            "prev",
            "h",
            "commit_hash",
            "commit_ts",
            "repo_id",
            "provenance",
        }
        for row in imported
    )
    assert binding.reconcile(repo, historical=True) == 0

    assert binding.reconcile(repo) == 2
    live = [
        row
        for row in Ledger().rows()
        if row["type"] == "binding" and row["commit_hash"] in {post1, post2}
    ]
    assert len(live) == 2
    assert all(row["schema_version"] == "1" for row in live)
    assert all("provenance" not in row for row in live)
    assert binding.reconcile(repo) == 0


def test_historical_reconcile_has_no_pre_history_for_unborn_enrollment(repo):
    enroll_disarmed(repo)
    commit(repo, filename="after1.txt")
    commit(repo, filename="after2.txt")
    assert binding.reconcile(repo, historical=True, dry_run=True) == 0
    assert binding.reconcile(repo, historical=True) == 0
    assert not Ledger().path.exists()
    assert binding.reconcile(repo) == 2


def test_reconcile_binds_only_the_gap_left_by_post_commit(repo):
    at_enroll = commit(repo, filename="base.txt")
    enroll_disarmed(repo)
    c1 = commit(repo, filename="a.txt")
    c2 = commit(repo, filename="b.txt")
    # Simulate post-commit having bound the tip (c2) already.
    Ledger().append_binding(
        commit_hash=c2,
        commit_ts="2026-07-11T00:00:00Z",
        repo_id=binding.repo_identity(repo.resolve()),
    )
    assert bound_hashes(repo) == {c2}

    assert binding.reconcile(repo) == 1  # only the un-bound in-window commit
    assert bound_hashes(repo) == {c1, c2}
    assert at_enroll not in bound_hashes(repo)
    assert binding.reconcile(repo) == 0


def test_reconcile_noop_without_enrollment_record(repo):
    mark_only(repo)  # marker present, but enrollment never stamped
    commit(repo, filename="a.txt")
    commit(repo, filename="b.txt")
    assert binding.reconcile(repo) == 0
    assert not Ledger().path.exists()  # must NOT silently backfill all-history


def test_reconcile_noop_without_marker(repo):
    commit(repo, filename="a.txt")
    assert binding.reconcile(repo) == 0
    assert not Ledger().path.exists()


def test_reconcile_noop_on_non_repo(tmp_path):
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    assert binding.reconcile(plain) == 0


# --- unborn-HEAD enrollment (enrolled at repo start) ----------------------------------


def test_enroll_unborn_head_then_commits_all_bound(repo):
    record = enroll_disarmed(repo)  # no commits yet; hook disarmed so reconcile does the work
    assert record["enroll_commit"] == ""
    assert binding.reconcile(repo) == 0  # still unborn — nothing to bind, no crash
    assert not Ledger().path.exists()

    c1 = commit(repo, filename="a.txt")
    c2 = commit(repo, filename="b.txt")
    assert binding.reconcile(repo) == 2  # empty enroll_commit → all of HEAD is in-window
    assert bound_hashes(repo) == {c1, c2}
    assert binding.reconcile(repo) == 0


def test_reconcile_noop_on_empty_repo(repo):
    binding.enroll(str(repo))  # unborn HEAD; marker + record present
    assert binding.reconcile(repo) == 0
    assert not Ledger().path.exists()


# --- squash-merge / merge / detached reachability -------------------------------------


def test_reconcile_catches_a_squash_merge_style_commit(repo):
    """A commit lands in the repo without post-commit firing (as a pulled GitHub
    squash-merge does: a new mainline hash born server-side) → bound after sweep."""
    commit(repo, filename="base.txt")
    enroll_disarmed(repo)
    first = commit(repo, filename="work.txt")
    binding.reconcile(repo)
    assert bound_hashes(repo) == {first}

    squashed = commit(repo, message="squashed on server", filename="feature.txt")
    assert squashed not in bound_hashes(repo)

    assert binding.reconcile(repo) == 1
    assert squashed in bound_hashes(repo)


def test_reconcile_binds_a_merge_commit(repo):
    commit(repo, filename="base.txt")
    enroll_disarmed(repo)
    git(repo, "checkout", "-q", "-b", "feature")
    feat = commit(repo, filename="feature.txt")
    git(repo, "checkout", "-q", "master")
    main = commit(repo, filename="main.txt")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge feature", "feature")
    merge_head = git(repo, "rev-parse", "HEAD").stdout.strip()

    n = binding.reconcile(repo)
    assert n == 3  # feature + main + merge commit (base is the enrollment point)
    assert bound_hashes(repo) == {feat, main, merge_head}
    assert binding.reconcile(repo) == 0


def test_reconcile_binds_in_detached_head(repo):
    at_enroll = commit(repo, filename="base.txt")
    enroll_disarmed(repo)
    c1 = commit(repo, filename="a.txt")
    c2 = commit(repo, filename="b.txt")
    git(repo, "checkout", "-q", c1)  # detached HEAD at c1
    assert git(repo, "rev-parse", "HEAD").stdout.strip() == c1

    # Window is at_enroll..HEAD with HEAD detached at c1, so only c1 is bound.
    assert binding.reconcile(repo) == 1
    assert bound_hashes(repo) == {c1}
    assert c2 not in bound_hashes(repo)
    assert at_enroll not in bound_hashes(repo)


def test_reconcile_noop_when_enroll_point_is_an_invalid_ref(repo):
    """A rebased-away enrollment commit makes the range error; must not crash or
    fall back to binding all-history."""
    commit(repo, filename="a.txt")
    record = enroll_disarmed(repo)
    commit(repo, filename="b.txt")
    # Corrupt the record to point at a commit that no longer exists as an object.
    path = paths.enrollment_path(record["repo_id"])
    bad = dict(record, enroll_commit="0" * 40)
    path.write_text(json.dumps(bad))

    assert binding.reconcile(repo) == 0
    assert not Ledger().path.exists()
    log = paths.data_dir() / "hooks.log"
    assert log.exists()  # logged via _log_error, exception class only
    assert "reconcile error" in log.read_text()  # attributed to the sweep, not the hook
    assert "0000000000" not in log.read_text()  # ...and no ref/hash leaked into the log


# --- CLI wiring -----------------------------------------------------------------------


def test_enroll_and_reconcile_cli(repo, capsys):
    commit(repo, filename="base.txt")
    assert hooks_cli(["enroll", str(repo)]) == 0
    assert "enrolled" in capsys.readouterr().out
    (repo / ".git" / "hooks" / "post-commit").unlink()  # isolate reconcile from the live hook
    made = {commit(repo, filename=f"f{i}.txt") for i in range(2)}
    assert hooks_cli(["reconcile", str(repo)]) == 0
    assert "bound 2 previously-missed commit(s)" in capsys.readouterr().out
    assert bound_hashes(repo) == made


# --- enroll --at: owner override for pre-record real enrollments ------------------------


def test_enroll_at_backdates_the_point_and_widens_the_sweep(repo):
    """A repo that truly opted in before record-stamping existed (untracked-marker
    real repos): --at anchors the window at the historical HEAD so the commits
    post-commit already missed are swept instead of mislabeled pre-enrollment."""
    c1 = commit(repo, filename="at-enroll.txt")
    c2 = commit(repo, filename="missed-by-hook.txt")  # landed before stamping

    record = binding.enroll(str(repo), at=c1)
    assert record["enroll_commit"] == c1  # not HEAD (= c2), the derived value

    (repo / ".git" / "hooks" / "post-commit").unlink()
    c3 = commit(repo, filename="after-stamp.txt")
    assert binding.reconcile(repo) == 2
    assert bound_hashes(repo) == {c2, c3}  # the backdated gap + new work; c1 excluded


def test_enroll_at_conflict_refused_matching_at_idempotent(repo):
    commit(repo, filename="a.txt")
    head = commit(repo, filename="b.txt")
    rec = binding.enroll(str(repo))  # untracked marker: point == HEAD
    assert rec["enroll_commit"] == head

    with pytest.raises(binding.HookError, match="first enrollment wins"):
        binding.enroll(str(repo), at="HEAD~1")  # would move the point — refused
    assert binding.enroll(str(repo), at=head) == rec  # same point: idempotent no-op
    assert json.loads(paths.enrollment_path(rec["repo_id"]).read_text()) == rec


def test_enroll_at_rejects_junk_and_non_ancestors(repo):
    c1 = commit(repo, filename="base.txt")
    git(repo, "checkout", "-q", "-b", "feature")
    f1 = commit(repo, filename="feature.txt")
    git(repo, "checkout", "-q", "master")
    commit(repo, filename="main.txt")

    with pytest.raises(binding.HookError, match="does not resolve"):
        binding.enroll(str(repo), at="0" * 40)
    with pytest.raises(binding.HookError, match="not an ancestor"):
        binding.enroll(str(repo), at=f1)  # reachable ref, but not in HEAD's history
    repo_id = binding.repo_identity(repo.resolve())
    assert not paths.enrollment_path(repo_id).exists()  # nothing stamped by refusals

    assert binding.enroll(str(repo), at=c1)["enroll_commit"] == c1  # ancestor: accepted


def test_enroll_at_cli(repo, capsys):
    c1 = commit(repo, filename="a.txt")
    commit(repo, filename="b.txt")
    assert hooks_cli(["enroll", str(repo), "--at", c1]) == 0
    assert c1 in capsys.readouterr().out
    assert hooks_cli(["enroll", str(repo), "--at", "HEAD"]) == 1  # conflicts with c1
    err = capsys.readouterr().err
    assert err.startswith("error:") and "first enrollment wins" in err


# --- raise posture: repo-level errors no-op, data-dir integrity errors surface ---------


def test_integrity_errors_surface_from_reconcile_but_never_from_run(repo):
    """MYB-2.1: loose perms on A2/A3 must reach the owner, not be masked as a
    quiet '0 bound' — except in the post-commit hook, which never blocks a
    commit and swallows everything to hooks.log."""
    commit(repo, filename="a.txt")
    enroll_disarmed(repo)
    commit(repo, filename="b.txt")
    os.chmod(paths.session_scope_key_path(), 0o644)

    assert binding.run(repo) == 0  # hook posture: swallowed
    with pytest.raises(paths.InsecurePermissionsError):
        binding.reconcile(repo)  # sweep posture: surfaced


def test_loose_ledger_perms_surface_from_reconcile(repo):
    commit(repo, filename="base.txt")
    enroll_disarmed(repo)
    commit(repo, filename="a.txt")
    assert binding.reconcile(repo) == 1  # ledger now exists
    os.chmod(Ledger().path, 0o644)
    commit(repo, filename="b.txt")
    with pytest.raises(paths.InsecurePermissionsError):
        binding.reconcile(repo)


def test_reconcile_cli_reports_integrity_errors_cleanly(repo, capsys):
    commit(repo, filename="a.txt")
    binding.enroll(str(repo))
    os.chmod(paths.session_scope_key_path(), 0o644)
    assert hooks_cli(["reconcile", str(repo)]) == 1  # clean error, not a traceback
    err = capsys.readouterr().err
    assert err.startswith("error:") and "chmod" in err


def test_mid_sweep_failure_logs_and_returns_partial_count(repo, monkeypatch):
    commit(repo, filename="base.txt")
    enroll_disarmed(repo)
    c1 = commit(repo, filename="a.txt")
    c2 = commit(repo, filename="b.txt")

    real = binding._committer_ts
    calls = []

    def flaky(top, commit_hash):
        calls.append(commit_hash)
        if len(calls) == 2:
            raise RuntimeError("synthetic mid-sweep failure")
        return real(top, commit_hash)

    monkeypatch.setattr(binding, "_committer_ts", flaky)
    assert binding.reconcile(repo) == 1  # partial count, no crash
    assert len(bound_hashes(repo)) == 1
    assert "reconcile error type=RuntimeError" in (paths.data_dir() / "hooks.log").read_text()

    monkeypatch.setattr(binding, "_committer_ts", real)
    assert binding.reconcile(repo) == 1  # idempotent re-run completes the gap
    assert bound_hashes(repo) == {c1, c2}


# --- shallow clones (AC #2) --------------------------------------------------------------


def test_reconcile_sweeps_normally_inside_a_shallow_clone(repo, tmp_path):
    for i in range(3):
        commit(repo, filename=f"pre{i}.txt")
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{repo}", str(shallow)],
        check=True, capture_output=True,
    )
    git(shallow, "config", "user.email", "synthetic@example.invalid")
    git(shallow, "config", "user.name", "Synthetic Committer")

    record = binding.enroll(str(shallow))  # untracked marker → HEAD (the shallow tip)
    (shallow / ".git" / "hooks" / "post-commit").unlink()
    assert record["enroll_commit"] == git(shallow, "rev-parse", "HEAD").stdout.strip()

    later = commit(shallow, filename="later.txt")
    assert binding.reconcile(shallow) == 1
    assert bound_hashes(shallow) == {later}


def test_reconcile_noop_when_enroll_point_is_beyond_the_shallow_boundary(repo, tmp_path):
    first = commit(repo, filename="pre0.txt")
    commit(repo, filename="pre1.txt")
    commit(repo, filename="pre2.txt")
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{repo}", str(shallow)],
        check=True, capture_output=True,
    )
    record = binding.enroll(str(shallow))
    # Point the record at a commit the shallow clone does not have.
    bad = dict(record, enroll_commit=first)
    paths.enrollment_path(record["repo_id"]).write_text(json.dumps(bad))

    assert binding.reconcile(shallow) == 0  # range errors → logged no-op, no crash
    assert not Ledger().path.exists()
    assert "reconcile error" in (paths.data_dir() / "hooks.log").read_text()
