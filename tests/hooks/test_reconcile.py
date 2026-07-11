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
    assert "0000000000" not in log.read_text()  # ...and no ref/hash leaked into the log


# --- CLI wiring -----------------------------------------------------------------------


def test_enroll_and_reconcile_cli(repo, capsys):
    commit(repo, filename="base.txt")
    assert hooks_cli(["enroll", str(repo)]) == 0
    assert "enrolled" in capsys.readouterr().out
    (repo / ".git" / "hooks" / "post-commit").unlink()  # isolate reconcile from the live hook
    made = {commit(repo, filename=f"f{i}.txt") for i in range(2)}
    assert hooks_cli(["reconcile", str(repo)]) == 0
    assert bound_hashes(repo) == made
