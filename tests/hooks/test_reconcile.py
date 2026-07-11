"""MYB-3.7: commit-binding reconciliation sweep — rev-list catch-up for missed commits.

The post-commit hook binds HEAD only, so it never fires for rebase/merge
commits, commits made on another machine, or GitHub server-side squash/
rebase-merge (a new hash born on GitHub, pulled later). ``reconcile`` walks
``git rev-list HEAD`` and binds every commit that lacks a binding row.

Uses a synthetic tmp git repo; XDG_DATA_HOME is isolated per test by the
suite-wide ``_isolated_data_dir`` fixture (tests/conftest.py), so these never
touch the real data dir (invariant #2/#3).
"""

import subprocess

import pytest

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


def enable(repo):
    (repo / ".mybench").mkdir(exist_ok=True)
    (repo / ".mybench" / "commit-binding-enabled").touch()


def bound_hashes(repo):
    repo_id = binding.repo_identity(repo.resolve())
    return {
        row["commit_hash"]
        for row in Ledger().rows()
        if row["type"] == "binding" and row["repo_id"] == repo_id
    }


# --- AC #1: binds unbound HEAD history, idempotently -----------------------------------


def test_reconcile_binds_all_unbound_commits_and_is_idempotent(repo):
    # Three commits WITHOUT the post-commit hook ever having fired: nothing bound.
    enable(repo)
    made = {commit(repo, filename=f"f{i}.txt") for i in range(3)}
    assert not Ledger().path.exists()  # no hook installed → no bindings yet

    n = binding.reconcile(repo)
    assert n == 3
    assert bound_hashes(repo) == made
    assert Ledger().verify_chain() == 4  # genesis + three bindings

    # Re-running adds nothing.
    assert binding.reconcile(repo) == 0
    assert Ledger().verify_chain() == 4
    assert bound_hashes(repo) == made


def test_reconcile_only_binds_the_gap_left_by_post_commit(repo):
    # HEAD is bound (as the post-commit hook would), earlier commits are not.
    enable(repo)
    c1 = commit(repo, filename="a.txt")
    c2 = commit(repo, filename="b.txt")
    Ledger().append_binding(
        commit_hash=c2, commit_ts="2026-07-10T00:00:00Z", repo_id=binding.repo_identity(repo.resolve())
    )
    assert bound_hashes(repo) == {c2}

    assert binding.reconcile(repo) == 1  # only the un-bound ancestor
    assert bound_hashes(repo) == {c1, c2}
    assert binding.reconcile(repo) == 0


# --- AC #3: squash-merge simulation ---------------------------------------------------


def test_reconcile_catches_a_squash_merge_style_commit(repo):
    """A commit lands in the repo without post-commit firing (as a pulled GitHub
    squash-merge does: a new mainline hash born server-side) → bound after sweep."""
    enable(repo)
    base = commit(repo, filename="base.txt")
    binding.reconcile(repo)  # base is now bound, as steady state would be
    assert bound_hashes(repo) == {base}

    # Simulate a mainline commit that never triggered the hook locally.
    squashed = commit(repo, message="squashed on server", filename="feature.txt")
    assert squashed not in bound_hashes(repo)

    assert binding.reconcile(repo) == 1
    assert squashed in bound_hashes(repo)


# --- AC #2: graceful on empty / no-marker / detached ----------------------------------


def test_reconcile_noop_without_marker(repo):
    commit(repo, filename="a.txt")  # enrolled repo would need the marker; this one lacks it
    assert binding.reconcile(repo) == 0
    assert not Ledger().path.exists()


def test_reconcile_noop_on_empty_repo(repo):
    enable(repo)  # marker present but unborn HEAD — must not crash
    assert binding.reconcile(repo) == 0
    assert not Ledger().path.exists()


def test_reconcile_noop_on_non_repo(tmp_path):
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    assert binding.reconcile(plain) == 0


def test_reconcile_binds_in_detached_head(repo):
    enable(repo)
    c1 = commit(repo, filename="a.txt")
    c2 = commit(repo, filename="b.txt")
    git(repo, "checkout", "-q", c1)  # detached HEAD at the parent
    assert git(repo, "rev-parse", "HEAD").stdout.strip() == c1

    # Only c1 is reachable from the detached HEAD, so only c1 gets bound.
    assert binding.reconcile(repo) == 1
    assert bound_hashes(repo) == {c1}
    assert c2 not in bound_hashes(repo)


def test_reconcile_binds_a_merge_commit(repo):
    enable(repo)
    commit(repo, filename="base.txt")
    git(repo, "checkout", "-q", "-b", "feature")
    commit(repo, filename="feature.txt")
    git(repo, "checkout", "-q", "master")
    commit(repo, filename="main.txt")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge feature", "feature")
    merge_head = git(repo, "rev-parse", "HEAD").stdout.strip()

    n = binding.reconcile(repo)
    assert n == 4  # base + feature + main + merge commit
    assert merge_head in bound_hashes(repo)
    assert binding.reconcile(repo) == 0


# --- CLI wiring -----------------------------------------------------------------------


def test_reconcile_cli_binds_named_repo(repo):
    enable(repo)
    made = {commit(repo, filename=f"f{i}.txt") for i in range(2)}
    assert hooks_cli(["reconcile", str(repo)]) == 0
    assert bound_hashes(repo) == made
