"""MYB-3.5: opt-in post-commit binding hook — real git repos, real commits."""

import os
import re
import subprocess
from pathlib import Path

import pytest

from mybench import paths
from mybench.hooks import binding
from mybench.hooks.__main__ import main as hooks_cli
from mybench.ledger import Ledger
from tests.fixtures import assert_no_canaries

CANARY_MSG = "MYBENCH-CANARY-commitmsg-0123abcd"
CANARY_FILE = "MYBENCH-CANARY-filename-4567ef01.txt"
CANARY_BRANCH = "MYBENCH-CANARY-branch-89ab2345"


def git(repo, *args, env=None, check=True):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=check,
        env=env,
    )


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "throwaway"
    r.mkdir()
    git(r, "init", "-q")
    git(r, "config", "user.email", "synthetic@example.invalid")
    git(r, "config", "user.name", "Synthetic Committer")
    return r


def commit(repo, message="synthetic commit", filename="synthetic.txt", env=None):
    (repo / filename).write_bytes(b"synthetic content\n")
    git(repo, "add", "-A", env=env)
    proc = git(repo, "commit", "-q", "-m", message, env=env)
    return git(repo, "rev-parse", "HEAD").stdout.strip(), proc


def enable(repo):
    (repo / ".mybench").mkdir()
    (repo / ".mybench" / "commit-binding-enabled").touch()


# --- Install discipline (AC #3) -----------------------------------------------------


def test_install_writes_one_hook_and_nothing_else(repo):
    local_cfg_before = (repo / ".git" / "config").read_bytes()
    global_cfg = Path.home() / ".gitconfig"
    global_before = global_cfg.read_bytes() if global_cfg.exists() else None
    hook = binding.install(str(repo))
    assert hook == repo / ".git" / "hooks" / "post-commit"
    assert os.access(hook, os.X_OK)
    assert binding.HOOK_SENTINEL in hook.read_text()
    assert (repo / ".git" / "config").read_bytes() == local_cfg_before
    assert (global_cfg.read_bytes() if global_cfg.exists() else None) == global_before
    hookspath = git(repo, "config", "--global", "core.hooksPath", check=False)
    assert hookspath.stdout.strip() == ""  # never set, before or after


def test_install_refuses_globalish_args_nonrepos_and_foreign_hooks(repo, tmp_path):
    with pytest.raises(binding.HookError, match="refused by design"):
        binding.install("--global")
    with pytest.raises(binding.HookError, match="not the top level"):
        binding.install(str(tmp_path / "not-a-repo"))
    foreign = repo / ".git" / "hooks" / "post-commit"
    foreign.parent.mkdir(exist_ok=True)
    foreign.write_text("#!/bin/sh\necho someone else's hook\n")
    with pytest.raises(binding.HookError, match="refusing to overwrite"):
        binding.install(str(repo))
    assert hooks_cli(["install", str(repo)]) == 1  # CLI surfaces it as exit 1


def test_installer_does_not_activate(repo, capsys):
    assert hooks_cli(["install", str(repo)]) == 0
    assert "NOT active" in capsys.readouterr().out
    commit(repo)
    assert not Ledger().path.exists()  # installed but not opted in: no writes


# --- Opt-in semantics (AC #1, #2) ------------------------------------------------------


def test_with_marker_one_commit_appends_one_binding_row(repo):
    binding.install(str(repo))
    enable(repo)
    head, _ = commit(repo)
    ledger = Ledger()
    assert ledger.verify_chain() == 2  # genesis + one binding
    row = ledger.rows()[-1]
    assert row["type"] == "binding"
    assert row["commit_hash"] == head
    assert re.fullmatch(r"[0-9a-f]{16}", row["repo_id"])
    assert set(row) == {
        "schema_version", "i", "type", "ts", "prev", "h",
        "commit_hash", "commit_ts", "repo_id",
    }
    head2, _ = commit(repo, filename="second.txt")
    assert Ledger().verify_chain() == 3
    assert Ledger().rows()[-1]["commit_hash"] == head2


def test_without_marker_no_writes_no_noise(repo):
    binding.install(str(repo))
    _, proc = commit(repo)
    assert proc.stderr == ""
    assert not Ledger().path.exists()
    assert not (paths.data_dir() / "hooks.log").exists()


def test_same_repo_same_id_different_repo_different_id(repo, tmp_path):
    top = repo.resolve()
    assert binding.repo_identity(top) == binding.repo_identity(top)
    other = tmp_path / "other"
    other.mkdir()
    assert binding.repo_identity(other.resolve()) != binding.repo_identity(top)


# --- Leak channels (AC #4) --------------------------------------------------------------


def test_message_filename_branch_canaries_reach_nothing(repo):
    binding.install(str(repo))
    enable(repo)
    git(repo, "checkout", "-q", "-b", CANARY_BRANCH)
    commit(repo, message=CANARY_MSG, filename=CANARY_FILE)
    ledger = Ledger()
    assert ledger.verify_chain() == 2
    canaries = [CANARY_MSG.encode(), CANARY_FILE.encode(), CANARY_BRANCH.encode()]
    targets = [ledger.path]
    if (paths.data_dir() / "hooks.log").exists():
        targets.append(paths.data_dir() / "hooks.log")
    assert assert_no_canaries(targets, canaries) == len(targets)


# --- Failure isolation (AC #5) ------------------------------------------------------------


def test_broken_data_dir_never_blocks_the_commit(repo, tmp_path):
    binding.install(str(repo))
    enable(repo)
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where a directory must be")
    env = dict(os.environ, XDG_DATA_HOME=str(blocker / "impossible"))
    head, proc = commit(repo, env=env)
    assert proc.returncode == 0 and len(head) in (40, 64)  # commit landed
    assert proc.stderr == ""  # and silently


def test_ledger_failure_is_logged_in_data_dir_only(repo):
    binding.install(str(repo))
    enable(repo)
    commit(repo)
    with Ledger().path.open("ab") as f:
        f.write(b'{"torn')  # simulate a crashed writer
    head, proc = commit(repo, filename="after-corruption.txt")
    assert proc.returncode == 0 and proc.stderr == ""
    log = paths.data_dir() / "hooks.log"
    assert log.exists()
    text = log.read_text()
    assert "TornTailError" in text  # exception class only…
    assert str(Ledger().path) not in text  # …never paths or messages
