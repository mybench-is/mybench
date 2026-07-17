"""MYB-11.8 OS-native scheduled capture and health receipt."""

from __future__ import annotations

import json
import os
import plistlib
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mybench import cli, paths, scheduler, status
from mybench.daemon.capture import WatchSpec
from mybench.hooks import binding
from mybench.scan_config import ScanConfig, store as store_scan_config
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures

FIXTURES = Path(__file__).parent / "fixtures" / "scheduler"


class FakeRunner:
    def __init__(self, *, active: bool = True):
        self.active = active
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, command: list[str], *, check: bool = True):
        call = tuple(command)
        self.calls.append(call)
        rc = 0
        if "is-enabled" in call or "is-active" in call or "print" in call:
            rc = 0 if self.active else 1
        result = subprocess.CompletedProcess(command, rc)
        if check and rc:
            raise subprocess.CalledProcessError(rc, command)
        return result


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _fake_executable(tmp_path: Path) -> Path:
    executable = tmp_path / "bin" / "mybench"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    return executable


def _systemd_environment(tmp_path: Path, monkeypatch, *, active: bool = True):
    runner = FakeRunner(active=active)
    executable = _fake_executable(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(scheduler, "_run", runner)
    monkeypatch.setattr(scheduler, "_select_backend", lambda: "systemd")
    monkeypatch.setattr(scheduler, "_systemd_binary", lambda: "/usr/bin/systemctl")
    monkeypatch.setattr(scheduler, "_cli_executable", lambda: executable)
    return runner, executable


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Synthetic"], check=True
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "synthetic@example.invalid"],
        check=True,
    )
    (repo / "README.md").write_text("synthetic\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "synthetic"], check=True)
    return repo


def _bootstrap_keys() -> None:
    paths.ensure_data_dir()
    paths.ensure_session_scope_key()
    paths.ensure_device_key()
    paths.ensure_identity_key()
    paths.ensure_commit_signing_key()


def test_generated_jobs_match_fixtures_and_have_no_resident_process_contract():
    executable = Path("/opt/mybench/bin/mybench")
    service, timer = scheduler.render_systemd(executable)
    launchd = scheduler.render_launchd(executable)

    assert service == (FIXTURES / "mybench-scan.service").read_bytes()
    assert timer == (FIXTURES / "mybench-scan.timer").read_bytes()
    assert launchd == (FIXTURES / "is.mybench.scan.plist").read_bytes()
    assert b"Type=oneshot" in service and b"Restart=" not in service
    assert b"scan --quiet --scheduled" in service
    assert b"--archive" not in service + timer + launchd
    assert b"--upgrade" not in service + timer + launchd
    assert b"--watch" not in service + timer + launchd
    assert b"--repo" not in service + timer + launchd
    parsed = plistlib.loads(launchd)
    assert parsed["KeepAlive"] is False and parsed["RunAtLoad"] is False
    assert parsed["ProgramArguments"][1:] == ["scan", "--quiet", "--scheduled"]


def test_systemd_registration_is_private_idempotent_and_cleanly_removed(
    tmp_path, monkeypatch
):
    runner, executable = _systemd_environment(tmp_path, monkeypatch)

    first = scheduler.enable()
    service_path, timer_path = scheduler.systemd_paths()
    before = {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in (service_path, timer_path, paths.schedule_path())
    }
    second = scheduler.enable()

    assert first == second
    assert first.backend == "systemd" and first.executable == str(executable)
    assert first.xdg_data_home == str(Path(os.environ["XDG_DATA_HOME"]).absolute())
    assert all(_mode(path) == 0o600 for path in (*scheduler.systemd_paths(), paths.schedule_path()))
    assert {
        path: (path.read_bytes(), path.stat().st_mtime_ns) for path in before
    } == before
    assert scheduler.inspect() == {
        "backend": "systemd",
        "registration_state": "active",
        "enabled": True,
        "last_attempt_at": None,
        "last_success_at": None,
        "last_result": "never",
        "last_exit_code": None,
    }
    assert any("enable" in call and scheduler.SYSTEMD_TIMER in call for call in runner.calls)
    assert not any(scheduler.SYSTEMD_SERVICE in call and "start" in call for call in runner.calls)

    assert scheduler.disable() is True
    assert not service_path.exists() and not timer_path.exists()
    assert not paths.schedule_path().exists()
    assert paths.schedule_lock_path().is_file() and _mode(paths.schedule_lock_path()) == 0o600
    assert scheduler.disable() is False


def test_launchd_registration_uses_bootstrap_and_removes_only_owned_file(
    tmp_path, monkeypatch
):
    runner = FakeRunner()
    executable = _fake_executable(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(scheduler, "_run", runner)
    monkeypatch.setattr(scheduler, "_select_backend", lambda: "launchd")
    monkeypatch.setattr(scheduler, "_launchd_binary", lambda: "/bin/launchctl")
    monkeypatch.setattr(scheduler, "_cli_executable", lambda: executable)

    assert scheduler.enable().backend == "launchd"
    assert scheduler.launchd_path().read_bytes() == scheduler.render_launchd(
        executable,
        xdg_data_home=Path(os.environ["XDG_DATA_HOME"]).absolute(),
    )
    assert any("bootstrap" in call for call in runner.calls)
    assert not any("kickstart" in call for call in runner.calls)
    assert scheduler.disable() is True
    assert not scheduler.launchd_path().exists()


def test_capture_enable_and_disable_wrap_configured_repo_and_schedule(
    tmp_path, monkeypatch, capsys
):
    _systemd_environment(tmp_path, monkeypatch)
    repo = _repo(tmp_path)
    store_scan_config(ScanConfig(repos=(repo,)))
    enable = ["capture", "enable", "--repo", str(repo), "--json"]

    assert cli.main(enable) == 0
    first = json.loads(capsys.readouterr().out)
    assert first == {
        "archive_enabled": False,
        "command": "capture enable",
        "repos_enrolled": 1,
        "schedule_backend": "systemd",
        "schedule_state": "active",
        "status": "ok",
    }
    assert (repo / ".git" / "hooks" / "post-commit").is_file()
    assert (repo / ".mybench" / "commit-binding-enabled").is_file()
    assert len(list(paths.enrollments_dir().glob("*.json"))) == 1

    assert cli.main(enable) == 0
    capsys.readouterr()
    assert len(list(paths.enrollments_dir().glob("*.json"))) == 1

    disable = ["capture", "disable", "--repo", str(repo), "--json"]
    assert cli.main(disable) == 0
    removed = json.loads(capsys.readouterr().out)
    assert removed == {
        "command": "capture disable",
        "repos_disabled": 1,
        "schedule_removed": True,
        "status": "ok",
    }
    assert not (repo / ".git" / "hooks" / "post-commit").exists()
    assert not (repo / ".mybench" / "commit-binding-enabled").exists()
    assert list(paths.enrollments_dir().glob("*.json")) == []
    assert not paths.schedule_path().exists()

    assert cli.main(disable) == 0
    assert json.loads(capsys.readouterr().out)["schedule_removed"] is False


def test_capture_enable_persists_explicit_archive_consent_in_generated_jobs(
    tmp_path, monkeypatch, capsys
):
    _systemd_environment(tmp_path, monkeypatch)
    repo = _repo(tmp_path)
    store_scan_config(ScanConfig(repos=(repo,)))
    command = ["capture", "enable", "--archive", "--repo", str(repo), "--json"]

    assert cli.main(command) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["archive_enabled"] is True
    state = scheduler.load()
    assert state is not None and state.archive_enabled is True
    assert state.as_dict()["schema_version"] == "2"
    assert scheduler.inspect()["registration_state"] == "active"
    service, timer = scheduler.systemd_paths()
    assert b"scan --quiet --scheduled --archive" in service.read_bytes()
    assert b"--archive" not in timer.read_bytes()
    before = {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in (service, timer, paths.schedule_path())
    }

    assert cli.main(command) == 0
    capsys.readouterr()
    assert {
        path: (path.read_bytes(), path.stat().st_mtime_ns) for path in before
    } == before

    launchd = plistlib.loads(
        scheduler.render_launchd(
            Path("/opt/mybench/bin/mybench"),
            archive_enabled=True,
        )
    )
    assert launchd["ProgramArguments"] == [
        "/opt/mybench/bin/mybench",
        "scan",
        "--quiet",
        "--scheduled",
        "--archive",
    ]


def test_scheduled_mode_requires_consented_config_but_manual_fallback_does_not(
    tmp_path, monkeypatch, capsys
):
    _systemd_environment(tmp_path, monkeypatch)
    repo = _repo(tmp_path)

    assert cli.main(["capture", "enable", "--repo", str(repo), "--json"]) == 1
    failure = json.loads(capsys.readouterr().err)
    assert failure["error"] == "scan_config_required"
    assert not (repo / ".git" / "hooks" / "post-commit").exists()
    assert not paths.schedule_path().exists()

    assert (
        cli.main(
            ["capture", "enable", "--repo", str(repo), "--no-schedule", "--json"]
        )
        == 0
    )
    manual = json.loads(capsys.readouterr().out)
    assert manual["schedule_backend"] == manual["schedule_state"] == "manual"
    assert scheduler.inspect()["registration_state"] == "manual"


def test_manual_fallback_refuses_archive_consent_without_writing(
    tmp_path, monkeypatch, capsys
):
    _systemd_environment(tmp_path, monkeypatch)
    repo = _repo(tmp_path)
    command = [
        "capture",
        "enable",
        "--no-schedule",
        "--archive",
        "--repo",
        str(repo),
        "--json",
    ]

    assert cli.main(command) == 1
    assert json.loads(capsys.readouterr().err)["error"] == "archive_requires_schedule"
    assert not (repo / ".git" / "hooks" / "post-commit").exists()
    assert not paths.schedule_path().exists()
    with pytest.raises(scheduler.SchedulerError, match="requires a scheduler"):
        scheduler.enable(schedule=False, archive_enabled=True)


def test_capture_enable_preflights_every_repo_before_any_write(
    tmp_path, monkeypatch, capsys
):
    _systemd_environment(tmp_path, monkeypatch)
    first = _repo(tmp_path)
    second_root = tmp_path / "second"
    second_root.mkdir()
    second = _repo(second_root)
    foreign = second / ".git" / "hooks" / "post-commit"
    foreign.write_text("#!/bin/sh\n# foreign\n")
    store_scan_config(ScanConfig(repos=(first, second)))

    assert (
        cli.main(
            [
                "capture",
                "enable",
                "--repo",
                str(first),
                "--repo",
                str(second),
                "--json",
            ]
        )
        == 1
    )
    capsys.readouterr()
    assert not (first / ".git" / "hooks" / "post-commit").exists()
    assert foreign.read_text() == "#!/bin/sh\n# foreign\n"
    assert not paths.schedule_path().exists()
    assert not any(path.exists() for path in scheduler.systemd_paths())


def test_capture_enable_preflights_every_enrollment_before_any_write(
    tmp_path, monkeypatch, capsys
):
    _systemd_environment(tmp_path, monkeypatch)
    first = _repo(tmp_path)
    second_root = tmp_path / "second-enrollment"
    second_root.mkdir()
    second = _repo(second_root)
    _bootstrap_keys()
    enrollment = paths.enrollment_path(binding.repo_identity_for_worktree(second))
    enrollment.write_text("{}\n")
    enrollment.chmod(0o644)
    store_scan_config(ScanConfig(repos=(first, second)))

    command = [
        "capture",
        "enable",
        "--repo",
        str(first),
        "--repo",
        str(second),
        "--json",
    ]
    assert cli.main(command) == 1
    capsys.readouterr()
    assert not (first / ".git" / "hooks" / "post-commit").exists()
    assert not (first / ".mybench" / "commit-binding-enabled").exists()
    assert enrollment.stat().st_mode & 0o777 == 0o644
    assert not paths.schedule_path().exists()


def test_capture_disable_preflights_every_repo_before_any_unlink(
    tmp_path, monkeypatch, capsys
):
    _systemd_environment(tmp_path, monkeypatch)
    first = _repo(tmp_path)
    second_root = tmp_path / "second"
    second_root.mkdir()
    second = _repo(second_root)
    store_scan_config(ScanConfig(repos=(first, second)))
    enable = [
        "capture",
        "enable",
        "--repo",
        str(first),
        "--repo",
        str(second),
        "--json",
    ]
    assert cli.main(enable) == 0
    capsys.readouterr()

    second_hook = second / ".git" / "hooks" / "post-commit"
    second_hook.write_text("#!/bin/sh\n# foreign replacement\n")
    first_hook = first / ".git" / "hooks" / "post-commit"
    first_marker = first / ".mybench" / "commit-binding-enabled"
    disable = [
        "capture",
        "disable",
        "--repo",
        str(first),
        "--repo",
        str(second),
        "--json",
    ]
    assert cli.main(disable) == 1
    capsys.readouterr()

    assert first_hook.is_file() and first_marker.is_file()
    assert second_hook.read_text() == "#!/bin/sh\n# foreign replacement\n"
    assert paths.schedule_path().is_file()


def test_capture_disable_preflights_scheduler_before_unlinking_repo(
    tmp_path, monkeypatch, capsys
):
    _systemd_environment(tmp_path, monkeypatch)
    repo = _repo(tmp_path)
    store_scan_config(ScanConfig(repos=(repo,)))
    assert cli.main(["capture", "enable", "--repo", str(repo), "--json"]) == 0
    capsys.readouterr()
    service, _timer = scheduler.systemd_paths()
    service.write_text("foreign replacement\n")

    assert cli.main(["capture", "disable", "--repo", str(repo), "--json"]) == 1
    capsys.readouterr()
    assert (repo / ".git" / "hooks" / "post-commit").is_file()
    assert (repo / ".mybench" / "commit-binding-enabled").is_file()
    assert service.read_text() == "foreign replacement\n"


def test_empty_data_home_is_not_embedded_in_generated_job(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", "")
    service, _timer = scheduler.render_systemd(
        _fake_executable(tmp_path), xdg_data_home=paths.configured_data_home()
    )
    assert b"Environment=" not in service


def test_failed_scheduled_scan_is_recorded_and_next_run_can_succeed(
    tmp_path, monkeypatch, capsys
):
    _systemd_environment(tmp_path, monkeypatch)
    _bootstrap_keys()
    scheduler.enable()
    times = iter(
        (
            datetime(2026, 7, 16, 10, tzinfo=UTC),
            datetime(2026, 7, 16, 11, tzinfo=UTC),
        )
    )
    monkeypatch.setattr(scheduler, "_clock_now", lambda: next(times))
    monkeypatch.setattr(cli, "_scan", lambda _args: 1)

    assert cli.main(["scan", "--quiet", "--scheduled", "--json"]) == 1
    capsys.readouterr()
    failed = scheduler.load()
    assert failed is not None
    assert failed.last_result == "failed" and failed.last_exit_code == 1
    result = status.collect(now=datetime(2026, 7, 16, 10, 1, tzinfo=UTC))
    assert result["schedule"]["registration_state"] == "active"
    assert "scheduled_scan_failed" in result["issues"]

    monkeypatch.setattr(cli, "_scan", lambda _args: 0)
    assert cli.main(["scan", "--quiet", "--scheduled", "--json"]) == 0
    capsys.readouterr()
    succeeded = scheduler.load()
    assert succeeded is not None
    assert succeeded.last_result == "success" and succeeded.last_exit_code == 0
    assert succeeded.last_success_at == "2026-07-16T11:00:00Z"
    assert "scheduled_scan_failed" not in status.collect()["issues"]


def test_real_quiet_scheduled_scan_exits_and_records_success(tmp_path, monkeypatch, capsys):
    _systemd_environment(tmp_path, monkeypatch)
    watch = tmp_path / "watch"
    watch.mkdir()
    (watch / "session.jsonl").write_text('{"synthetic":"line"}\n')
    store_scan_config(ScanConfig(watches=(WatchSpec(watch, "codex"),)))
    scheduler.enable()

    assert cli.main(["scan", "--quiet", "--scheduled", "--json"]) == 0
    output = capsys.readouterr()
    assert output.out == "" and output.err == ""
    state = scheduler.load()
    assert state is not None and state.last_result == "success"
    assert state.last_exit_code == 0


def test_real_quiet_scheduled_archive_scan_retains_private_preimage(
    tmp_path, monkeypatch, capsys
):
    _systemd_environment(tmp_path, monkeypatch)
    watch = tmp_path / "watch"
    watch.mkdir()
    (watch / "session.jsonl").write_text('{"synthetic":"archive-line"}\n')
    store_scan_config(ScanConfig(watches=(WatchSpec(watch, "codex"),)))
    scheduler.enable(archive_enabled=True)

    assert cli.main(["scan", "--quiet", "--scheduled", "--archive", "--json"]) == 0
    output = capsys.readouterr()
    assert output.out == "" and output.err == ""
    assert len(list(paths.archive_dir().glob("*/*"))) == 1
    state = scheduler.load()
    assert state is not None and state.archive_enabled is True
    assert state.last_result == "success"


def test_status_reports_inactive_or_invalid_schedule_without_repair(
    tmp_path, monkeypatch
):
    _bootstrap_keys()
    _systemd_environment(tmp_path, monkeypatch, active=False)
    scheduler.enable()
    inactive = status.collect()
    assert inactive["schedule"]["registration_state"] == "inactive"
    assert "schedule_inactive" in inactive["issues"]

    service, _timer = scheduler.systemd_paths()
    service.write_bytes(service.read_bytes() + b"# synthetic drift\n")
    before = (service.read_bytes(), service.stat().st_mode, service.stat().st_mtime_ns)
    invalid = status.collect()
    assert invalid["health"] == "error"
    assert invalid["schedule"]["registration_state"] == "invalid"
    assert "schedule_invalid" in invalid["issues"]
    assert (service.read_bytes(), service.stat().st_mode, service.stat().st_mtime_ns) == before


def test_scheduler_files_are_canary_clean_and_companion_fires(tmp_path):
    _bootstrap_keys()
    fx = generate_fixtures(tmp_path / "fixtures", claude_sessions=1, codex_sessions=1)
    service, timer = scheduler.render_systemd(Path("/opt/mybench/bin/mybench"))
    launchd = scheduler.render_launchd(Path("/opt/mybench/bin/mybench"))
    archive_service, archive_timer = scheduler.render_systemd(
        Path("/opt/mybench/bin/mybench"), archive_enabled=True
    )
    archive_launchd = scheduler.render_launchd(
        Path("/opt/mybench/bin/mybench"), archive_enabled=True
    )
    artifacts = []
    for name, content in (
        ("service", service),
        ("timer", timer),
        ("plist", launchd),
        ("archive-service", archive_service),
        ("archive-timer", archive_timer),
        ("archive-plist", archive_launchd),
    ):
        path = tmp_path / name
        path.write_bytes(content)
        artifacts.append(path)
    keys = [
        path.read_bytes()
        for path in (
            paths.device_key_path(),
            paths.identity_key_path(),
            paths.commit_signing_key_path(),
            paths.session_scope_key_path(),
        )
    ]
    canaries = fx.all_canaries() + keys + [bytes.fromhex("a5" * 32)]
    assert assert_no_canaries(artifacts, canaries) == 6

    planted = tmp_path / "planted.service"
    planted.write_bytes(service + fx.content_canaries[0].encode())
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([planted], canaries)


@pytest.mark.parametrize("attack", ("loose", "symlink", "hardlink"))
def test_schedule_state_loader_refuses_insecure_storage(tmp_path, attack):
    scheduler.enable(schedule=False)
    target = paths.schedule_path()
    if attack == "loose":
        target.chmod(0o644)
    elif attack == "symlink":
        original = target.with_suffix(".original")
        target.rename(original)
        target.symlink_to(original)
    else:
        target.with_suffix(".hardlink").hardlink_to(target)
    with pytest.raises((OSError, scheduler.SchedulerError)):
        scheduler.load()


def test_v1_schedule_state_loads_archive_off_and_upgrades_on_next_write():
    scheduler.enable(schedule=False)
    target = paths.schedule_path()
    legacy = json.loads(target.read_text())
    legacy["schema_version"] = "1"
    del legacy["archive_enabled"]
    target.write_text(json.dumps(legacy, sort_keys=True, separators=(",", ":")) + "\n")

    before = target.read_bytes()
    loaded = scheduler.load()
    assert loaded is not None and loaded.archive_enabled is False
    assert scheduler.inspect()["registration_state"] == "manual"
    assert target.read_bytes() == before
    scheduler.enable(schedule=False)
    upgraded = json.loads(target.read_text())
    assert upgraded["schema_version"] == "2"
    assert upgraded["archive_enabled"] is False


def test_foreign_scheduler_file_is_never_overwritten(tmp_path, monkeypatch):
    _systemd_environment(tmp_path, monkeypatch)
    service, _timer = scheduler.systemd_paths()
    service.parent.mkdir(parents=True)
    service.write_text("foreign unit\n")
    before = service.read_bytes()

    with pytest.raises(scheduler.SchedulerError):
        scheduler.enable()
    assert service.read_bytes() == before
