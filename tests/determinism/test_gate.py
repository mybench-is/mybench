"""MYB-10.3 gate integration and companion firing tests."""

from __future__ import annotations

import hashlib
import re
import subprocess
from importlib import metadata
from pathlib import Path

import pytest
from packaging.requirements import Requirement

from tests.determinism import gate
from tests.determinism.gate import (
    GateError,
    PipelineRoot,
    _run_once,
    assert_byte_identical,
    audit_module_closure,
    audit_source,
    discover_pipeline_modules,
    load_lock_pins,
    run_gate,
    validate_manifest_and_audit,
    verify_installed_dependency_versions,
)
from tests.determinism.stages import (
    RUNNERS,
    STAGES,
    EntryPoint,
    Invocation,
    ResultEncoding,
    Stage,
    execute_stage,
    validate_registration,
)
from tests.fixtures import assert_no_canaries
from tests.normalizer.synthetic import synthetic_normalizer_input

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_all_landed_stages_are_byte_identical_across_perturbed_processes():
    results = run_gate()
    assert [result.name for result in results] == [stage.name for stage in STAGES]
    assert all(result.size > 0 and len(result.sha256) == 64 for result in results)


def test_normalizer_subprocess_artifact_and_local_surfaces_have_no_canaries(tmp_path):
    stage = next(stage for stage in STAGES if stage.name == "claude-normalized-corpus")
    artifact = _run_once(
        stage,
        {
            "PYTHONHASHSEED": "303",
            "TZ": "UTC",
            "LC_ALL": "C",
            "LANG": "C",
            "MYBENCH_DETERMINISM_SENTINEL": "privacy-run",
        },
        tmp_path,
        1,
    )
    artifact_path = tmp_path / stage.name / "run-1" / "artifact.bin"
    assert artifact_path.read_bytes() == artifact
    assert assert_no_canaries([artifact_path], list(synthetic_normalizer_input().canaries)) == 1
    data_root = tmp_path / stage.name / "run-1" / "data" / "mybench"
    assert not any((data_root / name).exists() for name in ("normalized", "ledger", "anchors"))


def test_codex_subprocess_artifact_and_local_surfaces_have_no_canaries(tmp_path):
    from tests.normalizer.synthetic import synthetic_codex_normalizer_input

    stage = next(stage for stage in STAGES if stage.name == "codex-normalized-corpus")
    artifact = _run_once(
        stage,
        {
            "PYTHONHASHSEED": "404",
            "TZ": "America/Los_Angeles",
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "MYBENCH_DETERMINISM_SENTINEL": "codex-privacy-run",
        },
        tmp_path,
        1,
    )
    artifact_path = tmp_path / stage.name / "run-1" / "artifact.bin"
    assert artifact_path.read_bytes() == artifact
    assert (
        assert_no_canaries([artifact_path], list(synthetic_codex_normalizer_input().canaries)) == 1
    )
    data_root = tmp_path / stage.name / "run-1" / "data" / "mybench"
    assert not any((data_root / name).exists() for name in ("normalized", "ledger", "anchors"))


def test_git_subprocess_artifact_and_local_surfaces_have_no_canaries(tmp_path):
    from tests.normalizer.repo_synthetic import synthetic_repo_evidence_input

    stage = next(stage for stage in STAGES if stage.name == "git-normalized-corpus")
    artifact = _run_once(
        stage,
        {
            "PYTHONHASHSEED": "505",
            "TZ": "Pacific/Auckland",
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "MYBENCH_DETERMINISM_SENTINEL": "git-privacy-run",
        },
        tmp_path,
        1,
    )
    artifact_path = tmp_path / stage.name / "run-1" / "artifact.bin"
    assert artifact_path.read_bytes() == artifact
    assert assert_no_canaries([artifact_path], list(synthetic_repo_evidence_input().canaries)) == 1
    data_root = tmp_path / stage.name / "run-1" / "data" / "mybench"
    assert not any((data_root / name).exists() for name in ("normalized", "ledger", "anchors"))


def test_reference_join_subprocess_artifact_has_no_canaries(tmp_path):
    from tests.normalizer.reference_synthetic import synthetic_reference_target_input

    stage = next(stage for stage in STAGES if stage.name == "reference-target-join-corpus")
    artifact = _run_once(
        stage,
        {
            "PYTHONHASHSEED": "606",
            "TZ": "Asia/Kathmandu",
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "MYBENCH_DETERMINISM_SENTINEL": "reference-join-privacy-run",
        },
        tmp_path,
        1,
    )
    artifact_path = tmp_path / stage.name / "run-1" / "artifact.bin"
    assert artifact_path.read_bytes() == artifact
    assert (
        assert_no_canaries([artifact_path], list(synthetic_reference_target_input().canaries)) == 1
    )


def test_manifest_runner_registration_and_current_discovery_are_exact():
    validate_registration()
    assert {stage.name for stage in STAGES} == set(RUNNERS)
    assert all(callable(runner) for runner in RUNNERS.values())
    assert discover_pipeline_modules() == {
        "mybench.normalizer.codex",
        "mybench.normalizer.claude",
        "mybench.normalizer.repo",
        "mybench.normalizer.reference_join",
        "mybench.normalizer.session_timing",
        "mybench.normalizer.workflow_phase",
        "mybench.report.page",
        "mybench.scorer.agent_hours",
        "mybench.scorer.evidence_coverage",
        "mybench.scorer.score",
    }
    validate_manifest_and_audit()


@pytest.mark.parametrize(
    ("runners", "match"),
    [
        ({}, "missing=\\['fixture'\\]"),
        (
            {
                "fixture": lambda: Invocation((), {}),
                "extra": lambda: Invocation((), {}),
            },
            "extra=\\['extra'\\]",
        ),
        ({"fixture": b"not callable"}, "not callable"),
    ],
)
def test_manifest_runner_drift_fires(runners, match):
    stages = (
        Stage(
            "fixture",
            EntryPoint("mybench.scorer.score", "score"),
            ResultEncoding.BYTES,
            True,
            ("mybench.scorer.score",),
        ),
    )
    with pytest.raises(ValueError, match=match):
        validate_registration(stages, runners)


def test_call_then_constant_runner_cannot_define_artifact():
    invocation = RUNNERS["activity-report-json"]()
    scorer = STAGES[0].entrypoint.resolve()

    def call_then_return_unrelated_constant():
        scorer(*invocation.args, **dict(invocation.kwargs))
        return b"unrelated constant despite exercising the scorer"

    with pytest.raises(TypeError, match="returned bytes, not Invocation"):
        execute_stage(STAGES[0], call_then_return_unrelated_constant)


def test_bytes_artifact_is_exact_production_result():
    artifact = b"exact production bytes\x00"

    def production_entry(argument, *, option):
        assert argument == "synthetic" and option is True
        return artifact

    assert (
        execute_stage(
            STAGES[0],
            lambda: Invocation(("synthetic",), {"option": True}),
            production_entry,
        )
        is artifact
    )


def test_entry_point_must_be_owned_by_its_registered_module():
    stages = (
        Stage(
            "borrowed",
            EntryPoint("mybench.scorer.score", "json.dumps"),
            ResultEncoding.BYTES,
            True,
            ("mybench.scorer.score",),
        ),
    )
    with pytest.raises(ValueError, match="not owned by mybench.scorer.score"):
        validate_registration(stages, {"borrowed": lambda: Invocation((), {})})


def test_unregistered_pipeline_module_fails_closed_but_wrappers_do_not(tmp_path):
    source_root = tmp_path / "src"
    scorer = source_root / "mybench" / "scorer"
    scorer.mkdir(parents=True)
    for name in ("score.py", "unregistered.py", "__main__.py", "cli.py"):
        (scorer / name).write_text("def compute():\n    return b'synthetic'\n")

    stages = (
        Stage(
            "score",
            EntryPoint("mybench.scorer.score", "score"),
            ResultEncoding.BYTES,
            True,
            ("mybench.scorer.score",),
        ),
    )
    runners = {"score": lambda: Invocation((), {})}
    with pytest.raises(GateError, match="missing=\\['mybench.scorer.unregistered'\\]"):
        validate_manifest_and_audit(
            stages,
            runners,
            source_root=source_root,
            roots=(PipelineRoot("mybench.scorer", required=True),),
            reviewed_non_stages=frozenset(),
        )

    assert discover_pipeline_modules(
        source_root=source_root,
        roots=(PipelineRoot("mybench.scorer", required=True),),
        reviewed_non_stages=frozenset({"mybench.scorer.unregistered"}),
    ) == {"mybench.scorer.score"}


def test_byte_compare_fires_on_divergence_without_logging_artifact_bytes():
    with pytest.raises(GateError, match="run 1=14 bytes.*run 2=16 bytes") as caught:
        assert_byte_identical("synthetic-divergence", b"private-first!", b"private-second!!")
    assert "private-first" not in str(caught.value)
    assert "private-second" not in str(caught.value)


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        ("import os as operating_system\nvalue = operating_system.environ['X']\n", "environment"),
        ("from time import monotonic as tick\nvalue = tick()\n", "clock"),
        ("import urllib.request as client\nvalue = client.urlopen('https://invalid')\n", "network"),
        ("import socket\nvalue = socket.socket()\n", "network"),
        ("import subprocess\nvalue = subprocess.run(['git'])\n", "subprocess"),
        ("import random\nvalue = random.random()\n", "ambient randomness"),
        ("from datetime import datetime as instant\nvalue = instant.now()\n", "wall clock"),
        ("from datetime import date\nvalue = date.today()\n", "wall clock"),
        ("from pathlib import Path\nvalue = Path.home()\n", "environment home"),
        (
            "from mybench.commitments import generate_nonce as fresh\nvalue = fresh()\n",
            "ambient randomness",
        ),
        (
            "from mybench.nonce_generation import generate_nonce as fresh\nvalue = fresh()\n",
            "ambient randomness",
        ),
    ],
)
def test_ambient_state_audit_fires_for_aliases(tmp_path, source, reason):
    candidate = tmp_path / "candidate.py"
    candidate.write_text(source)
    issues = audit_source(candidate)
    assert issues and any(reason in issue.message for issue in issues)


def test_ambient_state_audit_allows_explicit_time_input_and_date_math(tmp_path):
    candidate = tmp_path / "candidate.py"
    candidate.write_text(
        "from datetime import date, timedelta\n"
        "def derive_day(timestamp):\n"
        "    return date.fromisoformat(timestamp[:10]) + timedelta(days=1)\n"
    )
    assert audit_source(candidate) == []


def test_transitive_audit_follows_first_party_helper_and_catches_indirection(tmp_path):
    source_root = tmp_path / "src"
    package = source_root / "mybench"
    scorer = package / "scorer"
    scorer.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (scorer / "entry.py").write_text(
        "from mybench import hidden_helper\ndef compute():\n    return hidden_helper.read()\n"
    )
    (package / "hidden_helper.py").write_text(
        "import os\n"
        "from pathlib import Path\n"
        "ENV = os.environ\n"
        "def read():\n"
        "    __import__('os')\n"
        "    return Path('ambient-input').read_text()\n"
    )

    closure = audit_module_closure(("mybench.scorer.entry",), source_root=source_root)
    assert "mybench.hidden_helper" in closure.modules
    messages = [issue.message for issue in closure.issues]
    assert any("environment import 'os'" in message for message in messages)
    assert any("dynamic import 'os'" in message for message in messages)
    assert any("filesystem call" in message and "read_text" in message for message in messages)


def test_packaged_data_reads_are_exact_reviewed_exceptions(tmp_path):
    candidate = tmp_path / "candidate.py"
    candidate.write_text(
        "from importlib import resources\n"
        "DATA = resources.files('mybench.schemas').joinpath('x.json').read_text()\n"
    )
    assert audit_source(candidate, module_name="mybench.schemas") == []
    issues = audit_source(candidate, module_name="mybench.unreviewed")
    assert any("filesystem call" in issue.message for issue in issues)


def test_reviewed_packaged_read_count_drift_fails_closed(tmp_path):
    source_root = tmp_path / "src"
    schemas = source_root / "mybench" / "schemas"
    schemas.mkdir(parents=True)
    (schemas / "__init__.py").write_text(
        "from importlib import resources\n"
        "ONE = resources.files('mybench.schemas').joinpath('one.json').read_text()\n"
        "TWO = resources.files('mybench.schemas').joinpath('two.json').read_text()\n"
    )
    closure = audit_module_closure(("mybench.schemas",), source_root=source_root)
    assert any("reviewed call count drift" in issue.message for issue in closure.issues)


def test_dynamic_import_is_rejected_without_a_static_import(tmp_path):
    candidate = tmp_path / "candidate.py"
    candidate.write_text("module = __import__('os')\n")
    issues = audit_source(candidate)
    assert any("dynamic import 'os'" in issue.message for issue in issues)


def test_pipeline_caller_cannot_inherit_claim_device_helper_exception(tmp_path):
    candidate = tmp_path / "candidate.py"
    candidate.write_text(
        "from mybench.claims import sign_with_device_key\nclaim = sign_with_device_key({})\n"
    )
    issues = audit_source(candidate, module_name="mybench.scorer.candidate")
    assert any("device/environment helper" in issue.message for issue in issues)


def test_current_transitive_closure_audits_pure_commitment_tree():
    closure = validate_manifest_and_audit()
    assert {
        "mybench.claims.envelope",
        "mybench.commitment_tree",
        "mybench.registry",
        "mybench.schemas",
    } <= closure.modules
    assert {
        "mybench.commitments",
        "mybench.nonce_generation",
        "mybench.paths",
    }.isdisjoint(closure.modules)


def test_failed_stage_reports_only_stderr_size_and_digest(tmp_path, monkeypatch):
    secret = b"MYBENCH-CANARY-private-stage-error"
    completed = subprocess.CompletedProcess(
        args=["synthetic"], returncode=17, stdout=b"also-private", stderr=secret
    )
    monkeypatch.setattr(gate.subprocess, "run", lambda *args, **kwargs: completed)

    with pytest.raises(GateError) as caught:
        _run_once(STAGES[0], {"PYTHONHASHSEED": "1"}, tmp_path, 1)
    message = str(caught.value)
    assert secret.decode() not in message and "also-private" not in message
    assert "exit 17" in message
    assert f"stderr={len(secret)} bytes" in message
    assert hashlib.sha256(secret).hexdigest() in message


def _direct_requirements(path: Path) -> set[str]:
    found = set()
    for raw_line in path.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-r "):
            found |= _direct_requirements(path.with_name(line.removeprefix("-r ")))
            continue
        found.add(re.split(r"[<>=!~\[]", line, maxsplit=1)[0].lower())
    return found


def test_ci_lockfile_is_exact_and_covers_direct_dependencies():
    lock = REPO_ROOT / "requirements-ci.lock"
    pins = load_lock_pins(lock)

    direct = {
        name.replace("_", "-") for name in _direct_requirements(REPO_ROOT / "requirements-ci.txt")
    }
    assert direct <= pins.keys(), (
        f"direct dependencies absent from lock: {sorted(direct - pins.keys())}"
    )

    missing_transitive = set()
    for package in pins:
        for requirement_text in metadata.requires(package) or ():
            requirement = Requirement(requirement_text)
            if requirement.marker and not requirement.marker.evaluate({"extra": ""}):
                continue
            dependency = requirement.name.lower().replace("_", "-")
            if dependency not in pins:
                missing_transitive.add(dependency)
    assert not missing_transitive, (
        f"active transitive dependencies absent from lock: {sorted(missing_transitive)}"
    )


def test_installed_runtime_and_test_dependencies_match_lock_exactly(tmp_path):
    verify_installed_dependency_versions()
    impossible = tmp_path / "requirements-ci.lock"
    impossible.write_text("pytest==0.0.0\n")
    with pytest.raises(GateError, match="pytest: expected 0.0.0, installed"):
        verify_installed_dependency_versions(impossible)
