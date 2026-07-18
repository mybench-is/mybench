"""MYB-13.2 deterministic, structural-only workflow phase classifier."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator, Mapping
from copy import deepcopy

import pytest
from jsonschema import ValidationError

from mybench import paths
from mybench.normalizer import (
    WORKFLOW_PHASE_CLASSIFIER_VERSION,
    classify_workflow_phases,
    workflow_phase_artifact,
)
from mybench.normalizer.workflow_phase_store import store_workflow_phase_artifact
from mybench.schemas import load_validator
from tests.conftest import REPO_ROOT
from tests.fixtures import CanaryLeakError, assert_no_canaries

CONTENT_CANARY = "MYBENCH-PHASE-CONTENT-CANARY-74de"
FILENAME_CANARY = "synthetic-private-phase-file-1d0a.py"
SESSION_CANARY = "synthetic-private-phase-session-882c"


def _event(event_kind: str, **fields: object) -> dict[str, object]:
    return {
        "event_kind": event_kind,
        "session_id": SESSION_CANARY,
        "message": CONTENT_CANARY,
        "filename": FILENAME_CANARY,
        **fields,
    }


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_v1_rule_table_is_versioned_and_unknown_is_fail_closed():
    events = [
        _event("turn", authorship="human-turn"),
        _event("reference", reference_kind="plan"),
        _event("reference", reference_kind="instruction"),
        _event("tool-call", tool_family="write"),
        _event("tool-call", tool_family="edit"),
        _event("test", test_scope="unit", test_status="failed"),
        _event("tool-result", result_status="error"),
        _event("forge-action", forge_action_kind="pr-comment"),
        _event("forge-action", forge_action_kind="pr-review-request"),
        _event("forge-action", forge_action_kind="push"),
        _event("forge-action", forge_action_kind="pr-merge-attempt"),
        _event("turn", authorship="agent-turn"),
        _event("future-structural-event"),
    ]

    phases = classify_workflow_phases(events)

    assert [item.phase for item in phases] == [
        "TASK",
        "PLAN",
        "PLAN",
        "BUILD",
        "BUILD",
        "TEST",
        "DEBUG",
        "REVIEW",
        "REVIEW",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
    ]
    assert [item.confidence for item in phases] == [
        "MEDIUM",
        "HIGH",
        "MEDIUM",
        "HIGH",
        "HIGH",
        "HIGH",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
    ]
    assert all(item.classifier_version == WORKFLOW_PHASE_CLASSIFIER_VERSION for item in phases)
    assert [item.ordinal for item in phases] == list(range(len(events)))
    assert "COMMIT" not in {item.phase for item in phases}


class _StructuralFieldGuard(Mapping[str, object]):
    """Fail the test if production reads any non-pinned field."""

    _allowed = {
        "event_kind",
        "authorship",
        "reference_kind",
        "tool_family",
        "result_status",
        "forge_action_kind",
    }

    def __init__(self, value: dict[str, object]):
        self.value = value

    def __getitem__(self, key: str) -> object:
        if key not in self._allowed:
            raise AssertionError(f"classifier read non-structural field {key!r}")
        return self.value[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.value)

    def __len__(self) -> int:
        return len(self.value)


def test_classifier_reads_only_pinned_fields_and_never_fuzzy_content():
    guarded = _StructuralFieldGuard(
        {
            "event_kind": "turn",
            "authorship": "agent-turn",
            "message": "please test debug review commit " + CONTENT_CANARY,
            "filename": FILENAME_CANARY,
            "session_id": SESSION_CANARY,
        }
    )
    assert classify_workflow_phases((guarded,))[0].phase == "UNKNOWN"

    first = [_event("tool-call", tool_family="edit")]
    second = deepcopy(first)
    second[0].update(
        {
            "message": "different private prose",
            "filename": "different-private-name.py",
            "session_id": "different-private-session",
            "pointer": {"private": "ignored"},
        }
    )
    assert workflow_phase_artifact(first) == workflow_phase_artifact(second)


def test_artifact_is_closed_identifier_free_and_schema_valid():
    artifact = workflow_phase_artifact(
        [
            _event("reference", reference_kind="plan"),
            _event("tool-call", tool_family="edit"),
        ]
    )
    value = json.loads(artifact)
    load_validator("workflow_phase.schema.json").validate(value)

    assert value["classifier_version"] == "1.0.0"
    assert all(item["classifier_version"] == "1.0.0" for item in value["phases"])
    assert CONTENT_CANARY.encode() not in artifact
    assert FILENAME_CANARY.encode() not in artifact
    assert SESSION_CANARY.encode() not in artifact
    assert b"session_id" not in artifact and b"filename" not in artifact

    invalid = deepcopy(value)
    invalid["phases"][0]["session_id"] = SESSION_CANARY
    with pytest.raises(ValidationError):
        load_validator("workflow_phase.schema.json").validate(invalid)


def test_pure_artifact_is_byte_identical_and_does_not_mutate_input():
    events = [
        _event("turn", authorship="human-turn"),
        _event("test", test_scope="integration", test_status="passed"),
    ]
    before = deepcopy(events)
    first = workflow_phase_artifact(events)
    second = workflow_phase_artifact(events)

    assert first == second
    assert events == before


def test_private_store_has_exact_modes_is_idempotent_and_emits_no_logs(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "private-data-home"))
    events = [
        _event("turn", authorship="human-turn"),
        _event("tool-call", tool_family="edit"),
    ]

    stored = store_workflow_phase_artifact(events)
    assert store_workflow_phase_artifact(events) == stored
    assert stored.read_bytes() == workflow_phase_artifact(events)
    assert stored.resolve().is_relative_to(paths.data_dir().resolve())
    assert stored.parent == paths.normalized_dir() / "workflow-phases"
    assert REPO_ROOT not in stored.resolve().parents
    assert _mode(paths.data_dir()) == 0o700
    assert _mode(paths.normalized_dir()) == 0o700
    assert _mode(stored.parent) == 0o700
    assert _mode(stored) == 0o600
    assert os.path.basename(stored).endswith(".json")

    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
    canaries = [value.encode() for value in (CONTENT_CANARY, FILENAME_CANARY, SESSION_CANARY)]
    assert assert_no_canaries([stored], canaries) == 1


def test_phase_leak_scan_companion_fires_on_planted_canary(tmp_path):
    planted = tmp_path / "planted-phase-artifact.json"
    planted.write_bytes(
        workflow_phase_artifact([_event("tool-call", tool_family="edit")])
        + CONTENT_CANARY.encode()
    )

    with pytest.raises(CanaryLeakError):
        assert_no_canaries(
            [planted],
            [value.encode() for value in (CONTENT_CANARY, FILENAME_CANARY, SESSION_CANARY)],
        )
