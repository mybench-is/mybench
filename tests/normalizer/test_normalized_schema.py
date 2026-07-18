"""Closed discriminated unions for normalized events and pointers."""

from __future__ import annotations

from copy import deepcopy

import pytest
from jsonschema import Draft202012Validator, ValidationError

from mybench.schemas import load_validator


COMMON = {
    "schema_version": "5",
    "kind": "normalized-event",
    "source": "codex",
    "session_id": "opaque-synthetic-session",
    "record_index": 0,
    "subevent_index": 0,
    "authorship": "agent-turn",
    "parent_link": {"status": "root"},
}
SHAPE = {"line_band": "single", "size_band": "short"}
TEXT_POINTER = {
    "field": "message-text",
    "start": 0,
    "end": 1,
    "unit": "unicode-scalar",
    "record_commitment": "11" * 32,
}
TOOL_INPUT_POINTER = {
    "field": "tool-input",
    "block_index": 0,
    "record_commitment": "22" * 32,
}


def _event_validator() -> Draft202012Validator:
    schema = load_validator("normalized_corpus.schema.json").schema
    return Draft202012Validator(
        {
            "$schema": schema["$schema"],
            "$defs": schema["$defs"],
            "$ref": "#/$defs/event",
        }
    )


def _event(event_kind: str, **fields) -> dict:
    event = {**COMMON, "event_kind": event_kind}
    event.update(fields)
    return event


@pytest.mark.parametrize(
    "event",
    [
        _event("turn", content_shape=SHAPE, pointer=TEXT_POINTER),
        _event(
            "turn",
            authorship="human-turn",
            content_shape=SHAPE,
        ),
        _event(
            "pasted-span",
            authorship="pasted-content-span",
            content_shape=SHAPE,
        ),
        _event("tool-call", tool_family="execute", pointer=TOOL_INPUT_POINTER),
        _event(
            "tool-result",
            authorship="pasted-content-span",
            content_shape=SHAPE,
            tool_relation={"status": "dangling"},
            result_status="unknown",
        ),
        _event("lifecycle", lifecycle_marker="context-boundary"),
        _event("model", model="gpt-5", provider="openai", reasoning_effort="high"),
        _event("token-usage", token_usage={"input_tokens": 0}),
        _event("reference", reference_kind="plan", pointer=TEXT_POINTER),
        _event(
            "test",
            test_scope="integration",
            test_status="passed",
            pointer=TOOL_INPUT_POINTER,
        ),
        _event(
            "forge-action",
            forge_action_kind="pr-open",
            classifier_version="1.0.0",
            outcome="unknown",
            repo_id="ab" * 8,
            pointer=TOOL_INPUT_POINTER,
            tool_relation={"status": "linked", "record_index": 0, "subevent_index": 0},
        ),
    ],
    ids=[
        "agent-turn",
        "human-turn",
        "pasted-span",
        "tool-call",
        "tool-result",
        "lifecycle",
        "model",
        "token-usage",
        "reference",
        "test",
        "forge-action",
    ],
)
def test_each_closed_event_variant_accepts_its_own_fields(event):
    _event_validator().validate(event)


@pytest.mark.parametrize(
    "event",
    [
        _event("turn", authorship="human-turn", content_shape=SHAPE, pointer=TEXT_POINTER),
        _event("turn", authorship="pasted-content-span", content_shape=SHAPE),
        _event(
            "pasted-span",
            authorship="pasted-content-span",
            content_shape=SHAPE,
            pointer=TEXT_POINTER,
        ),
        _event("tool-call", tool_family="read", pointer=TEXT_POINTER),
        _event("tool-call", tool_family="read", content_shape=SHAPE),
        _event("model", model="gpt-5", token_usage={"input_tokens": 1}),
        _event("test", test_scope="unit", test_status="passed", pointer=TEXT_POINTER),
        _event("turn", content_shape=SHAPE, context_generation_id=1),
        _event(
            "lifecycle",
            lifecycle_marker="session-start",
            context_generation_id=1,
        ),
        _event(
            "forge-action",
            forge_action_kind="pr-open",
            classifier_version="1.0.0",
            outcome="unknown",
            pointer=TEXT_POINTER,
            tool_relation={"status": "linked", "record_index": 0, "subevent_index": 0},
        ),
        _event(
            "forge-action",
            forge_action_kind="pr-open",
            classifier_version="1.0.0",
            outcome="unknown",
            pointer=TOOL_INPUT_POINTER,
            tool_relation={"status": "linked", "record_index": 0, "subevent_index": 0},
            pull_request_url="synthetic-forbidden",
        ),
    ],
    ids=[
        "human-pointer",
        "turn-pasted-authorship",
        "pasted-pointer",
        "tool-call-text-pointer",
        "cross-kind-shape",
        "cross-kind-usage",
        "cross-kind-pointer",
        "generation-without-boundary",
        "generation-on-non-boundary-lifecycle",
        "forge-text-pointer",
        "forge-rung-two-field",
    ],
)
def test_event_union_rejects_wrong_authorship_pointer_and_cross_kind_fields(event):
    with pytest.raises(ValidationError):
        _event_validator().validate(event)


@pytest.mark.parametrize("extra", ["start", "end", "unit"])
def test_tool_input_pointer_has_no_text_coordinates(extra):
    event = _event("tool-call", tool_family="execute", pointer=deepcopy(TOOL_INPUT_POINTER))
    event["pointer"][extra] = 0 if extra != "unit" else "unicode-scalar"
    with pytest.raises(ValidationError):
        _event_validator().validate(event)
