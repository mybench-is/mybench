"""Codex rollout JSONL -> normalized structural evidence (MYB-10.18).

The adapter consumes explicit ``VerifiedSession`` values and shares the exact
MYB-10.4 corpus schema, authorship policy, episode stitcher, commitment
domains, and validator.  It never discovers rollout files or copies message,
tool, path, or result bytes into A8.

Codex rollout v1 is an envelope with a top-level ``type`` and ``payload``.
This adapter recognizes the durable session, turn-context, response-item,
event-message, and compaction shapes.  Unknown or newly introduced variants
degrade to coverage counts rather than guessed events.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence

from mybench.claims.canonical import canonical_bytes
from mybench.normalizer.claude import (
    AUTHORSHIP_POLICY_VERSION,
    EPISODE_STITCHER_VERSION,
    NORMALIZER_VERSION,
    SCHEMA_VERSION,
    VerifiedRecord,
    VerifiedSession,
    _COVERAGE_KEYS,
    _EFFORTS,
    _MODEL,
    _PROVIDERS,
    _base_event,
    _canonical_timestamp,
    _check_input_sessions,
    _content_pointer,
    _episode_map,
    _event_sort_key,
    _is_label,
    _is_test_invocation,
    _json_object,
    _looks_like_paste,
    _reference_kind,
    _shape,
    _tool_family,
    _tool_relation,
    corpus_commitment,
)

CODEX_ADAPTER_VERSION = "1.0.0"
_SOURCE = "codex"

_MESSAGE_TYPES = frozenset({"input_text", "output_text"})
_CALL_TYPES = frozenset(
    {
        "function_call",
        "custom_tool_call",
        "local_shell_call",
        "tool_search_call",
        "web_search_call",
    }
)
_OUTPUT_TYPES = frozenset(
    {
        "function_call_output",
        "custom_tool_call_output",
        "tool_search_output",
    }
)
_COMPACTION_TYPES = frozenset({"compaction", "context_compaction"})


def _parent_link(normalized_record_index: int) -> dict:
    if normalized_record_index == 0:
        return {"status": "root"}
    return {"status": "linked", "record_index": normalized_record_index - 1}


def _observed_at(value: Mapping, coverage: Counter) -> str | None:
    raw = value.get("timestamp")
    observed = _canonical_timestamp(raw)
    if raw is not None and observed is None:
        coverage["metadata_invalid"] += 1
    return observed


def _partials_to_events(
    partials: Sequence[dict],
    *,
    session: VerifiedSession,
    normalized_record_index: int,
    episode_id: str | None,
    observed_at: str | None,
) -> list[dict]:
    parent_link = _parent_link(normalized_record_index)
    return [
        {
            **_base_event(
                session=session,
                normalized_record_index=normalized_record_index,
                subevent_index=subevent_index,
                episode_id=episode_id,
                observed_at=observed_at,
                parent_link=parent_link,
            ),
            **partial,
        }
        for subevent_index, partial in enumerate(partials)
    ]


def _model_partial(
    *,
    model: object = None,
    provider: object = None,
    effort: object = None,
    coverage: Counter,
) -> dict | None:
    metadata = {}
    if model is not None:
        if isinstance(model, str) and _MODEL.fullmatch(model):
            metadata["model"] = model
        else:
            coverage["metadata_invalid"] += 1
    if provider is not None:
        if _is_label(provider, _PROVIDERS):
            metadata["provider"] = provider
        else:
            coverage["metadata_invalid"] += 1
    if effort is not None:
        if _is_label(effort, _EFFORTS):
            metadata["reasoning_effort"] = effort
        else:
            coverage["metadata_invalid"] += 1
    if not metadata:
        return None
    return {"event_kind": "model", "authorship": "agent-turn", **metadata}


def _message_partials(
    payload: Mapping,
    record: VerifiedRecord,
    coverage: Counter,
) -> list[dict] | None:
    role = payload.get("role")
    content = payload.get("content")
    if role not in {"user", "assistant"} or not isinstance(content, list):
        return None
    partials = []
    for block_index, block in enumerate(content):
        coverage["blocks_seen"] += 1
        if not isinstance(block, dict) or block.get("type") not in _MESSAGE_TYPES:
            coverage["blocks_unsupported"] += 1
            continue
        expected_type = "input_text" if role == "user" else "output_text"
        text = block.get("text")
        if block.get("type") != expected_type or not isinstance(text, str):
            coverage["blocks_unsupported"] += 1
            continue
        if role == "user" and _looks_like_paste(text):
            partials.append(
                {
                    "event_kind": "pasted-span",
                    "authorship": "pasted-content-span",
                    "content_shape": _shape(text),
                }
            )
            coverage["content_unknown"] += 1
            continue
        authorship = "human-turn" if role == "user" else "agent-turn"
        partial = {
            "event_kind": "turn",
            "authorship": authorship,
            "content_shape": _shape(text),
        }
        if role == "assistant":
            pointer = _content_pointer(
                record,
                text,
                field_name="content-block-text",
                block_index=block_index,
            )
            if pointer is not None:
                partial["pointer"] = pointer
                coverage["content_references"] += 1
            else:
                coverage["content_unknown"] += 1
        else:
            # Codex v1 does not distinguish typed user text from injected or
            # pasted text strongly enough to grant a content pointer.
            coverage["content_unknown"] += 1
        partials.append(partial)
    return partials


def _decode_arguments(value: object) -> dict | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    return _json_object(value.encode())


def _call_details(payload: Mapping) -> tuple[object, object, object] | None:
    item_type = payload.get("type")
    if item_type == "function_call":
        return payload.get("name"), payload.get("arguments"), payload.get("call_id")
    if item_type == "custom_tool_call":
        return payload.get("name"), payload.get("input"), payload.get("call_id")
    if item_type == "local_shell_call":
        return "shell", payload.get("action"), payload.get("call_id") or payload.get("id")
    if item_type == "tool_search_call":
        return "tool_search", payload.get("arguments"), payload.get("call_id")
    if item_type == "web_search_call":
        return "web_search", payload.get("action"), payload.get("id")
    return None


def _classification_input(name: object, raw_input: object) -> dict | None:
    decoded = _decode_arguments(raw_input)
    if decoded is None:
        return None
    if isinstance(name, str) and name.lower() == "exec_command" and "cmd" in decoded:
        return {**decoded, "command": decoded["cmd"]}
    action_type = decoded.get("type")
    command = decoded.get("command")
    if action_type == "exec" and isinstance(command, list) and all(
        isinstance(part, str) for part in command
    ):
        return {**decoded, "command": " ".join(command)}
    return decoded


def _tool_pointer(record: VerifiedRecord, payload: Mapping) -> dict | None:
    details = _call_details(payload)
    if details is None:
        return None
    _, raw_input, _ = details
    if raw_input is None:
        return None
    return {
        "field": "tool-input",
        "block_index": 0,
        "record_commitment": record.record_commitment,
    }


def _call_partials(
    payload: Mapping,
    record: VerifiedRecord,
    normalized_record_index: int,
    tool_counts: Counter,
    tool_positions: dict[str, tuple[int, int]],
    coverage: Counter,
) -> list[dict] | None:
    details = _call_details(payload)
    if details is None:
        return None
    coverage["blocks_seen"] += 1
    name, raw_input, call_id = details
    pointer = _tool_pointer(record, payload)
    partial = {
        "event_kind": "tool-call",
        "authorship": "agent-turn",
        "tool_family": _tool_family(name),
    }
    if pointer is not None:
        partial["pointer"] = pointer
        coverage["content_references"] += 1
    partials = [partial]
    classified = _classification_input(name, raw_input)
    reference_kind = _reference_kind(name, classified)
    if pointer is not None and reference_kind is not None:
        partials.append(
            {
                "event_kind": "reference",
                "authorship": "agent-turn",
                "reference_kind": reference_kind,
                "pointer": pointer,
            }
        )
        coverage["content_references"] += 1
    if pointer is not None and _is_test_invocation(name, classified):
        partials.append(
            {
                "event_kind": "test",
                "authorship": "agent-turn",
                "test_scope": "other",
                "test_status": "unknown",
                "pointer": pointer,
            }
        )
        coverage["content_references"] += 1
    if isinstance(call_id, str) and tool_counts[call_id] == 1:
        tool_positions[call_id] = (normalized_record_index, 0)
    return partials


def _output_text(output: object) -> object:
    if isinstance(output, str):
        return output
    if isinstance(output, dict) and isinstance(output.get("content"), str):
        return output["content"]
    return None


def _output_partials(
    payload: Mapping,
    tool_counts: Counter,
    tool_positions: Mapping[str, tuple[int, int]],
    coverage: Counter,
) -> list[dict] | None:
    item_type = payload.get("type")
    if item_type not in _OUTPUT_TYPES:
        return None
    coverage["blocks_seen"] += 1
    output = payload.get("output")
    call_id = payload.get("call_id")
    status = payload.get("status")
    if status in {"completed", "success"}:
        result_status = "success"
    elif status in {"failed", "error", "incomplete"}:
        result_status = "error"
    else:
        result_status = "unknown"
    coverage["content_unknown"] += 1
    return [
        {
            "event_kind": "tool-result",
            "authorship": "pasted-content-span",
            "content_shape": _shape(_output_text(output)),
            "tool_relation": _tool_relation(call_id, tool_counts, tool_positions),
            "result_status": result_status,
        }
    ]


def _token_partial(payload: Mapping, coverage: Counter) -> dict | None:
    info = payload.get("info")
    if info is None:
        return None
    if not isinstance(info, dict):
        coverage["metadata_invalid"] += 1
        return None
    usage = info.get("last_token_usage")
    if usage is None:
        return None
    if not isinstance(usage, dict):
        coverage["metadata_invalid"] += 1
        return None
    mapping = {
        "input_tokens": "input_tokens",
        "output_tokens": "output_tokens",
        "cached_input_tokens": "cache_read_input_tokens",
    }
    normalized = {}
    for source_key, target_key in mapping.items():
        if source_key not in usage:
            continue
        value = usage[source_key]
        if type(value) is not int or value < 0:
            coverage["metadata_invalid"] += 1
            return None
        normalized[target_key] = value
    if not normalized:
        return None
    return {
        "event_kind": "token-usage",
        "authorship": "agent-turn",
        "token_usage": normalized,
    }


def _settings(payload: Mapping) -> tuple[object, object, object]:
    if payload.get("type") == "thread_settings_applied":
        settings = payload.get("thread_settings")
        if not isinstance(settings, dict):
            return None, None, None
        return (
            settings.get("model"),
            settings.get("model_provider_id"),
            settings.get("reasoning_effort"),
        )
    return (
        payload.get("model"),
        payload.get("model_provider") or payload.get("model_provider_id"),
        payload.get("effort") or payload.get("reasoning_effort"),
    )


def _metadata_partials(
    value: Mapping,
    payload: Mapping,
    record: VerifiedRecord,
    coverage: Counter,
    last_model: str | None,
) -> tuple[list[dict] | None, str | None]:
    record_type = value.get("type")
    if record_type == "session_meta":
        model, provider, effort = None, payload.get("model_provider"), None
        lifecycle = "session-start"
    elif record_type == "turn_context":
        model, provider, effort = _settings(payload)
        lifecycle = None
    elif record_type == "event_msg" and payload.get("type") in {
        "session_configured",
        "thread_settings_applied",
    }:
        model, provider, effort = _settings(payload)
        lifecycle = None
    else:
        return None, last_model
    partials = []
    metadata = _model_partial(
        model=model,
        provider=provider,
        effort=effort,
        coverage=coverage,
    )
    if metadata is not None:
        partials.append(metadata)
    if lifecycle is not None:
        partials.insert(
            0,
            {
                "event_kind": "lifecycle",
                "authorship": "agent-turn",
                "lifecycle_marker": lifecycle,
            },
        )
    valid_model = metadata.get("model") if metadata is not None else None
    if valid_model is not None and last_model is not None and valid_model != last_model:
        partials.append(
            {
                "event_kind": "lifecycle",
                "authorship": "agent-turn",
                "lifecycle_marker": "model-change",
            }
        )
    if record.context_generation_id is not None:
        coverage["metadata_invalid"] += 1
    return partials, valid_model or last_model


def _compaction_partials(
    value: Mapping,
    payload: Mapping,
    record: VerifiedRecord,
    coverage: Counter,
    last_context_generation: int,
) -> tuple[list[dict] | None, int]:
    compacted = value.get("type") == "compacted" or (
        value.get("type") == "event_msg" and payload.get("type") == "context_compacted"
    )
    if not compacted:
        return None, last_context_generation
    if value.get("type") == "compacted" and isinstance(payload.get("message"), str):
        coverage["blocks_seen"] += 1
        coverage["content_unknown"] += 1
    partial = {
        "event_kind": "lifecycle",
        "authorship": "agent-turn",
        "lifecycle_marker": "context-boundary",
    }
    generation = record.context_generation_id
    if generation is not None:
        if generation > last_context_generation:
            partial["context_generation_id"] = generation
            last_context_generation = generation
        else:
            coverage["metadata_invalid"] += 1
    return [partial], last_context_generation


def _unknown_partials(payload: Mapping, coverage: Counter) -> list[dict] | None:
    candidates = []
    if payload.get("type") == "message" and isinstance(payload.get("content"), list):
        for block in payload["content"]:
            coverage["blocks_seen"] += 1
            if isinstance(block, dict) and block.get("type") in _MESSAGE_TYPES:
                candidates.append(block.get("text"))
            else:
                coverage["blocks_unsupported"] += 1
    elif payload.get("type") in _OUTPUT_TYPES:
        coverage["blocks_seen"] += 1
        candidates.append(_output_text(payload.get("output")))
    else:
        return None
    partials = []
    for candidate in candidates:
        if not isinstance(candidate, str):
            coverage["blocks_unsupported"] += 1
            continue
        partials.append(
            {
                "event_kind": "pasted-span",
                "authorship": "pasted-content-span",
                "content_shape": _shape(candidate),
            }
        )
        coverage["content_unknown"] += 1
    return partials or None


def _tool_id_counts(decoded: Mapping[int, dict], records: Sequence[VerifiedRecord]) -> Counter:
    counts = Counter()
    for record in records:
        if record.attribution != "subject" or record.index not in decoded:
            continue
        value = decoded[record.index]
        if value.get("type") != "response_item" or not isinstance(value.get("payload"), dict):
            continue
        details = _call_details(value["payload"])
        if details is not None and isinstance(details[2], str):
            counts[details[2]] += 1
    return counts


def _record_partials(
    *,
    value: Mapping,
    record: VerifiedRecord,
    normalized_record_index: int,
    tool_counts: Counter,
    tool_positions: dict[str, tuple[int, int]],
    coverage: Counter,
    last_model: str | None,
    last_context_generation: int,
) -> tuple[list[dict] | None, str | None, int]:
    payload = value.get("payload")
    if not isinstance(payload, dict):
        return None, last_model, last_context_generation
    if record.attribution == "unknown":
        return _unknown_partials(payload, coverage), last_model, last_context_generation

    compaction, last_context_generation = _compaction_partials(
        value, payload, record, coverage, last_context_generation
    )
    if compaction is not None:
        return compaction, last_model, last_context_generation

    metadata, next_model = _metadata_partials(
        value, payload, record, coverage, last_model
    )
    if metadata is not None:
        return metadata, next_model, last_context_generation

    record_type = value.get("type")
    if record_type == "response_item":
        item_type = payload.get("type")
        if item_type == "message":
            partials = _message_partials(payload, record, coverage)
        elif item_type in _CALL_TYPES:
            partials = _call_partials(
                payload,
                record,
                normalized_record_index,
                tool_counts,
                tool_positions,
                coverage,
            )
        elif item_type in _OUTPUT_TYPES:
            partials = _output_partials(payload, tool_counts, tool_positions, coverage)
        elif item_type in _COMPACTION_TYPES or item_type == "reasoning":
            partials = []
        else:
            partials = None
        if record.context_generation_id is not None:
            coverage["metadata_invalid"] += 1
        return partials, last_model, last_context_generation

    if record_type == "event_msg":
        event_type = payload.get("type")
        if event_type == "token_count":
            token = _token_partial(payload, coverage)
            partials = [token] if token is not None else []
        elif event_type in {"task_started", "turn_started", "task_complete", "turn_complete"}:
            partials = []
        else:
            partials = None
        if record.context_generation_id is not None:
            coverage["metadata_invalid"] += 1
        return partials, last_model, last_context_generation
    return None, last_model, last_context_generation


def normalize_codex(sessions: Sequence[VerifiedSession]) -> bytes:
    """Normalize verified Codex rollout sessions into canonical A8 bytes."""
    checked = _check_input_sessions(sessions, expected_source=_SOURCE)
    coverage = Counter({key: 0 for key in _COVERAGE_KEYS})
    episodes, _, inferred_episode_links = _episode_map(checked, coverage)
    events = []
    manifest_sessions = []

    for session in checked:
        admitted_records = list(session.records)
        coverage["sessions_admitted"] += 1
        coverage["records_seen"] += len(admitted_records)
        coverage["records_ambiguous_authorship"] += sum(
            record.attribution == "unknown" for record in admitted_records
        )
        key = (session.source, session.session_id)
        manifest_session = {
            "source": session.source,
            "session_id": session.session_id,
            "admitted_record_count": len(admitted_records),
        }
        if key in episodes:
            manifest_session["task_episode_id"] = episodes[key]
        if session.parent_session_id is not None:
            manifest_session["parent_session_id"] = session.parent_session_id
        if key in inferred_episode_links:
            manifest_session["episode_predecessor"] = {
                "session_id": inferred_episode_links[key][1],
                "signals": ["repo-id", "head-continuity", "temporal-adjacency"],
            }
        manifest_sessions.append(manifest_session)

        decoded = {}
        for record in admitted_records:
            value = _json_object(record.raw_bytes)
            if value is None:
                coverage["records_malformed"] += 1
                continue
            decoded[record.index] = value
        tool_counts = _tool_id_counts(decoded, admitted_records)
        tool_positions: dict[str, tuple[int, int]] = {}
        last_model = None
        last_context_generation = -1
        for normalized_record_index, record in enumerate(admitted_records):
            value = decoded.get(record.index)
            if value is None:
                continue
            partials, last_model, last_context_generation = _record_partials(
                value=value,
                record=record,
                normalized_record_index=normalized_record_index,
                tool_counts=tool_counts,
                tool_positions=tool_positions,
                coverage=coverage,
                last_model=last_model,
                last_context_generation=last_context_generation,
            )
            if partials is None:
                coverage["records_unsupported"] += 1
                continue
            coverage["records_parsed"] += 1
            events.extend(
                _partials_to_events(
                    partials,
                    session=session,
                    normalized_record_index=normalized_record_index,
                    episode_id=episodes.get(key),
                    observed_at=_observed_at(value, coverage),
                )
            )

    events.sort(key=_event_sort_key)
    manifest_sessions.sort(key=lambda item: (item["source"].encode(), item["session_id"].encode()))
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "normalized-corpus-manifest",
        "normalizer": {
            "name": "mybench.normalizer",
            "version": NORMALIZER_VERSION,
            "authorship_policy_version": AUTHORSHIP_POLICY_VERSION,
            "episode_stitcher_version": EPISODE_STITCHER_VERSION,
        },
        "adapters": [{"source": _SOURCE, "version": CODEX_ADAPTER_VERSION}],
        "sessions": manifest_sessions,
        "coverage": {key: coverage[key] for key in _COVERAGE_KEYS},
        "event_count": len(events),
    }
    root = corpus_commitment(manifest, events)
    artifact = {
        "schema_version": SCHEMA_VERSION,
        "kind": "normalized-corpus-artifact",
        "corpus_commitment": root,
        "manifest": manifest,
        "events": events,
    }
    return canonical_bytes(artifact) + b"\n"


__all__ = ["CODEX_ADAPTER_VERSION", "normalize_codex"]
