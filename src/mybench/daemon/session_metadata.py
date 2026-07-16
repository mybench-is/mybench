"""Closed, structural transcript metadata adapters for capture-time session rows.

The adapters deliberately accept already-framed JSONL records rather than paths.
They deserialize each object but inspect only the field paths documented in
``docs/session-metadata-adapters.md``.  Message content, tool inputs/results,
paths, filenames, instructions, and every unknown field are ignored.

Missing or malformed observations are represented by absent fields.  An
explicit provider-reported zero remains a real observation; absence is never
converted to zero.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

TOKEN_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)

_PROVIDERS = frozenset(
    {"anthropic", "aws-bedrock", "google-vertex", "openai", "azure-openai", "synthetic"}
)
_EFFORTS = frozenset({"none", "minimal", "low", "medium", "high", "max", "xhigh"})
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True)
class SessionMetadata:
    """Whitelisted fields for one latest session-row observation."""

    models_seen: tuple[str, ...] = ()
    provider: str | None = None
    effort: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_creation_input_tokens: int | None = None
    cache_read_input_tokens: int | None = None
    harness_version: str | None = None

    def ledger_fields(self) -> dict:
        fields: dict[str, object] = {}
        if self.models_seen:
            fields["models_seen"] = list(self.models_seen)
        for name in (
            "provider",
            "effort",
            *TOKEN_FIELDS,
            "harness_version",
        ):
            value = getattr(self, name)
            if value is not None:
                fields[name] = value
        return fields


def _json_object(raw: bytes) -> dict | None:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateKey
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _identifier(value: object, pattern: re.Pattern[str]) -> str | None:
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def _label(value: object, allowed: frozenset[str]) -> str | None:
    return value if isinstance(value, str) and value in allowed else None


def _first_valid(values, validator) -> str | None:
    for value in values:
        if (valid := validator(value)) is not None:
            return valid
    return None


def _usage(value: object, mapping: Mapping[str, str]) -> dict[str, int] | None:
    """Map one provider usage object; a malformed mapped value rejects the snapshot."""
    if not isinstance(value, dict):
        return None
    result = {}
    for source_name, target_name in mapping.items():
        if source_name not in value:
            continue
        count = value[source_name]
        if type(count) is not int or count < 0:
            return None
        result[target_name] = count
    return result or None


def _claude(records: Sequence[bytes]) -> SessionMetadata:
    models: set[str] = set()
    provider = harness_version = None
    totals: dict[str, int] = {}
    mapping = {name: name for name in TOKEN_FIELDS}

    for raw in records:
        record = _json_object(raw)
        if record is None:
            continue
        if (version := _identifier(record.get("version"), _VERSION)) is not None:
            harness_version = version
        if record.get("type") != "assistant":
            continue
        message = record.get("message")
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        if (model := _identifier(message.get("model"), _MODEL)) is not None:
            models.add(model)
        if (observed_provider := _label(message.get("provider"), _PROVIDERS)) is not None:
            provider = observed_provider
        observed_usage = _usage(message.get("usage"), mapping)
        if observed_usage is not None:
            for name, value in observed_usage.items():
                totals[name] = totals.get(name, 0) + value

    return SessionMetadata(
        models_seen=tuple(sorted(models)),
        provider=provider,
        # Claude Code has no pinned stable effort field. Thinking-block
        # presence is deliberately not treated as an effort observation.
        effort=None,
        harness_version=harness_version,
        **{name: totals.get(name) for name in TOKEN_FIELDS},
    )


def _codex_settings(payload: Mapping) -> tuple[object, object, object]:
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


def _codex(records: Sequence[bytes]) -> SessionMetadata:
    models: set[str] = set()
    provider = effort = harness_version = None
    tokens: dict[str, int] = {}
    mapping = {
        "input_tokens": "input_tokens",
        "output_tokens": "output_tokens",
        "cached_input_tokens": "cache_read_input_tokens",
    }

    for raw in records:
        record = _json_object(raw)
        if record is None:
            continue
        record_type = record.get("type")
        payload = record.get("payload")
        if not isinstance(payload, dict):
            continue

        if record_type == "session_meta":
            if (version := _identifier(payload.get("cli_version"), _VERSION)) is not None:
                harness_version = version
            observed_provider = _first_valid(
                (payload.get("model_provider"), payload.get("model_provider_id")),
                lambda value: _label(value, _PROVIDERS),
            )
            if observed_provider is not None:
                provider = observed_provider
            continue

        settings = None
        if record_type == "turn_context":
            settings = _codex_settings(payload)
        elif record_type == "event_msg" and payload.get("type") in {
            "session_configured",
            "thread_settings_applied",
        }:
            settings = _codex_settings(payload)
        if settings is not None:
            raw_model, raw_provider, raw_effort = settings
            if (model := _identifier(raw_model, _MODEL)) is not None:
                models.add(model)
            if (observed_provider := _label(raw_provider, _PROVIDERS)) is not None:
                provider = observed_provider
            if (observed_effort := _label(raw_effort, _EFFORTS)) is not None:
                effort = observed_effort

        if record_type == "event_msg" and payload.get("type") == "token_count":
            info = payload.get("info")
            if isinstance(info, dict):
                # total_token_usage is a cumulative session snapshot. Using
                # last_token_usage here would turn a turn count into a total;
                # summing snapshots would double-count a growing session.
                observed = _usage(info.get("total_token_usage"), mapping)
                if observed is not None:
                    tokens = observed

    return SessionMetadata(
        models_seen=tuple(sorted(models)),
        provider=provider,
        effort=effort,
        harness_version=harness_version,
        **{name: tokens.get(name) for name in TOKEN_FIELDS},
    )


def extract_session_metadata(source: str, records: Sequence[bytes]) -> SessionMetadata:
    """Return only capture-whitelisted structural metadata for ``source``.

    The function is total over arbitrary byte records. Unsupported adapters
    return an empty observation so synthetic and future content-opaque sources
    keep their commitment-capture behavior without guessed metadata.
    """
    if source == "claude-code":
        return _claude(records)
    if source == "codex":
        return _codex(records)
    return SessionMetadata()
