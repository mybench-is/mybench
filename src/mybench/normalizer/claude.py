"""Claude Code JSONL -> normalized structural evidence (MYB-10.4).

This module is the pure MYB-10.3 determinism entry point.  Callers supply
already-verified A1/A9 records, opaque A3 identities, and existing salted
record commitments.  The normalizer never discovers files, reads ambient
state, invents an identity, or serializes transcript text.

Authorship is decided at content-block granularity.  In particular, a
``tool_result`` block inside a user-role message is untrusted content, not a
human turn.  Claude Code v1 does not reliably distinguish typed from pasted
user text, so human text contributes structural turn/shape evidence but no
content pointer.  Existing salted record commitments may be referenced for
subject-owned assistant text and tool inputs; the referenced bytes remain in
the live source/A9 authority and are never copied into A8.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone

from mybench.claims.canonical import CanonicalError, canonical_bytes
from mybench.commitment_tree import leaf_commitment, merkle_root

SCHEMA_VERSION = "1"
NORMALIZER_VERSION = "1.0.0"
AUTHORSHIP_POLICY_VERSION = "1.0.0"
EPISODE_STITCHER_VERSION = "1.0.0"
CLAUDE_ADAPTER_VERSION = "1.0.0"

DOMAIN_NORMALIZED_MANIFEST = b"mybench:v1:normalized-corpus-manifest"
DOMAIN_NORMALIZED_EVENT = b"mybench:v1:normalized-event"
DOMAIN_NORMALIZED_CORPUS = b"mybench:v1:normalized-corpus"

_SOURCE = "claude-code"
_ADAPTER_VERSIONS = {"claude-code": "1.0.0", "codex": "1.0.0"}
_OPAQUE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_GIT_HEAD = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_EPISODE_ID = re.compile(r"ep-[0-9a-f]{32}\Z")
_MODEL = re.compile(
    r"(?:(?:claude|synthetic|gpt|codex)-[a-z0-9][a-z0-9._-]{0,63}"
    r"|o[1-9](?:-[a-z0-9][a-z0-9._-]{0,63})?|sonnet|opus|haiku)\Z"
)
_CLAUDE_MODEL = re.compile(
    r"(?:(?:claude|synthetic)-[a-z0-9][a-z0-9._-]{0,63}|sonnet|opus|haiku)\Z"
)
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z\Z"
)
_ATTRIBUTIONS = frozenset({"subject", "non-subject", "unknown"})
_AUTHORSHIP = frozenset({"human-turn", "agent-turn", "pasted-content-span"})
_EVENT_KINDS = frozenset(
    {
        "turn",
        "pasted-span",
        "tool-call",
        "tool-result",
        "lifecycle",
        "model",
        "token-usage",
        "reference",
        "test",
    }
)
_PROVIDERS = frozenset(
    {"anthropic", "aws-bedrock", "google-vertex", "openai", "azure-openai", "synthetic"}
)
_CLAUDE_PROVIDERS = frozenset(
    {"anthropic", "aws-bedrock", "google-vertex", "synthetic"}
)
_EFFORTS = frozenset({"none", "minimal", "low", "medium", "high", "max", "xhigh"})
_TOKEN_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)
_LIFECYCLE_MARKERS = {
    "compact_boundary": "context-boundary",
    "session_start": "session-start",
    "session_end": "session-end",
    "model_change": "model-change",
}
_COVERAGE_KEYS = (
    "sessions_admitted",
    "records_seen",
    "records_ambiguous_authorship",
    "records_parsed",
    "records_malformed",
    "records_unsupported",
    "user_turns_ambiguous",
    "blocks_seen",
    "blocks_unsupported",
    "content_references",
    "content_unknown",
    "metadata_invalid",
    "lineage_unresolved",
)
EPISODE_ADJACENCY_SECONDS = 30 * 60


class NormalizationError(ValueError):
    """Invalid trusted input or normalized artifact; messages never echo content."""


class NoEvidence(NormalizationError):
    """No verified session input exists, so no corpus root may be minted."""


class ResolutionIntegrityError(NormalizationError):
    """A present archive or pointer is inconsistent with its commitment."""


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedRecord:
    """One A2/A3-verified JSONL item, with bytes deliberately hidden from repr."""

    index: int
    raw_bytes: bytes = field(repr=False)
    record_commitment: str
    attribution: str
    context_generation_id: int | None = None


@dataclass(frozen=True)
class VerifiedSession:
    """Opaque session metadata and ordered records authenticated by the I/O layer.

    The normalizer deliberately receives no nonce authority and does not
    re-authenticate these wrappers. ``session_root`` may cover records removed
    by the consent filter, so it is neither validated nor serialized into A8.
    """

    source: str
    session_id: str
    session_root: str
    records: tuple[VerifiedRecord, ...]
    subject_owned: bool
    parent_session_id: str | None = None
    repo_id: str | None = None
    head_before: str | None = None
    head_after: str | None = None
    started_at: str | None = None
    ended_at: str | None = None


@dataclass(frozen=True)
class ContentResolution:
    """Pointer resolution result whose repr cannot disclose the resolved value."""

    status: str
    source: str | None = None
    reason: str | None = None
    value: object | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.status == "resolved":
            valid = self.source in {"live", "archive"} and self.reason is None
        elif self.status == "unknown":
            valid = (
                self.source is None
                and self.reason == "target-missing"
                and self.value is None
            )
        else:
            valid = False
        if not valid:
            raise NormalizationError("content resolution has an invalid state")


@dataclass(frozen=True)
class ResolutionRecord:
    """One independently verified pointer-resolution candidate.

    Nonce and raw bytes are hidden from repr. Attribution comes from the same
    trusted I/O boundary as ``VerifiedRecord`` and is rechecked before a
    commitment match can disclose a value.
    """

    raw_bytes: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    attribution: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.raw_bytes, bytes)
            or not isinstance(self.nonce, bytes)
            or len(self.nonce) != 32
            or not _is_label(self.attribution, _ATTRIBUTIONS)
        ):
            raise ResolutionIntegrityError("pointer resolver received invalid verification input")


def _safe_error(message: str) -> NormalizationError:
    return NormalizationError(message)


def _is_label(value: object, allowed) -> bool:
    return isinstance(value, str) and value in allowed


def _json_object(raw: bytes) -> dict | None:
    def reject_duplicate(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateKey
            result[key] = value
        return result

    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=reject_duplicate)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _canonical_timestamp(value: object) -> str | None:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo != timezone.utc:
        return None
    return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _check_input_sessions(
    sessions: Sequence[VerifiedSession], *, expected_source: str = _SOURCE
) -> list[VerifiedSession]:
    """Return the admitted view after the ADR-0018 consent filter.

    Known non-subject sessions and records are discarded before any field that
    could affect A8 is validated.  An explicit ``unknown`` attribution remains
    eligible only for the shape-only path; that is distinct from a known
    third-party record and is validated because its derived shape is committed.
    """
    if isinstance(sessions, (str, bytes)) or not isinstance(sessions, Sequence):
        raise _safe_error("sessions must be an explicit sequence")
    if not sessions:
        raise NoEvidence("no verified sessions; no normalized corpus was created")
    checked = []
    seen = set()
    for session in sessions:
        if not isinstance(session, VerifiedSession):
            raise _safe_error("session input has the wrong type")
        # This branch is deliberately first.  No malformed field belonging to
        # a known non-subject session can change A8 bytes or success/failure.
        if session.subject_owned is not True:
            continue
        if not isinstance(session.records, tuple):
            raise _safe_error("verified session records must be an explicit tuple")
        admitted_entries = tuple(
            (position, record)
            for position, record in enumerate(session.records)
            if isinstance(record, VerifiedRecord)
            and _is_label(record.attribution, {"subject", "unknown"})
        )
        admitted_records = tuple(record for _, record in admitted_entries)
        if not admitted_records:
            continue
        if session.source != expected_source:
            raise _safe_error("transcript adapter received an unsupported source")
        if not isinstance(session.session_id, str) or not _OPAQUE_ID.fullmatch(
            session.session_id
        ):
            raise _safe_error("session input has an invalid opaque id")
        key = (session.source, session.session_id)
        if key in seen:
            raise _safe_error("duplicate opaque session input")
        seen.add(key)
        if session.parent_session_id is not None and (
            not isinstance(session.parent_session_id, str)
            or not _OPAQUE_ID.fullmatch(session.parent_session_id)
        ):
            raise _safe_error("session input has an invalid parent id")
        if session.parent_session_id == session.session_id:
            raise _safe_error("session input cannot be its own parent")
        if session.repo_id is not None and (
            not isinstance(session.repo_id, str) or not _HEX16.fullmatch(session.repo_id)
        ):
            raise _safe_error("session input has an invalid opaque repo id")
        for head in (session.head_before, session.head_after):
            if head is not None and (
                not isinstance(head, str) or not _GIT_HEAD.fullmatch(head)
            ):
                raise _safe_error("session input has an invalid git observation")
        started_at = (
            _canonical_timestamp(session.started_at)
            if session.started_at is not None
            else None
        )
        ended_at = (
            _canonical_timestamp(session.ended_at)
            if session.ended_at is not None
            else None
        )
        if (session.started_at is not None and started_at is None) or (
            session.ended_at is not None and ended_at is None
        ):
            raise _safe_error("session input has an invalid temporal observation")
        if started_at is not None and ended_at is not None and started_at > ended_at:
            raise _safe_error("session temporal observations are reversed")
        last_source_index = -1
        for _, record in admitted_entries:
            if (
                type(record.index) is not int
                or record.index < 0
                or record.index <= last_source_index
            ):
                raise _safe_error("admitted verified record indexes must strictly increase")
            last_source_index = record.index
            if not isinstance(record.raw_bytes, bytes) or b"\n" in record.raw_bytes:
                raise _safe_error("verified record bytes violate JSONL item framing")
            if not isinstance(record.record_commitment, str) or not _HEX64.fullmatch(
                record.record_commitment
            ):
                raise _safe_error("verified record has an invalid commitment")
            generation = record.context_generation_id
            if generation is not None and (type(generation) is not int or generation < 0):
                raise _safe_error("context generation must be an observed non-negative integer")
        checked.append(
            VerifiedSession(
                source=session.source,
                session_id=session.session_id,
                # The A2 root covers excluded bytes and is therefore never an
                # A8 input.  Retain the API field without validating/serializing
                # it so excluded material is presence-insensitive.
                session_root=session.session_root,
                records=admitted_records,
                subject_owned=True,
                parent_session_id=session.parent_session_id,
                repo_id=session.repo_id,
                head_before=session.head_before,
                head_after=session.head_after,
                started_at=started_at,
                ended_at=ended_at,
            )
        )
    return sorted(checked, key=lambda item: (item.source.encode(), item.session_id.encode()))


def _episode_map(
    sessions: Sequence[VerifiedSession], coverage: Counter
) -> tuple[
    dict[tuple[str, str], str],
    set[tuple[str, str]],
    dict[tuple[str, str], tuple[str, str]],
]:
    admitted = [
        session
        for session in sessions
        if session.subject_owned
        and any(record.attribution in {"subject", "unknown"} for record in session.records)
    ]
    keys = {(session.source, session.session_id) for session in admitted}
    parent = {key: key for key in keys}
    unresolved = set()
    recorded_parents = {
        (session.source, session.session_id): (session.source, session.parent_session_id)
        for session in admitted
        if session.parent_session_id is not None
        and (session.source, session.parent_session_id) in keys
    }
    for start in recorded_parents:
        cursor = start
        trail = set()
        while cursor in recorded_parents:
            if cursor in trail:
                raise _safe_error("session lineage contains a cycle")
            trail.add(cursor)
            cursor = recorded_parents[cursor]

    episode_edges: dict[tuple[str, str], set[tuple[str, str]]] = {
        child: {predecessor} for child, predecessor in recorded_parents.items()
    }

    def reaches(start, target) -> bool:
        pending = [start]
        seen = set()
        while pending:
            current = pending.pop()
            if current == target:
                return True
            if current in seen:
                continue
            seen.add(current)
            pending.extend(episode_edges.get(current, ()))
        return False

    inferred_links: dict[tuple[str, str], tuple[str, str]] = {}
    temporal = [
        session
        for session in admitted
        if session.repo_id is not None
        and session.head_before is not None
        and session.head_after is not None
        and session.started_at is not None
        and session.ended_at is not None
    ]
    def order(session):
        return (
            session.started_at,
            session.ended_at,
            session.source.encode(),
            session.session_id.encode(),
        )
    for later in sorted(temporal, key=order):
        later_key = (later.source, later.session_id)
        later_start = datetime.fromisoformat(later.started_at[:-1] + "+00:00")
        candidates = []
        for earlier in temporal:
            earlier_key = (earlier.source, earlier.session_id)
            if earlier_key == later_key or order(earlier) >= order(later):
                continue
            if earlier.repo_id != later.repo_id or earlier.head_after != later.head_before:
                continue
            earlier_end = datetime.fromisoformat(earlier.ended_at[:-1] + "+00:00")
            separation = (later_start - earlier_end).total_seconds()
            if 0 <= separation <= EPISODE_ADJACENCY_SECONDS:
                candidates.append(earlier)
        for earlier in sorted(candidates, key=order, reverse=True):
            earlier_key = (earlier.source, earlier.session_id)
            if reaches(earlier_key, later_key):
                continue
            episode_edges.setdefault(later_key, set()).add(earlier_key)
            if recorded_parents.get(later_key) != earlier_key:
                inferred_links[later_key] = earlier_key
            break

    def find(key):
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def union(left, right):
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            first, second = sorted((left_root, right_root))
            parent[second] = first

    for session in admitted:
        if session.parent_session_id is None:
            continue
        key = (session.source, session.session_id)
        parent_key = (session.source, session.parent_session_id)
        if parent_key in keys:
            union(key, parent_key)
        else:
            unresolved.add(key)
            coverage["lineage_unresolved"] += 1
    for child, predecessor in inferred_links.items():
        union(child, predecessor)

    components: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for key in sorted(keys):
        components.setdefault(find(key), []).append(key)
    result = {}
    for members in components.values():
        # A lone session is not silently promoted to a "task"; its episode
        # remains UNKNOWN/absent.
        if len(members) < 2:
            continue
        episode_id = _episode_id(members)
        for key in members:
            result[key] = episode_id
    return result, unresolved, inferred_links


def _episode_id(members: Sequence[tuple[str, str]]) -> str:
    identity = {
        "kind": "task-episode-id",
        "stitcher_version": EPISODE_STITCHER_VERSION,
        "sessions": [
            {"source": source, "session_id": session_id}
            for source, session_id in sorted(members)
        ],
    }
    return "ep-" + hashlib.sha256(canonical_bytes(identity)).hexdigest()[:32]


def _sidechain_mode(decoded: Mapping[int, dict], records: Sequence[VerifiedRecord]) -> bool | None:
    markers = []
    for record in records:
        if record.attribution != "subject" or record.index not in decoded:
            continue
        value = decoded[record.index]
        if not _is_label(value.get("type"), {"user", "assistant"}):
            continue
        marker = value.get("isSidechain")
        if type(marker) is not bool:
            return None
        markers.append(marker)
    return markers[0] if markers and len(set(markers)) == 1 else None


def _parent_links(
    decoded: Mapping[int, dict], normalized_indexes: Mapping[int, int]
) -> dict[int, dict]:
    uuids: dict[str, list[int]] = {}
    for index, value in decoded.items():
        uuid_value = value.get("uuid")
        if isinstance(uuid_value, str):
            uuids.setdefault(uuid_value, []).append(index)
    links = {}
    for index, value in decoded.items():
        raw_parent = value.get("parentUuid")
        if raw_parent is None:
            links[index] = {"status": "root"}
        elif not isinstance(raw_parent, str):
            links[index] = {"status": "missing"}
        elif len(uuids.get(raw_parent, ())) > 1:
            links[index] = {"status": "ambiguous"}
        elif raw_parent not in uuids or uuids[raw_parent][0] >= index:
            links[index] = {"status": "dangling"}
        else:
            links[index] = {
                "status": "linked",
                "record_index": normalized_indexes[uuids[raw_parent][0]],
            }
    return links


def _tool_id_counts(decoded: Mapping[int, dict]) -> Counter:
    counts = Counter()
    for value in decoded.values():
        if value.get("type") != "assistant":
            continue
        message = value.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                tool_id = block.get("id")
                if isinstance(tool_id, str):
                    counts[tool_id] += 1
    return counts


def _shape(value: object) -> dict:
    if not isinstance(value, str):
        return {"line_band": "unknown", "size_band": "unknown"}
    length = len(value)
    if length == 0:
        size_band = "empty"
    elif length <= 80:
        size_band = "short"
    elif length <= 1000:
        size_band = "medium"
    else:
        size_band = "long"
    lines = value.count("\n") + (1 if value else 0)
    if lines == 0:
        line_band = "none"
    elif lines == 1:
        line_band = "single"
    elif lines <= 10:
        line_band = "few"
    else:
        line_band = "many"
    return {"line_band": line_band, "size_band": size_band}


def _looks_like_paste(value: str) -> bool:
    """Recognize only an explicit fenced multi-line paste marker in v1."""
    stripped = value.strip()
    if not stripped.startswith("```") or "\n" not in stripped:
        return False
    lines = stripped.splitlines()
    return len(lines) >= 3 and lines[-1].strip() == "```"


def _tool_family(name: object) -> str:
    if not isinstance(name, str):
        return "other"
    lowered = name.lower()
    if lowered in {"read", "read_file", "view_image"}:
        return "read"
    if lowered in {"write", "write_file"}:
        return "write"
    if lowered in {"edit", "multiedit", "notebookedit", "apply_patch"}:
        return "edit"
    if lowered in {"glob", "grep", "rg", "search", "find"}:
        return "search"
    if lowered in {"bash", "execute", "shell", "exec_command", "write_stdin"}:
        return "execute"
    if lowered in {"webfetch", "websearch", "web_search", "search_query"}:
        return "web"
    if lowered in {
        "task",
        "agent",
        "spawn_agent",
        "send_message",
        "followup_task",
    }:
        return "task"
    if lowered.startswith("mcp__"):
        return "mcp"
    return "other"


def _tool_input_pointer(record: VerifiedRecord, block_index: int, block: dict) -> dict | None:
    if "input" not in block:
        return None
    return {
        "field": "tool-input",
        "block_index": block_index,
        "record_commitment": record.record_commitment,
    }


def _reference_kind(name: object, tool_input: object) -> str | None:
    if not isinstance(name, str) or not isinstance(tool_input, dict):
        return None
    lowered_name = name.lower()
    if lowered_name in {
        "task",
        "agent",
        "spawn_agent",
        "send_message",
        "followup_task",
    }:
        return "orchestration"
    if lowered_name not in {
        "read",
        "read_file",
        "view_image",
        "write",
        "write_file",
        "edit",
        "multiedit",
        "notebookedit",
        "apply_patch",
    }:
        return None
    path = next(
        (
            tool_input[key]
            for key in ("file_path", "path", "notebook_path")
            if isinstance(tool_input.get(key), str)
        ),
        None,
    )
    if path is None:
        return None
    normalized = path.replace("\\", "/").lower()
    basename = normalized.rsplit("/", 1)[-1]
    if basename in {"claude.md", "agents.md"}:
        return "instruction"
    if "/.claude/plans/" in f"/{normalized.lstrip('/')}" or normalized.startswith(
        ".claude/plans/"
    ):
        return "plan"
    return "source"


_TEST_COMMAND = re.compile(
    r"(?:python(?:3)?\s+-m\s+pytest|pytest|npm\s+(?:run\s+)?test|"
    r"pnpm\s+(?:run\s+)?test|yarn\s+(?:run\s+)?test|bun\s+test|"
    r"cargo\s+test|go\s+test|dotnet\s+test|mvn\s+test|"
    r"(?:./)?gradlew?\s+test|make\s+test|vitest|jest)(?:\s|$)",
    re.IGNORECASE,
)


def _is_test_invocation(name: object, tool_input: object) -> bool:
    if not isinstance(name, str) or name.lower() not in {
        "bash",
        "execute",
        "shell",
        "exec_command",
    }:
        return False
    if not isinstance(tool_input, dict):
        return False
    command = tool_input.get("command")
    return isinstance(command, str) and _TEST_COMMAND.match(command.lstrip()) is not None


def _metadata_events(message: dict, coverage: Counter) -> list[dict]:
    events = []
    model_value = message.get("model")
    provider_value = message.get("provider")
    effort_value = message.get("effort")
    metadata = {}
    if model_value is not None:
        if isinstance(model_value, str) and _CLAUDE_MODEL.fullmatch(model_value):
            metadata["model"] = model_value
        else:
            coverage["metadata_invalid"] += 1
    if provider_value is not None:
        if _is_label(provider_value, _CLAUDE_PROVIDERS):
            metadata["provider"] = provider_value
        else:
            coverage["metadata_invalid"] += 1
    if effort_value is not None:
        if _is_label(effort_value, _EFFORTS):
            metadata["reasoning_effort"] = effort_value
        else:
            coverage["metadata_invalid"] += 1
    if metadata:
        events.append({"event_kind": "model", "authorship": "agent-turn", **metadata})

    usage = message.get("usage")
    if usage is not None:
        valid = isinstance(usage, dict)
        values = {}
        if valid:
            for key in _TOKEN_FIELDS:
                if key not in usage:
                    continue
                value = usage[key]
                if type(value) is not int or value < 0:
                    valid = False
                    break
                values[key] = value
        if valid and values:
            events.append(
                {
                    "event_kind": "token-usage",
                    "authorship": "agent-turn",
                    "token_usage": values,
                }
            )
        elif not valid:
            coverage["metadata_invalid"] += 1
    return events


def _base_event(
    *,
    session: VerifiedSession,
    normalized_record_index: int,
    subevent_index: int,
    episode_id: str | None,
    observed_at: str | None,
    parent_link: dict,
) -> dict:
    event = {
        "schema_version": SCHEMA_VERSION,
        "kind": "normalized-event",
        "source": session.source,
        "session_id": session.session_id,
        "record_index": normalized_record_index,
        "subevent_index": subevent_index,
        "parent_link": parent_link,
    }
    if episode_id is not None:
        event["task_episode_id"] = episode_id
    if observed_at is not None:
        event["observed_at"] = observed_at
    return event


def _content_pointer(
    record: VerifiedRecord,
    text: str,
    *,
    field_name: str,
    block_index: int | None = None,
) -> dict | None:
    if not text:
        return None
    pointer = {
        "field": field_name,
        "start": 0,
        "end": len(text),
        "unit": "unicode-scalar",
        "record_commitment": record.record_commitment,
    }
    if block_index is not None:
        pointer["block_index"] = block_index
    return pointer


def _tool_relation(
    tool_id: object,
    counts: Counter,
    positions: Mapping[str, tuple[int, int]],
) -> dict:
    if not isinstance(tool_id, str):
        return {"status": "missing"}
    if counts[tool_id] > 1:
        return {"status": "ambiguous"}
    if tool_id not in positions:
        return {"status": "dangling"}
    record_index, subevent_index = positions[tool_id]
    return {
        "status": "linked",
        "record_index": record_index,
        "subevent_index": subevent_index,
    }


def _message_events(
    *,
    session: VerifiedSession,
    record: VerifiedRecord,
    normalized_record_index: int,
    value: dict,
    sidechain: bool | None,
    episode_id: str | None,
    parent_link: dict,
    tool_counts: Counter,
    tool_positions: dict[str, tuple[int, int]],
    coverage: Counter,
) -> list[dict] | None:
    record_type = value.get("type")
    message = value.get("message")
    if not _is_label(record_type, {"user", "assistant"}) or not isinstance(message, dict):
        return None
    if record.context_generation_id is not None:
        # Claude v1 exposes a trustworthy generation observation only on the
        # explicit compact-boundary record handled below.
        coverage["metadata_invalid"] += 1
    if message.get("role") != record_type:
        return None
    content = message.get("content")
    if isinstance(content, str):
        blocks = [(None, {"type": "text", "text": content})]
        text_only = True
    elif isinstance(content, list):
        blocks = list(enumerate(content))
        text_only = bool(blocks) and all(
            isinstance(block, dict) and block.get("type") == "text"
            for _, block in blocks
        )
    else:
        return None

    observed_at = _canonical_timestamp(value.get("timestamp"))
    if value.get("timestamp") is not None and observed_at is None:
        coverage["metadata_invalid"] += 1
    partials = _metadata_events(message, coverage) if record_type == "assistant" else []

    for block_index, block in blocks:
        coverage["blocks_seen"] += 1
        if not isinstance(block, dict):
            coverage["blocks_unsupported"] += 1
            continue
        block_type = block.get("type")
        if block_type == "text":
            text = block.get("text")
            if not isinstance(text, str):
                coverage["blocks_unsupported"] += 1
                continue
            if record_type == "user" and sidechain is None:
                coverage["user_turns_ambiguous"] += 1
                coverage["content_unknown"] += 1
                continue
            authorship = (
                "agent-turn" if record_type == "assistant" or sidechain else "human-turn"
            )
            if authorship == "human-turn" and _looks_like_paste(text):
                partials.append(
                    {
                        "event_kind": "pasted-span",
                        "authorship": "pasted-content-span",
                        "content_shape": _shape(text),
                    }
                )
                coverage["content_unknown"] += 1
                continue
            event = {
                "event_kind": "turn",
                "authorship": authorship,
                "content_shape": _shape(text),
            }
            if record_type == "assistant" and text_only:
                field_name = "message-text" if block_index is None else "content-block-text"
                pointer = _content_pointer(
                    record,
                    text,
                    field_name=field_name,
                    block_index=block_index,
                )
                if pointer is not None:
                    event["pointer"] = pointer
                    coverage["content_references"] += 1
                else:
                    coverage["content_unknown"] += 1
            else:
                coverage["content_unknown"] += 1
            partials.append(event)
        elif record_type == "assistant" and block_type == "tool_use":
            event = {
                "event_kind": "tool-call",
                "authorship": "agent-turn",
                "tool_family": _tool_family(block.get("name")),
            }
            pointer = (
                _tool_input_pointer(record, block_index, block)
                if isinstance(block_index, int)
                else None
            )
            if pointer is not None:
                event["pointer"] = pointer
                coverage["content_references"] += 1
            partials.append(event)
            reference_kind = _reference_kind(block.get("name"), block.get("input"))
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
            if pointer is not None and _is_test_invocation(
                block.get("name"), block.get("input")
            ):
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
            tool_id = block.get("id")
            if isinstance(tool_id, str) and tool_counts[tool_id] == 1:
                tool_positions[tool_id] = (
                    normalized_record_index,
                    next(
                        index
                        for index in range(len(partials) - 1, -1, -1)
                        if partials[index].get("event_kind") == "tool-call"
                    ),
                )
        elif record_type == "user" and block_type == "tool_result":
            event = {
                "event_kind": "tool-result",
                "authorship": "pasted-content-span",
                "content_shape": _shape(block.get("content")),
                "tool_relation": _tool_relation(
                    block.get("tool_use_id"), tool_counts, tool_positions
                ),
            }
            is_error = block.get("is_error")
            event["result_status"] = (
                "error" if is_error is True else "success" if is_error is False else "unknown"
            )
            partials.append(event)
            coverage["content_unknown"] += 1
        else:
            coverage["blocks_unsupported"] += 1

    events = []
    for subevent_index, partial in enumerate(partials):
        event = _base_event(
            session=session,
            normalized_record_index=normalized_record_index,
            subevent_index=subevent_index,
            episode_id=episode_id,
            observed_at=observed_at,
            parent_link=parent_link,
        )
        event.update(partial)
        events.append(event)
        if partial.get("event_kind") == "tool-call":
            block_tool_ids = [
                block.get("id")
                for _, block in blocks
                if isinstance(block, dict) and block.get("type") == "tool_use"
            ]
            tool_calls_before = sum(
                1 for prior in partials[:subevent_index] if prior.get("event_kind") == "tool-call"
            )
            if tool_calls_before < len(block_tool_ids):
                tool_id = block_tool_ids[tool_calls_before]
                if isinstance(tool_id, str) and tool_counts[tool_id] == 1:
                    tool_positions[tool_id] = (normalized_record_index, subevent_index)
    return events


def _unknown_authorship_events(
    *,
    session: VerifiedSession,
    record: VerifiedRecord,
    normalized_record_index: int,
    value: dict,
    episode_id: str | None,
    parent_link: dict,
    coverage: Counter,
) -> list[dict] | None:
    """Retain only structural paste shapes for explicitly ambiguous records."""
    message = value.get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    if isinstance(content, str):
        coverage["blocks_seen"] += 1
        candidates = [content]
    elif isinstance(content, list):
        candidates = []
        for block in content:
            coverage["blocks_seen"] += 1
            if not isinstance(block, dict):
                coverage["blocks_unsupported"] += 1
                continue
            if block.get("type") == "text":
                candidates.append(block.get("text"))
            elif block.get("type") == "tool_result":
                candidates.append(block.get("content"))
            else:
                coverage["blocks_unsupported"] += 1
    else:
        return None
    observed_at = _canonical_timestamp(value.get("timestamp"))
    if value.get("timestamp") is not None and observed_at is None:
        coverage["metadata_invalid"] += 1
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
    if not partials:
        return None
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


def _lifecycle_events(
    *,
    session: VerifiedSession,
    record: VerifiedRecord,
    normalized_record_index: int,
    value: dict,
    episode_id: str | None,
    parent_link: dict,
    coverage: Counter,
    observed_context_generation: int | None,
) -> list[dict] | None:
    if value.get("type") != "system":
        return None
    subtype = value.get("subtype")
    marker = _LIFECYCLE_MARKERS.get(subtype) if isinstance(subtype, str) else None
    if marker is None:
        return None
    observed_at = _canonical_timestamp(value.get("timestamp"))
    if value.get("timestamp") is not None and observed_at is None:
        coverage["metadata_invalid"] += 1
    event = _base_event(
        session=session,
        normalized_record_index=normalized_record_index,
        subevent_index=0,
        episode_id=episode_id,
        observed_at=observed_at,
        parent_link=parent_link,
    )
    event.update(
        {
            "event_kind": "lifecycle",
            "authorship": "agent-turn",
            "lifecycle_marker": marker,
        }
    )
    if marker == "context-boundary" and observed_context_generation is not None:
        event["context_generation_id"] = observed_context_generation
    elif marker != "context-boundary" and record.context_generation_id is not None:
        coverage["metadata_invalid"] += 1
    return [event]


def _normalized_leaf(domain: bytes, record: dict) -> bytes:
    encoded = canonical_bytes(record)
    return hashlib.sha256(domain + len(encoded).to_bytes(8, "big") + encoded).digest()


def manifest_leaf_hash(manifest: dict) -> bytes:
    """Hash one manifest with the owner-approved MYB-10.4 domain."""
    return _normalized_leaf(DOMAIN_NORMALIZED_MANIFEST, manifest)


def event_leaf_hash(event: dict) -> bytes:
    """Hash one normalized event with the owner-approved MYB-10.4 domain."""
    return _normalized_leaf(DOMAIN_NORMALIZED_EVENT, event)


def corpus_commitment(manifest: dict, events: Sequence[dict]) -> str:
    """Return the wrapped RFC-6962-shaped root over manifest + ordered events."""
    ordered = sorted(events, key=_event_sort_key)
    keys = [_event_sort_key(event) for event in ordered]
    if len(keys) != len(set(keys)):
        raise _safe_error("duplicate normalized event order key")
    leaves = [manifest_leaf_hash(manifest), *(event_leaf_hash(event) for event in ordered)]
    tree_root = merkle_root(leaves)
    return hashlib.sha256(DOMAIN_NORMALIZED_CORPUS + tree_root).hexdigest()


def _event_sort_key(event: Mapping) -> tuple:
    try:
        return (
            event["source"].encode(),
            event["session_id"].encode(),
            event["record_index"],
            event["subevent_index"],
        )
    except (AttributeError, KeyError, TypeError):
        raise _safe_error("normalized event has an invalid order key") from None


def normalize_claude(sessions: Sequence[VerifiedSession]) -> bytes:
    """Normalize verified Claude sessions and return one canonical artifact JSON line."""
    checked = _check_input_sessions(sessions)
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
        normalized_indexes = {
            record.index: normalized_index
            for normalized_index, record in enumerate(admitted_records)
        }
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

        subject_decoded = {
            record.index: decoded[record.index]
            for record in admitted_records
            if record.attribution == "subject" and record.index in decoded
        }
        raw_session_ids = {
            value["sessionId"]
            for value in subject_decoded.values()
            if isinstance(value.get("sessionId"), str)
        }
        inconsistent_raw_session = len(raw_session_ids) > 1
        sidechain = _sidechain_mode(subject_decoded, admitted_records)
        parent_links = _parent_links(subject_decoded, normalized_indexes)
        tool_counts = _tool_id_counts(subject_decoded)
        tool_positions: dict[str, tuple[int, int]] = {}
        last_context_generation = -1

        for record in admitted_records:
            if record.index not in decoded:
                continue
            if record.attribution == "subject" and inconsistent_raw_session:
                coverage["records_unsupported"] += 1
                continue
            value = decoded[record.index]
            if record.attribution == "unknown":
                raw_parent = value.get("parentUuid")
                ambiguous_parent_link = {
                    "status": "root" if raw_parent is None else "dangling"
                }
                parsed = _unknown_authorship_events(
                    session=session,
                    record=record,
                    normalized_record_index=normalized_indexes[record.index],
                    value=value,
                    episode_id=episodes.get(key),
                    parent_link=ambiguous_parent_link,
                    coverage=coverage,
                )
            else:
                parsed = _message_events(
                    session=session,
                    record=record,
                    normalized_record_index=normalized_indexes[record.index],
                    value=value,
                    sidechain=sidechain,
                    episode_id=episodes.get(key),
                    parent_link=parent_links[record.index],
                    tool_counts=tool_counts,
                    tool_positions=tool_positions,
                    coverage=coverage,
                )
            if parsed is None and record.attribution == "subject":
                observed_context_generation = None
                if (
                    value.get("type") == "system"
                    and value.get("subtype") == "compact_boundary"
                    and record.context_generation_id is not None
                ):
                    if record.context_generation_id > last_context_generation:
                        observed_context_generation = record.context_generation_id
                        last_context_generation = record.context_generation_id
                    else:
                        coverage["metadata_invalid"] += 1
                parsed = _lifecycle_events(
                    session=session,
                    record=record,
                    normalized_record_index=normalized_indexes[record.index],
                    value=value,
                    episode_id=episodes.get(key),
                    parent_link=parent_links[record.index],
                    coverage=coverage,
                    observed_context_generation=observed_context_generation,
                )
            if parsed is None:
                coverage["records_unsupported"] += 1
                continue
            coverage["records_parsed"] += 1
            events.extend(parsed)

    events.sort(key=_event_sort_key)
    manifest_sessions.sort(key=lambda item: (item["source"].encode(), item["session_id"].encode()))
    coverage_dict = {key: coverage[key] for key in _COVERAGE_KEYS}
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "normalized-corpus-manifest",
        "normalizer": {
            "name": "mybench.normalizer",
            "version": NORMALIZER_VERSION,
            "authorship_policy_version": AUTHORSHIP_POLICY_VERSION,
            "episode_stitcher_version": EPISODE_STITCHER_VERSION,
        },
        "adapters": [{"source": _SOURCE, "version": CLAUDE_ADAPTER_VERSION}],
        "sessions": manifest_sessions,
        "coverage": coverage_dict,
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


def _exact_keys(value: object, required: set[str], optional: set[str] = set()) -> bool:
    return isinstance(value, dict) and required <= set(value) <= required | optional


def _is_uint(value: object) -> bool:
    return type(value) is int and value >= 0


def _is_opaque_id(value: object) -> bool:
    return isinstance(value, str) and _OPAQUE_ID.fullmatch(value) is not None


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _is_episode_id(value: object) -> bool:
    return isinstance(value, str) and _EPISODE_ID.fullmatch(value) is not None


def _validate_pointer(pointer: object) -> None:
    if not isinstance(pointer, dict):
        raise _safe_error("normalized pointer has invalid fields")
    field_name = pointer.get("field")
    if field_name == "tool-input":
        if not _exact_keys(pointer, {"field", "block_index", "record_commitment"}):
            raise _safe_error("normalized tool-input pointer has invalid fields")
        if not _is_uint(pointer["block_index"]) or not _is_hex64(
            pointer["record_commitment"]
        ):
            raise _safe_error("normalized tool-input pointer is invalid")
        return
    required = {"field", "start", "end", "unit", "record_commitment"}
    if not _exact_keys(pointer, required, {"block_index"}):
        raise _safe_error("normalized text pointer has invalid fields")
    if not _is_label(field_name, {"message-text", "content-block-text"}):
        raise _safe_error("normalized pointer has an invalid field selector")
    if pointer["unit"] != "unicode-scalar":
        raise _safe_error("normalized pointer has an invalid coordinate unit")
    if not _is_uint(pointer["start"]) or not _is_uint(pointer["end"]):
        raise _safe_error("normalized pointer has invalid coordinates")
    if pointer["start"] >= pointer["end"]:
        raise _safe_error("normalized pointer has an empty coordinate range")
    if not _is_hex64(pointer["record_commitment"]):
        raise _safe_error("normalized pointer has an invalid record commitment")
    if pointer["field"] == "content-block-text":
        if not _is_uint(pointer.get("block_index")):
            raise _safe_error("content-block pointer is missing its block index")
    elif "block_index" in pointer:
        raise _safe_error("message pointer cannot carry a block index")


def _validate_event(event: object, allowed_sources: set[str]) -> None:
    common = {
        "schema_version",
        "kind",
        "source",
        "session_id",
        "record_index",
        "subevent_index",
        "event_kind",
        "authorship",
        "parent_link",
    }
    common_optional = {
        "observed_at",
        "task_episode_id",
    }
    if not isinstance(event, dict) or not common <= set(event):
        raise _safe_error("normalized event has invalid fields")
    if event["schema_version"] != SCHEMA_VERSION or event["kind"] != "normalized-event":
        raise _safe_error("normalized event has an invalid version or kind")
    if not _is_label(event["source"], allowed_sources) or not _is_opaque_id(
        event["session_id"]
    ):
        raise _safe_error("normalized event has an invalid source identity")
    if not _is_uint(event["record_index"]) or not _is_uint(event["subevent_index"]):
        raise _safe_error("normalized event has invalid indexes")
    if not _is_label(event["event_kind"], _EVENT_KINDS) or not _is_label(
        event["authorship"], _AUTHORSHIP
    ):
        raise _safe_error("normalized event has an invalid structural classification")
    event_kind = event["event_kind"]
    kind_spec = {
        "turn": ({"content_shape"}, {"pointer"}, {"human-turn", "agent-turn"}),
        "pasted-span": ({"content_shape"}, set(), {"pasted-content-span"}),
        "tool-call": ({"tool_family"}, {"pointer"}, {"agent-turn"}),
        "tool-result": (
            {"content_shape", "tool_relation", "result_status"},
            set(),
            {"pasted-content-span"},
        ),
        "lifecycle": (
            {"lifecycle_marker"},
            {"context_generation_id"},
            {"agent-turn"},
        ),
        "model": (set(), {"model", "provider", "reasoning_effort"}, {"agent-turn"}),
        "token-usage": ({"token_usage"}, set(), {"agent-turn"}),
        "reference": ({"reference_kind", "pointer"}, set(), {"agent-turn"}),
        "test": ({"test_scope", "test_status"}, {"pointer"}, {"agent-turn"}),
    }[event_kind]
    kind_required, kind_optional, allowed_authorship = kind_spec
    if not _exact_keys(event, common | kind_required, common_optional | kind_optional):
        raise _safe_error("normalized event has fields from another event kind")
    if event["authorship"] not in allowed_authorship:
        raise _safe_error("normalized event has invalid authorship for its kind")
    if "task_episode_id" in event and not _is_episode_id(event["task_episode_id"]):
        raise _safe_error("normalized event has an invalid episode id")
    if "context_generation_id" in event and not _is_uint(event["context_generation_id"]):
        raise _safe_error("normalized event has an invalid context generation")
    if "observed_at" in event and _canonical_timestamp(event["observed_at"]) != event[
        "observed_at"
    ]:
        raise _safe_error("normalized event has a non-canonical timestamp")
    if "pointer" in event:
        _validate_pointer(event["pointer"])
        pointer_field = event["pointer"]["field"]
        if event_kind == "turn" and (
            event["authorship"] != "agent-turn" or pointer_field == "tool-input"
        ):
            raise _safe_error("turn pointer violates the authorship or field policy")
        if event_kind in {"tool-call", "test"} and pointer_field != "tool-input":
            raise _safe_error("tool-derived event has an invalid pointer selector")
    parent_link = event["parent_link"]
    if not isinstance(parent_link, dict) or not _is_label(
        parent_link.get("status"),
        {"root", "linked", "missing", "dangling", "ambiguous"},
    ):
        raise _safe_error("normalized event has an invalid parent relation")
    if parent_link["status"] == "linked":
        if set(parent_link) != {"status", "record_index"} or not _is_uint(
            parent_link["record_index"]
        ):
            raise _safe_error("linked parent relation has invalid fields")
    elif set(parent_link) != {"status"}:
        raise _safe_error("unlinked parent relation has invalid fields")

    if "content_shape" in event:
        shape = event["content_shape"]
        if not _exact_keys(shape, {"line_band", "size_band"}):
            raise _safe_error("normalized event has an invalid content shape")
        if not _is_label(
            shape["line_band"], {"none", "single", "few", "many", "unknown"}
        ):
            raise _safe_error("normalized event has an invalid line band")
        if not _is_label(
            shape["size_band"], {"empty", "short", "medium", "long", "unknown"}
        ):
            raise _safe_error("normalized event has an invalid size band")
    if "tool_family" in event and not _is_label(
        event["tool_family"],
        {"read", "write", "edit", "search", "execute", "web", "mcp", "task", "other"},
    ):
        raise _safe_error("normalized event has an invalid tool family")
    if "tool_relation" in event:
        relation = event["tool_relation"]
        if not isinstance(relation, dict) or not _is_label(
            relation.get("status"), {"linked", "missing", "dangling", "ambiguous"}
        ):
            raise _safe_error("normalized event has an invalid tool relation")
        if relation["status"] == "linked":
            if set(relation) != {"status", "record_index", "subevent_index"} or not all(
                _is_uint(relation[key]) for key in ("record_index", "subevent_index")
            ):
                raise _safe_error("linked tool relation has invalid fields")
        elif set(relation) != {"status"}:
            raise _safe_error("unlinked tool relation has invalid fields")
    if "result_status" in event and not _is_label(
        event["result_status"], {"success", "error", "unknown"}
    ):
        raise _safe_error("normalized event has an invalid result status")
    if "model" in event and (
        not isinstance(event["model"], str) or not _MODEL.fullmatch(event["model"])
    ):
        raise _safe_error("normalized event has an invalid model identifier")
    if "provider" in event and not _is_label(event["provider"], _PROVIDERS):
        raise _safe_error("normalized event has an invalid provider")
    if "reasoning_effort" in event and not _is_label(
        event["reasoning_effort"], _EFFORTS
    ):
        raise _safe_error("normalized event has an invalid reasoning effort")
    if "token_usage" in event:
        usage = event["token_usage"]
        if (
            not isinstance(usage, dict)
            or not usage
            or not set(usage) <= set(_TOKEN_FIELDS)
            or any(not _is_uint(value) for value in usage.values())
        ):
            raise _safe_error("normalized event has invalid token usage")
    if "lifecycle_marker" in event and not _is_label(
        event["lifecycle_marker"], set(_LIFECYCLE_MARKERS.values())
    ):
        raise _safe_error("normalized event has an invalid lifecycle marker")
    if "reference_kind" in event and not _is_label(
        event["reference_kind"], {"plan", "instruction", "source", "orchestration"}
    ):
        raise _safe_error("normalized event has an invalid reference kind")
    if "test_scope" in event and not _is_label(
        event["test_scope"], {"unit", "integration", "end-to-end", "other"}
    ):
        raise _safe_error("normalized event has an invalid test scope")
    if "test_status" in event and not _is_label(
        event["test_status"], {"passed", "failed", "error", "unknown"}
    ):
        raise _safe_error("normalized event has an invalid test status")

    if event_kind == "lifecycle" and "context_generation_id" in event and event[
        "lifecycle_marker"
    ] != "context-boundary":
        raise _safe_error("context generation lacks an observed boundary")
    if event_kind == "model" and not {
        "model",
        "provider",
        "reasoning_effort",
    } & set(event):
        raise _safe_error("model event contains no whitelisted metadata")


def _validate_manifest(manifest: object, event_count: int) -> set[str]:
    required = {
        "schema_version",
        "kind",
        "normalizer",
        "adapters",
        "sessions",
        "coverage",
        "event_count",
    }
    if not _exact_keys(manifest, required):
        raise _safe_error("normalized manifest has invalid fields")
    assert isinstance(manifest, dict)
    if manifest["schema_version"] != SCHEMA_VERSION or manifest[
        "kind"
    ] != "normalized-corpus-manifest":
        raise _safe_error("normalized manifest has an invalid version or kind")
    expected_normalizer = {
        "name": "mybench.normalizer",
        "version": NORMALIZER_VERSION,
        "authorship_policy_version": AUTHORSHIP_POLICY_VERSION,
        "episode_stitcher_version": EPISODE_STITCHER_VERSION,
    }
    if manifest["normalizer"] != expected_normalizer:
        raise _safe_error("normalized manifest has an unsupported normalizer version")
    adapters = manifest["adapters"]
    if not isinstance(adapters, list) or not adapters:
        raise _safe_error("normalized manifest has an unsupported adapter inventory")
    adapter_sources = []
    for adapter in adapters:
        if not _exact_keys(adapter, {"source", "version"}):
            raise _safe_error("normalized manifest has an unsupported adapter inventory")
        source = adapter["source"]
        if not isinstance(source, str) or source not in _ADAPTER_VERSIONS:
            raise _safe_error("normalized manifest has an unsupported adapter inventory")
        if adapter["version"] != _ADAPTER_VERSIONS[source]:
            raise _safe_error("normalized manifest has an unsupported adapter inventory")
        adapter_sources.append(source)
    if adapter_sources != sorted(adapter_sources) or len(adapter_sources) != len(
        set(adapter_sources)
    ):
        raise _safe_error("normalized manifest has an unsupported adapter inventory")
    allowed_sources = set(adapter_sources)
    if not isinstance(manifest["sessions"], list):
        raise _safe_error("normalized manifest sessions must be an array")
    session_keys = []
    for session in manifest["sessions"]:
        required_session = {
            "source",
            "session_id",
            "admitted_record_count",
        }
        if not _exact_keys(
            session,
            required_session,
            {"parent_session_id", "task_episode_id", "episode_predecessor"},
        ):
            raise _safe_error("normalized manifest session has invalid fields")
        if not _is_label(session["source"], allowed_sources) or not _is_opaque_id(
            session["session_id"]
        ):
            raise _safe_error("normalized manifest session has an invalid identity")
        if not _is_uint(session["admitted_record_count"]) or session[
            "admitted_record_count"
        ] == 0:
            raise _safe_error("normalized manifest session has invalid structural metadata")
        if "task_episode_id" in session and not _is_episode_id(session["task_episode_id"]):
            raise _safe_error("normalized manifest session has an invalid episode id")
        if "parent_session_id" in session and not _is_opaque_id(session["parent_session_id"]):
            raise _safe_error("normalized manifest session has an invalid parent id")
        if "episode_predecessor" in session:
            predecessor = session["episode_predecessor"]
            if not _exact_keys(predecessor, {"session_id", "signals"}) or not _is_opaque_id(
                predecessor["session_id"]
            ):
                raise _safe_error("normalized manifest has an invalid episode edge")
            if predecessor["signals"] != [
                "repo-id",
                "head-continuity",
                "temporal-adjacency",
            ]:
                raise _safe_error("normalized manifest has unsupported episode signals")
        session_keys.append((session["source"].encode(), session["session_id"].encode()))
    if session_keys != sorted(session_keys) or len(session_keys) != len(set(session_keys)):
        raise _safe_error("normalized manifest sessions are not sorted and unique")
    coverage = manifest["coverage"]
    if not _exact_keys(coverage, set(_COVERAGE_KEYS)) or any(
        not _is_uint(value) for value in coverage.values()
    ):
        raise _safe_error("normalized manifest has invalid coverage counts")
    if manifest["event_count"] != event_count:
        raise _safe_error("normalized manifest event count does not match its records")
    if coverage["sessions_admitted"] != len(manifest["sessions"]):
        raise _safe_error("normalized manifest session coverage is inconsistent")
    if coverage["records_seen"] != sum(
        session["admitted_record_count"] for session in manifest["sessions"]
    ):
        raise _safe_error("normalized manifest record coverage is inconsistent")
    if (
        coverage["records_parsed"]
        + coverage["records_malformed"]
        + coverage["records_unsupported"]
        != coverage["records_seen"]
    ):
        raise _safe_error("normalized manifest parse coverage is inconsistent")
    if coverage["records_ambiguous_authorship"] > coverage["records_seen"]:
        raise _safe_error("normalized manifest authorship coverage is inconsistent")
    return allowed_sources


def _validate_identity_semantics(manifest: dict, events: Sequence[dict]) -> None:
    if manifest["coverage"]["content_references"] != sum(
        "pointer" in event for event in events
    ):
        raise _safe_error("normalized manifest reference coverage is inconsistent")
    sessions = manifest["sessions"]
    by_key = {(session["source"], session["session_id"]): session for session in sessions}
    graph_edges: dict[tuple[str, str], set[tuple[str, str]]] = {}
    unresolved = 0
    for key, session in by_key.items():
        parent_id = session.get("parent_session_id")
        if parent_id is not None:
            parent_key = (key[0], parent_id)
            if parent_key == key:
                raise _safe_error("normalized manifest session cannot parent itself")
            if parent_key in by_key:
                graph_edges.setdefault(key, set()).add(parent_key)
            else:
                unresolved += 1
        predecessor = session.get("episode_predecessor")
        if predecessor is not None:
            predecessor_key = (key[0], predecessor["session_id"])
            if predecessor_key == key or predecessor_key not in by_key:
                raise _safe_error("normalized manifest episode edge is unresolved")
            graph_edges.setdefault(key, set()).add(predecessor_key)

    def visit(node, active, complete):
        if node in active:
            raise _safe_error("normalized manifest lineage contains a cycle")
        if node in complete:
            return
        active.add(node)
        for predecessor in graph_edges.get(node, ()):
            visit(predecessor, active, complete)
        active.remove(node)
        complete.add(node)

    complete = set()
    for start in graph_edges:
        visit(start, set(), complete)

    parents = {key: key for key in by_key}

    def find(key):
        while parents[key] != key:
            parents[key] = parents[parents[key]]
            key = parents[key]
        return key

    def union(left, right):
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            first, second = sorted((left_root, right_root))
            parents[second] = first

    for child, predecessors in graph_edges.items():
        for predecessor in predecessors:
            union(child, predecessor)
    components = {}
    for key in sorted(by_key):
        components.setdefault(find(key), []).append(key)
    expected_episodes = {}
    for members in components.values():
        if len(members) < 2:
            continue
        episode_id = _episode_id(members)
        expected_episodes.update({member: episode_id for member in members})
    for key, session in by_key.items():
        if session.get("task_episode_id") != expected_episodes.get(key):
            raise _safe_error("normalized manifest episode identity is inconsistent")
    if manifest["coverage"]["lineage_unresolved"] != unresolved:
        raise _safe_error("normalized manifest lineage coverage is inconsistent")

    subevents = {}
    record_metadata = {}
    pointer_commitments = {}
    by_location = {}
    context_generations = {}
    for event in events:
        key = (event["source"], event["session_id"])
        session = by_key[key]
        if event["record_index"] >= session["admitted_record_count"]:
            raise _safe_error("normalized event record index exceeds its session")
        if event.get("task_episode_id") != session.get("task_episode_id"):
            raise _safe_error("normalized event episode identity is inconsistent")
        parent_link = event["parent_link"]
        if parent_link["status"] == "linked" and parent_link["record_index"] >= event[
            "record_index"
        ]:
            raise _safe_error("normalized event parent does not precede its record")
        record_key = (key, event["record_index"])
        subevents.setdefault(record_key, []).append(event["subevent_index"])
        metadata = (event["parent_link"], event.get("observed_at"))
        if record_key in record_metadata and record_metadata[record_key] != metadata:
            raise _safe_error("normalized events disagree about their source record")
        record_metadata[record_key] = metadata
        if "pointer" in event:
            commitment = event["pointer"]["record_commitment"]
            if (
                record_key in pointer_commitments
                and pointer_commitments[record_key] != commitment
            ):
                raise _safe_error("normalized pointers disagree about their source record")
            pointer_commitments[record_key] = commitment
        by_location[(key, event["record_index"], event["subevent_index"])] = event
        if "context_generation_id" in event:
            context_generations.setdefault(key, []).append(event["context_generation_id"])
    if any(indexes != list(range(len(indexes))) for indexes in subevents.values()):
        raise _safe_error("normalized event subevent indexes are not contiguous")
    if any(
        any(current <= previous for previous, current in zip(values, values[1:]))
        for values in context_generations.values()
    ):
        raise _safe_error("normalized context generations are not strictly increasing")
    for event in events:
        if event["event_kind"] != "tool-result":
            continue
        relation = event["tool_relation"]
        if relation["status"] != "linked":
            continue
        key = (event["source"], event["session_id"])
        target_location = (key, relation["record_index"], relation["subevent_index"])
        target = by_location.get(target_location)
        if target is None or target["event_kind"] != "tool-call" or (
            relation["record_index"], relation["subevent_index"]
        ) >= (event["record_index"], event["subevent_index"]):
            raise _safe_error("normalized tool relation does not target a prior tool call")

    coverage = manifest["coverage"]
    event_records = {
        (event["source"], event["session_id"], event["record_index"])
        for event in events
    }
    primary_block_events = sum(
        event["event_kind"] in {"turn", "pasted-span", "tool-call", "tool-result"}
        for event in events
    )
    minimum_unknown = sum(
        event["event_kind"] in {"pasted-span", "tool-result"}
        or (event["event_kind"] == "turn" and "pointer" not in event)
        for event in events
    )
    if coverage["records_parsed"] < len(event_records):
        raise _safe_error("normalized manifest parsed-record coverage is inconsistent")
    if not (
        primary_block_events <= coverage["blocks_seen"]
        and coverage["blocks_unsupported"] <= coverage["blocks_seen"]
    ):
        raise _safe_error("normalized manifest block coverage is inconsistent")
    if not (
        minimum_unknown <= coverage["content_unknown"] <= coverage["blocks_seen"]
        and coverage["user_turns_ambiguous"] <= coverage["content_unknown"]
    ):
        raise _safe_error("normalized manifest unknown-content coverage is inconsistent")


def validate_corpus_artifact(data: bytes) -> str:
    """Validate canonical shape and Merkle binding; return the content address."""
    if not isinstance(data, bytes) or not data.endswith(b"\n"):
        raise _safe_error("normalized corpus must be one canonical JSON line")
    try:
        text = data[:-1].decode("utf-8")
        artifact = json.loads(text)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _safe_error("normalized corpus is not valid JSON") from None
    if not isinstance(artifact, dict):
        raise _safe_error("normalized corpus artifact must be an object")
    try:
        if canonical_bytes(artifact) + b"\n" != data:
            raise _safe_error("normalized corpus is not canonically serialized")
    except (CanonicalError, ValueError, RecursionError):
        raise _safe_error("normalized corpus contains a non-canonical value") from None
    required = {"schema_version", "kind", "corpus_commitment", "manifest", "events"}
    if set(artifact) != required:
        raise _safe_error("normalized corpus artifact has invalid fields")
    if artifact["schema_version"] != SCHEMA_VERSION or artifact[
        "kind"
    ] != "normalized-corpus-artifact":
        raise _safe_error("normalized corpus artifact has an invalid version or kind")
    if not isinstance(artifact["events"], list):
        raise _safe_error("normalized corpus events must be an array")
    allowed_sources = _validate_manifest(artifact["manifest"], len(artifact["events"]))
    session_keys = {
        (session["source"], session["session_id"])
        for session in artifact["manifest"]["sessions"]
    }
    for event in artifact["events"]:
        _validate_event(event, allowed_sources)
        if (event["source"], event["session_id"]) not in session_keys:
            raise _safe_error("normalized event has no manifest session")
    _validate_identity_semantics(artifact["manifest"], artifact["events"])
    keys = [_event_sort_key(event) for event in artifact["events"]]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise _safe_error("normalized corpus events are not sorted and unique")
    expected = corpus_commitment(artifact["manifest"], artifact["events"])
    if artifact["corpus_commitment"] != expected:
        raise _safe_error("normalized corpus commitment does not match its records")
    return expected


def _committed_record(
    records: Sequence[ResolutionRecord] | None,
    commitment: str,
) -> bytes | None:
    if records is None:
        return None
    if isinstance(records, (str, bytes)) or not isinstance(records, Sequence):
        raise ResolutionIntegrityError("pointer resolver received invalid record input")
    matches = []
    for record in records:
        if (
            not isinstance(record, ResolutionRecord)
            or not isinstance(record.raw_bytes, bytes)
            or not isinstance(record.nonce, bytes)
            or len(record.nonce) != 32
            or not _is_label(record.attribution, _ATTRIBUTIONS)
        ):
            raise ResolutionIntegrityError("pointer resolver received invalid verification input")
        if leaf_commitment(record.nonce, record.raw_bytes).hex() == commitment:
            if record.attribution != "subject":
                raise ResolutionIntegrityError("pointer target has ineligible attribution")
            matches.append(record.raw_bytes)
    if len(matches) > 1:
        raise ResolutionIntegrityError("pointer commitment resolves ambiguously")
    return matches[0] if matches else None


def _codex_pointer_value(pointer: Mapping, value: Mapping) -> object:
    payload = value.get("payload")
    if not isinstance(payload, dict):
        raise ResolutionIntegrityError("resolved record is missing the pointed-to structure")
    if pointer["field"] == "content-block-text":
        content = payload.get("content")
        block_index = pointer["block_index"]
        if (
            payload.get("type") != "message"
            or payload.get("role") != "assistant"
            or not isinstance(content, list)
            or block_index >= len(content)
        ):
            raise ResolutionIntegrityError("resolved content block is unavailable")
        block = content[block_index]
        target = (
            block.get("text")
            if isinstance(block, dict) and block.get("type") == "output_text"
            else None
        )
        if not isinstance(target, str) or pointer["end"] > len(target):
            raise ResolutionIntegrityError("resolved pointer coordinates are invalid")
        return target[pointer["start"] : pointer["end"]]
    if pointer["field"] != "tool-input" or pointer["block_index"] != 0:
        raise ResolutionIntegrityError("resolved tool input is unavailable")
    item_type = payload.get("type")
    fields = {
        "function_call": "arguments",
        "custom_tool_call": "input",
        "local_shell_call": "action",
        "tool_search_call": "arguments",
        "web_search_call": "action",
    }
    field = fields.get(item_type)
    if field is None or field not in payload:
        raise ResolutionIntegrityError("resolved tool input is unavailable")
    return payload[field]


def _pointer_value(pointer: Mapping, raw: bytes) -> object:
    value = _json_object(raw)
    if value is None:
        raise ResolutionIntegrityError("resolved record is not valid structured data")
    if value.get("type") == "response_item":
        return _codex_pointer_value(pointer, value)
    if value.get("type") != "assistant":
        raise ResolutionIntegrityError("resolved record has ineligible authorship")
    message = value.get("message")
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise ResolutionIntegrityError("resolved record is missing the pointed-to structure")
    content = message.get("content")
    if pointer["field"] == "message-text":
        target = content
    elif pointer["field"] == "content-block-text":
        block_index = pointer["block_index"]
        if (
            not isinstance(content, list)
            or not content
            or block_index >= len(content)
            or not all(
                isinstance(block, dict) and block.get("type") == "text"
                for block in content
            )
        ):
            raise ResolutionIntegrityError("resolved content block is unavailable")
        block = content[block_index]
        target = (
            block.get("text")
            if isinstance(block, dict) and block.get("type") == "text"
            else None
        )
    else:
        block_index = pointer["block_index"]
        if not isinstance(content, list) or block_index >= len(content):
            raise ResolutionIntegrityError("resolved tool input is unavailable")
        block = content[block_index]
        if not isinstance(block, dict) or block.get("type") != "tool_use" or "input" not in block:
            raise ResolutionIntegrityError("resolved tool input is unavailable")
        return block["input"]
    if not isinstance(target, str) or pointer["end"] > len(target):
        raise ResolutionIntegrityError("resolved pointer coordinates are invalid")
    return target[pointer["start"] : pointer["end"]]


def resolve_content_pointer(
    pointer: Mapping,
    *,
    live_records: Sequence[ResolutionRecord] | None = None,
    archive_records: Sequence[ResolutionRecord] | None = None,
) -> ContentResolution:
    """Resolve a supported transcript pointer live-first, then verified A9.

    Live and archive nonce layouts are independent because the live harness
    may already have pruned a prefix. Missing both authorities is honest
    UNKNOWN. Enrolled-repo target pointers are a separate extractor contract.
    """
    _validate_pointer(pointer)
    commitment = pointer["record_commitment"]
    live = _committed_record(live_records, commitment)
    if live is not None:
        return ContentResolution(
            status="resolved",
            source="live",
            value=_pointer_value(pointer, live),
        )
    archived = _committed_record(archive_records, commitment)
    if archived is not None:
        return ContentResolution(
            status="resolved",
            source="archive",
            value=_pointer_value(pointer, archived),
        )
    if archive_records is not None:
        raise ResolutionIntegrityError("archive record commitment mismatch")
    return ContentResolution(status="unknown", reason="target-missing")


def resolution_coverage(resolutions: Sequence[ContentResolution]) -> dict:
    """Counts-only coverage; UNKNOWN is never coerced to zero evidence."""
    if isinstance(resolutions, (str, bytes)) or not isinstance(resolutions, Sequence):
        raise NormalizationError("resolution coverage requires an explicit sequence")
    resolved = unknown = 0
    for result in resolutions:
        if not isinstance(result, ContentResolution):
            raise NormalizationError("resolution coverage received an invalid result")
        if (
            result.status == "resolved"
            and result.source in {"live", "archive"}
            and result.reason is None
        ):
            resolved += 1
        elif (
            result.status == "unknown"
            and result.source is None
            and result.reason == "target-missing"
            and result.value is None
        ):
            unknown += 1
        else:
            raise NormalizationError("resolution coverage received an unknown status")
    if not resolutions:
        coverage_class = "not-applicable"
    elif unknown == 0:
        coverage_class = "complete"
    elif resolved == 0:
        coverage_class = "none"
    else:
        coverage_class = "partial"
    return {
        "coverage_class": coverage_class,
        "references_total": len(resolutions),
        "references_resolved": resolved,
        "references_unknown": unknown,
    }
