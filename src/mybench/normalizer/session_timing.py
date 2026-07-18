"""Private structural session-timing normalization (MYB-19.10).

The output of this module is an in-memory, local-only intermediate.  It
contains exact observed timestamps because the duration scorer needs them,
but it deliberately contains no session identifier, transcript content, or
source path.  Only the scorer's coarse registry bands may cross a publication
boundary.

Codex has no capture-side ``session_end`` in ADR-0013 v0.  Its close is
therefore inferred only when the rollout contains a timestamped structural
``task_complete`` record.  The timestamp on the last such record is the close;
the last arbitrary rollout timestamp is never substituted.  Missing or
malformed terminal evidence produces ``unknown``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from mybench.claims.canonical import canonical_bytes
from mybench.normalizer.claude import (
    NoEvidence,
    NormalizationError,
    VerifiedSession,
    _canonical_timestamp,
    _check_input_sessions,
    _json_object,
)

SESSION_TIMING_NORMALIZER_VERSION = "1.0.0"

_SOURCES = frozenset({"claude-code", "codex"})
_OPEN_STATUSES = frozenset({"observed", "scan-inferred", "unknown"})
_CLOSE_STATUSES = frozenset({"observed", "scan-inferred", "unknown"})
_OBSERVED_AT_STATUSES = frozenset({"complete", "partial", "unknown"})


@dataclass(frozen=True)
class SessionTiming:
    """One identifier-free, private duration-scorer input.

    Exact timestamps are hidden from ``repr`` to keep diagnostic surfaces
    structural.  :meth:`local_record` exists for deterministic local
    serialization tests and is never a publishable report shape.
    """

    source: str
    open_status: str
    close_status: str
    observed_at_status: str
    opened_at: str | None = field(default=None, repr=False)
    closed_at: str | None = field(default=None, repr=False)
    event_observed_at: tuple[str, ...] = field(default=(), repr=False)
    normalizer_version: str = SESSION_TIMING_NORMALIZER_VERSION

    def __post_init__(self) -> None:
        if (
            self.normalizer_version != SESSION_TIMING_NORMALIZER_VERSION
            or self.source not in _SOURCES
            or self.open_status not in _OPEN_STATUSES
            or self.close_status not in _CLOSE_STATUSES
            or self.observed_at_status not in _OBSERVED_AT_STATUSES
        ):
            raise NormalizationError("session timing has an invalid structural state")
        if (self.opened_at is None) != (self.open_status == "unknown"):
            raise NormalizationError("session timing has an inconsistent open boundary")
        if (self.closed_at is None) != (self.close_status == "unknown"):
            raise NormalizationError("session timing has an inconsistent close boundary")
        for value in (self.opened_at, self.closed_at, *self.event_observed_at):
            if value is not None and _canonical_timestamp(value) != value:
                raise NormalizationError("session timing has an invalid temporal observation")
        if tuple(sorted(self.event_observed_at)) != self.event_observed_at:
            raise NormalizationError("session timing observations are not ordered")
        if len(set(self.event_observed_at)) != len(self.event_observed_at):
            raise NormalizationError("session timing observations are not unique")
        if (
            self.opened_at is not None
            and self.closed_at is not None
            and self.opened_at > self.closed_at
        ):
            raise NormalizationError("session timing boundaries are reversed")
        if self.observed_at_status == "unknown" and self.event_observed_at:
            raise NormalizationError("unknown observed-at coverage cannot carry observations")

    def local_record(self) -> dict:
        """Return the closed, identifier-free local intermediate shape."""

        return {
            "normalizer_version": self.normalizer_version,
            "source": self.source,
            "open_status": self.open_status,
            "close_status": self.close_status,
            "observed_at_status": self.observed_at_status,
            "opened_at": self.opened_at or "unknown",
            "closed_at": self.closed_at or "unknown",
            "event_observed_at": list(self.event_observed_at),
        }


def _marker(
    records: Sequence[tuple[int, Mapping | None, str | None]],
    predicate,
    *,
    last: bool,
) -> tuple[int, str | None] | None:
    matches = [
        (index, observed_at)
        for index, value, observed_at in records
        if value is not None and predicate(value)
    ]
    if not matches:
        return None
    return matches[-1] if last else matches[0]


def _is_claude_marker(value: Mapping, subtype: str) -> bool:
    return value.get("type") == "system" and value.get("subtype") == subtype


def _is_codex_session_meta(value: Mapping) -> bool:
    return value.get("type") == "session_meta" and isinstance(value.get("payload"), Mapping)


def _is_codex_task_complete(value: Mapping) -> bool:
    payload = value.get("payload")
    return (
        value.get("type") == "event_msg"
        and isinstance(payload, Mapping)
        and payload.get("type") == "task_complete"
    )


def _normalize_one(session: VerifiedSession) -> SessionTiming:
    # The shared consent filter retains ``unknown`` records for shape-only
    # normalizers. Exact timing observations are stricter: only records
    # explicitly attributed to the subject may contribute a timestamp.
    subject_records = [record for record in session.records if record.attribution == "subject"]
    decoded = []
    for record in subject_records:
        value = _json_object(record.raw_bytes)
        observed_at = _canonical_timestamp(value.get("timestamp")) if value is not None else None
        decoded.append((record.index, value, observed_at))

    if session.source == "codex":
        raw_open = _marker(decoded, _is_codex_session_meta, last=False)
        raw_close = _marker(decoded, _is_codex_task_complete, last=True)
        if session.started_at is not None:
            opened_at, open_status, open_index = session.started_at, "observed", None
        elif raw_open is not None and raw_open[1] is not None:
            open_index, opened_at = raw_open
            open_status = "scan-inferred"
        else:
            opened_at, open_status = None, "unknown"
            open_index = raw_open[0] if raw_open is not None else None
        if session.ended_at is not None:
            closed_at, close_status, close_index = session.ended_at, "observed", None
        elif raw_close is not None and raw_close[1] is not None:
            close_index, closed_at = raw_close
            close_status = "scan-inferred"
        else:
            closed_at, close_status = None, "unknown"
            close_index = raw_close[0] if raw_close is not None else None
    else:
        raw_open = _marker(
            decoded,
            lambda value: _is_claude_marker(value, "session_start"),
            last=False,
        )
        raw_close = _marker(
            decoded,
            lambda value: _is_claude_marker(value, "session_end"),
            last=True,
        )
        if session.started_at is not None:
            opened_at, open_status, open_index = session.started_at, "observed", None
        elif raw_open is not None and raw_open[1] is not None:
            open_index, opened_at = raw_open
            open_status = "observed"
        else:
            opened_at, open_status = None, "unknown"
            open_index = raw_open[0] if raw_open is not None else None
        if session.ended_at is not None:
            closed_at, close_status, close_index = session.ended_at, "observed", None
        elif raw_close is not None and raw_close[1] is not None:
            close_index, closed_at = raw_close
            close_status = "observed"
        else:
            closed_at, close_status = None, "unknown"
            close_index = raw_close[0] if raw_close is not None else None

    # A reversed raw boundary is ambiguous rather than a negative duration.
    # Keep the structural marker indexes even when rejecting their timestamps:
    # they still bound the eligible record interval, so arbitrary records after
    # a malformed/reversed terminal marker cannot become timing observations.
    if opened_at is not None and closed_at is not None and opened_at > closed_at:
        closed_at, close_status = None, "unknown"

    eligible = [
        record
        for record in decoded
        if (open_index is None or record[0] >= open_index)
        and (close_index is None or record[0] <= close_index)
    ]
    valid_observations = []
    complete = bool(eligible)
    for _, value, observed_at in eligible:
        if value is None or observed_at is None:
            complete = False
            continue
        if opened_at is not None and observed_at < opened_at:
            complete = False
            continue
        if closed_at is not None and observed_at > closed_at:
            complete = False
            continue
        valid_observations.append(observed_at)
    observed_at = tuple(sorted(set(valid_observations)))
    observed_at_status = "unknown" if not eligible else "complete" if complete else "partial"

    return SessionTiming(
        source=session.source,
        open_status=open_status,
        close_status=close_status,
        observed_at_status=observed_at_status,
        opened_at=opened_at,
        closed_at=closed_at,
        event_observed_at=observed_at,
    )


def normalize_session_timings(sessions: Sequence[VerifiedSession]) -> tuple[SessionTiming, ...]:
    """Normalize explicit verified sessions into identifier-free timing inputs.

    The result order is independent of caller order.  Known non-subject
    sessions are filtered before their remaining fields are inspected, using
    the same ADR-0018 gate as the A8 transcript normalizers.
    """

    if isinstance(sessions, (str, bytes)) or not isinstance(sessions, Sequence):
        raise NormalizationError("sessions must be an explicit sequence")
    if not sessions:
        raise NoEvidence("no verified sessions; no session timing was created")

    admitted: list[VerifiedSession] = []
    seen = set()
    for session in sessions:
        if not isinstance(session, VerifiedSession):
            raise NormalizationError("session timing input has the wrong type")
        if session.subject_owned is not True:
            continue
        if session.source not in _SOURCES:
            raise NormalizationError("session timing input has an unsupported source")
        checked = _check_input_sessions((session,), expected_source=session.source)
        if not checked:
            continue
        normalized = checked[0]
        key = (normalized.source, normalized.session_id)
        if key in seen:
            raise NormalizationError("duplicate opaque session timing input")
        seen.add(key)
        admitted.append(normalized)
    if not admitted:
        raise NoEvidence("no subject-owned session timing evidence")

    admitted.sort(key=lambda item: (item.source.encode(), item.session_id.encode()))
    return tuple(_normalize_one(session) for session in admitted)


def normalize_session_timing_bytes(sessions: Sequence[VerifiedSession]) -> bytes:
    """Return deterministic local-only bytes for the versioned timing output."""

    timings = normalize_session_timings(sessions)
    return canonical_bytes([timing.local_record() for timing in timings]) + b"\n"


__all__ = [
    "SESSION_TIMING_NORMALIZER_VERSION",
    "SessionTiming",
    "normalize_session_timing_bytes",
    "normalize_session_timings",
]
