"""Trusted A2/A3/A9 loader for owner-supervised Claude normalization.

This module is intentionally narrower than source discovery.  It reads only
sessions that capture has already admitted to the private commitment ledger
and archived under A9, authenticates every raw record with its saved nonce,
and returns wrappers whose byte fields are hidden from ``repr``.  It never
logs or returns source paths.
"""

from __future__ import annotations

import json

from mybench import archive, commitments, nonces
from mybench.daemon.capture import capture_scan_lock
from mybench.ledger import Ledger
from mybench.normalizer.claude import (
    GitBindingObservation,
    VerifiedRecord,
    VerifiedSession,
)


class NormalizerLoaderError(RuntimeError):
    """A generic trusted-loader refusal with no private field in its message."""


class _DuplicateKey(ValueError):
    pass


def _observed_context_generations(items: tuple[bytes, ...]) -> dict[int, int]:
    """Number explicit compact boundaries in one session, starting at one."""

    def reject_duplicate(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateKey
            result[key] = value
        return result

    generation = 0
    observed = {}
    for index, raw in enumerate(items):
        try:
            value = json.loads(raw, object_pairs_hook=reject_duplicate)
        except (UnicodeDecodeError, ValueError, RecursionError):
            continue
        if (
            isinstance(value, dict)
            and value.get("type") == "system"
            and value.get("subtype") == "compact_boundary"
        ):
            generation += 1
            observed[index] = generation
    return observed


def _latest_claude_rows(rows: list[dict]) -> list[dict]:
    latest = {}
    for row in rows:
        if row.get("type") != "session" or row.get("source") != "claude-code":
            continue
        prior = latest.get(row["session_id"])
        if prior is None or row["item_count"] >= prior["item_count"]:
            latest[row["session_id"]] = row
    return sorted(latest.values(), key=lambda row: row["session_id"].encode())


def _lifecycle_observation(rows: list[dict], session_id: str) -> dict:
    """Return a conservative A3 boundary/binding view for one opaque session."""
    lifecycle = [
        row
        for row in rows
        if row.get("type") == "event"
        and row.get("harness") == "claude-code"
        and row.get("session_id") == session_id
    ]
    starts = sorted(
        (row for row in lifecycle if row.get("event_kind") == "session_start"),
        key=lambda row: row["i"],
    )
    ends = sorted(
        (row for row in lifecycle if row.get("event_kind") == "session_end"),
        key=lambda row: row["i"],
    )
    result = {
        "started_at": starts[0]["ts"] if starts else None,
        "ended_at": ends[-1]["ts"] if ends else None,
    }
    # Multiple starts/ends can describe resumes or an ambiguous delivery
    # history.  Preserve timestamp coverage, but never guess one Git range.
    if len(starts) != 1 or len(ends) != 1:
        return result
    start, end = starts[0], ends[0]
    if start["i"] >= end["i"]:
        return result
    start_fields = {"repo_id", "worktree_id", "head_before"}
    end_fields = {"repo_id", "worktree_id", "head_after"}
    if not start_fields <= set(start) or not end_fields <= set(end):
        return result
    if (
        start["repo_id"] != end["repo_id"]
        or start["worktree_id"] != end["worktree_id"]
    ):
        return result
    bindings = tuple(
        GitBindingObservation(
            row_index=row["i"],
            repo_id=row["repo_id"],
            commit_hash=row["commit_hash"],
        )
        for row in rows
        if row.get("type") == "binding"
        and start["i"] < row["i"] < end["i"]
        and row.get("repo_id") == start["repo_id"]
    )
    return {
        **result,
        "repo_id": start["repo_id"],
        "head_before": start["head_before"],
        "head_after": end["head_after"],
        "start_row_index": start["i"],
        "end_row_index": end["i"],
        "binding_observations": bindings,
    }


def load_owner_claude_sessions(*, confirm_subject_owned: bool) -> tuple[VerifiedSession, ...]:
    """Load a consistent, authenticated owner-corpus snapshot from A2/A3/A9.

    ``confirm_subject_owned`` has no permissive default.  Passing literal
    ``True`` is the supervised owner's assertion that these local harness
    sessions are the credentialed subject's human activity and own agent
    fleet.  Pasted spans and tool results remain subject to the normalizer's
    structural no-content rules; this confirmation creates no consent carveout.
    """
    if confirm_subject_owned is not True:
        raise NormalizerLoaderError("owner subject confirmation is required")

    try:
        with capture_scan_lock():
            ledger = Ledger()
            ledger.verify_chain()
            ledger_rows = ledger.rows()
            rows = _latest_claude_rows(ledger_rows)
            if not rows:
                raise NormalizerLoaderError("no committed Claude sessions are available")

            sessions = []
            for row in rows:
                saved_nonces = nonces.load_nonces(row["session_id"])
                if len(saved_nonces) < row["item_count"]:
                    raise NormalizerLoaderError("saved nonce coverage is incomplete")
                saved_nonces = saved_nonces[: row["item_count"]]
                items = archive.read_verified_items(
                    source="claude-code",
                    session_id=row["session_id"],
                    nonces=saved_nonces,
                    expected_item_count=row["item_count"],
                    expected_session_root=row["session_root"],
                )
                generations = _observed_context_generations(items)
                lifecycle = _lifecycle_observation(ledger_rows, row["session_id"])
                records = tuple(
                    VerifiedRecord(
                        index=index,
                        raw_bytes=raw,
                        record_commitment=commitments.leaf_commitment(
                            saved_nonces[index], raw
                        ).hex(),
                        attribution="subject",
                        context_generation_id=generations.get(index),
                    )
                    for index, raw in enumerate(items)
                )
                sessions.append(
                    VerifiedSession(
                        source="claude-code",
                        session_id=row["session_id"],
                        session_root=row["session_root"],
                        records=records,
                        subject_owned=True,
                        **lifecycle,
                    )
                )
    except NormalizerLoaderError:
        raise
    except Exception:
        # Library exceptions may carry a private local path.  Never relay one
        # across the operator boundary.
        raise NormalizerLoaderError("owner corpus loading failed") from None

    return tuple(sessions)
