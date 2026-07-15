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
from mybench.normalizer.claude import VerifiedRecord, VerifiedSession


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
            rows = _latest_claude_rows(ledger.rows())
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
                    )
                )
    except NormalizerLoaderError:
        raise
    except Exception:
        # Library exceptions may carry a private local path.  Never relay one
        # across the operator boundary.
        raise NormalizerLoaderError("owner corpus loading failed") from None

    return tuple(sessions)
