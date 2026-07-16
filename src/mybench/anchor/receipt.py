"""Private anchor-receipt lookup and deterministic latency derivation (MYB-9.5).

The public anchor event remains date-only.  This module joins that event to
its machine-local ``anchor_receipt`` ledger row and uses ``receipt_ts`` — never
the row's append-time ``ts`` — as the latency endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Mapping, Sequence


class ReceiptError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReceiptLatencies:
    """Exact local-clock intervals for one anchor receipt."""

    per_row: tuple[tuple[int, timedelta], ...]
    batch: timedelta


def _parse_timestamp(value: object, context: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ReceiptError(f"{context} is not a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ReceiptError(f"{context} is not a valid UTC timestamp") from exc
    if parsed.tzinfo != UTC:
        raise ReceiptError(f"{context} is not a UTC timestamp")
    return parsed


def receipt_for_event(
    rows: Sequence[Mapping[str, object]], event: Mapping[str, object]
) -> Mapping[str, object] | None:
    """Return the exact private receipt, or ``None`` when its time is unknown."""
    identity = (
        event.get("row_start"),
        event.get("row_end"),
        event.get("root"),
        event.get("chain_tip"),
    )
    matches = [
        row
        for row in rows
        if row.get("type") == "anchor_receipt"
        and (
            row.get("anchor_row_start"),
            row.get("anchor_row_end"),
            row.get("anchor_root"),
            row.get("anchor_chain_tip"),
        )
        == identity
    ]
    if len(matches) > 1:
        raise ReceiptError("multiple private receipts match one anchor event")
    return matches[0] if matches else None


def derive_receipt_latencies(
    rows: Sequence[Mapping[str, object]], event: Mapping[str, object]
) -> ReceiptLatencies | None:
    """Derive per-row and batch latency, or ``None`` for an unknown receipt.

    Per-row latency is ``receipt_ts - covered row ts``.  Batch latency is
    ``receipt_ts - newest covered row ts``.  Negative intervals fail closed.
    """
    receipt = receipt_for_event(rows, event)
    if receipt is None:
        return None
    try:
        row_start = int(event["row_start"])
        row_end = int(event["row_end"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ReceiptError("anchor event has an invalid covered range") from exc
    if row_start < 0 or row_end <= row_start or row_end > len(rows):
        raise ReceiptError("anchor event covered range is outside the ledger")

    endpoint = _parse_timestamp(receipt.get("receipt_ts"), "receipt_ts")
    intervals = []
    covered_times = []
    for index, row in enumerate(rows[row_start:row_end], start=row_start):
        row_time = _parse_timestamp(row.get("ts"), f"covered row {index} ts")
        latency = endpoint - row_time
        if latency < timedelta(0):
            raise ReceiptError(f"receipt_ts predates covered row {index}")
        covered_times.append(row_time)
        intervals.append((index, latency))

    batch = endpoint - max(covered_times)
    if batch < timedelta(0):  # defensive; the per-row checks above already prove this
        raise ReceiptError("receipt_ts predates the newest covered row")
    return ReceiptLatencies(tuple(intervals), batch)
