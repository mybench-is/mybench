"""MYB-12.5: reserved, private MYB-9.5 anchor-receipt ledger branch."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization

from mybench import paths
import mybench.anchor.__main__ as anchor_main
from mybench.anchor.__main__ import cut, main as anchor_cli
from mybench.anchor.batch import build_batch, signed_bytes
from mybench.anchor.event import build_event, event_bytes, stage_event
from mybench.anchor.receipt import (
    ReceiptError,
    derive_receipt_latencies,
    receipt_for_event,
)
from mybench.ledger import (
    ANCHOR_RECEIPT_DOMAIN,
    GENESIS_PREV,
    Ledger,
    LedgerError,
    anchor_receipt_id,
    row_hash,
)
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures
from tests.fixtures.ledgers import build_canary_ledger

ROW_TS = "2026-07-16T12:00:00Z"
RECEIPT_TS = "2026-07-16T12:01:00Z"
APPEND_TS = "2026-07-16T12:02:00Z"
SCOPE_KEY = bytes.fromhex("42" * 32)


def ledger_and_event() -> tuple[Ledger, dict]:
    ledger = Ledger()
    ledger.append_session(
        session_id="synthetic-receipt-session",
        session_root=bytes.fromhex("23" * 32),
        item_count=3,
        source="synthetic",
        ts=ROW_TS,
    )
    event = build_event(build_batch(ledger), ledger.rows(), date="2026-07-16")
    return ledger, event


def resign(event: dict) -> dict:
    result = dict(event)
    key_path, _ = paths.ensure_device_key()
    private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    result["sig"] = private.sign(signed_bytes(result)).hex()
    return result


def test_receipt_id_uses_exact_typed_canonical_event_identity():
    _, event = ledger_and_event()
    identity = {
        name: event[name]
        for name in ("identity_id", "date", "row_start", "row_end", "root", "chain_tip")
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(
        SCOPE_KEY, ANCHOR_RECEIPT_DOMAIN + encoded, hashlib.sha256
    ).hexdigest()[:16]
    assert anchor_receipt_id(event, SCOPE_KEY) == expected
    assert len(expected) == 16 and expected == expected.lower()
    with pytest.raises(LedgerError, match="32-byte"):
        anchor_receipt_id(event, b"short")


def test_append_receipt_has_exact_closed_shape_and_verifies_chain():
    ledger, event = ledger_and_event()
    row = ledger.append_anchor_receipt(
        staged_event=event,
        receipt_ts=RECEIPT_TS,
        ts=APPEND_TS,
        scope_key=SCOPE_KEY,
    )
    assert row is not None
    assert set(row) == {
        "schema_version",
        "i",
        "type",
        "ts",
        "prev",
        "h",
        "anchor_row_start",
        "anchor_row_end",
        "anchor_root",
        "anchor_chain_tip",
        "receipt_ts",
        "receipt_id",
    }
    assert row["schema_version"] == "2" and row["type"] == "anchor_receipt"
    assert row["ts"] == APPEND_TS and row["receipt_ts"] == RECEIPT_TS
    assert row["anchor_row_start"] == event["row_start"]
    assert row["anchor_row_end"] == event["row_end"]
    assert row["anchor_root"] == event["root"]
    assert row["anchor_chain_tip"] == event["chain_tip"]
    assert row["receipt_id"] == anchor_receipt_id(event, SCOPE_KEY)
    assert ledger.verify_chain() == 3

    for forbidden in ("session_id", "context_gen", "harness", "trigger", "nonce"):
        assert forbidden not in row


def test_exact_receipt_replay_is_idempotent_but_conflicting_clock_fails():
    ledger, event = ledger_and_event()
    kwargs = {
        "staged_event": event,
        "receipt_ts": RECEIPT_TS,
        "ts": APPEND_TS,
        "scope_key": SCOPE_KEY,
    }
    assert ledger.append_anchor_receipt(**kwargs) is not None
    baseline = ledger.path.read_bytes()
    assert ledger.append_anchor_receipt(**kwargs) is None
    assert ledger.path.read_bytes() == baseline
    with pytest.raises(LedgerError, match="conflicting"):
        ledger.append_anchor_receipt(
            staged_event=event,
            receipt_ts="2026-07-16T12:01:30Z",
            ts=APPEND_TS,
            scope_key=SCOPE_KEY,
        )
    assert ledger.verify_chain() == 3


@pytest.mark.parametrize("field", ["root", "chain_tip"])
def test_signed_but_ledger_inconsistent_event_fails_semantic_validation(field):
    ledger, event = ledger_and_event()
    tampered = resign({**event, field: "f" * 64})
    with pytest.raises(LedgerError, match="root|chain tip"):
        ledger.append_anchor_receipt(
            staged_event=tampered,
            receipt_ts=RECEIPT_TS,
            ts=APPEND_TS,
            scope_key=SCOPE_KEY,
        )
    assert ledger.verify_chain() == 2


def test_signed_event_range_must_exist_in_the_recomputed_ledger():
    ledger, event = ledger_and_event()
    tampered = resign(
        {
            **event,
            "row_end": event["row_end"] + 1,
            "row_count": event["row_count"] + 1,
        }
    )
    with pytest.raises(LedgerError, match="outside"):
        ledger.append_anchor_receipt(
            staged_event=tampered,
            receipt_ts=RECEIPT_TS,
            ts=APPEND_TS,
            scope_key=SCOPE_KEY,
        )


@pytest.mark.parametrize(
    ("receipt_ts", "append_ts", "match"),
    [
        ("2026-07-16T11:59:59Z", APPEND_TS, "predates a covered"),
        (RECEIPT_TS, "2026-07-16T12:00:30Z", "append ts predates"),
    ],
)
def test_impossible_receipt_timestamp_ordering_fails_closed(receipt_ts, append_ts, match):
    ledger, event = ledger_and_event()
    with pytest.raises(LedgerError, match=match):
        ledger.append_anchor_receipt(
            staged_event=event,
            receipt_ts=receipt_ts,
            ts=append_ts,
            scope_key=SCOPE_KEY,
        )
    assert ledger.verify_chain() == 2


def test_unsigned_or_mutated_staged_event_is_rejected_before_append():
    ledger, event = ledger_and_event()
    with pytest.raises(LedgerError, match="staged event"):
        ledger.append_anchor_receipt(
            staged_event={**event, "date": "2026-07-17"},
            receipt_ts=RECEIPT_TS,
            ts=APPEND_TS,
            scope_key=SCOPE_KEY,
        )


def test_receipt_fields_and_id_never_enter_public_event_or_staging():
    ledger, event = ledger_and_event()
    before = event_bytes(event)
    event_path, proof_path = stage_event(
        event, b"synthetic-pending-proof", paths.anchors_dir()
    )
    row = ledger.append_anchor_receipt(
        staged_event=event,
        receipt_ts=RECEIPT_TS,
        ts=APPEND_TS,
        scope_key=SCOPE_KEY,
    )
    assert event_path.read_bytes() == before
    assert proof_path.read_bytes() == b"synthetic-pending-proof"
    staged = event_path.read_bytes() + proof_path.read_bytes()
    for field in (b"receipt_ts", b"receipt_id", row["receipt_id"].encode()):
        assert field not in staged


def test_receipt_schema_rejects_missing_or_session_lifecycle_fields():
    ledger, event = ledger_and_event()
    row = ledger.append_anchor_receipt(
        staged_event=event,
        receipt_ts=RECEIPT_TS,
        ts=APPEND_TS,
        scope_key=SCOPE_KEY,
    )
    assert row is not None
    missing = {name: value for name, value in row.items() if name != "receipt_ts"}
    missing["h"] = row_hash(missing)
    with pytest.raises(LedgerError, match="schema"):
        ledger._validate_row(missing, "synthetic missing receipt field")
    for forbidden in ("session_id", "context_gen", "harness", "trigger"):
        injected = {**row, forbidden: "synthetic"}
        if forbidden == "context_gen":
            injected[forbidden] = 0
        injected["h"] = row_hash(injected)
        with pytest.raises(LedgerError, match="schema"):
            ledger._validate_row(injected, "synthetic forbidden receipt field")


def test_frozen_v1_rows_validate_unchanged_and_are_not_rewritten():
    paths.ensure_data_dir()
    ledger = Ledger()
    genesis = {
        "schema_version": "1",
        "i": 0,
        "type": "genesis",
        "ts": ROW_TS,
        "prev": GENESIS_PREV,
    }
    genesis["h"] = row_hash(genesis)
    session = {
        "schema_version": "1",
        "i": 1,
        "type": "session",
        "ts": ROW_TS,
        "prev": genesis["h"],
        "session_id": "synthetic-frozen-v1",
        "session_root": "34" * 32,
        "item_count": 1,
        "source": "synthetic",
    }
    session["h"] = row_hash(session)
    frozen = b"".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        for row in (genesis, session)
    )
    ledger.path.write_bytes(frozen)
    ledger.path.chmod(0o600)
    assert ledger.verify_chain() == 2

    ledger.append_session(
        session_id="synthetic-new-v2",
        session_root=bytes.fromhex("45" * 32),
        item_count=2,
        source="synthetic",
        ts=APPEND_TS,
    )
    assert ledger.path.read_bytes().startswith(frozen)
    assert ledger.rows()[-1]["schema_version"] == "2"
    assert ledger.verify_chain() == 3


def test_cut_stages_before_appending_first_response_receipt(calendar, monkeypatch):
    ledger, _event = ledger_and_event()
    real_stage = anchor_main.stage_event
    order = []

    def observed_stage(event, proof, staging):
        assert receipt_for_event(ledger.rows(), event) is None
        order.append("stage")
        return real_stage(event, proof, staging)

    monkeypatch.setattr(anchor_main, "stage_event", observed_stage)
    result = cut(
        "2026-07-16",
        [calendar.base_url],
        ledger=ledger,
        receipt_clock=lambda: datetime(2026, 7, 16, 12, 1, tzinfo=UTC),
        append_ts=APPEND_TS,
    )
    order.append("append")

    assert order == ["stage", "append"]
    assert result.event_path.exists() and result.proof_path.exists()
    assert result.receipt["receipt_ts"] == "2026-07-16T12:01:00.000000Z"
    assert result.receipt["ts"] == APPEND_TS
    assert receipt_for_event(ledger.rows(), result.event) == result.receipt
    assert ledger.verify_chain() == 3


def test_staging_failure_never_appends_a_receipt(calendar, monkeypatch):
    ledger, _event = ledger_and_event()

    def fail_stage(*args, **kwargs):
        raise anchor_main.EventError("synthetic stage failure")

    monkeypatch.setattr(anchor_main, "stage_event", fail_stage)
    with pytest.raises(anchor_main.EventError, match="stage failure"):
        cut(
            "2026-07-16",
            [calendar.base_url],
            ledger=ledger,
            receipt_clock=lambda: datetime(2026, 7, 16, 12, 1, tzinfo=UTC),
            append_ts=APPEND_TS,
        )
    assert all(row["type"] != "anchor_receipt" for row in ledger.rows())
    assert ledger.verify_chain() == 2


def test_staged_without_receipt_stays_unknown_across_recovery(calendar, monkeypatch):
    ledger, _event = ledger_and_event()

    def crash_after_stage(**kwargs):
        raise LedgerError("synthetic crash boundary")

    monkeypatch.setattr(ledger, "append_anchor_receipt", crash_after_stage)

    def first_clock():
        return datetime(2026, 7, 16, 12, 1, tzinfo=UTC)

    with pytest.raises(LedgerError, match="crash boundary"):
        cut(
            "2026-07-16",
            [calendar.base_url],
            ledger=ledger,
            receipt_clock=first_clock,
            append_ts=APPEND_TS,
        )

    event_path = next(paths.anchors_dir().rglob("*.json"))
    event = json.loads(event_path.read_bytes())
    assert receipt_for_event(ledger.rows(), event) is None
    assert derive_receipt_latencies(ledger.rows(), event) is None

    # Neither changed filesystem metadata nor a later retry clock may invent
    # the lost first-response instant.
    os.utime(event_path, (1_900_000_000, 1_900_000_000))
    retry_clock_calls = []
    with pytest.raises(anchor_main.EventError, match="one event per identity per UTC day"):
        cut(
            "2026-07-16",
            [calendar.base_url],
            ledger=ledger,
            receipt_clock=lambda: retry_clock_calls.append(datetime.now(UTC)),
            append_ts="2030-03-17T17:46:40Z",
        )
    assert retry_clock_calls == []
    assert receipt_for_event(ledger.rows(), event) is None
    assert ledger.verify_chain() == 2


def test_cut_retry_keeps_exactly_one_receipt(calendar):
    ledger, _event = ledger_and_event()
    result = cut(
        "2026-07-16",
        [calendar.base_url],
        ledger=ledger,
        receipt_clock=lambda: datetime(2026, 7, 16, 12, 1, tzinfo=UTC),
        append_ts=APPEND_TS,
    )
    baseline = ledger.path.read_bytes()
    with pytest.raises(anchor_main.EventError, match="one event per identity per UTC day"):
        cut(
            "2026-07-16",
            [calendar.base_url],
            ledger=ledger,
            receipt_clock=lambda: datetime(2026, 7, 16, 12, 5, tzinfo=UTC),
            append_ts="2026-07-16T12:06:00Z",
        )
    assert ledger.path.read_bytes() == baseline
    assert receipt_for_event(ledger.rows(), result.event) == result.receipt
    assert sum(row["type"] == "anchor_receipt" for row in ledger.rows()) == 1


def test_latency_derivation_uses_receipt_clock_not_append_clock():
    ledger, event = ledger_and_event()
    ledger.append_anchor_receipt(
        staged_event=event,
        receipt_ts=RECEIPT_TS,
        ts=APPEND_TS,
        scope_key=SCOPE_KEY,
    )
    derived = derive_receipt_latencies(ledger.rows(), event)
    assert derived is not None
    assert derived.per_row == ((0, timedelta(minutes=1)), (1, timedelta(minutes=1)))
    assert derived.batch == timedelta(minutes=1)
    assert derived.batch != timedelta(minutes=2)  # envelope append ts is not the endpoint


def test_negative_latency_derivation_fails_closed():
    ledger, event = ledger_and_event()
    ledger.append_anchor_receipt(
        staged_event=event,
        receipt_ts=RECEIPT_TS,
        ts=APPEND_TS,
        scope_key=SCOPE_KEY,
    )
    rows = ledger.rows()
    rows[-1] = {**rows[-1], "receipt_ts": "2026-07-16T11:59:59Z"}
    with pytest.raises(ReceiptError, match="predates covered row"):
        derive_receipt_latencies(rows, event)


def test_cut_receipt_surface_is_canary_clean_and_scanner_fires(
    tmp_path, calendar, capsys
):
    fixtures = generate_fixtures(tmp_path / "synthetic-fixtures")
    ledger, canaries = build_canary_ledger(fixtures)
    paths.ensure_identity_key()

    assert anchor_cli(
        ["cut", "--date", "2026-07-16", "--calendar", calendar.base_url]
    ) == 0
    captured = capsys.readouterr()
    log_path = tmp_path / "anchor-cut.log"
    log_path.write_text(captured.out + captured.err)
    event_path = next(paths.anchors_dir().rglob("*.json"))
    receipt = ledger.rows()[-1]

    assert receipt["type"] == "anchor_receipt"
    assert calendar.base_url not in json.dumps(receipt)
    assert calendar.base_url.encode() not in log_path.read_bytes()
    assert calendar.base_url.encode() not in event_path.read_bytes()
    for forbidden in ("receipt_ts", "receipt_id", "latency"):
        assert forbidden.encode() not in event_path.read_bytes()

    scanned = assert_no_canaries(
        [ledger.path, log_path, paths.anchors_dir()], canaries
    )
    assert scanned >= 4  # ledger, log, date-only event, and pending proof

    log_path.write_bytes(log_path.read_bytes() + canaries[0])
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([log_path], canaries)
