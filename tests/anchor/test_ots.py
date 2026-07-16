"""MYB-3.2: OTS stamping — wire discipline, pending→upgraded lifecycle, leak scan."""

import hashlib
import os
import stat
from datetime import UTC, datetime

import pytest
from opentimestamps.core.notary import PendingAttestation
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import Timestamp

from mybench import paths
from mybench.anchor import ots
from mybench.anchor.batch import build_batch
from tests.anchor.conftest import BLOCK_HEIGHT
from tests.fixtures import assert_no_canaries, generate_fixtures
from tests.fixtures.ledgers import build_canary_ledger


def calendar_response(root: bytes, uri: str) -> bytes:
    timestamp = Timestamp(root)
    timestamp.attestations.add(PendingAttestation(uri))
    context = BytesSerializationContext()
    timestamp.serialize(context)
    return context.getbytes()


@pytest.fixture
def canary_batch(tmp_path):
    fx = generate_fixtures(tmp_path / "fx")
    led, canaries = build_canary_ledger(fx)
    return build_batch(led), canaries


# --- Stamping + wire discipline (AC #1, #2) -----------------------------------------


def test_stamp_root_returns_pending_proof(calendar):
    root = hashlib.sha256(b"synthetic root").digest()
    proof = ots.stamp_root(root, calendars=[calendar.base_url])
    info = ots.proof_info(root, proof)
    assert info["digest_matches"]
    assert info["pending"] == [calendar.base_url]
    assert not info["confirmed"]


def test_wire_payload_is_exactly_the_root_digest(calendar, canary_batch):
    batch, canaries = canary_batch
    ots.stamp_root(bytes.fromhex(batch["root"]), calendars=[calendar.base_url])
    posts = [c for c in calendar.captures if c[0] == "POST"]
    assert len(posts) == 1
    method, path, body = posts[0]
    assert path == "/digest"
    assert body == bytes.fromhex(batch["root"]) and len(body) == 32
    for canary in canaries:  # nothing content/nonce-derived crosses the wire
        assert canary not in body and canary.hex().encode() not in body


def test_one_dead_calendar_does_not_block_stamping(calendar):
    root = hashlib.sha256(b"synthetic root 2").digest()
    proof = ots.stamp_root(
        root, calendars=["http://127.0.0.1:1", calendar.base_url], timeout=2.0
    )
    assert ots.proof_info(root, proof)["pending"] == [calendar.base_url]


def test_observed_stamp_freezes_first_success_while_later_attempts_finish(monkeypatch):
    root = hashlib.sha256(b"synthetic observed root").digest()
    calendars = [
        "https://synthetic-first.invalid",
        "https://synthetic-later.invalid",
        "https://synthetic-failure.invalid",
        "https://synthetic-timeout.invalid",
    ]
    calls = []

    def fake_http(url, data=None, timeout=15.0):
        calls.append((url, data, timeout))
        if "first" in url:
            return calendar_response(root, calendars[0])
        if "later" in url:
            return calendar_response(root, calendars[1])
        if "timeout" in url:
            raise TimeoutError("synthetic timeout")
        raise RuntimeError("synthetic failure")

    clock_calls = []

    def clock():
        clock_calls.append(len(calls))
        return datetime(2026, 7, 16, 12, 1, 2, 345678, tzinfo=UTC)

    monkeypatch.setattr(ots, "_http", fake_http)
    result = ots.stamp_root_observed(root, calendars=calendars, clock=clock)

    assert result.receipt_ts == "2026-07-16T12:01:02.345678Z"
    assert clock_calls == [1]
    assert len(calls) == 4  # later success/failure/timeout attempts still ran
    assert ots.proof_info(root, result.proof)["pending"] == calendars[:2]


def test_observed_stamp_ignores_responses_that_do_not_deserialize(monkeypatch):
    root = hashlib.sha256(b"synthetic deserialize root").digest()
    calendars = ["https://synthetic-bad.invalid", "https://synthetic-good.invalid"]
    calls = []

    def fake_http(url, data=None, timeout=15.0):
        calls.append(url)
        if "bad" in url:
            return b"not-an-ots-timestamp"
        return calendar_response(root, calendars[1])

    observed_after_attempt = []

    def clock():
        observed_after_attempt.append(len(calls))
        return datetime(2026, 7, 16, 12, 2, tzinfo=UTC)

    monkeypatch.setattr(ots, "_http", fake_http)
    result = ots.stamp_root_observed(root, calendars=calendars, clock=clock)
    assert observed_after_attempt == [2]
    assert result.receipt_ts == "2026-07-16T12:02:00.000000Z"


def test_all_calendars_dead_is_an_error():
    private_url = "http://127.0.0.1:1/synthetic-private-calendar"
    with pytest.raises(ots.OtsError, match="no calendar") as raised:
        ots.stamp_root(bytes(32), calendars=[private_url], timeout=2.0)
    assert private_url not in str(raised.value)


def test_all_calendar_failures_never_sample_receipt_clock(monkeypatch):
    def fail(*args, **kwargs):
        raise TimeoutError("synthetic")

    calls = []
    monkeypatch.setattr(ots, "_http", fail)
    with pytest.raises(ots.OtsError, match="no calendar"):
        ots.stamp_root_observed(
            bytes(32),
            calendars=["https://one.invalid", "https://two.invalid"],
            clock=lambda: calls.append(True),
        )
    assert calls == []


def test_bad_digest_length_rejected():
    with pytest.raises(ots.OtsError, match="32-byte"):
        ots.stamp_root(b"short", calendars=["http://127.0.0.1:1"])


# --- Storage + upgrade lifecycle (AC #3, #4) ------------------------------------------


def test_stamp_batch_stores_under_data_dir_idempotently(calendar, canary_batch):
    batch, _ = canary_batch
    artifact, proof = ots.stamp_batch(batch, calendars=[calendar.base_url])
    assert artifact.parent == proof.parent == paths.anchors_dir()
    for p in (artifact, proof):
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    stamps = len([c for c in calendar.captures if c[0] == "POST"])
    ots.stamp_batch(batch, calendars=[calendar.base_url])  # second call: no restamp
    assert len([c for c in calendar.captures if c[0] == "POST"]) == stamps
    tampered = dict(batch, ts="2027-01-01T00:00:00Z")
    with pytest.raises(ots.OtsError, match="refusing overwrite"):
        ots.stamp_batch(tampered, calendars=[calendar.base_url])


def test_upgrade_path_pending_to_bitcoin(calendar, canary_batch):
    batch, _ = canary_batch
    root = bytes.fromhex(batch["root"])
    _, proof_path = ots.stamp_batch(batch, calendars=[calendar.base_url])
    assert not ots.proof_info(root, proof_path.read_bytes())["confirmed"]
    assert ots.upgrade_batch_proof(proof_path) is True
    info = ots.proof_info(root, proof_path.read_bytes())
    assert info["confirmed"] and info["bitcoin_heights"] == [BLOCK_HEIGHT]
    assert info["digest_matches"]


def test_proof_info_detects_wrong_root(calendar):
    root = hashlib.sha256(b"synthetic root 3").digest()
    proof = ots.stamp_root(root, calendars=[calendar.base_url])
    assert ots.proof_info(bytes(32), proof)["digest_matches"] is False
    with pytest.raises(ots.OtsError, match="unparseable"):
        ots.proof_info(root, b"garbage")


# --- Leak scan (AC #5) -----------------------------------------------------------------


def test_stored_artifact_and_proof_are_leak_free(calendar, canary_batch):
    batch, canaries = canary_batch
    artifact, proof = ots.stamp_batch(batch, calendars=[calendar.base_url])
    ots.upgrade_batch_proof(proof)
    assert assert_no_canaries([artifact, proof], canaries) == 2


# --- Live network check (optional; SETUP_TODO #4) ----------------------------------------


@pytest.mark.skipif(
    not os.environ.get("MYBENCH_LIVE_OTS"),
    reason="live public-calendar test; set MYBENCH_LIVE_OTS=1 (network, synthetic digest only)",
)
def test_live_public_calendars_accept_synthetic_digest():
    root = hashlib.sha256(b"mybench synthetic live-test digest").digest()
    proof = ots.stamp_root(root, timeout=30.0)
    info = ots.proof_info(root, proof)
    assert info["digest_matches"] and info["pending"]
