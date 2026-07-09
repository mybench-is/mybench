"""MYB-3.1: anchor batch builder — determinism, whitelist, continuity, leaks."""

import hashlib
import json
import random
import subprocess
import sys

import pytest

from mybench import commitments as c
from mybench.anchor.batch import (
    AnchorError,
    build_batch,
    canonical_bytes,
    validate_batch,
    verify_batch,
)
from mybench.ledger import Ledger
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures

TS = "2026-01-01T00:00:{i:02d}Z"


@pytest.fixture
def fx(tmp_path):
    return generate_fixtures(tmp_path / "fx")


@pytest.fixture
def canary_ledger(fx):
    """Ledger whose session roots commit canary-fixture content via canary nonces."""
    led = Ledger()
    used = []
    for i, s in enumerate(fx.sessions * 3):  # 9 session rows
        items = s.read_bytes().splitlines()
        nonces = list(fx.nonce_canaries[: len(items)])
        nonces += [c.generate_nonce() for _ in items[len(nonces) :]]
        used.extend(nonces)
        leaves = [c.leaf_commitment(k, m) for k, m in zip(nonces, items)]
        led.append_session(
            session_id=f"synthetic-{i}",
            session_root=c.session_root(leaves),
            item_count=len(items),
            source="synthetic",
            ts=TS.format(i=i),
        )
    return led, fx.all_canaries() + used


# --- Determinism (AC #1) ---------------------------------------------------------


def test_same_ledger_prefix_gives_byte_identical_artifact(canary_ledger):
    led, _ = canary_ledger
    a = canonical_bytes(build_batch(Ledger()))
    b = canonical_bytes(build_batch(Ledger()))  # fresh objects, fresh validator
    assert a == b
    # And across a process boundary: a subprocess builds the same bytes.
    script = (
        "from mybench.anchor.batch import build_batch, canonical_bytes;"
        "import hashlib;"
        "print(hashlib.sha256(canonical_bytes(build_batch())).hexdigest())"
    )
    out = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == hashlib.sha256(a).hexdigest()


def test_ts_is_ledger_derived_not_build_time(canary_ledger):
    led, _ = canary_ledger
    batch = build_batch(led)
    assert batch["ts"] == max(r["ts"] for r in led.rows())


# --- Schema whitelist (AC #2) -----------------------------------------------------


def test_valid_batch_passes_and_verifies(canary_ledger):
    led, _ = canary_ledger
    batch = build_batch(led)
    validate_batch(batch)
    verify_batch(batch, led.rows())


def test_injected_field_rejected(canary_ledger):
    led, _ = canary_ledger
    batch = build_batch(led)
    for injected in ("filename", "note", "content"):
        with pytest.raises(AnchorError, match="schema"):
            validate_batch({**batch, injected: "x"})


def test_missing_or_malformed_fields_rejected(canary_ledger):
    led, _ = canary_ledger
    batch = build_batch(led)
    for field in batch:
        with pytest.raises(AnchorError):
            validate_batch({k: v for k, v in batch.items() if k != field})
    with pytest.raises(AnchorError, match="row_count"):
        validate_batch({**batch, "row_count": batch["row_count"] + 1})


def test_tampered_batch_fails_signature_or_recompute(canary_ledger):
    led, _ = canary_ledger
    batch = build_batch(led)
    for field, value in (
        ("root", "0" * 64),
        ("chain_tip", "1" * 64),
        ("row_start", 0 if batch["row_start"] else 1),
        ("sig", "2" * 128),
    ):
        tampered = {**batch, field: value}
        if field == "row_start":
            tampered["row_count"] = tampered["row_end"] - tampered["row_start"]
        with pytest.raises(AnchorError):
            verify_batch(tampered, led.rows())


# --- Continuity (AC #3) -----------------------------------------------------------


def test_consecutive_batches_are_contiguous_and_recompute(canary_ledger):
    led, _ = canary_ledger
    rng = random.Random(31)
    total = led.verify_chain()
    cuts = sorted(rng.sample(range(2, total), 2)) + [total]
    batches, previous = [], None
    for cut in cuts:
        previous = build_batch(led, previous=previous, row_end=cut)
        batches.append(previous)
    assert batches[0]["row_start"] == 0
    for a, b in zip(batches, batches[1:]):
        assert b["row_start"] == a["row_end"]  # contiguous, non-overlapping
    assert batches[-1]["row_end"] == total
    rows = led.rows()
    for b in batches:
        verify_batch(b, rows[b["row_start"] : b["row_end"]])
    # The final batch's tip guards the whole chain against trailing truncation.
    assert led.verify_chain(expect_tip=batches[-1]["chain_tip"]) == total


def test_empty_or_sessionless_ranges_refuse(canary_ledger):
    led, _ = canary_ledger
    full = build_batch(led)
    with pytest.raises(AnchorError, match="empty"):
        build_batch(led, previous=full)  # nothing new to anchor
    with pytest.raises(AnchorError, match="no session rows"):
        build_batch(led, row_end=1)  # genesis only
    with pytest.raises(AnchorError, match="beyond"):
        build_batch(led, row_end=full["row_end"] + 10)


# --- Leak scan (AC #4) --------------------------------------------------------------


def test_artifact_from_canary_ledger_is_leak_free(canary_ledger, tmp_path):
    led, canaries = canary_ledger
    artifact = tmp_path / "anchor-batch.json"
    artifact.write_bytes(canonical_bytes(build_batch(led)))
    assert assert_no_canaries([artifact], canaries) == 1


def test_scan_fires_on_canary_planted_into_artifact(canary_ledger, tmp_path):
    led, canaries = canary_ledger
    batch = build_batch(led)
    planted = {**batch, "sig": canaries[0].hex() + batch["sig"][len(canaries[0]) * 2 :]}
    artifact = tmp_path / "anchor-batch.json"
    artifact.write_bytes(json.dumps(planted).encode())
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([artifact], canaries)
