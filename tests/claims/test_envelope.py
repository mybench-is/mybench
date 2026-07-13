"""MYB-10.1: claim envelope — schema whitelist, signing, golden bytes, leak scan."""

import json
from pathlib import Path

import pytest

from mybench import commitments
from mybench.claims import (
    ClaimError,
    build_claim,
    claim_file_bytes,
    dev_signing_key,
    sign_claim,
    sign_with_device_key,
    validate_claim,
    verify_claim,
)
from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures

GOLDEN = Path(__file__).parent / "golden" / "claim-local-unattested.json"
DEV_SEED = bytes(range(32))  # fixed, clearly synthetic — golden-fixture key
CORPUS = "ab" * 32  # synthetic 64-hex corpus commitment


def make_unsigned(**overrides):
    kwargs = dict(
        claim_type="metric",
        registry_id="transcript.tool_mix",
        registry_version="0.1.0",
        scorer_name="mybench.tool_mix",
        scorer_version="0.1.0",
        corpus_commitment=CORPUS,
        window_start="2026-01-01T00:00:00Z",
        window_end="2026-01-31T00:00:00Z",
        output={"band": "medium", "n_sessions_band": "10-99"},
        derivation_class="measured",
        signed_at="2026-02-01T00:00:00Z",
    )
    kwargs.update(overrides)
    return build_claim(**kwargs)


def make_signed(**overrides):
    return sign_claim(make_unsigned(**overrides), dev_signing_key(DEV_SEED), kind="dev")


# --- Golden fixture: byte-identical round trip (AC #1) --------------------------


def test_golden_claim_rebuilds_byte_identically():
    assert claim_file_bytes(make_signed()) == GOLDEN.read_bytes()


def test_golden_claim_loads_validates_verifies_and_reserializes():
    claim = json.loads(GOLDEN.read_text())
    assert verify_claim(claim) == "dev"
    assert claim_file_bytes(claim) == GOLDEN.read_bytes()


def test_identical_inputs_are_byte_identical_and_signed_at_is_an_input():
    a, b = make_signed(), make_signed()
    assert claim_file_bytes(a) == claim_file_bytes(b)  # no clock/env reads anywhere
    c = make_signed(signed_at="2026-02-02T00:00:00Z")
    assert claim_file_bytes(c) != claim_file_bytes(a)


# --- Schema whitelist (AC #2) ---------------------------------------------------


def test_unknown_fields_rejected_at_every_level():
    for mutate in (
        lambda c: c.__setitem__("extra", 1),
        lambda c: c["scorer"].__setitem__("extra", 1),
        lambda c: c["inputs"].__setitem__("extra", 1),
        lambda c: c["inputs"]["evidence_window"].__setitem__("tz", "UTC"),
        lambda c: c["signer"].__setitem__("extra", 1),
    ):
        claim = make_signed()
        mutate(claim)
        with pytest.raises(ClaimError, match="schema violation"):
            validate_claim(claim)


def test_registry_identity_is_mandatory():
    for field in ("registry_id", "registry_version"):
        claim = make_signed()
        del claim[field]
        with pytest.raises(ClaimError, match="schema violation"):
            validate_claim(claim)
    with pytest.raises(ClaimError, match="schema violation"):
        validate_claim(make_signed(registry_id="NoNamespace"))
    with pytest.raises(ClaimError, match="schema violation"):
        validate_claim(make_signed(registry_version="1.0"))


def test_floats_rejected_inside_output():
    claim = make_signed()
    claim["output"]["ratio"] = 0.5
    with pytest.raises(ClaimError, match="not canonical-JSON-safe"):
        validate_claim(claim)


def test_enum_and_format_fields_are_whitelisted():
    cases = [
        dict(claim_type="opinion"),
        dict(derivation_class="vibe"),
        dict(corpus_commitment="zz" * 32),
        dict(signed_at="2026-02-01 00:00:00"),
        dict(window_start="yesterday"),
    ]
    for overrides in cases:
        with pytest.raises(ClaimError, match="schema violation"):
            sign_claim(make_unsigned(**overrides), dev_signing_key(DEV_SEED), kind="dev")


def test_evidence_window_must_be_ordered():
    with pytest.raises(ClaimError, match="start is after"):
        make_signed(window_start="2026-03-01T00:00:00Z", window_end="2026-01-01T00:00:00Z")


def test_corpus_commitment_accepts_multiple_roots():
    claim = make_signed(corpus_commitment=["ab" * 32, "cd" * 32])
    assert verify_claim(claim) == "dev"


def test_local_unattested_forces_zero_element_attestation_and_null_measurement():
    # The MYB-7.18 hook: local-unattested == zero-element attestation_evidence.
    unsigned = make_unsigned()
    unsigned["attestation_evidence"] = [{"kind": "synthetic-quote"}]
    with pytest.raises(ClaimError, match="schema violation"):
        sign_claim(unsigned, dev_signing_key(DEV_SEED), kind="dev")
    with pytest.raises(ClaimError, match="schema violation"):
        make_signed(measurement="deadbeef")
    # tee-attested is the mirror image: it REQUIRES evidence + a measurement.
    with pytest.raises(ClaimError, match="schema violation"):
        make_signed(execution_env="tee-attested")


# --- Signing and verification ----------------------------------------------------


def test_dev_signature_verifies_and_reports_dev_kind():
    claim = make_signed()
    assert verify_claim(claim) == "dev"
    assert claim["signer"]["kind"] == "dev"


def test_tampered_claim_fails_verification():
    claim = make_signed()
    claim["output"]["band"] = "high"
    with pytest.raises(ClaimError, match="does not verify"):
        verify_claim(claim)


def test_device_key_signing_reports_device_kind():
    # conftest isolates XDG_DATA_HOME, so this exercises the real key-path
    # machinery against a per-test data dir — never the owner's key.
    claim = sign_with_device_key(make_unsigned())
    assert verify_claim(claim) == "device"


def test_double_signing_is_refused():
    claim = make_signed()
    with pytest.raises(ClaimError, match="already signed"):
        sign_claim(claim, dev_signing_key(DEV_SEED), kind="dev")


def test_dev_seed_must_be_32_bytes_and_ephemeral_keys_differ():
    with pytest.raises(ClaimError, match="32 bytes"):
        dev_signing_key(b"short")
    a, b = dev_signing_key(), dev_signing_key()
    sig_a = sign_claim(make_unsigned(), a, kind="dev")["signer"]["pub"]
    sig_b = sign_claim(make_unsigned(), b, kind="dev")["signer"]["pub"]
    assert sig_a != sig_b


# --- Leak surface (AC #3) ---------------------------------------------------------


def test_serialized_claims_pass_leak_scan_and_scanner_fires(tmp_path):
    fx = generate_fixtures(tmp_path / "fx")
    # Corpus commitment computed over canary content with canary nonces — the
    # exact worst case: everything secret feeds the claim, only the salted
    # root may surface.
    leaves = [
        commitments.leaf_commitment(nonce, canary.encode())
        for nonce, canary in zip(fx.nonce_canaries, fx.content_canaries)
    ]
    claim = make_signed(corpus_commitment=commitments.session_root(leaves).hex())
    out = tmp_path / "claim.json"
    out.write_bytes(claim_file_bytes(claim))
    assert assert_no_canaries([out], fx.all_canaries()) == 1

    # Companion firing test: a canary smuggled into output IS caught.
    smuggled = make_signed(output={"band": fx.content_canaries[0]})
    bad = tmp_path / "smuggled.json"
    bad.write_bytes(claim_file_bytes(smuggled))
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([bad], fx.all_canaries())
