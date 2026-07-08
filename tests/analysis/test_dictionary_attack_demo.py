"""Runnable demo for docs/analysis/short-content-dictionary-attack.md (MYB-1.3).

Shows that a dictionary search recovers short plaintexts from unsalted hashes,
and that the same search recovers nothing from salted commitments.

Every plaintext here is SYNTHETIC, defined in this file (privacy invariant #3).
Deterministic: demo nonces come from a seeded PRNG so runs are reproducible.
Production code MUST instead use the OS CSPRNG (secrets.token_bytes) — a seeded
or seedable nonce path voids the entire analysis (see analysis §4).
"""

import hashlib
import random

SEED = 20260708

# Demo-only domain string; ADR-0002 pins the production domains (mybench:v1:*).
DOMAIN = b"mybench:demo:leaf:"

# Synthetic stand-ins for low-entropy transcript items an adversary would
# plant in a precomputed dictionary: short prompts, commands, file headers.
CANDIDATE_DICTIONARY = [
    b"fix the tests",
    b"continue",
    b"y",
    b"make it faster",
    b"synthetic prompt: refactor the widget factory",
    b"synthetic prompt: add a retry to the flux client",
    b"git commit -m 'wip'",
    b"import os",
    b"#!/usr/bin/env python3",
    b"TODO: remove before shipping",
    b"synthetic filename: flux_capacitor_test_plan.md",
    b"",  # empty item — boundary case from analysis §5.3
] + [b"synthetic filler entry %03d" % i for i in range(500)]

# The "user's" items: a low-entropy subset the attack should recover, all drawn
# from strings an adversary plausibly has in a dictionary.
PLANTED_ITEMS = [
    b"fix the tests",
    b"synthetic prompt: refactor the widget factory",
    b"synthetic filename: flux_capacitor_test_plan.md",
    b"",
]


def unsalted_hash(content: bytes) -> bytes:
    return hashlib.sha256(DOMAIN + content).digest()


def salted_commitment(nonce: bytes, content: bytes) -> bytes:
    assert len(nonce) == 32
    preimage = DOMAIN + nonce + len(content).to_bytes(8, "big") + content
    return hashlib.sha256(preimage).digest()


def dictionary_search(published: list[bytes]) -> dict[bytes, bytes]:
    """The adversary: hash every candidate, match against published values."""
    table = {unsalted_hash(c): c for c in CANDIDATE_DICTIONARY}
    return {h: table[h] for h in published if h in table}


def demo_nonces(n: int) -> list[bytes]:
    rng = random.Random(SEED)  # demo-only determinism; production: secrets.token_bytes(32)
    return [rng.randbytes(32) for _ in range(n)]


def test_dictionary_search_recovers_unsalted_plaintexts():
    published = [unsalted_hash(m) for m in PLANTED_ITEMS]
    recovered = dictionary_search(published)
    # Total break: every planted low-entropy item is recovered, not merely one.
    assert set(recovered.values()) == set(PLANTED_ITEMS)


def test_dictionary_search_fails_against_salted_commitments():
    nonces = demo_nonces(len(PLANTED_ITEMS))
    published = [salted_commitment(k, m) for k, m in zip(nonces, PLANTED_ITEMS)]
    assert dictionary_search(published) == {}


def test_confirmation_attack_fails_without_nonce():
    # Adversary suspects an exact plaintext and tests it directly (analysis §1.3).
    [nonce] = demo_nonces(1)
    target = salted_commitment(nonce, b"fix the tests")
    assert unsalted_hash(b"fix the tests") != target
    # Even knowing the exact scheme, guessing wrong nonces confirms nothing.
    rng = random.Random(SEED + 1)
    wrong_nonces = (rng.randbytes(32) for _ in range(10_000))
    assert all(salted_commitment(k, b"fix the tests") != target for k in wrong_nonces)


def test_unsalted_hashes_correlate_identical_content_salted_do_not():
    items = [b"continue", b"continue", b"y"]
    unsalted = [unsalted_hash(m) for m in items]
    assert unsalted[0] == unsalted[1]  # equality leaks even without recovery
    nonces = demo_nonces(len(items))
    salted = [salted_commitment(k, m) for k, m in zip(nonces, items)]
    assert len(set(salted)) == len(items)


def test_demo_nonces_are_unique_and_deterministic():
    a, b = demo_nonces(100), demo_nonces(100)
    assert a == b  # seeded: the demo is reproducible
    assert len(set(a)) == 100  # per-item uniqueness (analysis §4, nonce reuse)
