"""MYB-2.3: commitment primitives against ADR-0002 — vectors, properties, proofs, leaks."""

import inspect
import json
import random

import pytest

from mybench import commitments as c
from tests.fixtures import assert_no_canaries, generate_fixtures

# --- ADR-0002 test vectors, verbatim (synthetic content only) -----------------

N1, N2, N3 = bytes(range(0x00, 0x20)), bytes(range(0x20, 0x40)), bytes(range(0x40, 0x60))
M1 = b"synthetic: fix the tests"
M2 = b""
M3 = b"synthetic: refactor the widget factory"

VECTORS = {
    "L1": "ae42d74f9cfae14123d731747b19a821c5a93ceaa298cfccbc705dca01733450",
    "L2": "fe0499cbc8ab2588498ffdb9d6d68946510e5bc51f28160c6a4af18c256db77b",
    "L3": "3df0b27f80affdfa2a877952796c6a1897e72d84938f621a9f3d2834c54a5f88",
    "N12": "0deb6d81fcbfd7ba8be97054e7f2794e20f7d194752f8355bea70c277f91ee02",
    "MTH3": "525838e6d1b0c9b7d2460f72ab29d8664ecf8e39c56cecf030c887c1d50e33fb",
    "S_A": "f2346717f278a94dc68f36b034ca572c20eaf36f8e96af84123ff5502426ee57",
    "S_B": "c94a28f837bbeb223ec5b218fa3f8b18edaf4fe20dd72e2b21dd0ed5247e99a7",
    "DAY": "44e004a74a1c5bf6cf638be91019ec2b1f1879b5c4b4f11c51bb81d307ddc300",
}


def test_adr0002_vectors_byte_for_byte():
    l1, l2, l3 = c.leaf_commitment(N1, M1), c.leaf_commitment(N2, M2), c.leaf_commitment(N3, M3)
    assert l1.hex() == VECTORS["L1"]
    assert l2.hex() == VECTORS["L2"]
    assert l3.hex() == VECTORS["L3"]
    assert c.node_hash(l1, l2).hex() == VECTORS["N12"]
    assert c.merkle_root([l1, l2, l3]).hex() == VECTORS["MTH3"]
    s_a, s_b = c.session_root([l1, l2, l3]), c.session_root([l3])
    assert s_a.hex() == VECTORS["S_A"]
    assert s_b.hex() == VECTORS["S_B"]
    assert c.day_root([s_a, s_b]).hex() == VECTORS["DAY"]


# --- Properties (AC #2) --------------------------------------------------------


def test_commitment_is_deterministic():
    assert c.leaf_commitment(N1, M1) == c.leaf_commitment(N1, M1)


def test_equal_content_distinct_nonces_distinct_commitments():
    rng = random.Random(7)
    nonces = [rng.randbytes(32) for _ in range(200)]
    commits = {c.leaf_commitment(k, b"fix the tests") for k in nonces}
    assert len(commits) == len(nonces)


def test_preimage_encoding_is_injective():
    # Fixed-width nonce + u64 length prefix: distinct (nonce, content) pairs
    # yield distinct preimages, including boundary-shifting attempts.
    rng = random.Random(11)
    pairs = [(rng.randbytes(32), rng.randbytes(rng.randrange(0, 40))) for _ in range(300)]
    pairs += [
        (N1, b"AB"),
        (N1, b"A"),
        (N1, b"A\x00"),
        (N1, b""),
        (N1[:-1] + b"A", b"B"),  # byte moved across the nonce/content boundary
    ]
    preimages = {n + len(m).to_bytes(8, "big") + m for n, m in pairs}
    commits = {c.leaf_commitment(n, m) for n, m in pairs}
    assert len(commits) == len(preimages) == len(set(pairs))


def test_wrong_nonce_length_rejected():
    for bad in (b"", b"short", bytes(31), bytes(33)):
        with pytest.raises(ValueError):
            c.leaf_commitment(bad, b"x")


def test_generate_nonce_shape_uniqueness_and_no_seed_path():
    batch = {c.generate_nonce() for _ in range(10_000)}
    assert len(batch) == 10_000
    assert all(len(n) == 32 for n in batch)
    # ADR-0002 §1 / analysis §4: no seedable production path may exist.
    assert not inspect.signature(c.generate_nonce).parameters


def test_domains_separate_leaf_node_session_day():
    l3 = c.leaf_commitment(N3, M3)
    # A lone leaf's MTH root equals the leaf; the wrappers must still differ
    # from it and from each other (no cross-context replay).
    values = {l3, c.merkle_root([l3]), c.session_root([l3]), c.day_root([l3])}
    assert len(values) == 3  # merkle_root([x]) == x by design; both wrappers distinct
    assert c.session_root([l3]) != c.day_root([l3])


def test_empty_tree_is_an_error():
    with pytest.raises(ValueError):
        c.merkle_root([])
    with pytest.raises(ValueError):
        c.session_root([])


# --- Inclusion proofs (AC #3) ---------------------------------------------------


def test_inclusion_proofs_verify_for_all_indices_and_sizes():
    rng = random.Random(13)
    for size in range(1, 18):
        leaves = [rng.randbytes(32) for _ in range(size)]
        root, sroot = c.merkle_root(leaves), c.session_root(leaves)
        for i, leaf in enumerate(leaves):
            proof = c.inclusion_proof(leaves, i)
            assert c.verify_inclusion(leaf, proof, root)
            assert c.verify_session_inclusion(leaf, proof, sroot)


def flip_byte(b: bytes, pos: int = 0) -> bytes:
    return b[:pos] + bytes([b[pos] ^ 0x01]) + b[pos + 1 :]


def test_any_mutation_fails_verification():
    rng = random.Random(17)
    for size in (1, 2, 3, 8, 13):
        leaves = [rng.randbytes(32) for _ in range(size)]
        root = c.merkle_root(leaves)
        i = rng.randrange(size)
        proof = c.inclusion_proof(leaves, i)
        assert not c.verify_inclusion(flip_byte(leaves[i]), proof, root)
        assert not c.verify_inclusion(leaves[i], proof, flip_byte(root))
        if proof:
            side, sib = proof[0]
            assert not c.verify_inclusion(leaves[i], [(side, flip_byte(sib))] + proof[1:], root)
            flipped = "L" if side == "R" else "R"
            assert not c.verify_inclusion(leaves[i], [(flipped, sib)] + proof[1:], root)
        if size > 1:
            wrong = (i + 1) % size
            assert not c.verify_inclusion(leaves[wrong], proof, root)


# --- Published forms are leak-free (AC #4) ---------------------------------------


def test_published_forms_from_canary_fixtures_pass_leak_scan(tmp_path):
    fx = generate_fixtures(tmp_path / "fx")
    out = tmp_path / "published"
    out.mkdir()
    log_lines, session_roots, used_nonces = [], [], []
    for s in fx.sessions:
        items = s.read_bytes().splitlines()
        # Use the fixture nonce canaries as real nonces for the first items —
        # exactly their purpose: if any published form echoed a nonce, the
        # scan below would fire.
        nonces = list(fx.nonce_canaries[: len(items)])
        nonces += [c.generate_nonce() for _ in items[len(nonces) :]]
        used_nonces.extend(nonces)
        leaves = [c.leaf_commitment(k, m) for k, m in zip(nonces, items)]
        sroot = c.session_root(leaves)
        session_roots.append(sroot)
        proof = c.inclusion_proof(leaves, 0)
        (out / f"session-{len(session_roots)}.json").write_text(
            json.dumps(
                {
                    "leaves": [x.hex() for x in leaves],
                    "session_root": sroot.hex(),
                    "proof": [[side, sib.hex()] for side, sib in proof],
                }
            )
        )
        log_lines.append(f"committed {len(items)} items, root {sroot.hex()}")
    (out / "day.json").write_text(json.dumps({"day_root": c.day_root(session_roots).hex()}))
    (out / "run.log").write_text("\n".join(log_lines))
    scanned = assert_no_canaries([out], fx.all_canaries() + used_nonces)
    assert scanned == len(fx.sessions) + 2
