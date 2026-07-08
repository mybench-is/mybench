"""MYB-2.2 AC #1/#2: generator determinism, realistic structure, embedded canaries."""

import json

from tests.fixtures import generate_fixtures


def tree_bytes(root):
    return {
        str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()
    }


def test_generator_is_deterministic(tmp_path):
    a = generate_fixtures(tmp_path / "a", seed=1)
    b = generate_fixtures(tmp_path / "b", seed=1)
    assert tree_bytes(a.root) == tree_bytes(b.root)
    assert a.content_canaries == b.content_canaries
    assert a.nonce_canaries == b.nonce_canaries


def test_different_seeds_differ(tmp_path):
    a = generate_fixtures(tmp_path / "a", seed=1)
    b = generate_fixtures(tmp_path / "b", seed=2)
    assert a.content_canaries != b.content_canaries


def test_claude_sessions_shaped_like_jsonl_transcripts(tmp_path):
    fx = generate_fixtures(tmp_path)
    claude = [s for s in fx.sessions if "claude" in s.parts]
    assert claude
    for session in claude:
        lines = [json.loads(ln) for ln in session.read_text().splitlines()]
        assert lines
        for line in lines:
            assert line["type"] in {"user", "assistant"}
            assert {"uuid", "timestamp", "sessionId", "message", "cwd"} <= line.keys()


def test_codex_sessions_shaped_like_jsonl_transcripts(tmp_path):
    fx = generate_fixtures(tmp_path)
    codex = [s for s in fx.sessions if "codex" in s.parts]
    assert codex
    for session in codex:
        lines = [json.loads(ln) for ln in session.read_text().splitlines()]
        assert lines
        for line in lines:
            assert {"timestamp", "type", "payload"} <= line.keys()
            assert line["payload"]["role"] in {"user", "assistant"}


def test_fixtures_embed_content_filename_and_low_entropy_canaries(tmp_path):
    fx = generate_fixtures(tmp_path)
    corpus = b"".join(s.read_bytes() for s in fx.sessions)
    assert any(c.encode() in corpus for c in fx.content_canaries)
    assert any(f.encode() in corpus for f in fx.filename_canaries)
    assert any(line.encode() in corpus for line in fx.low_entropy_lines)


def test_nonce_canaries_are_adr0002_shaped_and_not_in_transcripts(tmp_path):
    fx = generate_fixtures(tmp_path)
    corpus = b"".join(s.read_bytes() for s in fx.sessions)
    assert len(fx.nonce_canaries) >= 2
    for nonce in fx.nonce_canaries:
        assert len(nonce) == 32  # ADR-0002 §1
        # Nonces are pipeline inputs, not transcript content — they must not
        # start out inside the fixtures or every later scan would false-fire.
        assert nonce not in corpus and nonce.hex().encode() not in corpus


def test_all_canaries_covers_every_kind(tmp_path):
    fx = generate_fixtures(tmp_path)
    allc = fx.all_canaries()
    assert len(allc) == len(fx.content_canaries) + len(fx.filename_canaries) + len(
        fx.nonce_canaries
    )
    assert all(isinstance(c, bytes) for c in allc)
