"""Seeded, deterministic generator of synthetic agent-transcript fixtures.

Output mimics the *structure* of Claude Code and Codex JSONL session logs;
every piece of content is synthetic and clearly marked. Fixtures embed known
canaries (content strings, fake filenames) so that negative tests can prove
published artifacts contain nothing transcript-derived, plus deterministic
nonce values usable as nonce-leak canaries (ADR-0002 nonces are 32 bytes).
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SEED = 20260708

# Dictionary-attack-relevant short/low-entropy lines (MYB-1.3): these are the
# kinds of items an unsalted scheme would leak; later pipeline tests commit
# them and prove the published side is clean.
LOW_ENTROPY_LINES = ["fix the tests", "y", "continue", "make it faster"]


@dataclass
class FixtureSet:
    root: Path
    sessions: list[Path]  # generated JSONL files (Claude Code + Codex shapes)
    content_canaries: list[str]
    filename_canaries: list[str]
    nonce_canaries: list[bytes]  # 32-byte values; use as nonces in pipeline tests
    low_entropy_lines: list[str]

    def all_canaries(self) -> list[bytes]:
        return (
            [c.encode() for c in self.content_canaries]
            + [f.encode() for f in self.filename_canaries]
            + list(self.nonce_canaries)
        )


def _ts(i: int) -> str:
    # Fixed synthetic clock — keeps output byte-deterministic.
    return f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}.000Z"


def _uuid(rng: random.Random) -> str:
    h = rng.randbytes(16).hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def _claude_session(rng: random.Random, path: Path, fx: FixtureSet) -> None:
    sid = _uuid(rng)
    cwd = f"/synthetic/project/{rng.choice(fx.filename_canaries).removesuffix('.py')}"
    lines, prev = [], None
    texts = [
        rng.choice(fx.low_entropy_lines),
        f"synthetic user prompt {rng.randbytes(4).hex()} {rng.choice(fx.content_canaries)}",
        f"please edit {rng.choice(fx.filename_canaries)}",
    ]
    for i, text in enumerate(texts):
        u = _uuid(rng)
        lines.append(
            {
                "parentUuid": prev,
                "isSidechain": False,
                "cwd": cwd,
                "sessionId": sid,
                "type": "user",
                "message": {"role": "user", "content": text},
                "uuid": u,
                "timestamp": _ts(2 * i),
            }
        )
        prev = u
        u = _uuid(rng)
        lines.append(
            {
                "parentUuid": prev,
                "isSidechain": False,
                "cwd": cwd,
                "sessionId": sid,
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "text",
                            "text": f"synthetic assistant reply {rng.randbytes(4).hex()}",
                        }
                    ],
                },
                "uuid": u,
                "timestamp": _ts(2 * i + 1),
            }
        )
        prev = u
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))
    fx.sessions.append(path)


def _codex_session(rng: random.Random, path: Path, fx: FixtureSet) -> None:
    lines = []
    texts = [
        rng.choice(fx.low_entropy_lines),
        f"synthetic codex prompt {rng.choice(fx.content_canaries)}",
        f"open {rng.choice(fx.filename_canaries)}",
    ]
    for i, text in enumerate(texts):
        role = "user" if i % 2 == 0 else "assistant"
        lines.append(
            {
                "timestamp": _ts(i),
                "type": "message",
                "payload": {"role": role, "content": [{"type": "input_text", "text": text}]},
            }
        )
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))
    fx.sessions.append(path)


def generate_fixtures(
    dest: Path,
    *,
    seed: int = DEFAULT_SEED,
    claude_sessions: int = 2,
    codex_sessions: int = 1,
) -> FixtureSet:
    """Generate a deterministic fixture tree under ``dest`` and return its manifest."""
    rng = random.Random(seed)
    fx = FixtureSet(
        root=dest,
        sessions=[],
        content_canaries=[f"MYBENCH-CANARY-{rng.randbytes(8).hex()}" for _ in range(3)],
        filename_canaries=[f"canary_{rng.randbytes(4).hex()}_secret_plan.py" for _ in range(2)],
        nonce_canaries=[rng.randbytes(32) for _ in range(2)],
        low_entropy_lines=list(LOW_ENTROPY_LINES),
    )
    claude_dir = dest / "claude" / "projects" / "-synthetic-project"
    codex_dir = dest / "codex" / "sessions"
    claude_dir.mkdir(parents=True, exist_ok=True)
    codex_dir.mkdir(parents=True, exist_ok=True)
    for _ in range(claude_sessions):
        _claude_session(rng, claude_dir / f"{_uuid(rng)}.jsonl", fx)
    for i in range(codex_sessions):
        _codex_session(rng, codex_dir / f"rollout-2026-01-01T00-00-0{i}.jsonl", fx)
    return fx
