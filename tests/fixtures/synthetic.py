"""Seeded, deterministic generator of synthetic fingerprint-input fixtures.

Output mimics the *structure* of Claude Code and Codex JSONL session logs;
every piece of content is synthetic and clearly marked. Fixtures embed known
canaries (content strings, fake filenames) so that negative tests can prove
published artifacts contain nothing transcript-derived, plus deterministic
nonce values usable as nonce-leak canaries (ADR-0002 nonces are 32 bytes).

The same seed also produces lifecycle streams, Git-evidence shapes, and
plan/instruction/orchestration trees.  Those inputs cover every private class
that a fingerprint report or preview must exclude.  They are generated from
constants plus ``random.Random(seed)`` only; no local repository or transcript
is ever inspected (privacy invariant #3).
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SEED = 20260708

# Public inventory for later parser/report stories.  Keep these names stable:
# tests cite the class names when proving their output excludes each class.
NEW_CANARY_CLASSES = (
    "repo_name",
    "worktree_name",
    "branch_name",
    "local_path",
    "plan_filename",
    "plan_content",
    "instruction_filename",
    "instruction_content",
    "orchestration_filename",
    "orchestration_content",
    "employer_name",
    "client_name",
    "private_url",
    "secret_token",
    "full_precision_timestamp",
    "test_command",
    "test_result",
)

# Dictionary-attack-relevant short/low-entropy lines (MYB-1.3): these are the
# kinds of items an unsalted scheme would leak; later pipeline tests commit
# them and prove the published side is clean.
LOW_ENTROPY_LINES = ["fix the tests", "y", "continue", "make it faster"]


@dataclass
class FixtureSet:
    root: Path
    sessions: list[Path]  # generated JSONL files (Claude Code + Codex shapes)
    lifecycle_event_streams: list[Path]
    git_evidence_files: list[Path]
    plan_orchestration_files: list[Path]
    content_canaries: list[str]
    filename_canaries: list[str]
    nonce_canaries: list[bytes]  # 32-byte values; use as nonces in pipeline tests
    new_canaries: dict[str, bytes]
    low_entropy_lines: list[str]

    def all_canaries(self) -> list[bytes]:
        return (
            [c.encode() for c in self.content_canaries]
            + [f.encode() for f in self.filename_canaries]
            + list(self.nonce_canaries)
            + list(self.new_canaries.values())
        )

    def canary(self, class_name: str) -> bytes:
        """Return the planted bytes for one class in ``NEW_CANARY_CLASSES``."""
        return self.new_canaries[class_name]


def _ts(i: int) -> str:
    # Fixed synthetic clock — keeps output byte-deterministic.
    return f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}.000Z"


def _uuid(rng: random.Random) -> str:
    h = rng.randbytes(16).hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def _new_canaries(seed: int) -> dict[str, bytes]:
    """Derive the v2 canary catalog from a seed without perturbing v1 fixtures."""
    rng = random.Random(seed ^ 0x16_04_CAFE)

    def tag(label: str, *, suffix: str = "") -> str:
        return f"MYBENCH-CANARY-{label}-{rng.randbytes(8).hex()}{suffix}"

    values = {
        "repo_name": tag("repo-name"),
        "worktree_name": tag("worktree-name"),
        "branch_name": tag("branch-name"),
        "local_path": f"/synthetic/private/{tag('local-path')}",
        "plan_filename": tag("plan-filename", suffix=".md"),
        "plan_content": tag("plan-content"),
        "instruction_filename": tag("instruction-filename", suffix=".md"),
        "instruction_content": tag("instruction-content"),
        "orchestration_filename": tag("orchestration-filename", suffix=".json"),
        "orchestration_content": tag("orchestration-content"),
        "employer_name": f"{tag('employer-name')} Synthetic Holdings",
        "client_name": f"{tag('client-name')} Synthetic Client",
        "private_url": f"https://{tag('private-url').lower()}.synthetic.invalid/private",
        # Deliberately secret-shaped but unmistakably synthetic and unusable.
        "secret_token": f"sk_test_MYBENCH_CANARY_{rng.randbytes(24).hex()}",
        # A future date prevents confusion with a real capture timestamp.
        "full_precision_timestamp": (
            f"2099-12-31T23:59:59.{int.from_bytes(rng.randbytes(3)) % 1_000_000:06d}Z"
        ),
        "test_command": f"pytest -q synthetic_private_{rng.randbytes(8).hex()}::test_canary",
        "test_result": f"FAILED synthetic canary result {rng.randbytes(8).hex()}",
    }
    assert tuple(values) == NEW_CANARY_CLASSES
    return {name: value.encode() for name, value in values.items()}


def _text(fx: FixtureSet, class_name: str) -> str:
    return fx.canary(class_name).decode()


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records))


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
    thread_id = _uuid(rng)
    call_id = _uuid(rng)
    filename = rng.choice(fx.filename_canaries)
    content = rng.choice(fx.content_canaries)
    cwd = f"/synthetic/codex/{filename.removesuffix('.py')}"
    lines = [
        {
            "timestamp": _ts(0),
            "type": "session_meta",
            "payload": {
                "id": thread_id,
                "session_id": thread_id,
                "timestamp": _ts(0),
                "cwd": cwd,
                "originator": "synthetic_codex_cli",
                "cli_version": "0.1.0-synthetic",
                "source": "cli",
                "model_provider": "openai",
                "base_instructions": {"text": f"synthetic base {content}"},
            },
        },
        {
            "timestamp": _ts(1),
            "type": "turn_context",
            "payload": {
                "cwd": cwd,
                "model": "gpt-5-codex",
                "effort": "high",
                "approval_policy": "never",
                "sandbox_policy": {"type": "workspace_write"},
                "summary": "auto",
            },
        },
        {
            "timestamp": _ts(2),
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": f"{rng.choice(fx.low_entropy_lines)} {content}",
                    }
                ],
            },
        },
        {
            "timestamp": _ts(3),
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "assistant",
                "content": [
                    {"type": "output_text", "text": f"synthetic reply {rng.randbytes(4).hex()}"}
                ],
                "phase": "commentary",
            },
        },
        {
            "timestamp": _ts(4),
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "exec_command",
                "arguments": json.dumps(
                    {"cmd": f"pytest tests/{filename}"},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "call_id": call_id,
            },
        },
        {
            "timestamp": _ts(5),
            "type": "response_item",
            "payload": {
                "type": "function_call_output",
                "call_id": call_id,
                "output": f"synthetic result {content} {filename}",
            },
        },
        {
            "timestamp": _ts(6),
            "type": "event_msg",
            "payload": {
                "type": "token_count",
                "info": {
                    "total_token_usage": {
                        "input_tokens": 13,
                        "cached_input_tokens": 2,
                        "output_tokens": 5,
                        "reasoning_output_tokens": 1,
                        "total_tokens": 18,
                    },
                    "last_token_usage": {
                        "input_tokens": 13,
                        "cached_input_tokens": 2,
                        "output_tokens": 5,
                        "reasoning_output_tokens": 1,
                        "total_tokens": 18,
                    },
                    "model_context_window": 272000,
                },
                "rate_limits": None,
            },
        },
        {
            "timestamp": _ts(7),
            "type": "event_msg",
            "payload": {"type": "context_compacted"},
        },
    ]
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))
    fx.sessions.append(path)


def _lifecycle_streams(rng: random.Random, fx: FixtureSet) -> None:
    """Write synthetic Claude hook and Codex structural-lifecycle streams."""
    synthetic_session = f"synthetic-session-{rng.randbytes(8).hex()}"
    local_path = _text(fx, "local_path")
    cwd = f"{local_path}/{_text(fx, 'repo_name')}/{_text(fx, 'worktree_name')}"
    timestamp = _text(fx, "full_precision_timestamp")

    claude = fx.root / "lifecycle" / "claude-hook-events.jsonl"
    _write_jsonl(
        claude,
        [
            {
                "hook_event_name": "SessionStart",
                "session_id": synthetic_session,
                "transcript_path": f"{local_path}/claude/synthetic-session.jsonl",
                "cwd": cwd,
                "source": "startup",
                "model": "synthetic-model-v1",
                "observed_at": timestamp,
            },
            {
                "hook_event_name": "PreCompact",
                "session_id": synthetic_session,
                "transcript_path": f"{local_path}/claude/synthetic-session.jsonl",
                "cwd": cwd,
                "trigger": "manual",
                "custom_instructions": _text(fx, "instruction_content"),
                "observed_at": timestamp,
            },
            {
                "hook_event_name": "SessionEnd",
                "session_id": synthetic_session,
                "transcript_path": f"{local_path}/claude/synthetic-session.jsonl",
                "cwd": cwd,
                "reason": "other",
                "observed_at": timestamp,
            },
        ],
    )

    # Codex has no capture-side SessionEnd hook in v0.  Its fixture therefore
    # models the structural rollout boundary and an explicit task-complete
    # observation without inventing hook parity.
    codex = fx.root / "lifecycle" / "codex-rollout-events.jsonl"
    call_id = f"synthetic-call-{rng.randbytes(8).hex()}"
    _write_jsonl(
        codex,
        [
            {
                "timestamp": timestamp,
                "type": "session_meta",
                "payload": {
                    "id": synthetic_session,
                    "cwd": cwd,
                    "model_provider": "synthetic",
                },
            },
            {
                "timestamp": timestamp,
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "name": "exec_command",
                    "arguments": json.dumps({"cmd": _text(fx, "test_command")}),
                    "call_id": call_id,
                },
            },
            {
                "timestamp": timestamp,
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": _text(fx, "test_result"),
                },
            },
            {
                "timestamp": timestamp,
                "type": "event_msg",
                "payload": {"type": "task_complete"},
            },
        ],
    )
    fx.lifecycle_event_streams.extend((claude, codex))


def _git_evidence_tree(fx: FixtureSet) -> None:
    """Write a Git-evidence shape containing identity-sensitive raw inputs."""
    path = fx.root / "git-evidence" / "snapshot.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    local_path = _text(fx, "local_path")
    path.write_text(
        json.dumps(
            {
                "synthetic": True,
                "repository": {
                    "name": _text(fx, "repo_name"),
                    "path": f"{local_path}/{_text(fx, 'repo_name')}",
                    "remote": _text(fx, "private_url"),
                    "employer": _text(fx, "employer_name"),
                    "client": _text(fx, "client_name"),
                    "credential": _text(fx, "secret_token"),
                },
                "worktrees": [
                    {
                        "name": _text(fx, "worktree_name"),
                        "path": f"{local_path}/{_text(fx, 'worktree_name')}",
                        "branch": _text(fx, "branch_name"),
                        "head": "a5" * 20,
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n"
    )
    fx.git_evidence_files.append(path)


def _plan_orchestration_tree(fx: FixtureSet) -> None:
    """Write synthetic plan, instruction, and orchestration files."""
    plan = fx.root / "planning" / "plans" / _text(fx, "plan_filename")
    instruction = fx.root / "planning" / "instructions" / _text(fx, "instruction_filename")
    orchestration = fx.root / "planning" / "orchestration" / _text(fx, "orchestration_filename")
    for path in (plan, instruction, orchestration):
        path.parent.mkdir(parents=True, exist_ok=True)

    plan.write_text(
        "# Synthetic private plan\n\n"
        f"Content marker: {_text(fx, 'plan_content')}\n"
        f"Instruction file: {_text(fx, 'instruction_filename')}\n"
    )
    instruction.write_text(
        f"# Synthetic agent instructions\n\nContent marker: {_text(fx, 'instruction_content')}\n"
    )
    orchestration.write_text(
        json.dumps(
            {
                "synthetic": True,
                "content_marker": _text(fx, "orchestration_content"),
                "plan": _text(fx, "plan_filename"),
                "instruction": _text(fx, "instruction_filename"),
            },
            sort_keys=True,
        )
        + "\n"
    )
    fx.plan_orchestration_files.extend((plan, instruction, orchestration))


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
        lifecycle_event_streams=[],
        git_evidence_files=[],
        plan_orchestration_files=[],
        content_canaries=[f"MYBENCH-CANARY-{rng.randbytes(8).hex()}" for _ in range(3)],
        filename_canaries=[f"canary_{rng.randbytes(4).hex()}_secret_plan.py" for _ in range(2)],
        nonce_canaries=[rng.randbytes(32) for _ in range(2)],
        new_canaries=_new_canaries(seed),
        low_entropy_lines=list(LOW_ENTROPY_LINES),
    )
    claude_dir = dest / "claude" / "projects" / "-synthetic-project"
    codex_dir = dest / "codex" / "sessions"
    claude_dir.mkdir(parents=True, exist_ok=True)
    for _ in range(claude_sessions):
        _claude_session(rng, claude_dir / f"{_uuid(rng)}.jsonl", fx)
    for i in range(codex_sessions):
        # Mirror the real rollout layout (current as of 2026-07-13):
        # sessions/YYYY/MM/DD/rollout-*.jsonl (MYB-12.2). Fixed synthetic
        # dates keep output deterministic.
        day_dir = codex_dir / "2026" / "01" / f"{i + 1:02d}"
        day_dir.mkdir(parents=True, exist_ok=True)
        _codex_session(rng, day_dir / f"rollout-2026-01-{i + 1:02d}T00-00-00.jsonl", fx)
    _lifecycle_streams(rng, fx)
    _git_evidence_tree(fx)
    _plan_orchestration_tree(fx)
    return fx
