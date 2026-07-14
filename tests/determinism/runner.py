"""Fresh-process entry point for one determinism stage.

Artifact bytes are written to the parent-provided temporary path.  The gate
logs only their size and SHA-256 digest, never the artifact itself.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from tests.determinism.stages import STAGES, run_stage


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybench-determinism-stage")
    parser.add_argument("stage", choices=[stage.name for stage in STAGES])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    args.out.write_bytes(run_stage(args.stage))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
