"""CLI: render a report JSON into the static page.

    python -m mybench.report --report report.json \
        --anchors-url https://github.com/USER/mybench-anchors --out index.html
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mybench.report.page import PageError, render_page


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybench-report")
    parser.add_argument("--report", required=True, help="path to the scorer's report JSON")
    parser.add_argument("--anchors-url", required=True, help="public anchors repo URL")
    parser.add_argument("--out", required=True, help="output HTML path")
    args = parser.parse_args(argv)
    try:
        page = render_page(json.loads(Path(args.report).read_bytes()),
                           anchors_url=args.anchors_url)
    except (ValueError, PageError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    Path(args.out).write_bytes(page)
    print(f"wrote {args.out} ({len(page)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
