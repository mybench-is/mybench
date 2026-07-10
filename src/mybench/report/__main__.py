"""CLI: render a report JSON into the static page.

    python -m mybench.report --report report.json --handle ckeenan --out index.html

Anchors URL defaults to https://mybench.is/anchors (ADR-0005: published
URLs are domain-rooted; the GitHub location is reached via redirect).
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
    parser.add_argument("--anchors-url", default="https://mybench.is/anchors",
                        help="anchors location (default: the mybench.is redirect)")
    parser.add_argument("--handle", help="owner handle for page identity + canonical URL")
    parser.add_argument("--out", required=True, help="output HTML path")
    args = parser.parse_args(argv)
    try:
        page = render_page(json.loads(Path(args.report).read_bytes()),
                           anchors_url=args.anchors_url, handle=args.handle)
    except (ValueError, PageError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    Path(args.out).write_bytes(page)
    print(f"wrote {args.out} ({len(page)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
