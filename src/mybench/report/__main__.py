"""CLI: assemble a signed, immutable private local report bundle.

    python -m mybench.report --report report.json --open
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mybench.report.cli import (
    BundleError,
    assemble_bundle,
    create_server,
    local_evidence_manifest,
    open_report,
    report_url,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mybench-report")
    parser.add_argument("--report", required=True, help="path to the scorer's report JSON")
    parser.add_argument("--anchors-url", default="https://mybench.is/anchors",
                        help="anchors location (default: the mybench.is redirect)")
    parser.add_argument("--handle", help="owner handle for page identity + canonical URL")
    parser.add_argument(
        "--evidence-manifest",
        help="closed evidence-manifest JSON (default: derive references from local scorer inputs)",
    )
    parser.add_argument("--open", action="store_true", help="open the private local report")
    parser.add_argument("--serve", action="store_true", help="serve on 127.0.0.1 only")
    parser.add_argument("--port", type=int, default=0, help="loopback port (requires --serve)")
    args = parser.parse_args(argv)
    if args.port and not args.serve:
        parser.error("--port requires --serve")
    server = None
    try:
        report = json.loads(Path(args.report).read_bytes())
        manifest = (
            json.loads(Path(args.evidence_manifest).read_bytes())
            if args.evidence_manifest
            else local_evidence_manifest(report)
        )
        directory = assemble_bundle(
            report,
            manifest,
            anchors_url=args.anchors_url,
            handle=args.handle,
        )
        url = None
        if args.serve:
            server = create_server(directory, port=args.port)
            url = report_url(server)
        opened = open_report(url or directory / "index.html") if args.open else None
    except (BundleError, OSError, ValueError):
        if server is not None:
            server.server_close()
        print("error: local report bundle failed", file=sys.stderr)
        return 1
    print(
        f"report ready: id={directory.name} (private, local only)"
        + (f"; serving {url}" if url else "")
        + ("; browser unavailable" if args.open and not opened else "")
    )
    if server is not None:
        sys.stdout.flush()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
