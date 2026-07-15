"""Owner-supervised, aggregate-only normalized-evidence runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

from mybench import normalized_store
from mybench.normalizer import normalize_claude, validate_corpus_artifact
from mybench.normalizer.loader import load_owner_claude_sessions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mybench.normalizer")
    parser.add_argument(
        "--owner-dogfood",
        action="store_true",
        help="normalize the authenticated local Claude archive",
    )
    parser.add_argument(
        "--confirm-subject-owned",
        action="store_true",
        help="confirm the local sessions belong to the credentialed subject and own agent fleet",
    )
    args = parser.parse_args(argv)
    if not args.owner_dogfood:
        parser.error("--owner-dogfood is required")

    try:
        sessions = load_owner_claude_sessions(
            confirm_subject_owned=args.confirm_subject_owned
        )
        artifact = normalize_claude(sessions)
        commitment = validate_corpus_artifact(artifact)
        normalized_store.store_corpus_artifact(artifact)
        value = json.loads(artifact)
        coverage = value["manifest"]["coverage"]
        print("normalization=pass source=claude-code store=pass")
        print(
            "sessions_admitted=%d records_seen=%d records_parsed=%d events=%d"
            % (
                coverage["sessions_admitted"],
                coverage["records_seen"],
                coverage["records_parsed"],
                value["manifest"]["event_count"],
            )
        )
        print(
            "records_malformed=%d records_unsupported=%d "
            "records_ambiguous_authorship=%d content_unknown=%d"
            % (
                coverage["records_malformed"],
                coverage["records_unsupported"],
                coverage["records_ambiguous_authorship"],
                coverage["content_unknown"],
            )
        )
        print(f"corpus_commitment={commitment}")
        print(f"artifact_sha256={hashlib.sha256(artifact).hexdigest()}")
        return 0
    except Exception as exc:  # noqa: BLE001 - suppress all private exception messages
        print(f"normalization=fail type={type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
