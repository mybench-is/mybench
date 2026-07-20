# Local report bundles

A local report is a private product artifact, not a publication preview. It
always remains below `${XDG_DATA_HOME:-$HOME/.local/share}/mybench`, whose data
directories are mode 0700:

```text
reports/<report-id>/
├── index.html
├── report.json
├── report.sig
├── evidence-manifest.json
└── assets/
```

The four files are mode 0600. `assets/` is mode 0700 and empty in v0 because
the page is self-contained and has no JavaScript. An existing bundle is
write-once: rebuilding verifies every byte and permission rather than replacing
anything.

Build and view a report with:

```sh
mybench report --format html,json --generated-at 2026-07-18T00:00:00Z --open
```

`--open` hands the private `index.html` file URL to the user's browser and
succeeds even when no browser is available. Mybench does not start a local
HTTP server or listen on any network port, preserving THREAT_MODEL ADV-4.
The compatibility `--format` selector is retained; assembly always writes the
complete signed bundle.

The component's original static-renderer form also remains available:

```sh
python -m mybench.report --report report.json --out index.html
```

That form renders only the explicitly supplied report. Bundle mode does not
accept a prebuilt report: it captures ledger rows, anchor events, and opted-in
repository facts once as an immutable in-memory snapshot, then derives both
the scored report and evidence manifest from that exact snapshot.

## Identity and signature

`report.json` is schema-validated and serialized as sorted, compact,
ASCII-safe JSON. Its report ID is:

```text
hex(SHA-256("mybench:v1:local-report-id\\0" || report.json bytes))
```

`report.sig` is the lowercase hexadecimal Ed25519 signature, followed by one
newline, over the exact bytes stored in `report.json`. Verify it against the
local device public key:

```python
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_public_key

data = Path("report.json").read_bytes()
signature = bytes.fromhex(Path("report.sig").read_text().strip())
public_key = load_pem_public_key(Path("device.pub").read_bytes())
public_key.verify(signature, data)
```

Use the `device.pub` from the same mybench data directory. A successful check
proves only that those report bytes were signed by that key; binding the key to
an identity remains the identity-chain verifier's responsibility.

## Evidence manifest boundary

`evidence-manifest.json` is local-only and is **never part of any publication
set**. Its closed schema admits only ledger row ranges and chain tip, anchor
event dates, corpus commitments, claim digests, and scorer/classifier/schema/
registry/pricing/formula versions; pricing references bind version, digest,
and currency to the report and verified cost claims. Unknown properties fail validation at every
level, so nonce, preimage, prompt, content, path, and filename fields cannot be
added. The complete bundle still receives leak-scan coverage because a local
report can contain details that must never be uploaded.

Publication preview, sanitization, upload, hosted IDs, revocation, and device
key rotation are separate gated features. This command implements none of
them.
