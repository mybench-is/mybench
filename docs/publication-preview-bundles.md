# Local publication-preview bundles

MYB-14.1 creates an exact candidate-publication preview without publishing
anything. It is an A10 local artifact under the existing content-addressed
private report directory:

```text
reports/<local-report-id>/publication-preview/
├── index.html
├── public-report.json
├── public-report.sig
└── redaction-manifest.json
```

The existing report id is only a local staging locator. Preview generation
mints no hosted, canonical, account, subject, or publication identifier. The
directory is mode 0700 and the four files are mode 0600. There is no assets
directory, JavaScript, upload client, publication record, state transition, or
network call.

Build the preview explicitly after reviewing the local report id:

```sh
python -m mybench.report.preview <64-hex-local-report-id> --preset employer-safe
```

Run `mybench init` first. Preview resolves and strictly verifies the
init-owned canonical identity chain under the local identity-control store;
it never reads anchor-publication staging, a Git clone, or the network. A
malformed chain or one that does not bind the current device fails before any
preview bytes are finalized.

`full` is the other registry-defined preset. V0 has no per-field disclosure
toggles. Before first finalization the command prints the complete categorical
will/won't listing plus the registry fields selected, excluded, or absent. An
existing preview is immutable: rerunning verifies every byte and permission.

## Public projection

`public-report.json` is not the private report schema with optional keys
deleted. It has its own closed schema and is built only after the source
report-v2 schema, registry identity, field order/uniqueness, report location,
value shape, caveats, controls, disclosure, risk, and preset membership all
validate. Only atomic fields marked `PUBLISHABLE`, admitted by the selected
preset, and in `covered` or `not-applicable` anchor state survive. Local-only,
preset-excluded, and uncovered fields are named by registry id and reason in
the redaction manifest, not copied into the report.

The public envelope omits the private report's exact generation timestamp,
legacy migration metrics, binding tips, pricing snapshot, anchored-through
date, backfill prose, and evidence manifest. Its evidence window is reduced to
ISO-week bounds. The seven fingerprint sections and generic catalog lane stay
closed and registry-governed.

`redaction-manifest.json` has a strict `additionalProperties: false` schema and
enumerates exactly these eleven categorical exclusions, all with status
`excluded`:

1. prompts
2. responses
3. code
4. repository names
5. filenames
6. local paths
7. employer/client names
8. exact timestamps
9. secrets
10. private URLs
11. raw orchestration-file contents

Its eligible/excluded policy is derived from the pinned descriptor registry;
internal-feature-only descriptor ids remain structurally hidden.

## Exact-byte signature and leak gate

`public-report.sig` is a canonical-JSON Ed25519 envelope using the MYB-10.1
sorted/compact/no-float byte discipline. It carries the signer device public
key, the self-certifying identity id, and SHA-256 digests of exact
`public-report.json`, `redaction-manifest.json`, and `index.html` bytes. The
envelope signature covers those fields; changing any of the four files makes
verification fail. Trust in the signer additionally requires a valid
identity-key-signed device-binding record for that device.

All four files are first written to a private staging directory under the
local report. Before the atomic rename, the mandatory gate scans the exact
staged paths and bytes against every local nonce and private-key file, the
active signing seed, local-only evidence-reference bytes, and any supplied
test canaries. Raw, lower/upper hex, all base64 byte phases, URL-safe base64,
and embedded gzip streams are checked. Empty file or secret sets fail rather
than passing vacuously; errors identify only a bundle-relative file and corpus
index, never the secret bytes or private parent path.

Tests plant synthetic transcript-content, repository-name, filename,
local-path, nonce, and key-material canaries in every encoding and prove each
one prevents finalization. Real transcripts are never fixtures.

## Governance boundary

This implements THREAT_MODEL §2 A10 and §3.2–3.6's local preview controls,
ADR-0019's atomic registry disclosure, and ADR-0022's local-only four-file
boundary. It does not authorize egress. A future uploader may consume only
these exact reviewed bytes after its separate hosted-operation, custody,
publication-record, and owner-confirmation gates land.
