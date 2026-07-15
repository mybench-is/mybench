# Normalized evidence

The normalizer turns supported transcript records into deterministic,
content-opaque structure. It does not copy prompts, responses, commands,
paths, tool results, source files, or test output into its artifact.

## What is stored

One corpus artifact contains:

- opaque session identities and conservative task-episode links;
- turn, paste, tool, lifecycle, model, token, reference, and test structure;
- coarse content shapes such as `short` and `single`;
- pointers to eligible fields in a committed transcript record; and
- aggregate coverage counts, including honest ambiguity and missing evidence.

The artifact is validated against a closed JSON Schema and stored at:

```text
${XDG_DATA_HOME:-~/.local/share}/mybench/
  normalized/<corpus-commitment>/corpus.json
```

The directories are mode 0700 and the artifact is mode 0600. The store refuses
symlinks, hard-linked artifacts, loose existing permissions, non-canonical
bytes, and content-address mismatches.

## What a pointer means

A transcript pointer names a field and carries the salted commitment of its
source record. Resolution checks the live transcript first and then the
retained transcript archive. Each candidate keeps its raw record, nonce, and
verified authorship attribution together; non-subject matches are refused.
Each source supplies its own candidate layout, so resolution still works if
the live harness has pruned a prefix while the archive remains complete.

If neither source still has the target, resolution returns `unknown` and
coverage drops. Missing content is never treated as empty, reconstructed, or a
pipeline error.

Reference and test events in the Claude adapter point to the subject agent's
tool invocation. This proves which committed invocation was classified; it
does not claim to commit the bytes of a file named by that invocation or any
pasted tool output. Enrolled-repository target pointers are a separate
extractor contract.

## Consent and authorship

Filtering happens before normalized derivation:

- known non-subject sessions and records have no effect on artifact bytes,
  counters, identities, or success/failure;
- subject human and agent activity may contribute structural evidence;
- explicitly unknown authorship may contribute only a shape-only
  `pasted-span`; and
- pasted/tool-result bytes never receive a pointer or commitment in the
  artifact.

The synthetic tests add, remove, reorder, and corrupt excluded records to
prove that the known non-subject view is presence-insensitive.

## Corpus commitment

Canonical manifest and event records are hashed without their line terminator.
The manifest leaf comes first, followed by events sorted by source, session,
record, and subevent. Leaves use the fixed manifest/event domains and 8-byte
big-endian length framing. The existing RFC-6962-shaped tree uses
`mybench:v1:node` without duplicating odd leaves, and the result is wrapped by
`mybench:v1:normalized-corpus`.

Zero input sessions produce no artifact. A nonempty input whose consent filter
admits no records produces a valid manifest-only commitment.

## Owner-supervised ingestion

The pure adapter accepts records that an I/O layer has already authenticated
against capture commitments. The trusted loader takes a consistent snapshot
under the capture lock, selects the latest committed Claude rows, verifies the
A9 bytes against their A2 nonces and A3 roots, and only then constructs parser
inputs. It requires an explicit owner assertion that the local harness sessions
belong to the credentialed subject and that subject's own agent fleet.

The operator entry point is deliberately not ambient or automatic:

```text
python -m mybench.normalizer --owner-dogfood --confirm-subject-owned
```

It stores the content-opaque A8 artifact privately and prints aggregate counts,
coverage, the corpus commitment, and an artifact digest only. It never prints a
source path, filename, session identifier, nonce, raw record, or resolved field.
Real corpus verification remains owner-supervised and never becomes a fixture.
