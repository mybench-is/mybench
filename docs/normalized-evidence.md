# Normalized evidence

The normalizer turns supported transcript records and explicitly enrolled Git
repositories into deterministic, content-opaque structure. It does not copy
prompts, responses, commands, paths, tool results, source files, config bytes,
commit messages, ref names, or test output into its artifacts.

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

## Enrolled-repository adapter

`mybench.normalizer.repo_loader` is the trusted Git boundary. It accepts one
worktree only when both the `.mybench/commit-binding-enabled` marker and its
matching private enrollment record exist. The caller supplies the
credentialed subject's declared author-email identity set; identities are used
only for comparison inside the loader and are never serialized or logged.
ADR-0018 filtering happens before a `VerifiedRepoSnapshot` exists.

The pure `mybench.normalizer.repo` stage emits four record classes:

- subject-authored commits, their direct subject-authored parent links, and
  first-parent change structure;
- unique subject-authored local branch tips;
- unique subject-authored commits retained by any reflog; and
- opaque keyed-HMAC worktree ids whose HEAD is subject-authored.

Commit structure contains fixed change-kind counts and fixed file-class counts
(`manifest`, `lockfile`, `ci`, `other`). Filenames and paths are inspected only
long enough to assign one of those classes. A subject-authored merge is kept as
a commit pointer but its tree structure is `unknown`: a merge diff may carry
third-party branch content. Non-subject commits create no record, parent,
pointer, commitment, counter, or failure and a non-subject side branch is
artifact-byte-invisible.

Each eligible Git target uses a closed pointer containing only the keyed-HMAC
`repo_id`, Git object type, object id, the matching `git-sha1` or `git-sha256`
object commitment, and—for a blob—the admitted subject commit from which it was
derived. Git object ids are existing local repository commitments and remain
inside A8; they are never a publication field. Live resolution rechecks
enrollment, the opaque repo id, declared-subject authorship, blob membership in
the origin commit's admitted change set, object type, and Git object hash. A
pruned object returns `unknown / target-missing`, never empty bytes,
reconstruction, or a pipeline error.

Provenance is reachability-based and deterministic. With a recorded enrollment
commit, that commit and subject commits not descended from it are `IMPORTED`;
strict descendants are `LIVE`. An empty enrollment boundary means the repo was
enrolled before its first commit, so admitted commits are `LIVE`. IMPORTED is
an evidence annotation, not a trust tier.

## Transcript adapters

Claude Code and Codex are sibling pure adapters over the same verified-record
input and normalized-corpus contract. Both use the same schema version,
authorship policy, task-episode stitcher, event commitment domains, validator,
private A8 store, and honest UNKNOWN coverage semantics.

The Codex v1 adapter recognizes durable rollout envelopes for session metadata,
turn context, response items, event messages, and compaction. It maps observed
message, tool, model/provider/effort, token, and lifecycle structure only where
the rollout carries it. Missing or unsupported fields stay absent or increment
coverage; they are never zero-filled or inferred. Agent text and tool inputs
may receive commitment-bound pointers. Human text, tool results, compaction
summaries, and ambiguous records remain shape-only and receive no pointer.

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
extractor contract described above.

## Consent and authorship

Filtering happens before normalized derivation:

- known non-subject sessions and records have no effect on artifact bytes,
  counters, identities, or success/failure;
- subject human and agent activity may contribute structural evidence;
- explicitly unknown authorship may contribute only a shape-only
  `pasted-span`; and
- pasted/tool-result bytes never receive a pointer or commitment in the
  artifact.

The synthetic tests add, remove, reorder, and corrupt excluded records and Git
commits to prove that the known non-subject view is presence-insensitive.

## Corpus commitment

Canonical manifest and event records are hashed without their line terminator.
The manifest leaf comes first, followed by events sorted by source, session,
record, and subevent. Leaves use the fixed manifest/event domains and 8-byte
big-endian length framing. The existing RFC-6962-shaped tree uses
`mybench:v1:node` without duplicating odd leaves, and the result is wrapped by
`mybench:v1:normalized-corpus`.

Zero transcript sessions or zero verified repository snapshots produce no
artifact. A nonempty input whose consent filter admits no records produces a
valid manifest-only commitment. Transcript and repository records use separate
closed schemas but the identical manifest/event domains, u64BE framing,
manifest-first ordering, tree reduction, and final corpus wrapper.

## Owner-supervised ingestion

Each pure adapter accepts records that an I/O layer has already authenticated
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

The supervised loader currently admits Claude rows only. Production Codex
discovery and loading remain a separate capture-adapter task; MYB-10.18 adds no
ambient access to Codex rollout directories. Codex adapter validation uses
seeded synthetic rollout-v1 records and the same two-process determinism gate.
The repository loader likewise has no ambient scan-all-repos entry point: a
caller must name an already enrolled worktree and declare the subject identity
set. MYB-10.5 validation uses synthetic Git repositories only; no owner
repository is scanned by its automated path.
