# Local identity state

Mybench identity has three deliberately separate layers:

1. **Private local keys.** The identity key controls the durable identity
   namespace. The current device key signs local reports and anchor events.
   They live under the private, mode-0700 Mybench data directory; private key
   files are mode 0600 and never enter a report, repository, or network call.
2. **Signed local control records.** Exact genesis and device/handle-binding
   bytes live under `identity/records/<identity-id>/` in that same data
   directory. Directories are mode 0700 and records are mode 0600. These bytes
   are public-candidate trust material, but their presence here is local state,
   not evidence that a service accepted or published them.
3. **The project-global identity and anchors log.** This is the independently
   verifiable append-only log. Its current founder-era implementation is
   Git-backed; the intended self-service path is a project-operated API with
   Git/checkpoints as a mirror. Registration and log submission are separate,
   explicit operations. `mybench init` does neither.

## Fresh initialization

On a genuinely fresh installation, `mybench init` atomically creates one
self-certifying genesis record and one active binding for the current device.
It creates no handle: handle uniqueness and account linkage belong to the
separate identity-authority service. A repeated init verifies the existing
chain without rewriting its bytes or metadata. Initialization and verification
are offline and never upload, register, anchor, or publish anything.

Normal users never need an anchors-repository clone. Local report construction
and publication preview consume the canonical local record store, not Git and
not the network.

## Founder-era compatibility migration

An installation that already has founder-era identity/device keys but no
canonical local records must migrate rather than generate replacement history:

```sh
mybench init --migrate-founder-records-from /path/to/legacy-anchors-clone
```

The explicit clone is inspected only for the current identity's three signed
public records. Mybench validates the self-certifying genesis, closed canonical
schemas, signatures, chronology, handle sequence, and current-device binding;
then it copies the exact bytes and timestamps atomically into the local store.
It never edits or deletes the clone, changes a key or identity id, or treats the
clone as the durable source after success. Repeating the command verifies the
canonical state without reopening or rewriting the clone. Malformed,
conflicting, unrelated, duplicate, symlinked, noncanonical, or unbound input
fails with a content-safe error.

This option is a bounded compatibility path for the founder installation, not
an onboarding step or a requirement for later users.

## Backup implications

Back up the private Mybench data directory using encrypted, owner-controlled
storage and preserve its permissions. The identity private key is critical:
losing it loses namespace control until a separately governed recovery
mechanism exists. The current device key and exact signed record chronology are
also needed to reproduce the local authorization chain. The legacy clone is
not a substitute for this backup after migration, and copying signed records
does not back up either private key.
