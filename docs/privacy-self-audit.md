# Privacy self-audit checklist (MYB-4.3)

The v0 goal requires "pass a privacy self-audit." This document is the
checklist: every surface mybench writes to, what could leak there, the exact
check to run, and an unambiguous pass criterion. Execution against the real
deployment is MYB-4.4 (owner sitting; findings recorded in mybench-ops with
metadata-level notes only — never paste suspect content into findings).

**Estimated total time: 45–60 minutes** in one sitting. Run everything from
the mybench repo root with `V=.venv/bin/python`. `DD=~/.local/share/mybench`.

## Write-site → surface completeness mapping (AC #2)

Every filesystem/network write site in `src/mybench` (mechanical sweep:
`grep -rn -E "os\.open|write_bytes|write_text|open\(|urlopen|subprocess\.run|mkdir|chmod|fdopen" src/mybench`)
maps to a surface below:

| Module | Write sites | Surface |
|---|---|---|
| `paths.py` | data-dir/subdir creation + chmod; device/scope key writes | S1, S2 |
| `nonces.py` | per-session nonce file append | S3 |
| `ledger.py` | ledger row append; quarantine write + truncate | S4 |
| `daemon/capture.py` | none directly (writes via nonces/ledger); log records | S5 |
| `hooks/binding.py` | hook file into enrolled repo's .git/hooks; hooks.log | S6, S5 |
| `anchor/ots.py` | HTTP POST/GET to calendars; staged artifact + proof files | S7, S8 |
| `anchor/publish.py` | clone writes; `git push` to anchors repo | S9 |
| `scorer/__main__.py` | report file (`--out`); git subprocess reads (no writes) | S10 |

Any future module that adds a write site MUST add a surface here (the
MYB-4.4 re-run starts by re-running the grep and diffing this table).

## Surfaces

### S1 — Data directory tree (location + permissions)
- **Risk:** data dir inside a repo/synced folder; loose permissions exposing
  A2/A3 to other users.
- **Check:** `ls -la $DD $DD/nonces $DD/ledger $DD/keys $DD/anchors | head -30`
  and `git -C $DD rev-parse --git-dir 2>&1`.
- **Pass:** all dirs `0700`, owner-only; the `rev-parse` FAILS (not inside
  any git worktree); path is not under a sync/backup mount that leaves the
  machine unencrypted (owner attests).

### S2 — Key material
- **Risk:** private keys world-readable or duplicated outside the data dir.
- **Check:** `stat -c "%a %n" $DD/keys/*` ;
  `find / -name "device.key" -not -path "$DD/*" 2>/dev/null | head` (long —
  scope to home: `find ~ -name "device.key" -not -path "$DD/*"`).
- **Pass:** `device.key`, `session-scope.key`, `anchors-deploy` are `600`
  (`.pub` may be 644); no copies outside the data dir.

### S3 — Nonce store (asset A2, CRITICAL)
- **Risk:** nonce bytes anywhere outside `$DD/nonces` — each leaked nonce
  reduces its item to an unsalted hash.
- **Check:** `stat -c "%a" $DD/nonces/*.jsonl | sort -u` ; filenames opaque:
  `ls $DD/nonces | grep -vE '^[A-Za-z0-9_-]{1,64}\.jsonl$' | wc -l` ; then
  the gate self-check: `$V -c "from mybench.anchor.publish import local_secret_corpus; print(len(local_secret_corpus()), 'secrets in scan corpus')"`.
- **Pass:** all files `600`; zero non-opaque names; corpus count ≈ committed
  items (sanity: > 0). Nonce values themselves are never displayed.

### S4 — Ledger + quarantine (asset A3)
- **Risk:** content/filename fields smuggled into rows; quarantine bytes
  containing more than torn metadata rows.
- **Check:** `$V -c "from mybench.ledger import Ledger; led=Ledger(); print(led.verify_chain(), 'rows'); print(sorted({k for r in led.rows() for k in r}))"` ;
  quarantine: `ls -la $DD/ledger/*.quarantine 2>/dev/null` and, if present,
  confirm contents are truncated JSON row fragments (inspect LOCALLY, do not
  copy anywhere).
- **Pass:** chain verifies; field set is exactly the schema-v1 whitelist
  (10 session/genesis fields + 3 binding fields); quarantine (if any) holds
  only row-shaped fragments.

### S5 — Logs (daemon stderr logs, hooks.log)
- **Risk:** logs are a leak channel for paths, session ids, messages.
- **Check:** `cat $DD/hooks.log 2>/dev/null` ; plus wherever daemon stderr
  was redirected this deployment (owner locates; e.g. scratchpad run logs):
  `grep -cE "event=|scan complete" <logfile>` vs
  `grep -cE "$HOME|session|\.jsonl" <logfile>`.
- **Pass:** hooks.log lines are `ts + event + exception CLASS` only; daemon
  logs contain event names/counts/row indices and ZERO absolute paths,
  session ids, or filenames.

### S6 — Enrolled repos (hook + marker blast radius)
- **Risk:** hook installed beyond opted-in repos; global git config touched.
- **Check:** `git config --global core.hooksPath ; for r in typer typer-curriculum typer-ops mybench-ops; do ls /srv/agents/typer/repos/$r/.git/hooks/post-commit 2>/dev/null; done` ;
  in the enrolled repo: `git -C /srv/agents/typer/repos/mybench diff HEAD --stat -- .mybench/`.
- **Pass:** global hooksPath unset; no hook file in non-enrolled repos; the
  enrolled repo contains only the empty marker under `.mybench/`.

### S7 — OTS wire payloads (network egress #1)
- **Risk:** anything beyond the 32-byte root digest crossing the wire.
- **Check:** code-level (the gate for this is structural):
  `grep -n "data=" src/mybench/anchor/ots.py` — confirm the only POST body
  is `root`; re-run the capture test:
  `$V -m pytest tests/anchor/test_ots.py::test_wire_payload_is_exactly_the_root_digest -q`.
- **Pass:** single POST call site whose body is the digest; test green.

### S8 — Anchor staging (`$DD/anchors`)
- **Check:** `ls $DD/anchors | grep -vE '^anchor-[0-9]{8}-[0-9]{8}\.(json|root\.ots)$' | wc -l` ;
  `for f in $DD/anchors/anchor-*.json; do $V -c "import json,sys; from mybench.anchor.batch import verify_batch; verify_batch(json.load(open('$f')))" ; done`.
- **Pass:** zero non-whitelisted filenames; every artifact schema-valid and
  signature-verified.

### S9 — Published anchors repo (the public surface)
- **Risk:** the one surface where a leak is product-ending.
- **Check:** fresh clone to tmp; list every file ever committed:
  `git -C <tmpclone> log --all --name-only --format=` | sort -u` ; run the
  gate against the clone's full tree:
  `$V -c "from pathlib import Path; from mybench.anchor.publish import gate; gate(sorted(p for p in Path('<tmpclone>').iterdir() if p.is_file() and p.name!='README.md'))"` ;
  confirm history is append-only: `git log --diff-filter=DM --name-only --format=` — deletions/modifications of `.json` artifacts must be empty (`.root.ots` modifications allowed: proof upgrades).
- **Pass:** tree = README + whitelisted pairs only, gate passes on the real
  published bytes, no artifact was ever deleted or modified.

### S10 — Report JSON (and where it was written)
- **Check:** `$V -m pytest tests/scorer -q` (whitelist + leak tests) ; for
  any real report produced: validate + field-list it:
  `$V -c "import json; from mybench.schemas import load_validator; r=json.load(open('<report>')); load_validator('report.schema.json').validate(r); print(sorted(r))"` ;
  confirm no report file is inside any repo: `git -C /srv/agents/typer/repos/mybench status --porcelain; git -C /srv/agents/typer/repos/mybench-ops status --porcelain`.
- **Pass:** schema-valid; top-level fields ⊆ whitelist; no report files in
  repo worktrees.

### S11 — Git histories of mybench + mybench-ops (accidental data commits)
- **Risk:** real transcript content, nonces, ledger fragments, or real
  session ids committed at any point in history.
- **Check:** `git -C <repo> log --all --name-only --format= | sort -u | grep -vE '^(src/|tests/|docs/|ops/|epics/|backlog/|decisions/|reviews/|ideas/|\.mybench/|schemas/|README|CLAUDE|ROADMAP|SETUP_TODO|pyproject|pytest|requirements)'`
  (any unexplained path fails); then keyword sweep over all blobs:
  `git -C <repo> grep -I -l -E "MYBENCH-CANARY|BEGIN (OPENSSH|EC|RSA) PRIVATE" $(git -C <repo> rev-list --all) | head` — canaries may
  legitimately appear in test SOURCE files only; private-key markers never.
- **Pass:** file inventory fully explained; no private-key blob anywhere;
  canary strings only in `tests/` and `src/mybench/leakscan.py` contexts.

### S12 — Test + CI output
- **Risk:** tests writing real data, or fixtures drifting to real content.
- **Check:** `$V -m pytest -q` then
  `git -C /srv/agents/typer/repos/mybench status --porcelain` (suite-wide
  repo-tree guard also runs inside the suite); confirm the only checked-in
  test artifact is synthetic: `head -c 300 tests/scorer/golden_report_v0.json`;
  CI: none configured yet — when CI lands, its logs join this surface.
- **Pass:** suite green; worktree clean after run; golden file contains
  synthetic values only.

### S13 — Shell/session residue (owner machine hygiene)
- **Risk:** audit/ops commands echoing sensitive values into shell history
  or agent-session transcripts (which are themselves captured!).
- **Check:** review that checks in THIS document never print nonce/key
  bytes (they print counts, modes, field names); owner confirms no ad-hoc
  `cat` of nonce/key files happened during sittings (search shell history:
  `grep -E "cat .*nonces|cat .*device.key" ~/.bash_history | wc -l`).
- **Pass:** zero such commands (or documented+rotated if any).

## Failure protocol (MYB-4.4)

Any FAIL: file a task (blocking if the surface is public or key/nonce
material), fix, re-run that item. Findings doc records item → pass/fail →
metadata-level evidence reference. Owner sign-off closes the audit and is
the MYB-5.3 publishing gate.
