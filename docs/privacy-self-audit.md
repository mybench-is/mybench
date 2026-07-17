# Privacy self-audit checklist (MYB-4.3)

The v0 goal requires "pass a privacy self-audit." This document is the
checklist: every surface mybench writes to, what could leak there, the exact
check to run, and an unambiguous pass criterion. Execution against the real
deployment is MYB-4.4 (owner sitting; findings recorded in mybench-ops with
metadata-level notes only — never paste suspect content into findings).

**Estimated total time: 50–65 minutes** in one sitting. Run everything from
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
| `scan_config.py` | confirmed source/exclusion config, atomically replaced | S16 |
| `scan_health.py` | successful-scan receipt + writer lock, atomically replaced | S17 |
| `scheduler.py` | private schedule receipt/lock + owned systemd/launchd files | S18 |
| `hooks/binding.py` | hook file into enrolled repo's .git/hooks; hooks.log | S6, S5 |
| `hooks/lifecycle.py` | whitelisted tuple queue; failure counter; hooks.log; explicit user-settings install/uninstall | S15, S5 |
| `anchor/ots.py` | HTTP POST/GET to calendars; staged artifact + proof files | S7, S8 |
| `anchor/publish.py` | clone writes; `git push` to anchors repo | S9 |
| `scorer/__main__.py` | report file (`--out`); git subprocess reads (no writes) | S10 |
| site repo `functions/api/waitlist.js` | D1 `INSERT` of submitted email (off-machine, Cloudflare) | S14 |

Any future module that adds a write site MUST add a surface here (the
MYB-4.4 re-run starts by re-running the grep and diffing this table). Note S14
lives outside `src/mybench` — it is the public site's Worker (MYB-5.10), the
first surface that stores third-party PII, and is audited on the Cloudflare side
rather than by the `src/mybench` grep.

## Surfaces

### S1 — Data directory tree (location + permissions)
- **Risk:** data dir inside a repo/synced folder; loose permissions exposing
  A2/A3 to other users.
- **Check:** `ls -la $DD $DD/nonces $DD/ledger $DD/keys $DD/anchors $DD/queue | head -40`
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
- **Pass:** chain verifies; every row is in the closed schema-v1/v2 whitelist;
  v1 remains limited to genesis/session/binding, while v2 lifecycle events
  contain only the ADR-0013 structural fields; quarantine (if any) holds only
  row-shaped fragments.

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
- **Receipt check:**
  `$V -m pytest tests/anchor/test_ots.py::test_observed_stamp_freezes_first_success_while_later_attempts_finish tests/anchor/test_receipt.py::test_cut_receipt_surface_is_canary_clean_and_scanner_fires -q`.
  The first successfully merged response time is retained only for the private
  ledger receipt; calendar URLs are absent from receipt rows and cut logs.

### S8 — Anchor staging (`$DD/anchors`)
- **Check (layout v1, ADR-0004):** staged paths match the whitelist:
  `$V -c "from mybench.anchor.publish import staged_files, gate; fs=staged_files(); gate(fs) if fs else print('staging empty'); print(len(fs), 'staged files pass the gate')"`
  (the gate IS the check: path whitelist + event signatures + proof binding
  + secret-corpus scan; archives under anchors/archive* are excluded).
- **Pass:** zero non-whitelisted filenames; every artifact schema-valid and
  signature-verified.
- **Receipt boundary:** staged event/proof bytes remain unchanged and date-only;
  `receipt_ts`, `receipt_id`, and derived latency are structurally absent. A
  staged event without its private receipt remains `unknown` after recovery.

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
- **Check:** `git -C <repo> log --all --name-only --format= | sort -u | grep -vE '^(src/|tests/|docs/|ops/|epics/|backlog/|decisions/|reviews/|ideas/|\.mybench/|\.github/|\.gitignore|schemas/|README|CLAUDE|ROADMAP|SETUP_TODO|pyproject|pytest|requirements)'`
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
  CI: GitHub Actions runs lint+pytest on every push/PR
  (`.github/workflows/ci.yml`); its logs are public-adjacent, safe by
  construction because tests are synthetic-only, XDG-isolated, and the
  live-OTS network test is env-gated off in CI — verify no workflow step
  sets MYBENCH_LIVE_OTS or mounts real data:
  `grep -E "MYBENCH_LIVE_OTS|\.local/share" .github/workflows/*.yml | wc -l`.
- **Pass:** suite green; worktree clean after run; golden file contains
  synthetic values only; workflow grep returns 0.

### S13 — Shell/session residue (owner machine hygiene)
- **Risk:** audit/ops commands echoing sensitive values into shell history
  or agent-session transcripts (which are themselves captured!).
- **Check:** review that checks in THIS document never print nonce/key
  bytes (they print counts, modes, field names); owner confirms no ad-hoc
  `cat` of nonce/key files happened during sittings (search shell history:
  `grep -E "cat .*nonces|cat .*device.key" ~/.bash_history | wc -l`).
- **Pass:** zero such commands (or documented+rotated if any).

### S14 — Waitlist database (public site, off-machine PII — NEW class)
- **Risk:** the site's waitlist is the first surface that stores third-party
  PII (submitted emails). Leaks here are (a) joining an email to any
  anchor/identity/report/ledger datum, (b) disclosing list membership, (c)
  storing more than the visitor typed, (d) shipping the address to any
  third-party service, or (e) an analytics beacon on report pages.
- **Check:** read the site repo's `functions/api/waitlist.js` and `schema.sql`
  (staged in `mybench-ops/ops/site/` until the public site repo exists) —
  confirm the only columns are `email`, `created_at` (date-only), `referrer`
  (capped, optional); no identity/anchor/report column exists or is joinable.
  Confirm the endpoint returns the SAME response for new vs. duplicate emails
  (no membership disclosure) and writes to no external service. Confirm
  `_headers` sets `default-src 'none'` with no `script-src` and no analytics
  origin; edge analytics only (ADR-0005 §5, no JS beacon). D1 access is
  Cloudflare-account-scoped; verify no export/replication to a third party.
- **Pass:** schema = the three columns above and nothing joinable; identical
  new/duplicate responses; zero third-party egress; report pages beacon-free.

### S15 — Claude lifecycle hook queue + user settings
- **Risk:** raw hook payloads contain paths, prompt-adjacent compact
  instructions, model data, and identifiers; installer could overwrite
  unrelated user hooks or imply publication.
- **Check:** `$V -m pytest tests/hooks/test_lifecycle.py -q`; inspect
  `$DD/queue` with `stat -c "%a %n" $DD/queue $DD/queue/*`; run
  `$V -c "from mybench.hooks.lifecycle import flush_queue; print(flush_queue(), 'lifecycle rows flushed')"`;
  then verify `$V -c "from mybench.ledger import Ledger; print(Ledger().verify_chain())"`.
  For settings, run install twice and uninstall once under a synthetic `HOME`
  (the test does this) and diff the JSON object before/after.
- **Pass:** queue dir is 0700 and files 0600; queued objects have exactly
  `queue_version,ts,event_kind,trigger,session_id,harness`; failure state is an
  integer and hook logs contain exception classes only; raw `cwd`,
  `transcript_path`, Claude session id, model, compact instructions, filenames,
  and unknown fields are absent in raw/common encodings; chain verifies after
  flush/replay/crash recovery; config round-trips with unrelated settings and
  hooks unchanged; handlers are async with a one-second timeout; no publication
  state is touched.

### S16 — Confirmed source-discovery scan config
- **Risk:** scanning begins before informed consent; an excluded tree is
  entered; confirmed local paths escape the private data dir through logs,
  reports, CI output, or an accidental repo copy; config permissions expose
  the owner's source layout.
- **Check:** `$V -m pytest tests/test_scan_config.py -q`; then inspect metadata
  without printing paths:
  `$V -c "import stat; from mybench import paths; from mybench.scan_config import load; c=load(); p=paths.scan_config_path(); print(oct(stat.S_IMODE(p.stat().st_mode)), len(c.watches), len(c.repos), len(c.exclusions))"`.
  Confirm `git -C /srv/agents/typer/repos/mybench status --porcelain` shows no
  `scan-config.json`. Run a proposal locally and verify every proposed path is
  shown before confirmation; decline it and verify the config mtime is
  unchanged.
- **Pass:** proposal-only and decline modes write nothing; an accepted config
  is a single regular, unlinked 0600 file under the 0700 data dir and validates
  against the closed schema; Git discovery has only explicit roots; tests
  prove excluded directories are pruned before `scandir` and both unified scan
  and daemon honor the same persisted exclusions. Full paths appear only in
  the explicit local consent proposal and the private config—never in daemon
  logs, report artifacts, CI summaries, or publication surfaces. Synthetic
  negative leak scans pass and the repo-copy firing test fails as intended.

### S17 — Successful-scan receipt + local status output

- **Risk:** a forged/manual timestamp overclaims capture freshness; receipt
  identifiers disclose paths; status mutates the state it is meant to inspect,
  networks while checking proofs, leaks content/key/nonce bytes, or silently
  repairs loose permissions.
- **Check:** `$V -m pytest tests/test_status.py -q`; inspect only receipt
  metadata with
  `$V -c "import json,stat; from mybench import paths; p=paths.scan_health_path(); d=json.loads(p.read_bytes()); print(oct(stat.S_IMODE(p.stat().st_mode)), sorted(d), len(d['watches']), len(d['repos']))"`.
  Run `mybench status --json` twice around a recursive file size/mode/mtime/hash
  snapshot of `$DD` and confirm the snapshots are identical.
- **Pass:** successful scan paths automatically write canonical 0600 receipt
  and lock files below the 0700 data dir; failed scans do not advance them;
  receipt location ids are full keyed HMACs and contain no paths. Existing
  activity stays `unknown` until a real post-upgrade scan. Status makes zero
  filesystem writes and zero network calls, reports rather than repairs loose
  permissions, validates its closed JSON schema, passes content/key/nonce
  canary scans in both renderings, and the planted-output companion fires.

### S18 — OS-native scheduled capture

- **Risk:** an installed job embeds a source/repository path, nonce, key,
  transcript marker, credential, network/publication flag, or shell payload;
  enable overwrites a foreign unit/hook; disable removes unrelated state; a
  resident process remains; failed scans silently disable future capture; or
  status mutates scheduler state while inspecting it.
- **Check:** `$V -m pytest tests/test_scheduler.py -q`; inspect generated job
  metadata with `stat -c "%a %n" ~/.config/systemd/user/mybench-scan.*`
  (Linux) or `stat -f "%Lp %N" ~/Library/LaunchAgents/is.mybench.scan.plist`
  (macOS), then run `mybench status --json` without copying path fields into an
  external log. Diff the owned job files and `$DD` snapshot before/after status.
- **Pass:** fixture-locked jobs invoke only the installed CLI with
  `scan --quiet --scheduled`; systemd uses `Type=oneshot` and launchd uses
  `KeepAlive=false`, with no restart/resident command. Job files pass raw/common
  encoding scans for synthetic content/filenames, nonces, and private keys; the
  planted companion fires. Registration/teardown are idempotent, foreign or
  insecure files are refused, scheduled failure leaves the job registered for
  a later run, private state/lock are 0600, and read-only/offline status reports
  active/inactive/manual and last-result health without repair.

## Failure protocol (MYB-4.4)

Any FAIL: file a task (blocking if the surface is public or key/nonce
material), fix, re-run that item. Findings doc records item → pass/fail →
metadata-level evidence reference. Owner sign-off closes the audit and is
the MYB-5.3 publishing gate.
