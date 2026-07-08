# Dictionary attacks on hashes of short content — analysis (MYB-1.3)

**Status:** Done — feeds ADR-0002 (salted-commitment scheme).
**Runnable demo:** `tests/analysis/test_dictionary_attack_demo.py` (synthetic
strings only, per privacy invariant #3).
**Threat-model hook:** THREAT_MODEL.md §4 (commitment scheme), ADV-1
(curious verifier).

## 1. The attack

Suppose mybench published unsalted hashes `H(m)` of transcript items. Hashes
are one-way only against *unguessable* inputs. For guessable inputs the
adversary does not invert the hash — they enumerate candidates:

1. **Precomputed dictionary.** Hash a corpus of likely strings once (common
   prompts, shell commands, well-known file headers, popular OSS lines) and
   match every published hash against the table. Cost is amortized across all
   targets of all users forever; a match is a *proof* of content, not a guess.
2. **Online brute force.** For a specific target, enumerate a template's
   variable parts ("fix the <noun>", small integer diffs, dates, usernames).
3. **Confirmation attack.** The adversary already suspects a specific `m`
   (e.g. "did this person work for client X?" with a known filename) and needs
   only one hash evaluation to confirm. This is the cheapest and most damaging
   variant: it turns a published hash into an oracle for yes/no questions
   about private content.
4. **Correlation without recovery.** Even when content is never guessed,
   identical items hash identically. Unsalted hashes leak equality — repeated
   prompts, re-used snippets, identical files across sessions — which is
   itself behavioral information.

## 2. Cost model vs content entropy

Enumeration cost is `2^H` hash evaluations, where `H` is the entropy of the
content *from the adversary's point of view* — not its length. SHA-256
throughput is ~10^9–10^10 H/s on one GPU and ~10^13 H/s for a modest rig
(Bitcoin-era ASICs are far beyond that).

| Content class (synthetic examples)             | Adversary-view entropy | Time @ 10^10 H/s |
|------------------------------------------------|------------------------|-------------------|
| Top-10k prompt list ("fix the tests", "continue") | ~13 bits            | instant (precomputed) |
| Short template + small variation               | ~20–30 bits            | < 1 s             |
| One-line command / import line                 | ~30–40 bits            | seconds–minutes   |
| Short unique diff hunk                         | ~50–60 bits            | hours–months      |
| Line containing a UUID or random token         | > 122 bits             | infeasible        |

The load-bearing observation: **a large fraction of real transcript lines sit
in the top three rows.** JSONL transcripts are full of short, formulaic,
low-entropy items, and the adversary picks the weakest items — the scheme's
privacy is set by the *least* entropic item, not the average. Confirmation
attacks (row-independent, cost = 1 hash) make even the "infeasible" row unsafe
whenever the adversary can source the candidate some other way.

Conclusion: unsalted `H(m)` provides **no meaningful privacy** for transcript
content. Any published unsalted hash must be treated as a disclosure of its
preimage.

## 3. Why salting defeats it

The committed form is

```
commit = SHA-256(domain || nonce || len(m) || m)     nonce = CSPRNG(32 bytes), per item
```

- **Guessing is now joint.** The adversary must enumerate `nonce || m`
  simultaneously: cost `2^(256 + H_m)` ≥ `2^256` even for an empty `m`.
  Security no longer depends on content entropy at all — it rests entirely on
  nonce entropy, which we control.
- **Precomputation is dead.** A dictionary must be rebuilt per (item, nonce)
  pair; since the nonce is secret, it cannot be built at all.
- **Confirmation is dead.** Checking a suspected `m` requires the nonce; the
  published value is a commitment (binding + hiding), not an oracle.
- **Correlation is dead.** Unique per-item nonces make identical content
  commit to independent values; equality leaks only when the user *chooses*
  to open both items.

## 4. Residual risks (must appear in ADR-0002)

- **Nonce leakage** reduces that item to the unsalted case (§1–2). Nonces are
  asset A2: 0700 dir / 0600 files, never in a repo, log, or test output.
- **Nonce reuse** restores correlation between the items sharing it. Per-item
  generation, uniqueness enforced by property test (§8 test matrix).
- **Weak or seeded RNG** silently voids §3's arithmetic. OS CSPRNG only
  (`secrets.token_bytes` / `getrandom`); no fallback path, no seeding, and a
  test asserting the production code path cannot be given a seed.
- **Selective disclosure is per-item irreversible**: opening an item reveals
  `m` and its nonce forever; sibling Merkle nodes reveal nothing further.
- **Encoding ambiguity**: without a length prefix and domain separation,
  concatenation games can equate distinct `(nonce, m)` splits or replay a
  leaf as a node. The ADR must pin exact byte encodings (see below).

## 5. Recommendation (ADR-consumable)

1. **Nonce: 32 bytes (256 bits), OS CSPRNG, fresh per item, never reused,
   never derived from content or other nonces.**
   - *Floor:* 128 bits already puts joint enumeration out of reach and makes
     accidental collision negligible (~2^-38 at 10^12 items).
   - *Why 256:* margin against multi-target attacks, uniqueness without any
     coordination or persistence, alignment with the SHA-256 block/output
     size, and no meaningful cost (32 bytes/item of A2 storage).
2. **Hash: SHA-256** over the domain-separated, length-prefixed preimage
   `domain || nonce || len(m) || m`, with `len(m)` as fixed-width 8-byte
   big-endian and distinct domain strings for leaf / node / day-root
   (`mybench:v1:leaf` etc.). Fixed-width length + fixed-length nonce make the
   preimage parse unambiguous.
3. **Boundary cases:** empty and one-character items are exactly as protected
   as long ones (security rests on the nonce alone) — no minimum-content rule
   is needed, and none should be added, since padding/normalization rules
   would themselves leak length classes. Length disclosure at the *report*
   level is a separate policy decision (mybench-ops OPEN_QUESTIONS #11);
   `len(m)` inside the preimage is never published.
4. **Never publish an unsalted hash of any content-derived value**, including
   "harmless" ones (filenames, repo names, prompt titles). §2's confirmation
   attack applies to all of them.
