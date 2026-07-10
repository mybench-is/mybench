# Contributing

mybench's trust-surface code is Apache-2.0 (see LICENSE) — the verifier,
scorer, capture pipeline, and schemas are open because their openness is
the product claim.

**All contributions require a Developer Certificate of Origin sign-off**
(`git commit -s`, certifying https://developercertificate.org/). This is
deliberate: it preserves the project's ability to make licensing decisions
while accepting outside work. PRs without signed-off commits will be asked
to amend.

Ground rules that will not bend in review: the privacy invariants in
CLAUDE.md, the schema whitelists, determinism of the scorer/renderer, and
the leak-gate discipline on anything that writes or publishes.
