# report

**Single responsibility:** assemble the scorer's validated report into an
immutable, signed local bundle and render its static HTML page. The bundle is
private A10 state under the mode-0700 data directory. It is never a publication
set and has no upload path.

`cli.py` owns canonical report bytes, the report content address, the
closed evidence-manifest whitelist, exact-byte Ed25519 signing, and write-once
storage. `page.py` remains the one zero-JavaScript whitelist renderer.
It accepts schema-v1 activity reports and registry-pinned schema-v2 Workflow
Fingerprint reports through the same validate-then-render path. V2 fields
must cite an active registry entry with an explicit report location and exact
version, disclosure, inference-risk, caveat, and derivation metadata; unknown
wrapper fields and inactive reserved blocks fail the build.
For multi-property claims, report-v2 uses dimension-sorted path cells. Primitive
leaves carry `value`; nested arrays and objects have explicit closed `container`
nodes, including empty containers. The registry validates the complete claim
output before encoding and reconstructs that exact structure before comparing
it to the verified signed claim, so nested values are not an arbitrary JSON
escape hatch. The renderer then adds the wrapper's tier/caveats and validates
the result against the entry's closed output schema before emitting HTML.
Registry-owned controls activate optional report
metadata and registry-owned caveat copy turns wrapper codes into display text.
Evidence tiers use labelled border geometry,
derivation class is a text pill, and rule-based
characterizations show confidence without being called JUDGED. The renderer
refuses a public v2 mode: publication preview remains a separate gated task.
The legacy `--report/--out` compatibility command is treated as public-capable
and therefore refuses v2; v2 HTML is emitted only inside the private,
content-addressed local bundle.
The stateful boundary captures one immutable input snapshot for scoring and
manifest derivation and opens the completed page as a file URL only as a best
effort. It never starts a network listener. The v0 page inlines its CSS and
SVG, leaving the required `assets/` directory empty.

See `docs/local-report-bundles.md` for layout, local-only handling, and the
signature verification recipe.

`preview/` is the separate MYB-14.1 local publication-preview boundary. It
projects only registry/preset-admitted atomic fields, coarsens the evidence
window to ISO weeks, renders a second closed zero-JavaScript page, signs the
three payload artifacts into `public-report.sig`, and leak-scans all four exact
staged files before atomic finalization below the existing local report id.
It has no upload, hosted-id, publication-record, or network path. See
`docs/publication-preview-bundles.md`.
