# report

**Single responsibility:** assemble the scorer's validated report into an
immutable, signed local bundle and render its static HTML page. The bundle is
private A10 state under the mode-0700 data directory. It is never a publication
set and has no upload path.

`cli.py` owns canonical report bytes, the report content address, the
closed evidence-manifest whitelist, exact-byte Ed25519 signing, and write-once
storage. `page.py` remains the one zero-JavaScript whitelist renderer.
The stateful boundary captures one immutable input snapshot for scoring and
manifest derivation and opens the completed page as a file URL only as a best
effort. It never starts a network listener. The v0 page inlines its CSS and
SVG, leaving the required `assets/` directory empty.

See `docs/local-report-bundles.md` for layout, local-only handling, and the
signature verification recipe.
