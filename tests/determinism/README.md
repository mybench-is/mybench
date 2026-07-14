# Determinism CI gate

`python -m tests.determinism.gate` audits and runs every declared stage twice
in fresh processes, perturbing hash seed, time zone, locale, HOME/XDG paths,
and a sentinel environment value. It compares exact output bytes and logs
only byte counts and SHA-256 digests. Every input and fixture is synthetic.

The current landed stages are the activity `report.json`, signed-claim
serialization, registry disclosure manifest, and static report HTML. Parsers,
normalizers, fingerprint scorers, and the publication-preview bundle do not
exist on this branch yet. Each owning story must add its byte-producing runner
and implementation module(s) to `stages.py`; any new module under
`mybench.scorer` fails closed until it is registered.

The AST audit rejects clock, network, environment, subprocess, locale, and
ambient-randomness access in every declared implementation module. Determinism
that depends on unordered traversal is exercised under distinct
`PYTHONHASHSEED` values.

MYB-10.3 AC #3 deliberately starts with the first Wave-2 story. At that point,
extend the CI workflow with two OS images and compare the per-stage digests
reported by this same gate; do not pull the hermetic MYB-10.14 build into that
change.
