# Determinism CI gate

`python -m tests.determinism.gate` audits and runs every declared stage twice
in fresh processes, perturbing hash seed, time zone, locale, HOME/XDG paths,
and a sentinel environment value. It compares exact output bytes and logs
only byte counts and SHA-256 digests. Every input and fixture is synthetic.

The current landed stages are the activity `report.json`, signed-claim
serialization, registry disclosure manifest, and static report HTML. Parsers,
normalizers, fingerprint scorers, and the publication-preview bundle do not
exist on this branch yet. Each owning story must add both a byte-producing
callable to `RUNNERS` and a same-name `Stage`; exact key equality and
callability are checked before anything runs. Compute/render modules discovered
under scorer, parser/normalizer, report, and publication package roots must also
be owned by a stage marked `discovery_entry`. Every stage carries a production
`EntryPoint(module, qualname)`; registration imports it, proves it is callable
and owned by that module, then passes an invocation-recording wrapper into the
fixture runner. A runner that returns unrelated constant bytes without calling
the bound entry point fails. `__main__.py`/`cli.py` I/O shells are excluded by
convention; other helpers require an explicit reviewed non-stage entry.

The AST audit follows static first-party imports transitively and rejects
clock, network, environment, subprocess, locale, dynamic-import,
ambient-randomness, and filesystem access. Its reviewed boundaries are exact,
code-visible pairs rather than whole-module exemptions:

- packaged schema and descriptor-registry reads are committed inputs;
- `Registry.load(path)` is an explicit caller-supplied test/config input and is
  dormant in the fixed packaged-manifest runner;
- claim-envelope device-key and seedless ephemeral-key conveniences are
  dormant in the fixed-seed claim runner. The exact envelope→`mybench.paths`
  import edge and those exact calls are recorded; pipeline callers invoking
  the re-exported device helpers still fail.

Determinism that depends on unordered traversal is exercised under distinct
`PYTHONHASHSEED` values. Child failures never relay stderr: only exit status,
byte count, and SHA-256 are reported.

`requirements-ci.lock` pins distributions imported or executed by the runtime
and test gate. CI installs those pins, runs `pip check`, and the gate verifies
the installed versions still match exactly after the editable project install.
It does **not** pin the Python interpreter, pip, setuptools/build isolation, OS
image, or native wheels; hermetic build/toolchain identity remains MYB-10.14.

MYB-10.3 AC #3 deliberately starts with the first Wave-2 story. At that point,
extend the CI workflow with two OS images and compare the per-stage digests
reported by this same gate; do not pull the hermetic MYB-10.14 build into that
change.
