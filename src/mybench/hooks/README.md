# hooks

**Single responsibility:** provide an OPT-IN git commit-binding hook that records
a commit↔session binding commitment when a developer enables it in a specific
repo. Activation is per repo via a marker file (`.mybench/commit-binding-enabled`)
that the installed hook checks; **mybench never installs a global git hook or
sets `core.hooksPath`.** Only commitments and timestamps are recorded — never
diff content or filenames. See
`../../../../mybench-ops/decisions/ADR-0001-workspace-structure.md`.
