"""mybench.hooks — opt-in git commit-binding hooks (see README)."""

COMPONENT = "hooks"
RESPONSIBILITY = (
    "provide opt-in, per-repo git commit-binding hooks gated on a marker file "
    "(never a global hook)"
)

# A commit-binding hook activates ONLY when this marker file exists in the target
# repo. mybench never installs a global git hook or sets core.hooksPath.
MARKER_RELPATH = ".mybench/commit-binding-enabled"
