# Private orchestration-delegation metrics

MYB-6.8 adds four deterministic, ANCHORED distributions to the private A10
Workflow Fingerprint report. The scorer consumes normalized-corpus v5 session
lineage and event timestamps only. It does not read transcripts, resolve a
pointer, inspect a filename/path, or emit an identifier.

These fields are `local-report-only` registry entries. They are absent from
both publication presets. The archetype gallery and every public projection of
these four fields remain unimplemented; this task does not activate or widen a
THREAT_MODEL §3 public class.

## Structural contract v1.0.0

An eligible lane graph is a rooted forest over admitted Claude sessions:

- a root is explicitly `lane_role=primary` and has no parent;
- a child is explicitly `lane_role=subagent`, names one admitted Claude parent,
  and reaches a valid root through accepted parent edges;
- malformed, absent, dangling, cross-source, or cyclic lineage is UNKNOWN and
  excluded from the activity denominator; and
- Codex v5 has no admitted lane markers, so Codex sessions remain UNKNOWN rather
  than being guessed from originator, path, or tool data.

`lineage_coverage_basis_points` is eligible sessions divided by all admitted
sessions. It travels with every field. The four metrics are:

1. `fingerprint.topology.spawning_session_rate`: eligible sessions with one or
   more accepted direct subagent children divided by all eligible sessions,
   rounded to integer basis points.
2. `fingerprint.topology.delegation_depth_distribution`: one count per eligible
   session, where depth is accepted-parent-edge distance from its root. Each
   observed depth carries an exact aggregate count.
3. `fingerprint.topology.fan_out_distribution`: one count per eligible session,
   where fan-out is its accepted direct-child count. Each observed fan-out
   value carries an exact aggregate count.
4. `fingerprint.topology.peak_parallel_lanes.exact`: one peak per root
   graph. A lane's closed observed-activity envelope runs from its earliest to
   latest normalized event timestamp. Peak is the greatest number of distinct
   lane envelopes covering any observed boundary. Each observed peak carries
   an exact aggregate graph count. A graph missing any lane timestamp is UNKNOWN. This
   is an activity-envelope overlap, not proof of simultaneous execution. The
   registry support floor is five interval-eligible sessions; below it the
   peak field is absent, never emitted as a zero-valued substitute.

All counts are corpus aggregates. The scorer discards in-memory graph keys and
timestamps before output. The closed output schema has no property for session
or episode ids, parent ids, names, paths, timestamps, graph shapes, or ordered
event/lane sequences.

## Trust and privacy boundary

The four metrics are ANCHORED: commitment/anchor continuity supports the timing
and existence of the underlying captured records, while lineage classification
and timestamp-envelope interpretation remain deterministic local assertions.
They are not PROVEN public facts and make no effectiveness, quality, autonomy,
or capability claim.

Tests use a deterministic synthetic forest with nested and overlapping
subagents. They prove exact buckets, UNKNOWN/coverage behavior, byte stability,
closed-schema rejection, whole-artifact canary absence, and a planted leak-scan
firing case.
