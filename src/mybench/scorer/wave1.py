"""Deterministic Wave-1 transcript scorers (MYB-10.6).

The six scorers consume the closed normalized-corpus artifact and emit only
registry-governed bands, booleans, and the R1 harness inventory admitted by
the registry. They never emit transcript content, event/session identifiers,
tool/server names, paths, timestamps, or ordered streams.

Harness currency and per-event MCP category observations are explicit,
content-addressed inputs. The former prevents a score-time network lookup. The
latter binds each upstream local category assertion to one normalized event
leaf; the scorer proves exact one-to-one MCP-event coverage and derives
distinct-session recurrence itself. The emitted recurrence snapshot is
aggregate and identifier-free. All time, signing, and evidence inputs are
caller-supplied.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from fractions import Fraction

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mybench.claims import build_claim, canonical_bytes, sign_claim
from mybench.normalizer.contract import event_leaf_hash, validate_corpus_artifact
from mybench.registry import Registry
from mybench.schemas import load_validator

SCORER_VERSION = "1.1.0"
MCP_TAXONOMY_VERSION = "1.0.0"

_WAVE1_IDS = (
    "transcript.wellformed",
    "transcript.tool_mix",
    "transcript.autonomy_band",
    "transcript.verification_ratio",
    "transcript.orchestrators",
    "transcript.mcp_breadth",
)
_PERCENT_BAND_RE = re.compile(r"([0-9]+)-([0-9]+)%")
_RANGE_BAND_RE = re.compile(r"([0-9]+)-([0-9]+)")
_PLUS_BAND_RE = re.compile(r"([0-9]+)\+")
_EXACT_BAND_RE = re.compile(r"[0-9]+")
_SEMVER_RE = re.compile(r"([0-9]+)\.([0-9]+)\.([0-9]+)")

_HARNESS_SNAPSHOT_DOMAIN = b"mybench:wave1:harness-currency:v1\0"
_MCP_OBSERVATIONS_DOMAIN = b"mybench:wave1:mcp-observations:v1\0"
_MCP_SNAPSHOT_DOMAIN = b"mybench:wave1:mcp-recurrence:v2\0"


class Wave1ScorerError(ValueError):
    """A normalized input, control snapshot, or scorer invariant is invalid."""


def _digest_snapshot(snapshot: dict, domain: bytes) -> str:
    payload = {key: value for key, value in snapshot.items() if key != "digest"}
    encoded = canonical_bytes(payload)
    return hashlib.sha256(domain + len(encoded).to_bytes(8, "big") + encoded).hexdigest()


def build_harness_currency_snapshot(versions: Mapping[str, str], *, snapshot_version: str) -> dict:
    """Build the exact offline version input consumed by ``orchestrators``."""

    if not isinstance(versions, Mapping) or not versions:
        raise Wave1ScorerError("harness currency versions must be a non-empty mapping")
    rows = [{"harness": name, "latest": version} for name, version in sorted(versions.items())]
    snapshot = {
        "schema_version": "1",
        "kind": "harness-version-currency-snapshot",
        "snapshot_version": snapshot_version,
        "versions": rows,
    }
    snapshot["digest"] = _digest_snapshot(snapshot, _HARNESS_SNAPSHOT_DOMAIN)
    _validate_harness_snapshot(snapshot)
    return snapshot


def build_mcp_category_observations(
    source_corpus_commitment: str,
    observations: Sequence[Mapping[str, str]],
) -> dict:
    """Build the closed event-commitment/category provenance carrier.

    This builder canonicalizes and commits caller-supplied rows. Membership,
    event kind, duplicate, and completeness checks require the normalized
    corpus and are therefore enforced by the scorer, not asserted here.
    """

    if isinstance(observations, (str, bytes)) or not isinstance(observations, Sequence):
        raise Wave1ScorerError("MCP category observations must be a sequence")
    rows = []
    for observation in observations:
        if not isinstance(observation, Mapping) or set(observation) != {
            "event_commitment",
            "category",
        }:
            raise Wave1ScorerError("MCP category observation has invalid fields")
        if not all(
            isinstance(observation[field], str) for field in ("event_commitment", "category")
        ):
            raise Wave1ScorerError("MCP category observation values must be strings")
        rows.append(
            {
                "event_commitment": observation["event_commitment"],
                "category": observation["category"],
            }
        )
    rows.sort(key=lambda row: (row["event_commitment"], row["category"]))
    artifact = {
        "schema_version": "1",
        "kind": "mcp-category-event-observations",
        "taxonomy_version": MCP_TAXONOMY_VERSION,
        "source_corpus_commitment": source_corpus_commitment,
        "observations": rows,
    }
    artifact["digest"] = _digest_snapshot(artifact, _MCP_OBSERVATIONS_DOMAIN)
    _validate_mcp_observations(artifact)
    return artifact


def build_mcp_recurrence_snapshot(corpus: dict, observations: dict) -> dict:
    """Derive an aggregate, identifier-free snapshot from proven event rows."""

    root, sessions, _ = _checked_corpus(corpus)
    return _derive_mcp_snapshot(corpus, root, sessions, observations)


def _schema_check(value: dict, schema_name: str, label: str) -> None:
    try:
        errors = sorted(load_validator(schema_name).iter_errors(value), key=str)
    except Exception as exc:  # noqa: BLE001 - keep private values out of errors
        raise Wave1ScorerError(f"{label} validation failed") from exc
    if errors:
        raise Wave1ScorerError(f"{label} violates its closed schema")


def _validate_harness_snapshot(snapshot: dict) -> None:
    _schema_check(snapshot, "harness_currency_snapshot.schema.json", "harness snapshot")
    rows = snapshot["versions"]
    names = [row["harness"] for row in rows]
    if names != sorted(set(names)):
        raise Wave1ScorerError("harness snapshot rows must be sorted and unique")
    if snapshot["digest"] != _digest_snapshot(snapshot, _HARNESS_SNAPSHOT_DOMAIN):
        raise Wave1ScorerError("harness snapshot digest does not match its content")


def _validate_mcp_observations(observations: dict) -> None:
    _schema_check(
        observations,
        "mcp_category_observations.schema.json",
        "MCP category observations",
    )
    rows = observations["observations"]
    expected = sorted(rows, key=lambda row: (row["event_commitment"], row["category"]))
    if rows != expected:
        raise Wave1ScorerError("MCP category observation rows must be sorted")
    if observations["digest"] != _digest_snapshot(observations, _MCP_OBSERVATIONS_DOMAIN):
        raise Wave1ScorerError("MCP category observations digest does not match content")


def _validate_mcp_snapshot(snapshot: dict) -> None:
    _schema_check(snapshot, "mcp_recurrence_snapshot.schema.json", "MCP snapshot")
    rows = snapshot["category_session_counts"]
    categories = [row["category"] for row in rows]
    if categories != sorted(set(categories)):
        raise Wave1ScorerError("MCP snapshot rows must be sorted and unique")
    if snapshot["digest"] != _digest_snapshot(snapshot, _MCP_SNAPSHOT_DOMAIN):
        raise Wave1ScorerError("MCP snapshot digest does not match its content")


def _checked_corpus(corpus: dict) -> tuple[str, tuple[tuple[str, str], ...], dict]:
    if not isinstance(corpus, dict):
        raise Wave1ScorerError("normalized corpus must be an object")
    try:
        root = validate_corpus_artifact(canonical_bytes(corpus) + b"\n")
    except Exception as exc:  # noqa: BLE001 - normalizer errors are intentionally path-free
        raise Wave1ScorerError("normalized corpus validation failed") from exc
    session_keys = tuple(
        (session["source"], session["session_id"]) for session in corpus["manifest"]["sessions"]
    )
    grouped: dict[tuple[str, str], list[dict]] = {key: [] for key in session_keys}
    for event in corpus["events"]:
        grouped[(event["source"], event["session_id"])].append(event)
    return root, session_keys, grouped


def _derive_mcp_snapshot(
    corpus: dict,
    corpus_root: str,
    session_keys: Sequence[tuple[str, str]],
    observations: dict,
) -> dict:
    """Prove exact MCP-event provenance and derive distinct-session counts."""

    _validate_mcp_observations(observations)
    if observations["source_corpus_commitment"] != corpus_root:
        raise Wave1ScorerError("MCP category observations are stale for this corpus")

    event_index: dict[str, tuple[dict, tuple[str, str]]] = {}
    mcp_commitments = set()
    for event in corpus["events"]:
        commitment = event_leaf_hash(event).hex()
        if commitment in event_index:
            raise Wave1ScorerError("normalized corpus has duplicate event commitments")
        session_key = (event["source"], event["session_id"])
        event_index[commitment] = (event, session_key)
        if event["event_kind"] == "tool-call" and event["tool_family"] == "mcp":
            mcp_commitments.add(commitment)

    seen = set()
    category_sessions: dict[str, set[tuple[str, str]]] = {}
    for observation in observations["observations"]:
        commitment = observation["event_commitment"]
        if commitment in seen:
            raise Wave1ScorerError("MCP category observations duplicate an event commitment")
        seen.add(commitment)
        indexed = event_index.get(commitment)
        if indexed is None:
            raise Wave1ScorerError("MCP category observation is absent from the exact corpus")
        event, session_key = indexed
        if event["event_kind"] != "tool-call" or event["tool_family"] != "mcp":
            raise Wave1ScorerError("MCP category observation references a non-MCP event")
        category_sessions.setdefault(observation["category"], set()).add(session_key)

    if seen != mcp_commitments:
        raise Wave1ScorerError("MCP category observations do not cover every MCP event")
    admitted_sessions = set(session_keys)
    if any(not sessions <= admitted_sessions for sessions in category_sessions.values()):
        raise Wave1ScorerError("MCP category observation has no admitted session")

    rows = [
        {"category": category, "sessions": len(sessions)}
        for category, sessions in sorted(category_sessions.items())
    ]
    snapshot = {
        "schema_version": "2",
        "kind": "mcp-category-recurrence-snapshot",
        "taxonomy_version": MCP_TAXONOMY_VERSION,
        "source_corpus_commitment": corpus_root,
        "source_observations_digest": observations["digest"],
        "category_session_counts": rows,
    }
    snapshot["digest"] = _digest_snapshot(snapshot, _MCP_SNAPSHOT_DOMAIN)
    _validate_mcp_snapshot(snapshot)
    return snapshot


def _entry(registry: Registry, registry_id: str) -> dict:
    entry = registry.entry(registry_id)
    if entry["status"] != "active" or entry["class"] != "measured":
        raise Wave1ScorerError("Wave-1 registry entry is not active and measured")
    return entry


def _has_support(entry: dict, sessions: int) -> bool:
    floor = entry["min_support"].get("sessions")
    if type(floor) is not int or floor <= 0:
        raise Wave1ScorerError("Wave-1 registry entry has no positive session floor")
    return sessions >= floor


def _bands(entry: dict, field: str) -> tuple[str, ...]:
    matches = [row["bands"] for row in entry["band_definitions"] if row["field"] == field]
    if len(matches) != 1:
        raise Wave1ScorerError("registry band definition is missing or duplicated")
    return tuple(matches[0])


def _numeric_band(entry: dict, field: str, value: Fraction, *, percent: bool = False) -> str:
    """Resolve an exact rational against registry labels, with no scorer edges."""

    candidate = value * 100 if percent else value
    for label in _bands(entry, field):
        match = _PERCENT_BAND_RE.fullmatch(label) if percent else None
        if match is None and not percent:
            match = _RANGE_BAND_RE.fullmatch(label)
        if match is not None:
            low, high = (int(part) for part in match.groups())
            if Fraction(low) <= candidate < Fraction(high + 1):
                return label
            continue
        plus = _PLUS_BAND_RE.fullmatch(label)
        if plus is not None and candidate >= int(plus.group(1)):
            return label
        if _EXACT_BAND_RE.fullmatch(label) and candidate == int(label):
            return label
    raise Wave1ScorerError("value does not fit the registry's complete band set")


def _score_wellformed(
    entry: dict, corpus: dict, session_keys: Sequence, grouped: dict
) -> dict | None:
    if not _has_support(entry, len(session_keys)):
        return None

    timestamps_ok = 0
    pairing_ok = 0
    splice_ok = 0
    wellformed = 0
    coverage = corpus["manifest"]["coverage"]
    unresolved_lineage = coverage["lineage_unresolved"] != 0
    harness_clean = not any(
        coverage[field]
        for field in (
            "records_malformed",
            "records_unsupported",
            "records_ambiguous_authorship",
            "blocks_unsupported",
            "metadata_invalid",
        )
    )

    for key in session_keys:
        events = grouped[key]
        timestamps = [event["observed_at"] for event in events if "observed_at" in event]
        monotonic = timestamps == sorted(timestamps)

        calls = {
            (event["record_index"], event["subevent_index"])
            for event in events
            if event["event_kind"] == "tool-call"
        }
        result_counts: Counter[tuple[int, int]] = Counter()
        pairing = True
        for event in events:
            if event["event_kind"] != "tool-result":
                continue
            relation = event["tool_relation"]
            if relation["status"] != "linked":
                pairing = False
                continue
            target = (relation["record_index"], relation["subevent_index"])
            if target not in calls:
                pairing = False
            result_counts[target] += 1
        pairing = pairing and all(result_counts[target] == 1 for target in calls)

        records: dict[int, dict] = {}
        splice = not unresolved_lineage
        for event in events:
            record_index = event["record_index"]
            parent = event["parent_link"]
            if record_index in records and records[record_index] != parent:
                splice = False
            records[record_index] = parent
        for position, record_index in enumerate(sorted(records)):
            parent = records[record_index]
            if position == 0:
                splice = splice and parent["status"] == "root"
            else:
                splice = splice and parent["status"] == "linked"
                if parent["status"] == "linked":
                    splice = splice and parent["record_index"] in records
                    splice = splice and parent["record_index"] < record_index

        timestamps_ok += monotonic
        pairing_ok += pairing
        splice_ok += splice
        wellformed += harness_clean and monotonic and pairing and splice

    total = len(session_keys)
    output = {
        "sessions_checked_band": _numeric_band(entry, "sessions_checked_band", Fraction(total)),
        "wellformed_share_band": _numeric_band(
            entry, "wellformed_share_band", Fraction(wellformed, total), percent=True
        ),
        "timestamp_monotonic_share_band": _numeric_band(
            entry,
            "timestamp_monotonic_share_band",
            Fraction(timestamps_ok, total),
            percent=True,
        ),
        "tool_pairing_intact_share_band": _numeric_band(
            entry,
            "tool_pairing_intact_share_band",
            Fraction(pairing_ok, total),
            percent=True,
        ),
        "splice_artifacts_found": splice_ok != total,
    }
    return output


def _score_tool_mix(entry: dict, session_keys: Sequence, grouped: dict) -> dict | None:
    if not _has_support(entry, len(session_keys)):
        return None
    family_groups = {
        "read_share_band": {"read"},
        "write_share_band": {"write", "edit"},
        "execute_share_band": {"execute"},
        "browse_share_band": {"search", "web"},
    }
    sums = {field: Fraction(0) for field in family_groups}
    tool_sessions = 0
    for key in session_keys:
        families = [
            event["tool_family"] for event in grouped[key] if event["event_kind"] == "tool-call"
        ]
        if not families:
            continue
        tool_sessions += 1
        counts = Counter(families)
        for field, admitted in family_groups.items():
            sums[field] += Fraction(sum(counts[name] for name in admitted), len(families))
    if tool_sessions == 0:
        return None
    return {
        field: _numeric_band(entry, field, total / tool_sessions, percent=True)
        for field, total in sums.items()
    }


def _score_autonomy(entry: dict, session_keys: Sequence, grouped: dict) -> dict | None:
    if not _has_support(entry, len(session_keys)):
        return None
    runs: list[int] = []
    interventions = 0
    action_count = 0
    for key in session_keys:
        current_run = 0
        for event in grouped[key]:
            is_agent_action = (
                event["event_kind"] in {"turn", "tool-call"} and event["authorship"] == "agent-turn"
            )
            if is_agent_action:
                current_run += 1
                action_count += 1
            elif event["event_kind"] == "turn" and event["authorship"] == "human-turn":
                if current_run:
                    runs.append(current_run)
                    current_run = 0
                    interventions += 1
        if current_run:
            runs.append(current_run)
    if not runs or action_count == 0:
        return None
    ordered = sorted(runs)
    lower_median = ordered[(len(ordered) - 1) // 2]
    interventions_per_1k = Fraction(1000 * interventions, action_count)
    return {
        "median_run_band": _numeric_band(entry, "median_run_band", Fraction(lower_median)),
        "interventions_per_1k_band": _numeric_band(
            entry, "interventions_per_1k_band", interventions_per_1k
        ),
    }


def _score_verification(entry: dict, session_keys: Sequence, grouped: dict) -> dict | None:
    if not _has_support(entry, len(session_keys)):
        return None
    with_tests = sum(
        any(event["event_kind"] == "test" for event in grouped[key]) for key in session_keys
    )
    return {
        "sessions_with_test_events_band": _numeric_band(
            entry,
            "sessions_with_test_events_band",
            Fraction(with_tests, len(session_keys)),
            percent=True,
        )
    }


def _semver(value: str) -> tuple[int, int, int]:
    match = _SEMVER_RE.fullmatch(value)
    if match is None:
        raise Wave1ScorerError("harness version is not exact semver")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _currency_label(entry: dict, observed: str, latest: str) -> str:
    observed_version = _semver(observed)
    latest_version = _semver(latest)
    if observed_version > latest_version:
        raise Wave1ScorerError("currency snapshot predates an observed harness version")
    major_gap = latest_version[0] - observed_version[0]
    minor_gap = latest_version[1] - observed_version[1]
    if major_gap == 0 and minor_gap <= 1:
        label = "within-one-minor"
    elif major_gap <= 1:
        label = "within-one-major"
    else:
        label = "older"
    if label not in _bands(entry, "version_currency_band"):
        raise Wave1ScorerError("currency result is absent from the registry")
    return label


def _score_orchestrators(
    entry: dict, corpus: dict, session_keys: Sequence, currency_snapshot: dict
) -> dict | None:
    if not _has_support(entry, len(session_keys)):
        return None
    _validate_harness_snapshot(currency_snapshot)
    current = {row["harness"]: row["latest"] for row in currency_snapshot["versions"]}
    adapters = sorted(corpus["manifest"]["adapters"], key=lambda row: row["source"])
    harnesses = [row["source"] for row in adapters]
    if len(harnesses) != len(set(harnesses)):
        raise Wave1ScorerError("normalized corpus has duplicate harness adapters")
    if any(harness not in current for harness in harnesses):
        raise Wave1ScorerError("currency snapshot does not cover every observed harness")
    rank = {"within-one-minor": 0, "within-one-major": 1, "older": 2}
    labels = [_currency_label(entry, row["version"], current[row["source"]]) for row in adapters]
    return {
        "harnesses": harnesses,
        "version_currency_band": max(labels, key=rank.__getitem__),
    }


def _score_mcp(
    entry: dict,
    session_keys: Sequence,
    mcp_snapshot: dict,
) -> dict | None:
    _validate_mcp_snapshot(mcp_snapshot)
    if not _has_support(entry, len(session_keys)):
        return None
    counts = {row["category"]: row["sessions"] for row in mcp_snapshot["category_session_counts"]}
    recurrence_floor = entry["min_support"]["sessions"]
    breadth = sum(value >= recurrence_floor for value in counts.values())
    return {
        "category_breadth_band": _numeric_band(entry, "category_breadth_band", Fraction(breadth))
    }


def score_wellformed(corpus: dict, *, registry: Registry | None = None) -> dict | None:
    """Score evidence integrity, or return ``None`` below registry support."""

    registry = registry or Registry.load()
    _, sessions, grouped = _checked_corpus(corpus)
    return _score_wellformed(_entry(registry, "transcript.wellformed"), corpus, sessions, grouped)


def score_tool_mix(corpus: dict, *, registry: Registry | None = None) -> dict | None:
    """Score session-equal tool-family composition without tool names."""

    registry = registry or Registry.load()
    _, sessions, grouped = _checked_corpus(corpus)
    return _score_tool_mix(_entry(registry, "transcript.tool_mix"), sessions, grouped)


def score_autonomy_band(corpus: dict, *, registry: Registry | None = None) -> dict | None:
    """Score neutral delegating/interactive workflow shape."""

    registry = registry or Registry.load()
    _, sessions, grouped = _checked_corpus(corpus)
    return _score_autonomy(_entry(registry, "transcript.autonomy_band"), sessions, grouped)


def score_verification_ratio(corpus: dict, *, registry: Registry | None = None) -> dict | None:
    """Score the share of sessions containing a normalized test event."""

    registry = registry or Registry.load()
    _, sessions, grouped = _checked_corpus(corpus)
    return _score_verification(_entry(registry, "transcript.verification_ratio"), sessions, grouped)


def score_orchestrators(
    corpus: dict,
    currency_snapshot: dict,
    *,
    registry: Registry | None = None,
) -> dict | None:
    """Score harness inventory/currency from an explicit offline snapshot."""

    registry = registry or Registry.load()
    _, sessions, _ = _checked_corpus(corpus)
    return _score_orchestrators(
        _entry(registry, "transcript.orchestrators"), corpus, sessions, currency_snapshot
    )


def score_mcp_breadth(
    corpus: dict,
    mcp_observations: dict,
    *,
    registry: Registry | None = None,
) -> dict | None:
    """Score only categories recurring at the registry's session floor."""

    registry = registry or Registry.load()
    root, sessions, _ = _checked_corpus(corpus)
    mcp_snapshot = _derive_mcp_snapshot(corpus, root, sessions, mcp_observations)
    return _score_mcp(
        _entry(registry, "transcript.mcp_breadth"),
        sessions,
        mcp_snapshot,
    )


def score_wave1_claims(
    corpus: dict,
    currency_snapshot: dict,
    mcp_observations: dict,
    *,
    window_start: str,
    window_end: str,
    signed_at: str,
    private_key: Ed25519PrivateKey,
    signer_kind: str,
    registry: Registry | None = None,
) -> dict:
    """Emit the deterministic local-only set of supported Wave-1 claims.

    A below-support scorer is omitted entirely. It never emits a zero-valued
    substitute. Every emitted claim is checked against the same immutable
    registry snapshot before and after signing.
    """

    registry = registry or Registry.load()
    root, sessions, grouped = _checked_corpus(corpus)
    mcp_snapshot = _derive_mcp_snapshot(corpus, root, sessions, mcp_observations)
    entries = {registry_id: _entry(registry, registry_id) for registry_id in _WAVE1_IDS}
    outputs = {
        "transcript.wellformed": _score_wellformed(
            entries["transcript.wellformed"], corpus, sessions, grouped
        ),
        "transcript.tool_mix": _score_tool_mix(entries["transcript.tool_mix"], sessions, grouped),
        "transcript.autonomy_band": _score_autonomy(
            entries["transcript.autonomy_band"], sessions, grouped
        ),
        "transcript.verification_ratio": _score_verification(
            entries["transcript.verification_ratio"], sessions, grouped
        ),
        "transcript.orchestrators": _score_orchestrators(
            entries["transcript.orchestrators"], corpus, sessions, currency_snapshot
        ),
        "transcript.mcp_breadth": _score_mcp(
            entries["transcript.mcp_breadth"], sessions, mcp_snapshot
        ),
    }
    snapshot_refs = {
        "transcript.orchestrators": [f"harness-currency:sha256:{currency_snapshot['digest']}"],
        "transcript.mcp_breadth": [
            f"mcp-observations:sha256:{mcp_observations['digest']}",
            f"mcp-recurrence:sha256:{mcp_snapshot['digest']}",
        ],
    }
    claims = []
    for registry_id in sorted(outputs):
        output = outputs[registry_id]
        if output is None:
            continue
        entry = entries[registry_id]
        anchor_refs = [f"registry:sha256:{registry.digest()}"]
        anchor_refs.extend(snapshot_refs.get(registry_id, ()))
        unsigned = build_claim(
            claim_type="wellformed" if registry_id == "transcript.wellformed" else "metric",
            registry_id=registry_id,
            registry_version=entry["version"],
            scorer_name=f"mybench.wave1.{registry_id.removeprefix('transcript.')}",
            scorer_version=SCORER_VERSION,
            corpus_commitment=(
                [root, mcp_observations["digest"], mcp_snapshot["digest"]]
                if registry_id == "transcript.mcp_breadth"
                else root
            ),
            window_start=window_start,
            window_end=window_end,
            output=output,
            derivation_class=entry["class"],
            signed_at=signed_at,
            anchor_refs=anchor_refs,
        )
        registry.check_claim(unsigned)
        signed = sign_claim(unsigned, private_key, kind=signer_kind)
        registry.check_claim(signed)
        claims.append(signed)

    claim_set = {
        "schema_version": "1",
        "kind": "wave1-transcript-claim-set",
        "claims": claims,
    }
    _schema_check(claim_set, "wave1_claim_set.schema.json", "Wave-1 claim set")
    return claim_set


__all__ = [
    "MCP_TAXONOMY_VERSION",
    "SCORER_VERSION",
    "Wave1ScorerError",
    "build_harness_currency_snapshot",
    "build_mcp_category_observations",
    "build_mcp_recurrence_snapshot",
    "score_autonomy_band",
    "score_mcp_breadth",
    "score_orchestrators",
    "score_tool_mix",
    "score_verification_ratio",
    "score_wave1_claims",
    "score_wellformed",
]
