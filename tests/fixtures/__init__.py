"""Synthetic fixture transcripts + canary leak-scan helpers (MYB-2.2).

Privacy invariant #3: real transcripts are NEVER test data. Everything under
this package is generated, synthetic-by-construction content — see README.md.
"""

from tests.fixtures.leakscan import CanaryLeakError, assert_no_canaries
from tests.fixtures.synthetic import DEFAULT_SEED, FixtureSet, generate_fixtures

__all__ = [
    "CanaryLeakError",
    "assert_no_canaries",
    "DEFAULT_SEED",
    "FixtureSet",
    "generate_fixtures",
]
