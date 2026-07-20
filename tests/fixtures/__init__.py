"""Synthetic fixture transcripts + canary leak-scan helpers (MYB-2.2).

Privacy invariant #3: real transcripts are NEVER test data. Everything under
this package is generated, synthetic-by-construction content — see README.md.
"""

from tests.fixtures.leakscan import (
    CanaryLeakError,
    assert_no_canaries,
    assert_no_canaries_in_directory,
)
from tests.fixtures.delegation import (
    SyntheticDelegationInput,
    synthetic_delegation_input,
)
from tests.fixtures.synthetic import (
    DEFAULT_SEED,
    NEW_CANARY_CLASSES,
    FixtureSet,
    generate_fixtures,
)

__all__ = [
    "CanaryLeakError",
    "assert_no_canaries",
    "assert_no_canaries_in_directory",
    "DEFAULT_SEED",
    "NEW_CANARY_CLASSES",
    "FixtureSet",
    "SyntheticDelegationInput",
    "generate_fixtures",
    "synthetic_delegation_input",
]
