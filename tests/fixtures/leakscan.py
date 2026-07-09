"""Compatibility shim: the scanner is production code now (mybench.leakscan).

Moved in MYB-3.4 because the publisher's pre-push gate uses it at publish
time; test imports keep working through this re-export.
"""

from mybench.leakscan import (  # noqa: F401
    GZIP_MAGIC,
    CanaryLeakError,
    assert_no_canaries,
    scan_file,
)
