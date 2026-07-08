"""MYB-2.2 AC #3/#4: scanner detects planted canaries in all encodings; never vacuous."""

import base64
import gzip

import pytest

from tests.fixtures import CanaryLeakError, assert_no_canaries, generate_fixtures

CANARY = b"MYBENCH-CANARY-0123456789abcdef"
NONCE = bytes(range(0x60, 0x80))  # 32-byte synthetic nonce canary


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_clean_artifacts_pass_and_report_scan_count(tmp_path):
    write(tmp_path, "a.json", b'{"root": "abc123", "count": 4}')
    write(tmp_path, "b.txt", b"nothing to see")
    assert assert_no_canaries([tmp_path], [CANARY, NONCE]) == 2


@pytest.mark.parametrize(
    "encode",
    [
        lambda c: c,  # raw
        lambda c: c.hex().encode(),  # hex lower
        lambda c: c.hex().upper().encode(),  # hex upper
        lambda c: base64.b64encode(c),  # base64 phase 0
        lambda c: base64.b64encode(b"x" + c),  # base64 phase 1 (embedded)
        lambda c: base64.b64encode(b"xy" + c),  # base64 phase 2 (embedded)
        lambda c: base64.b64encode(b"prefix" + c + b"suffix"),  # mid-stream
        lambda c: base64.urlsafe_b64encode(b"x" + c),  # urlsafe variant
        lambda c: gzip.compress(c, mtime=0),  # inside gzip
        lambda c: gzip.compress(b"pad " + c.hex().encode(), mtime=0),  # hex inside gzip
    ],
    ids=["raw", "hex", "HEX", "b64-0", "b64-1", "b64-2", "b64-mid", "b64url", "gzip", "gzip-hex"],
)
@pytest.mark.parametrize("canary", [CANARY, NONCE], ids=["content", "nonce"])
def test_planted_canary_detected_in_every_encoding(tmp_path, encode, canary):
    write(tmp_path, "artifact.bin", b"harmless header " + encode(canary) + b" trailer")
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([tmp_path], [canary])


def test_scan_fails_loudly_not_vacuously(tmp_path):
    # AC #4 companions: an empty scan or empty canary list must error, never pass.
    with pytest.raises(ValueError):
        assert_no_canaries([tmp_path], [CANARY])  # no files
    write(tmp_path, "a.txt", b"data")
    with pytest.raises(ValueError):
        assert_no_canaries([tmp_path], [])  # no canaries


def test_fixture_canaries_end_to_end(tmp_path):
    # The generator's own canaries are detectable in its own output (planted
    # self-test), and a disjoint canary set scans clean over the same files.
    fx = generate_fixtures(tmp_path / "fx")
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([fx.root], fx.all_canaries())
    other = generate_fixtures(tmp_path / "other", seed=999)
    assert assert_no_canaries([fx.root], other.all_canaries()) > 0


def test_error_message_names_file_and_encoding(tmp_path):
    write(tmp_path, "leaky.json", CANARY.hex().encode())
    with pytest.raises(CanaryLeakError, match=r"leaky\.json.*hex"):
        assert_no_canaries([tmp_path], [CANARY])
