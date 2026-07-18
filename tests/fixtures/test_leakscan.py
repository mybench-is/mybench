"""Leak scanner detects every canary class and encoding; never vacuous."""

import base64
import gzip

import pytest

from tests.fixtures import (
    NEW_CANARY_CLASSES,
    CanaryLeakError,
    assert_no_canaries,
    assert_no_canaries_in_directory,
    generate_fixtures,
)

CANARY = b"MYBENCH-CANARY-0123456789abcdef"
NONCE = bytes(range(0x60, 0x80))  # 32-byte synthetic nonce canary


ENCODERS = [
    pytest.param(lambda c: c, id="raw"),
    pytest.param(lambda c: c.hex().encode(), id="hex"),
    pytest.param(lambda c: c.hex().upper().encode(), id="HEX"),
    pytest.param(lambda c: base64.b64encode(c), id="b64-0"),
    pytest.param(lambda c: base64.b64encode(b"x" + c), id="b64-1"),
    pytest.param(lambda c: base64.b64encode(b"xy" + c), id="b64-2"),
    pytest.param(lambda c: base64.b64encode(b"prefix" + c + b"suffix"), id="b64-mid"),
    pytest.param(lambda c: base64.urlsafe_b64encode(b"x" + c), id="b64url"),
    pytest.param(lambda c: gzip.compress(c, mtime=0), id="gzip"),
    pytest.param(lambda c: gzip.compress(b"pad " + c.hex().encode(), mtime=0), id="gzip-hex"),
]


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
    ENCODERS,
)
@pytest.mark.parametrize("canary", [CANARY, NONCE], ids=["content", "nonce"])
def test_planted_canary_detected_in_every_encoding(tmp_path, encode, canary):
    write(tmp_path, "artifact.bin", b"harmless header " + encode(canary) + b" trailer")
    with pytest.raises(CanaryLeakError):
        assert_no_canaries([tmp_path], [canary])


@pytest.mark.parametrize("bundle_name", ["report-dir", "preview-bundle"])
@pytest.mark.parametrize("encode", ENCODERS)
def test_whole_directory_helper_scans_report_and_preview_encodings(tmp_path, bundle_name, encode):
    bundle = tmp_path / bundle_name
    nested = bundle / "nested" / "artifact.bin"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(b"header " + encode(CANARY) + b" trailer")
    with pytest.raises(CanaryLeakError):
        assert_no_canaries_in_directory(bundle, [CANARY])


def test_directory_scan_detects_canary_in_nested_filename(tmp_path):
    bundle = tmp_path / "preview-bundle"
    planted = bundle / "nested" / CANARY.decode()
    planted.parent.mkdir(parents=True)
    planted.write_bytes(b"content is otherwise clean")
    with pytest.raises(CanaryLeakError, match=r"path:raw"):
        assert_no_canaries_in_directory(bundle, [CANARY])


def test_directory_scan_does_not_treat_private_parent_as_bundle_output(tmp_path):
    bundle = tmp_path / CANARY.decode() / "report-bundle"
    bundle.mkdir(parents=True)
    (bundle / "artifact.json").write_bytes(b'\x7b"safe":true\x7d')
    assert assert_no_canaries_in_directory(bundle, [CANARY]) == 1


def test_content_hit_diagnostic_uses_only_bundle_relative_label(tmp_path):
    private_parent = tmp_path / "synthetic-private-parent"
    bundle = private_parent / "synthetic-private-report-root"
    target = bundle / "nested" / "artifact.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b'{"private":"' + CANARY + b'"}')

    with pytest.raises(CanaryLeakError) as raised:
        assert_no_canaries_in_directory(bundle, [CANARY])

    diagnostic = str(raised.value)
    assert "nested/artifact.json: raw form" in diagnostic
    assert str(private_parent) not in diagnostic
    assert str(bundle) not in diagnostic
    assert str(target) not in diagnostic
    assert private_parent.name not in diagnostic
    assert bundle.name not in diagnostic


def test_filename_hit_diagnostic_redacts_name_and_absolute_target(tmp_path):
    private_parent = tmp_path / "synthetic-private-parent"
    bundle = private_parent / "synthetic-private-report-root"
    target = bundle / "nested" / CANARY.decode()
    target.parent.mkdir(parents=True)
    target.write_bytes(b"content is otherwise clean")

    with pytest.raises(CanaryLeakError) as raised:
        assert_no_canaries_in_directory(bundle, [CANARY])

    diagnostic = str(raised.value)
    assert "nested/<redacted-canary-name>: path:raw form" in diagnostic
    assert str(private_parent) not in diagnostic
    assert str(bundle) not in diagnostic
    assert str(target) not in diagnostic
    assert private_parent.name not in diagnostic
    assert bundle.name not in diagnostic
    assert target.name not in diagnostic


@pytest.mark.parametrize("class_name", NEW_CANARY_CLASSES)
def test_generated_fixture_fires_for_each_new_canary_class(tmp_path, class_name):
    fixtures = generate_fixtures(tmp_path / "fixtures", seed=41)
    with pytest.raises(CanaryLeakError):
        assert_no_canaries_in_directory(
            fixtures.root,
            [fixtures.canary(class_name)],
        )


@pytest.mark.parametrize("class_name", NEW_CANARY_CLASSES)
@pytest.mark.parametrize("encode", ENCODERS)
def test_each_new_class_passes_clean_artifacts_in_every_encoding(tmp_path, class_name, encode):
    fixtures = generate_fixtures(tmp_path / "canary-source", seed=41)
    clean_bundle = tmp_path / "clean-report"
    clean_bundle.mkdir()
    clean = f"synthetic-safe-value-for-{class_name}".encode()
    (clean_bundle / "artifact.bin").write_bytes(b"header " + encode(clean) + b" trailer")
    assert (
        assert_no_canaries_in_directory(
            clean_bundle,
            [fixtures.canary(class_name)],
        )
        == 1
    )


def test_scan_fails_loudly_not_vacuously(tmp_path):
    # AC #4 companions: an empty scan or empty canary list must error, never pass.
    with pytest.raises(ValueError):
        assert_no_canaries([tmp_path], [CANARY])  # no files
    write(tmp_path, "a.txt", b"data")
    with pytest.raises(ValueError):
        assert_no_canaries([tmp_path], [])  # no canaries
    with pytest.raises(ValueError):
        assert_no_canaries_in_directory(tmp_path / "missing", [CANARY])


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
