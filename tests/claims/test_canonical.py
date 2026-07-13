"""MYB-10.1: canonical JSON discipline — sorted, compact, float-free (handoff §4)."""

import pytest

from mybench.claims import CanonicalError, canonical_bytes, signed_bytes


def test_canonical_form_is_sorted_compact_and_stable():
    obj = {"b": 1, "a": [1, "x", None, True], "c": {"z": 0, "y": "s"}}
    expected = b'{"a":[1,"x",null,true],"b":1,"c":{"y":"s","z":0}}'
    assert canonical_bytes(obj) == expected
    # Insertion order is irrelevant: same content, same bytes.
    reordered = {"c": {"y": "s", "z": 0}, "a": [1, "x", None, True], "b": 1}
    assert canonical_bytes(reordered) == expected


def test_non_ascii_is_escaped_deterministically():
    data = canonical_bytes({"label": "plané→build"})
    assert data == b'{"label":"plan\\u00e9\\u2192build"}'
    assert max(data) < 128  # pure ASCII bytes — no encoding wobble


@pytest.mark.parametrize(
    "obj, at",
    [
        ({"x": 1.5}, "$.x"),
        ({"out": {"ratio": 0.25}}, "$.out.ratio"),
        ({"bands": [1, 2, 3.0]}, "$.bands[2]"),
        ({"x": float("nan")}, "$.x"),
        ({"x": float("inf")}, "$.x"),
    ],
)
def test_floats_rejected_at_any_depth_with_path(obj, at):
    with pytest.raises(CanonicalError, match="float at") as excinfo:
        canonical_bytes(obj)
    assert at in str(excinfo.value)  # the error names the offending path


def test_non_string_keys_and_unsupported_types_rejected():
    with pytest.raises(CanonicalError, match="non-string key"):
        canonical_bytes({"a": {1: "x"}})
    with pytest.raises(CanonicalError, match="unsupported type"):
        canonical_bytes({"a": b"raw-bytes"})
    with pytest.raises(CanonicalError, match="unsupported type"):
        canonical_bytes({"a": {1, 2}})


def test_bools_and_ints_are_fine_where_floats_are_not():
    assert canonical_bytes({"n": 3, "flag": False}) == b'{"flag":false,"n":3}'


def test_signed_bytes_excludes_exactly_the_signature_field():
    claim = {"b": 1, "signature": "ff", "a": 2}
    assert signed_bytes(claim) == b'{"a":2,"b":1}'
    # Everything else stays covered — a second sig-like field is NOT excluded.
    claim2 = {"a": 2, "sig": "ff"}
    assert signed_bytes(claim2) == b'{"a":2,"sig":"ff"}'
