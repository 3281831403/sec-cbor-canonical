"""Contract tests for canonical CBOR encoding.

The suite is fixed: 15 tests, one per defect in the task statement plus five
cross-cutting consistency checks.  Every test is red until cbor.canon stops
raising NotImplementedError.  The tests assert byte-for-byte equality of
encodings, rejection of non-shortest forms and duplicate keys, and map key
ordering by encoded bytes.
"""

import hashlib

import pytest

from cbor.canon import (
    canon_batch,
    canonical_digest,
    decode,
    encode,
    encode_bytes,
    encode_head,
    encode_int,
    sort_map,
)


# ---------------------------------------------------------------------------
# One test per defect, in task-statement order.
# ---------------------------------------------------------------------------


def test_defect_01_head_uses_shortest_length_form():
    assert encode_head(0, 0) == b"\x00"
    assert encode_head(0, 23) == b"\x17"
    assert encode_head(0, 24) == b"\x18\x18"
    assert encode_head(0, 255) == b"\x18\xff"
    assert encode_head(0, 256) == b"\x19\x01\x00"
    assert encode_head(0, 65535) == b"\x19\xff\xff"
    assert encode_head(0, 65536) == b"\x1a\x00\x01\x00\x00"
    assert encode_head(2, 1000) == b"\x59\x03\xe8"
    assert encode_head(4, 0) == b"\x80"


def test_defect_02_decode_rejects_non_shortest_lengths():
    with pytest.raises(ValueError):
        decode(b"\x19\x00\x01")
    with pytest.raises(ValueError):
        decode(b"\x1a\x00\x00\x00\x17")
    with pytest.raises(ValueError):
        decode(b"\x58\x01\x41")
    with pytest.raises(ValueError):
        decode(b"\x78\x01a")
    assert decode(b"\x01") == 1


def test_defect_03_map_keys_order_by_encoded_bytes_not_string_order():
    pairs = [("aa", 1), (2, "two"), (b"a", 3), (100, 4), ("a", 5)]
    ordered = sort_map(pairs)
    keys = [key for key, _ in ordered]
    assert keys == [2, 100, b"a", "a", "aa"]
    encoded_keys = [encode(key) for key in keys]
    assert encoded_keys == sorted(encoded_keys)
    assert encode({"b": 1, "aa": 2, "a": 3}) == b"\xa3\x61a\x03\x61b\x01\x62aa\x02"


def test_defect_04_duplicate_map_keys_are_rejected_not_overwritten():
    with pytest.raises(ValueError):
        decode(b"\xa2\x61a\x01\x61a\x02")
    with pytest.raises(ValueError):
        decode(b"\xa2\x02\x01\x02\x02")
    with pytest.raises(ValueError):
        decode(b"\xa1\x61a\xa2\x01\x00\x01\x01")


def test_defect_05_negative_integers_use_the_cbor_convention():
    assert encode_int(0) == b"\x00"
    assert encode_int(23) == b"\x17"
    assert encode_int(-1) == b"\x20"
    assert encode_int(-24) == b"\x37"
    assert encode_int(-25) == b"\x38\x18"
    assert encode_int(-256) == b"\x38\xff"
    assert encode_int(-257) == b"\x39\x01\x00"
    assert encode_int(-1000) == b"\x39\x03\xe7"
    assert encode(-1) == b"\x20"


def test_defect_06_text_strings_are_validated_as_utf8():
    with pytest.raises(ValueError):
        decode(b"\x62\xff\xfe")
    with pytest.raises(ValueError):
        decode(b"\x61\x80")
    with pytest.raises(ValueError):
        decode(b"\x63\xed\xa0\x80")
    assert decode(b"\x62\xc3\xa9") == "\u00e9"
    assert decode(b"\x64\xf0\x9f\x98\x80") == "\U0001f600"
    assert encode("caf\u00e9") == b"\x65caf\xc3\xa9"
    assert encode_bytes(b"abc") == b"\x43abc"
    assert encode_bytes("abc") == b"\x63abc"


def test_defect_07_indefinite_length_items_are_rejected():
    with pytest.raises(ValueError):
        decode(b"\x9f\x01\x02\xff")
    with pytest.raises(ValueError):
        decode(b"\x5f\x41a\x41b\xff")
    with pytest.raises(ValueError):
        decode(b"\x7f\x61a\xff")
    with pytest.raises(ValueError):
        decode(b"\xbf\x61a\x01\xff")
    assert decode(b"\x83\x01\x02\x03") == [1, 2, 3]


def test_defect_08_floats_have_a_fixed_platform_independent_encoding():
    assert encode(1.5) == b"\xfb\x3f\xf8\x00\x00\x00\x00\x00\x00"
    assert encode(0.1) == b"\xfb\x3f\xb9\x99\x99\x99\x99\x99\x9a"
    assert encode(-0.0) == b"\xfb\x80\x00\x00\x00\x00\x00\x00\x00"
    assert encode(float("inf")) == b"\xfb\x7f\xf0\x00\x00\x00\x00\x00\x00"
    assert encode(1.5) == encode(3.0 / 2.0)


def test_defect_09_digest_is_taken_over_canonical_bytes():
    expected = hashlib.sha256(b"\xa2\x61a\x02\x61b\x01").hexdigest()
    assert canonical_digest({"b": 1, "a": 2}) == expected
    assert canonical_digest({"a": 2, "b": 1}) == expected
    assert canonical_digest(b"raw") == hashlib.sha256(b"\x43raw").hexdigest()
    digest = canonical_digest({"b": 1, "a": 2})
    assert len(digest) == 64
    assert digest == digest.lower()


def test_defect_10_batch_does_not_reuse_the_previous_documents_order():
    documents = [
        {"b": 1, "a": 2},
        {"a": 1, "b": 2, "c": 3},
        {"z": 0, "m": 1},
        {"nested": {"y": 1, "x": 2}, "top": [{"b": 1, "a": 2}]},
    ]
    result = canon_batch(documents, "canonical")
    assert result["policy"] == "canonical"
    assert result["encoded"] == [encode(document) for document in documents]
    assert result["digests"] == [canonical_digest(document) for document in documents]
    assert result["digests"] == canon_batch(documents, "canonical")["digests"]
    assert result["digests"][0] != result["digests"][1]


# ---------------------------------------------------------------------------
# Cross-cutting checks: shortest form, byte equality, duplicates, batch parity.
# ---------------------------------------------------------------------------


def test_extra_01_simple_integers_encode_in_shortest_form():
    assert encode(0) == b"\x00"
    assert encode(10) == b"\x0a"
    assert encode(23) == b"\x17"
    assert encode(24) == b"\x18\x18"
    assert encode(255) == b"\x18\xff"
    assert encode(256) == b"\x19\x01\x00"
    assert encode(65536) == b"\x1a\x00\x01\x00\x00"


def test_extra_02_reordered_maps_encode_to_identical_bytes():
    left = {"z": 1, "aa": [1, {"b": 2, "a": 3}], "m": {"y": 1, "x": 2}}
    right = {"m": {"x": 2, "y": 1}, "aa": [1, {"a": 3, "b": 2}], "z": 1}
    assert encode(left) == encode(right)
    assert type(encode(left)) is bytes


def test_extra_03_duplicate_keys_raise_instead_of_collapsing():
    with pytest.raises(ValueError):
        decode(b"\xa3\x61a\x01\x61b\x02\x61a\x03")
    with pytest.raises(ValueError):
        decode(b"\xa2\x62ab\x01\x62ab\x02")
    with pytest.raises(ValueError):
        decode(b"\xa1\x61x\xa2\x00\x01\x00\x02")


def test_extra_04_non_shortest_integers_are_rejected():
    for raw in (
        b"\x18\x00",
        b"\x19\x00\x17",
        b"\x19\x00\xff",
        b"\x1a\x00\x00\xff\xff",
        b"\x1b\x00\x00\x00\x00\x00\x00\x00\x01",
        b"\x38\x00",
        b"\x39\x00\x00",
    ):
        with pytest.raises(ValueError):
            decode(raw)
    assert decode(b"\x18\x18") == 24


def test_extra_05_batch_matches_per_document_normalization():
    documents = [
        {"beta": [1, 2], "alpha": {"b": 2, "a": 1}},
        {"k": {"z": 1, "y": [True, None]}, "j": 3},
        b"payload",
        [1, "two", {"b": 2, "a": 1}],
    ]
    batch = canon_batch(documents, "canonical")
    assert batch["digests"] == [canonical_digest(document) for document in documents]
    assert batch["encoded"] == [encode(document) for document in documents]
    with pytest.raises(ValueError):
        canon_batch(documents, "unknown-policy")