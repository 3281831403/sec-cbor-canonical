"""Canonical CBOR primitives for the signed-request pipeline.

Every public function in this module is a stub: the body raises
NotImplementedError and nothing else.  The docstrings describe the contract
that tests/test_canon.py turns into executable assertions.

Wire-format invariants the finished implementation must preserve:

* every head is emitted in the shortest additional-information form;
* map keys are ordered by the bytes produced by encoding the key, never by a
  language-level string or length comparison;
* duplicate map keys are a decoding error and never last-writer-wins;
* negative integers use the CBOR convention value = -1 - n;
* text strings are validated as UTF-8 instead of being accepted blindly;
* indefinite-length items are rejected instead of being echoed back;
* floats use one fixed, platform-independent byte representation;
* digests are computed over canonical bytes, never over raw caller input;
* batch normalization never shares ordering state between documents.
"""

from typing import Any, List, Sequence, Tuple, Union


def decode(data: bytes) -> object:
    """Decode one complete CBOR data item from data.

    Only the canonical form is accepted.  A length or integer value that
    could have been written in a shorter additional-information form is an
    error, so two byte strings never map to the same value.  Indefinite
    length strings, arrays and maps are rejected.  Duplicate map keys raise
    ValueError, including duplicates that only become equal after decoding.
    Text strings whose payload is not valid UTF-8 raise ValueError.

    Raises:
        ValueError: on non-canonical, indefinite-length, duplicate-key or
            invalid-UTF-8 input.
    """
    raise NotImplementedError


def encode_head(major: int, value: int) -> bytes:
    """Encode a CBOR head for the given major type and unsigned value.

    major is 0 through 7.  value is a non-negative integer.  The head uses
    the shortest length form: value below 24 is encoded in the additional
    information bits, then one, two, four and eight byte big-endian forms
    are used at the 24, 256, 65536 and 4294967296 boundaries.  A fixed
    four-byte length field is never emitted.

    Raises:
        ValueError: if major or value is outside its permitted range.
    """
    raise NotImplementedError


def encode_int(value: int) -> bytes:
    """Encode a Python integer as a canonical CBOR integer.

    Non-negative values use major type 0.  Negative values use major type 1
    with the convention value = -1 - n, so -1 becomes 0x20 (-1 - (-1) = 0)
    and -1000 becomes 0x39 0x03 0xe7.  Bools are not accepted here; they are
    handled by encode with the simple-value encodings 0xf4 and 0xf5.

    Raises:
        ValueError: if value is not an int, or is a bool.
    """
    raise NotImplementedError


def encode_bytes(data: Union[bytes, str]) -> bytes:
    """Encode a byte string or a text string, keeping the major types apart.

    bytes uses major type 2; str is encoded as UTF-8 and uses major type 3.
    Text strings are validated before encoding, so lone surrogates and other
    non-UTF-8 text raise ValueError.  Lengths are written with the shortest
    head form.

    Raises:
        ValueError: if data is neither bytes nor str, or if a str cannot be
            encoded as UTF-8.
    """
    raise NotImplementedError


def sort_map(pairs: Sequence[Tuple[Any, Any]]) -> List[Tuple[Any, Any]]:
    """Return map pairs ordered by the canonical encoding of each key.

    Ordering compares the encoded key bytes lexicographically, so integer
    keys, byte-string keys and text-string keys participate in one total
    order determined by their CBOR heads.  The key type is part of the
    comparison: a text key is never compared as if it were the same bytes as
    an integer key.  Input order must not influence the result.

    Raises:
        ValueError: if a key is unhashable, duplicated, or not encodable.
    """
    raise NotImplementedError


def encode(value: Any) -> bytes:
    """Encode value into canonical CBOR bytes.

    Supported values: None, bool, int, float, bytes, str, list, tuple and
    dict.  Integers and lengths always use the shortest head form.  Map keys
    are sorted by their encoded bytes and duplicate keys raise ValueError.
    Indefinite-length encodings are never produced and tags are rejected
    instead of being copied through.  Floats use one fixed IEEE-754
    big-endian binary64 representation, so the output does not depend on the
    platform, locale or the default str() of a float.

    Raises:
        ValueError: for unsupported types, duplicate map keys, out-of-range
            integers or non-UTF-8 text.
    """
    raise NotImplementedError


def canonical_digest(value: Any) -> str:
    """Return the lowercase SHA-256 hex digest of the canonical encoding.

    value is first encoded with encode; the digest is taken over those
    canonical bytes.  Raw input bytes, repr output and any caller-provided
    serialization are never hashed directly.  Two equivalent values, such as
    the same map with different insertion order, therefore produce the same
    digest string of 64 lowercase hexadecimal characters.
    """
    raise NotImplementedError


def canon_batch(documents: Sequence[Any], policy: str) -> dict:
    """Canonicalize each document independently and return per-document data.

    policy must be "canonical"; any other value raises ValueError.  The
    result is a dict with keys "policy", "encoded" and "digests": "encoded"
    holds one canonical bytes object per document in input order, and
    "digests" holds the matching lowercase SHA-256 hex strings.  Sorting
    state, memo tables and key orders are rebuilt for every document, so the
    second document never inherits the first document's ordering.

    Raises:
        ValueError: for an unknown policy or a document that encode rejects.
    """
    raise NotImplementedError