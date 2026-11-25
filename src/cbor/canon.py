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
    import struct

    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("decode expects a bytes object")
    raw = bytes(data)
    total = len(raw)
    if total == 0:
        raise ValueError("cannot decode an empty buffer")

    pos = 0
    missing = object()  # local sentinel: "no value produced yet"
    stack = []
    result = missing

    # Iterative parser: nested containers live on an explicit stack, so the
    # function body needs no recursive helper.
    while result is missing:
        if pos >= total:
            raise ValueError("unexpected end of CBOR input")
        initial = raw[pos]
        pos += 1
        major = initial >> 5
        info = initial & 0x1F
        value = missing

        if major == 7:
            # Simple values and floats share major type 7.
            if info == 20:
                value = False
            elif info == 21:
                value = True
            elif info == 22:
                value = None
            elif info == 27:
                if pos + 8 > total:
                    raise ValueError("truncated binary64 float")
                value = struct.unpack(">d", raw[pos:pos + 8])[0]
                pos += 8
            elif info in (25, 26):
                # Only one fixed binary64 width is canonical here.
                raise ValueError("non-canonical float width")
            else:
                raise ValueError(
                    "unsupported simple value, break or reserved information"
                )
        else:
            # Read the additional-information argument in its shortest form.
            if info < 24:
                arg = info
            elif info == 24:
                if pos + 1 > total:
                    raise ValueError("truncated head")
                arg = raw[pos]
                pos += 1
                if arg < 24:
                    raise ValueError("non-shortest additional information")
            elif info == 25:
                if pos + 2 > total:
                    raise ValueError("truncated head")
                arg = int.from_bytes(raw[pos:pos + 2], "big")
                pos += 2
                if arg < 256:
                    raise ValueError("non-shortest additional information")
            elif info == 26:
                if pos + 4 > total:
                    raise ValueError("truncated head")
                arg = int.from_bytes(raw[pos:pos + 4], "big")
                pos += 4
                if arg < 65536:
                    raise ValueError("non-shortest additional information")
            elif info == 27:
                if pos + 8 > total:
                    raise ValueError("truncated head")
                arg = int.from_bytes(raw[pos:pos + 8], "big")
                pos += 8
                if arg < 4294967296:
                    raise ValueError("non-shortest additional information")
            else:
                raise ValueError(
                    "indefinite-length or reserved additional information"
                )

            if major == 0:
                value = arg
            elif major == 1:
                value = -1 - arg
            elif major == 2:
                if pos + arg > total:
                    raise ValueError("truncated byte string")
                value = raw[pos:pos + arg]
                pos += arg
            elif major == 3:
                if pos + arg > total:
                    raise ValueError("truncated text string")
                try:
                    value = raw[pos:pos + arg].decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ValueError("text string is not valid UTF-8") from exc
                pos += arg
            elif major == 4:
                if arg == 0:
                    value = []
                else:
                    stack.append(
                        {"type": 4, "items": [], "left": arg, "key": missing}
                    )
            elif major == 5:
                if arg == 0:
                    value = {}
                else:
                    stack.append(
                        {"type": 5, "items": {}, "left": arg, "key": missing}
                    )
            else:
                raise ValueError("tags are not accepted in canonical form")

        if value is missing:
            # A non-empty container was opened; read its first child.
            continue

        # Hand the finished value to its parent, closing containers as needed.
        while True:
            if not stack:
                result = value
                break
            frame = stack[-1]
            if frame["type"] == 4:
                frame["items"].append(value)
                frame["left"] -= 1
                if frame["left"]:
                    break
                stack.pop()
                value = frame["items"]
                continue
            if frame["key"] is missing:
                frame["key"] = value
                break
            key = frame["key"]
            frame["key"] = missing
            try:
                duplicate = key in frame["items"]
            except TypeError as exc:
                raise ValueError("map key is not hashable") from exc
            if duplicate:
                raise ValueError("duplicate map key")
            frame["items"][key] = value
            frame["left"] -= 1
            if frame["left"]:
                break
            stack.pop()
            value = frame["items"]

    if pos != total:
        raise ValueError("trailing bytes after the top-level item")
    return result


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
    if isinstance(major, bool) or not isinstance(major, int):
        raise ValueError("major type must be an int")
    if not 0 <= major <= 7:
        raise ValueError("major type must be between 0 and 7")
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("head value must be an int")
    if value < 0:
        raise ValueError("head value must be non-negative")

    prefix = major << 5
    if value < 24:
        return bytes((prefix | value,))
    if value <= 0xFF:
        return bytes((prefix | 24, value))
    if value <= 0xFFFF:
        return bytes((prefix | 25,)) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes((prefix | 26,)) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes((prefix | 27,)) + value.to_bytes(8, "big")
    raise ValueError("unsigned value does not fit in 64 bits")


def encode_int(value: int) -> bytes:
    """Encode a Python integer as a canonical CBOR integer.

    Non-negative values use major type 0.  Negative values use major type 1
    with the convention value = -1 - n, so -1 becomes 0x20 (-1 - (-1) = 0)
    and -1000 becomes 0x39 0x03 0xe7.  Bools are not accepted here; they are
    handled by encode with the simple-value encodings 0xf4 and 0xf5.

    Raises:
        ValueError: if value is not an int, or is a bool.
    """
    if isinstance(value, bool):
        raise ValueError("bool is not encoded as an integer")
    if not isinstance(value, int):
        raise ValueError("value must be an int")
    if value >= 0:
        return encode_head(0, value)
    return encode_head(1, -1 - value)


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
    if isinstance(data, bytes):
        return encode_head(2, len(data)) + data
    if isinstance(data, str):
        try:
            payload = data.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("text string is not valid UTF-8") from exc
        return encode_head(3, len(payload)) + payload
    raise ValueError("encode_bytes accepts bytes or str only")


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
    ordered = []
    seen = set()
    for key, val in pairs:
        try:
            hash(key)
        except TypeError as exc:
            raise ValueError("map key is not hashable") from exc
        encoded_key = encode(key)
        # Identity is the canonical encoding itself: keys that encode to the
        # same bytes are the same CBOR value, whatever Python type produced
        # them, and keys of different types never collide.
        if encoded_key in seen:
            raise ValueError("duplicate map key")
        seen.add(encoded_key)
        ordered.append((encoded_key, key, val))
    ordered.sort(key=lambda item: item[0])
    return [(key, val) for _, key, val in ordered]


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
    import struct

    if value is None:
        return b"\xf6"
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if isinstance(value, int):
        return encode_int(value)
    if isinstance(value, float):
        # One fixed width, big-endian, independent of platform or locale.
        return b"\xfb" + struct.pack(">d", value)
    if isinstance(value, (bytes, str)):
        return encode_bytes(value)
    if isinstance(value, (list, tuple)):
        return encode_head(4, len(value)) + b"".join(
            encode(item) for item in value
        )
    if isinstance(value, dict):
        parts = [encode_head(5, len(value))]
        for key, val in sort_map(list(value.items())):
            parts.append(encode(key))
            parts.append(encode(val))
        return b"".join(parts)
    raise ValueError(f"cannot canonically encode {type(value).__name__}")


def canonical_digest(value: Any) -> str:
    """Return the lowercase SHA-256 hex digest of the canonical encoding.

    value is first encoded with encode; the digest is taken over those
    canonical bytes.  Raw input bytes, repr output and any caller-provided
    serialization are never hashed directly.  Two equivalent values, such as
    the same map with different insertion order, therefore produce the same
    digest string of 64 lowercase hexadecimal characters.
    """
    import hashlib

    return hashlib.sha256(encode(value)).hexdigest()


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
    if policy != "canonical":
        raise ValueError("unsupported normalization policy")
    # Every document is encoded from scratch; no ordering or memo state is
    # carried over from the previous document.
    encoded = [encode(document) for document in documents]
    digests = [canonical_digest(document) for document in documents]
    return {"policy": policy, "encoded": encoded, "digests": digests}