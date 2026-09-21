"""arrowcontent: three frame types that ride as the PAYLOAD of an arrowenvelope, to make a
reply the receiver already holds cost one frame instead of many, and a novel reply cost less
air time by compressing against a published, content-addressed dictionary.

It does NOT encrypt, sign, or authenticate on its own. Wire format, worked example and the
legal reading are in SPEC-CONTENT.md. Verify the envelope BEFORE decoding any frame here:
never inflate unverified input.
"""
import hashlib
import zlib

REFERENCE = b"\x03"
COMPRESSED = b"\x04"
HOLDS = b"\x05"

ID_LEN = 8
OBJECT_ID_LEN = 32
REFERENCE_LEN = 1 + ID_LEN + OBJECT_ID_LEN  # 41
HOLDS_LEN = 1 + ID_LEN  # 9
MAX_DICTIONARY_BYTES = 32506  # zlib window (32768) minus 262 bytes of internal overhead
INFLATE_CAP = 4096  # named cap on decoded output; a bigger corpus needs windowing or zstd


class ContentError(ValueError):
    pass


def content_id(data: bytes) -> bytes:
    """8-byte short id: first 8 bytes of SHA-256, used for both corpus id and dictionary id."""
    return hashlib.sha256(data).digest()[:ID_LEN]


def object_id(content: bytes) -> bytes:
    """Full 32-byte SHA-256 of the exact content bytes (R-332 invariant 1)."""
    return hashlib.sha256(content).digest()


# ---- 0x03 CONTENT REFERENCE: 0x03 || corpus id (8) || object id (32). 41 bytes. ----

def build_reference(corpus: bytes, content: bytes) -> bytes:
    """corpus: the exact dictionary/corpus artifact bytes. content: the exact reply bytes."""
    return REFERENCE + content_id(corpus) + object_id(content)


def parse_reference(frame: bytes) -> tuple[bytes, bytes]:
    """Returns (corpus_id, object_id). Does not resolve content; that needs a local index."""
    if len(frame) != REFERENCE_LEN or frame[:1] != REFERENCE:
        raise ContentError("not a reference frame")
    return frame[1:1 + ID_LEN], frame[1 + ID_LEN:REFERENCE_LEN]


def resolve_reference(frame: bytes, corpus: bytes, index: dict[bytes, bytes]) -> bytes:
    """corpus: the local corpus artifact bytes, to check the id matches. index: object id ->
    content, built locally from the same corpus. Named error, never silence, never garbage."""
    cid, oid = parse_reference(frame)
    if cid != content_id(corpus):
        raise ContentError("reference not held")
    content = index.get(oid)
    if content is None or object_id(content) != oid:
        raise ContentError("reference not held")
    return content


# ---- 0x04 DICTIONARY COMPRESSED: 0x04 || dictionary id (8) || raw deflate bytes. ----
# Each chunk is compressed on its own against the dictionary, never as one running stream
# (research section 5, FLAMP): a lost frame loses one frame, not everything after it.

def build_compressed(dictionary: bytes, plaintext: bytes) -> bytes:
    if len(dictionary) > MAX_DICTIONARY_BYTES:
        raise ContentError("dictionary too large")
    co = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=dictionary)
    return COMPRESSED + content_id(dictionary) + co.compress(plaintext) + co.flush()


def decode_compressed(frame: bytes, dictionaries: dict[bytes, bytes], cap: int = INFLATE_CAP) -> bytes:
    """dictionaries: dictionary id -> dictionary bytes, the ids this receiver holds. Any valid
    deflate stream must decode, not only bytes produced by this encoder (deterministic per
    zlib version and inputs, but a decoder accepts any conforming stream)."""
    if len(frame) < 1 + ID_LEN or frame[:1] != COMPRESSED:
        raise ContentError("not a compressed frame")
    did = frame[1:1 + ID_LEN]
    dictionary = dictionaries.get(did)
    if dictionary is None:
        raise ContentError("unknown dictionary")
    do = zlib.decompressobj(-15, zdict=dictionary)
    try:
        out = do.decompress(frame[1 + ID_LEN:], cap + 1)
        if not do.unconsumed_tail:
            out += do.flush()
    except zlib.error:
        raise ContentError("bad inflate") from None
    if len(out) > cap or do.unconsumed_tail:
        raise ContentError("too long")
    return bytes(out)


# ---- 0x05 HOLDS: 0x05 || dictionary or corpus id (8). 9 bytes. ----
# The advertise-before-compress rule (RFC 9842): a sender emits 0x03 or 0x04 only to a peer
# that has announced it holds that id; otherwise plain text. Default over a broadcast leg
# with unknown listeners is plain text.

def build_holds(any_id: bytes) -> bytes:
    if len(any_id) != ID_LEN:
        raise ContentError("id must be 8 bytes")
    return HOLDS + any_id


def parse_holds(frame: bytes) -> bytes:
    if len(frame) != HOLDS_LEN or frame[:1] != HOLDS:
        raise ContentError("not a holds frame")
    return frame[1:HOLDS_LEN]
