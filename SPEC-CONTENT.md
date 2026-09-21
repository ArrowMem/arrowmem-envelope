# arrowcontent wire format, version 1

Three frame types that ride as the PAYLOAD of an arrowenvelope (SPEC.md: payload is any
bytes, n >= 0). They make a reply the receiver already holds cost one frame instead of
many, and make a novel reply smaller by compressing it against a published, content-
addressed dictionary. **Verify the envelope first. Decode a content frame only after the
signature verifies. MUST. Never inflate unverified input.**

None of the three frames encrypts or authenticates on its own. Authentication is the
envelope's job (SPEC.md); these frames are its payload.

## 0x03, CONTENT REFERENCE

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 1 | `0x03` |
| 1 | 8 | corpus id |
| 9 | 32 | object id |

41 bytes.

- Corpus id: the first 8 bytes of SHA-256 of the dictionary/corpus artifact's exact bytes
  (see "The dictionary artifact" below for how that artifact is built).
- Object id: SHA-256 of the exact content bytes, the same object id rule SPEC.md already
  uses for the envelope payload (R-332 invariant 1).

A receiver that holds the corpus named by the corpus id, and a local index from object id
to content built from that corpus, renders the content locally: no bytes of the reply ever
cross the air. A receiver that does not hold that corpus id, or whose index has no entry
for that object id, raises the named error `reference not held`. Never silence, never a
best-effort guess, never rendering something else under that object id.

## 0x04, DICTIONARY COMPRESSED

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 1 | `0x04` |
| 1 | 8 | dictionary id |
| 9 | n | raw deflate bytes, n >= 0 |

- Dictionary id: the first 8 bytes of SHA-256 of the dictionary bytes. Same construction as
  the corpus id above; a corpus artifact and a dictionary artifact may be the same bytes and
  therefore the same id, or different bytes for different purposes. This spec does not
  require they be the same artifact, only that each id is the first 8 bytes of SHA-256 of
  whatever bytes were actually used.
- Payload: `zlib.compressobj(level=9, wbits=-15, zdict=dictionary)`, i.e. raw DEFLATE (RFC
  1951), no zlib header (RFC 1950), no Adler-32 checksum. The envelope's own SHA-256 already
  covers integrity end to end; a second checksum inside the frame would be redundant weight
  on an air link where every byte costs seconds.
- **Each chunk of a reply is compressed on its own against the dictionary, never as one
  running stream across multiple frames.** A single deflate stream is not independently
  recoverable per frame: losing frame 4 of 11 makes frames 5 through 11 undecodable too,
  because each depends on the compressor's running state from everything before it
  (research section 5, citing FLAMP's block-and-checksum repair scheme). Splitting per
  chunk means a lost frame loses exactly that frame, the same failure mode plain text
  already has, and no worse.
- Compression level 9, deterministic: the same bytes from the same zlib version produce the
  same compressed output, byte for byte (`test_deterministic_same_bytes_same_output`). This
  determinism is a property of the reference encoder, not a wire requirement. **A decoder
  MUST accept any valid deflate stream against the named dictionary, not only bytes this
  reference encoder produced.** The vectors below test the decoder against a stream built
  with the reference encoder AND separately against one built with a different compression
  level through the stdlib directly, to prove the decoder is not coupled to one encoder's
  exact bytes.

### Decoder errors, named, in order

1. Frame shorter than 9 bytes, or byte 0 not `0x04`: reject before touching the dictionary
   table (`not a compressed frame`).
2. Dictionary id not held: `unknown dictionary`. Never fall back to a different dictionary
   and never guess.
3. `zlib.error` during inflate (truncated stream, corrupt bytes, wrong dictionary content
   under a colliding id): `bad inflate`.
4. Decoded output exceeds the cap, **4096 bytes**, named `INFLATE_CAP` in `arrowcontent.py`:
   `too long`. The cap exists because a hostile or corrupt stream can claim to decompress to
   an arbitrarily large output; 4096 bytes is well above any reply this pack produces (the
   largest measured reply is 2,913 bytes, see the cost section) and is cheap to raise later
   if a bigger corpus needs it.

A receiver that cannot decode says so, with one of the four named errors above. It never
renders a partial result and never falls back to treating the compressed bytes as text.

## 0x05, HOLDS

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 1 | `0x05` |
| 1 | 8 | dictionary or corpus id |

9 bytes. The advertise-before-compress rule, the same shape RFC 9842 (Compression
Dictionary Transport) uses for HTTP: a sender emits an `0x03` or `0x04` frame to a given
peer only after that peer has announced, via a `0x05` frame, that it holds the named
dictionary or corpus id. Over a broadcast leg with unknown listeners, where no such
announcement can ever be confirmed, the default is plain text. This is the fallback rule
and it is what keeps the format interoperable with a receiver that never adopts it: such a
receiver simply never announces, so it is never sent a compressed or reference frame, and
sees ordinary readable text exactly as it does today.

## The dictionary artifact

Built deterministically from the four ERP pack content files, concatenated in a fixed
order, LF line endings as-is, no separator bytes beyond each file's own content:

    citations.json || content/basic_vehicle.json || safety/hard_lines.json || content/bush_lost.json

**This order is pinned by measurement, not guessed.** zlib's own manual instructs that the
most useful strings belong nearest the END of a preset dictionary, because DEFLATE's LZ77
match distance is cheaper for closer matches. All four single-file-last orderings were
built and measured against every reply in the pack's closed grammar (`ERP`, `ERP BASIC`,
`ERP BUSH`, `ERP LINES`, `ERP BASIC 1..7`, `ERP BUSH 1..8`, and every `n.m` step under each
bush section: 39 replies, 16,059 raw bytes total), each compressed with the full dictionary
in that ordering:

| file placed last | total compressed bytes | ratio vs raw |
| --- | --- | --- |
| citations.json | 1,413 | 11.365x |
| basic_vehicle.json | 1,407 | 11.414x |
| hard_lines.json | 1,417 | 11.333x |
| **bush_lost.json** | **1,397** | **11.495x** |

`bush_lost.json` last wins, so it is pinned last. The margin is small (about 1.4% over the
worst ordering) because the dictionary already contains every reply's own source file in
this measurement; see "Honest cost numbers" below for why that is the reference case, not
the general one.

- Total dictionary size: 29,864 bytes (four files, `citations.json` 7,074 +
  `content/basic_vehicle.json` 3,827 + `safety/hard_lines.json` 9,196 +
  `content/bush_lost.json` 9,767).
- Ceiling: zlib's window is 32,768 bytes, of which about 262 bytes are internal overhead,
  giving a usable maximum of **32,506 bytes** (`MAX_DICTIONARY_BYTES` in
  `arrowcontent.py`). The pinned dictionary fits with 2,642 bytes of headroom. A corpus
  that grows past this ceiling needs windowing (dropping the least useful bytes) or a move
  to Zstandard, which has no small fixed window but needs a compiled dependency this
  runtime (Python 3.12, stdlib only) does not have until Python 3.14 (PEP 784).
- Expected dictionary id, this pinned order, this exact corpus:
  **`5ffbd490ada4f969`** (first 8 bytes of SHA-256
  `5ffbd490ada4f969071ac1e8102a3a49ff16b3080cb59bc5aa3ad46ce7955f8`).
- **The corpus itself is NOT vendored into this repository.** This spec names the build
  order and the expected id; the ERP pack repository carries the four content files (never
  edited by this spec's author) and will carry the builder script as a later stage. A
  receiver builds the dictionary from its own copy of the pack and checks the id matches
  before trusting any `0x03` or `0x04` frame against it.

### Vector dictionary, for the vectors below only

The vectors in this file use a tiny, self-contained dictionary instead of the ERP pack, so
a port can check its bytes with no pack checkout: SPEC.md's own example shout, repeated 4
times.

    dictionary bytes, 164 bytes
      6e6f20696e7465726e657420686572652e20616c6c206f6b2e206e65787420636865636b20303930306e6f20696e7465726e657420686572652e20616c6c206f6b2e206e65787420636865636b20303930306e6f20696e7465726e657420686572652e20616c6c206f6b2e206e65787420636865636b20303930306e6f20696e7465726e657420686572652e20616c6c206f6b2e206e65787420636865636b2030393030
    dictionary id, 8 bytes
      7abee4440de73529

## Worked example

Printed by `python vector_content.py`. `test_arrowcontent.py` asserts these bytes are what
the code produces, so this file cannot drift from the implementation.

    plaintext, 23 bytes
      616c6c206f6b2e206e65787420636865636b2030393030
    0x04 dictionary-compressed frame, 13 bytes
      047abee4440de73529c3210c00
    0x03 content-reference frame, 41 bytes
      037abee4440de735291aa8fbc280d2e0934e9a9d9a30e57396d7ebf446e5a7b5fc721a9198d8e3ab0a
    0x05 holds frame, 9 bytes
      057abee4440de73529
    0x04 frame sealed in an envelope (RFC 8032 test key), 86 bytes
      0121fe31dfa154a2613b4b0c7b89a52a46b400f7d9ebfb8443b716340a069f9de6adaaba49e00f8e3871cab619e186d9ea6e154120732967571f4a7d43f5c6fa0d1a1481bcc3596406047abee4440de73529c3210c00

## Honest cost numbers

**Frames at 127 bytes (sealed) and 200 (crosstalk PAYLOAD max, per SPEC.md's own cost
section).** The 73-byte envelope header leaves 127 bytes of a 200-byte PAYLOAD for content.

Both honest numbers below, measured against the real pack over its full closed grammar (39
replies, 16,059 raw bytes total), not the single best-case reply:

**(a) Dictionary excludes the reply's own source file.** For each reply, the dictionary is
built from the other three files only (the file the reply's content actually came from is
removed, so the corpus cannot simply contain the answer). Aggregate: 16,059 raw bytes
compress to 6,253 bytes, **2.57x**. This is the honest number for a reply that is genuinely
novel to the corpus, such as a free-form answer the corpus does not already contain
verbatim. It is lower than the 3.08x figure in the research report's single-reply
measurement; the two numbers were built from different measurement shapes (one reply there,
the full 39-reply grammar aggregate here) and neither should be quoted as the other's
result. Report both, and label each by what it measured.

**(b) Full shipping dictionary, all four files, reply's own source included.** Aggregate:
16,059 raw bytes compress to 1,397 bytes (pinned ordering, `bush_lost.json` last),
**11.495x**. **This is the reference case, not a general ratio.** It applies only when the
dictionary already contains the exact bytes of the reply, which is true for this node's own
pack today because the pack IS the dictionary source. Never quote this number as a general
compression ratio for arbitrary text; quote it only as "a reply whose exact source text is
already inside the shipping dictionary."

**(c) The 0x03 reference case: content the receiver already holds.** One reference frame is
41 bytes regardless of the reply's length, because it carries no content, only two hashes.
Sealed in an envelope (73-byte header) that is 114 bytes, well inside a single 127-byte or
200-byte PAYLOAD: one frame. This is the node-to-node case: a receiver that already holds
this exact pack, indexed by object id, renders the reply from its own copy and the air
carries only the two hashes. **The 33-to-1 saving named in the beacon doc's own measurement
is this case**, and it requires the receiver to already hold the pack; it is not free for a
receiver seeing this content for the first time, which must be sent the full text (case a)
or, if it holds no dictionary at all, plain text with no arrowcontent frame at all (the
0x05 HOLDS fallback rule).

**For this node specifically: the request already is the reference case.** The ERP node's
own replies are drawn verbatim from its own pack (`erp_node.py`'s own header: "the pack's
exact strings out"). A second ERP node running the identical pack is exactly the receiver
case (c) describes. A human operator with a radio and no ERP node software, asking a
free-form question that a person on the other end answers in their own words, is case (a):
novel text, dictionary-compressed, not referenced.

## Layering

Any of the three frames above is valid as the `payload` field of an arrowenvelope
(SPEC.md offset 73). **Verify the envelope's signature first. Only after verification
succeeds, decode the content frame. This is a MUST, not a suggestion**: inflating
unverified bytes hands an attacker a decompression target before their identity is
checked, and a reference frame resolved before verification renders content under no
proven signer at all.

## Legal reading

A published algorithm (RFC 1951, DEFLATE) applied against a published, content-addressed
dictionary obscures nothing: the original is always recoverable by anyone who holds, or can
obtain, the named dictionary bytes, and the dictionary's identity is provable by hash rather
than by trusting a filename or a version number. That is why, in our reading, this is not
"encoded for the purpose of obscuring meaning" under 47 CFR 97.113(a)(4), and is a "code or
cipher that is not secret" under SOR/96-484 s.47(b). This is our own direct reading of the
statutory text, not a regulator's ruling on this exact scheme; see SIGNED_BEACON_PRIVACY
LAYERS_2026-09-20.md section 1 and the research report for the full citation trail,
including FCC RM-11831 (2019), which is the closest existing test of "compression is not
encryption" on amateur bands and resolved without adopting a transparency requirement. **A
SECRET dictionary would fail this reading entirely**; publishing the corpus and its build
order in this file is not incidental, it is the reason the reading holds.

Winlink's B2F protocol has run LZHUF dictionary compression on HF amateur bands for decades
(research section 1), so compression itself on the air is not new. What is different here,
as far as this search found, is a dictionary whose identity is proven by a published SHA-256
hash rather than baked into a fixed protocol version.

Neither reading is backed by case law or by either regulator's own interpretation of this
exact scheme. The control operator remains responsible for every emission. Verify before
you key.

## Placeholder call signs

Any call sign appearing in this document or its tests is the placeholder `N0CALL`, never a
real station.
