# arrowenvelope wire format, version 1

Byte layout, exact. Every field is fixed length except the payload. There is no
timestamp, no validity window and no clock anywhere in the format: a receiver with
no GPS, no internet and a dead RTC verifies the same as one with all three.

## Envelope, first byte 0x01

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 1 | version, `0x01` |
| 1 | 8 | key id: the first 8 bytes of SHA-256 of the raw 32-byte Ed25519 public key |
| 9 | 64 | Ed25519 signature |
| 73 | n | payload, any bytes, n >= 0 |

Header: 73 bytes. Total: 73 + n.

The signature is pure Ed25519 (RFC 8032, no prehash, no context string) over exactly
41 bytes:

    0x01 || key id (8) || SHA-256(payload) (32)

The payload is content-addressed: SHA-256(payload) is the object id. Ed25519 is
deterministic, so the same payload from the same key always produces the same
envelope, byte for byte, and two different keys sealing the same payload produce two
different envelopes. A receiver that keeps the set of envelope hashes it has already
accepted therefore has replay detection for free. The envelope itself does not detect
replay.

## Announce, first byte 0x02

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 1 | `0x02` |
| 1 | 32 | raw Ed25519 public key |

33 bytes. A listener that hears an announce learns a key and can compute its id. It
learns nothing about who holds it. A small-order key (order 1, 2, 4 or 8; libsodium's
blacklist of 7 values, sign bit masked) is refused on receipt: a signature under one
verifies for anyone, and no honest party holds one. Trust in a first-seen key is trust on first use;
the honest confirmation is out of band: read the 16 hex characters of the key id
over voice, or compare them on a page you already trust.

## Verify, in this order

1. Length < 73: `truncated`. Reject.
2. Byte 0 != `0x01`: `bad version`. Reject. An announce frame lands here.
3. Key id not in the receiver's trust store: `unknown key`. Reject. Do not fall back to
   treating the payload as unsigned.
4. Stored key, or the signature's first 32 bytes (R), is a small-order point:
   `small-order key` or `bad signature`. Reject before verifying. Cofactorless Ed25519
   verify accepts R = identity, S = 0 under such a key for any message.
5. Ed25519 verify(signature, `0x01 || key id || SHA-256(payload)`) with the stored
   public key. Failure: `bad signature`. Reject.
6. Deliver the payload. The signer's identity is the key. Nothing outside the
   envelope is authenticated by it.

The key id is a lookup index, 64 bits of a hash. The signature is the proof. Two keys
sharing an id is a nuisance (try each), not a break.

## What this format does not do

- Encryption: none. The payload is in the clear by design. A channel carrying this is
  exactly as public as it was before.
- Replay: not detected. Mitigation is one line at the receiver: keep a set of accepted
  envelope hashes, drop a hash you have seen. Sealing a sequence number with the text
  keeps a legitimately repeated message from looking like a replay.
- Metadata: anything outside the payload (call sign, destination, sequence number,
  timing, signal direction) is neither signed nor hidden. A field that must be
  authenticated goes inside the payload before sealing.
- Origin binding: none, at the format level. A receiver that binds a call sign to a key
  id (see the reference hook) is doing TOFU on unauthenticated metadata: any transmitter
  can announce, or replay, a previously heard announce, under any call sign. The
  reference hook binds only the first key id it sees for a call sign and never rebinds
  it; a second, different announce for that call sign is recorded as a mismatch flag on
  the call sign, not refused and not rebound. The flag is advisory only: a sealed frame
  that verifies is delivered with the key id it actually verifies against regardless of
  the call sign's bound state, so a forged announce can make a call sign's frames read
  mismatched but can never silence them.
- Revocation and expiry: none. Remove the key from the trust store.

## Worked example

Printed by `python vector.py`. The private key is RFC 8032 section 7.1, test 1, so a
port can check its Ed25519 against the RFC and its envelope against this file. That key
is public. Never use it for anything.

    private key (seed), 32 bytes
      9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    public key, 32 bytes
      d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    key id, 8 bytes
      21fe31dfa154a261
    payload, 41 bytes
      6e6f20696e7465726e657420686572652e20616c6c206f6b2e206e65787420636865636b2030393030
    sha256(payload), 32 bytes
      d5173e583abd0c73fbda98976d7ff7d2572bbde55af12dcaed124e073f09745c
    signed message = 0x01 || key id || sha256(payload), 41 bytes
      0121fe31dfa154a261d5173e583abd0c73fbda98976d7ff7d2572bbde55af12dcaed124e073f09745c
    signature, 64 bytes
      2f98bb0cc63c322ce8b6e32cf6963d2bba58c78875406aac788d1b3b34e12637cffe98ccdc1dbd2f1f535f3e5967d155641ee664d0b891ea14cc4b8d8ca36805
    envelope, 114 bytes
      0121fe31dfa154a2612f98bb0cc63c322ce8b6e32cf6963d2bba58c78875406aac788d1b3b34e12637cffe98ccdc1dbd2f1f535f3e5967d155641ee664d0b891ea14cc4b8d8ca368056e6f20696e7465726e657420686572652e20616c6c206f6b2e206e65787420636865636b2030393030
    announce, 33 bytes
      02d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

The payload is the text `no internet here. all ok. next check 0900`, the example shout
in crosstalk's own codec document. `test_arrowenvelope.py` asserts that the envelope
above is what the code produces, so this file cannot drift from the implementation.

## Cost on the crosstalk 10 m codec

Numbers retyped from crosstalk `docs/hf_codec.md`: inner frame PAYLOAD max 200 bytes,
LDPC (128, 64) rate 1/2, 100 baud. That is 16 air bits per payload byte, 0.16 s per byte.

- The 73-byte header leaves 127 bytes of text in a 200-byte PAYLOAD.
- 73 bytes is 1168 air bits, about 11.7 s, before LDPC block rounding.
- Their 41-character example shout: 71-byte inner frame, 9 LDPC blocks, about 14 s.
  Sealed: 144-byte inner frame, 18 blocks, 2584 air bits, about 26 s.
- An announce as its own shout: 63-byte inner frame, 8 blocks, 1304 air bits, about 13 s.
  Sent once per key, not once per message.

The 64-byte signature is the floor for Ed25519. Shrinking the key id to 4 bytes would
save 0.6 s and is not worth a second format.
