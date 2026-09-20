# arrowenvelope

A 73-byte signature envelope for open channels. Anyone can check who sealed a message,
offline, with no clock and no network. Nobody is stopped from reading it.

Built for a gap the crosstalk HF bridge has by design. Its codec document says the radio
hop is plaintext: the station decrypts locally and shouts call sign, destination hash and
UTF-8 text, and anyone with a receiver can read the shout. Our reading of the consequence:
nothing on the air proves who sent a frame, so any station can send one carrying any call
sign. (The general point that spoofing is not something crosstalk itself solves, though a
signature could still prove who sent a message, is the author's own remark in his overview
video, not a claim made in the crosstalk repository: youtube.com/watch?v=5vbl5FL-nsI,
around 27:48, "We're not going to solve spoofing in this video, although cryptographic
signatures could still prove mathematically that a message originated from a specific
sender.") This is a piece that fits that gap: Ed25519 over a content hash, one Python
file, MIT.

## What it fixes

- Spoofing on the plaintext leg. A receiver that knows a key rejects anything claiming
  that key that is not sealed by it, and the identity is the key, not the call sign in
  the header. The reference hook binds each call sign to the key id of the first announce
  it sees for that call sign, known_hosts style, and reports the verified key id as the
  signer on every sealed frame that verifies; whether that signer matches the call sign's
  bound key is a separate advisory flag, bound, unbound or mismatch, and is never a drop
  condition. This holds only if the receiver also marks unsigned frames claiming a bound
  station as unverified rather than trusting them (see below).
- Tampering. One flipped bit anywhere in the header or payload fails verification.
- Offline verification. No certificate authority, no clock, no lookup: a 32-byte key and
  41 bytes of arithmetic.

## What it does not fix

- Replay. A valid envelope heard twice verifies twice. Mitigation is one line: the
  receiver keeps a set of envelope hashes it has accepted and drops a repeat. Content
  addressing makes that free, and hashing the whole envelope, not just the payload, means
  two different keys sealing the identical text are two frames, not one replayed twice.
  See `examples/crosstalk_hook.py`.
- Metadata. Call sign, destination, sequence number and timing are outside the envelope.
  They are neither signed nor hidden. Anything that must be authenticated goes inside the
  payload before sealing.
- Unsigned frames. The envelope cannot stop a frame that never carried one. Once a
  receiver holds a key for a station it must drop, or visibly mark as unverified, unsigned
  frames claiming that station. The hook marks them unverified rather than dropping them.
  A call sign on an open channel is unverifiable metadata; only the key id is proven, by
  the signature, never by who claims it. Origin binding is TOFU and forgeable: announcing,
  or replaying, a key under any call sign can bind it, or leave it flagged mismatched, to
  a key the real station never chose, confirmed out of band by comparing key ids over
  voice. A garbage announce can flag a station's key mismatched. Still,
  it cannot drop a sealed frame, and it can never mute a station.
- Privacy. This is not encryption. Everything stays readable by anyone with a receiver.
  Never describe a channel carrying this as private.
- Who holds a key. A key learned from an announce frame is trust on first use. Read the
  16 hex characters of the key id over voice, or compare them on a page you already
  trust.

## Legal reading

United States, 47 CFR 97.113(a)(4) (text confirmed against the LII mirror, eCFR not yet):
prohibits "messages encoded for the purpose of obscuring their meaning." A detached
signature over an unmodified plaintext frame obscures nothing; the text is exactly as
readable as before. A novel envelope is an unspecified digital code under 97.309(b), which
carries no public-documentation requirement. What 97.309(b) does require: no transmission
to a station in a country the US has no agreement with for that code, the code must not be
used to obscure meaning, and on a Regional Director's instruction the station must cease
or restrict its digital transmissions as instructed and must maintain a record,
convertible to the original information, of all digital communications transmitted. That
last duty is the operator's own to keep. Publishing SPEC.md does not satisfy a
published-code requirement, because 97.309(b) has none; it forecloses any argument that
the envelope obscures meaning, and it is good practice regardless.

Canada: RBR-4 is silent on codes and ciphers. The operative rule is the Radiocommunication
Regulations, SOR/96-484, s. 47(b) (text confirmed at laws-lois.justice.gc.ca): an amateur
may only "use a code or cipher that is not secret." A published byte layout satisfies that
on its face. "Code or cipher" is not defined in the Radiocommunication Act or its
Regulations.

Neither reading above is backed by case law or by either regulator's own interpretation of
a detached signature over plaintext. Both are direct readings of the statutory and
regulatory text, done by us, not confirmed with either regulator. The control operator
remains responsible for every emission. Verify before you key.

The envelope is authentication. It is never privacy: the text stays exactly as readable
as it was before sealing.

## Cost

From crosstalk's codec document: PAYLOAD max 200 bytes, LDPC rate 1/2 at 100 baud, so
0.16 s per byte. The 73-byte header costs about 11.7 s per shout and leaves 127 bytes of
text. Their 14 s example shout becomes about 26 s sealed. Numbers and the block math are
in `SPEC.md`.

## Quickstart

    pip install cryptography
    python -m arrowenvelope keygen station.key            # station.key (PKCS#8) and station.key.pub (raw 32 bytes)
    python -m arrowenvelope id < station.key.pub           # 16 hex chars, read these over voice
    python -m arrowenvelope announce < station.key.pub > announce.bin   # 33 bytes, send once
    printf 'no internet here. all ok.' | python -m arrowenvelope seal station.key > shout.bin
    python -m arrowenvelope open station.key.pub < shout.bin   # prints the text, or exits 1 with the reason
    python -m unittest -v

`station.key` is written 0600 on POSIX. On Windows the file inherits its folder's
permissions instead, so keep it inside your user profile and out of any synced or shared
folder. Optional hardening on Windows, native, no shell wrapper needed:
`icacls station.key /inheritance:r /grant:r <user>:F`.

Python:

    import arrowenvelope as ae
    sk = ae.generate(); pk = ae.public_bytes(sk)
    env = ae.seal(sk, b"all ok")
    ae.open(env, {ae.key_id(pk): pk})   # b"all ok", or raises ae.EnvelopeError

## Files

- `arrowenvelope.py`: the module and the CLI. Python 3.10+, depends on `cryptography` only.
- `SPEC.md`: exact byte layout, verification order, worked example vector.
- `vector.py`: prints the example vector so a C or Rust port can test against it.
- `examples/crosstalk_hook.py`: where seal and open go in a crosstalk-shaped bridge. A
  sketch, not a working plugin.
- `test_arrowenvelope.py`: `python -m unittest -v`.

## Origin

arrowenvelope comes from ArrowMem, a private assistant that runs on your own hardware.
arrowmem.ca
