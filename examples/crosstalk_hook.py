"""Where the envelope goes in a crosstalk-shaped HF bridge.

SKETCH. Not run against their code. The station software that builds and parses
the 28-byte inner frame lives in their companion repo, so build_inner_frame,
parse_inner_frame and deliver below are stand-ins for it. Offsets and limits are
from crosstalk docs/hf_codec.md ("Inner frame").

One change is on their side: the text gate (src/backend/hf_airtext.py) refuses
control bytes, hex runs of 40+ and base64 runs, so the envelope cannot ride
inside PAYLOAD as text in any encoding. Give it its own frame TYPE (the VER/TYPE
low nibble is free, 0 is data) and run the text gate on the inner text only.
The text is still plaintext on the air, at PAYLOAD offset 75.
"""
import hashlib

import arrowenvelope as ae

TYPE_ENVELOPE = 1  # proposed VER/TYPE low nibble: PAYLOAD is an envelope or an announce


def build_inner_frame(**fields) -> bytes: raise NotImplementedError("their station software")
def parse_inner_frame(frame: bytes): raise NotImplementedError("their station software")
def deliver(hdr, text: str, signer: bytes | None, binding: str | None): raise NotImplementedError("their LXMF hand-off")


# Egress, TX bridge, once per shout. Sealing MSG_ID with the text makes "all ok"
# sent twice two distinct objects, so replay dedup on the far side does not eat it.
def egress(sk, msg_id: int, text: str) -> bytes:
    body = ae.seal(sk, msg_id.to_bytes(2, "big") + text.encode())  # 73 + 2 + len(text) <= 200
    return build_inner_frame(type=TYPE_ENVELOPE, msg_id=msg_id, payload=body)


# Ingress, RX bridge.
known: dict[bytes, bytes] = {}      # key id -> public key, from announce frames (TOFU) or typed in
signs: dict[str, bytes] = {}        # ORIGIN call sign -> first key id announced under it (known_hosts shape)
mismatched: set[str] = set()        # ORIGIN call signs that have announced a second, different key
seen: set[bytes] = set()            # sha256 of every envelope delivered; that set is the whole replay guard
# note: unbounded tables, fine at one shout per 15 s; bound them if a station runs for months
# note: ORIGIN is unsigned, so announcing or replaying a key under any call sign still
# binds, or flags mismatched, that call sign; TOFU cannot see the forgery. Identity is the
# verified key id, never ORIGIN: a sealed frame that verifies is always delivered with
# signer=key id. The call sign's bound key is advisory only (bound, unbound, mismatch) and
# is never a drop condition, so a forged announce can make a station's frames read
# mismatched but can never mute them.


def ingress(frame: bytes) -> None:
    hdr, payload = parse_inner_frame(frame)
    if hdr.type != TYPE_ENVELOPE:
        # Metadata (ORIGIN included) is never authenticated: every unsigned frame is
        # delivered, but always marked unverified. Never dropped here: dropping is what
        # let a single forged announce silence a station (see README, SPEC).
        return deliver(hdr, payload.decode(), signer=None, binding=None)
    try:
        if payload[:1] == ae.ANNOUNCE:
            pk = ae.parse_announce(payload)  # EnvelopeError: bad length, small-order key, not a point
            kid = ae.key_id(pk)
            known.setdefault(kid, pk)
            bound = signs.setdefault(hdr.origin, kid)  # first seen wins, never rebinds
            if bound != kid:
                mismatched.add(hdr.origin)  # recorded as a flag, not refused, not rebound
            return
        body = ae.open(payload, known)  # EnvelopeError: unknown key or bad signature
    except ae.EnvelopeError:
        return  # drop it, log it, never deliver it
    digest = hashlib.sha256(payload).digest()  # whole envelope: two keys sealing the same
    if digest in seen:                         # body are two frames, not one replayed twice
        return  # replay
    seen.add(digest)
    kid = payload[1:9]
    # Identity is the key, not ORIGIN. Always report the verified signer; whether it
    # matches the call sign's bound key is a separate advisory flag, never a drop condition.
    bound = signs.get(hdr.origin)
    binding = "unbound" if bound is None else ("bound" if bound == kid else "mismatch")
    deliver(hdr, body[2:].decode(), signer=kid, binding=binding)
