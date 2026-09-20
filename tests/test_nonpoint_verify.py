"""Adversarial check: does a 32-byte value that decodes but is not a valid curve point
still fail signature verification? Constructs y=2 (no valid x per the code's own comment)
and a handful of other non-canonical/edge values, seals a real message with a real key,
then swaps in the bad key bytes at open() time to force verify() against garbage. Also
directly calls Ed25519PublicKey.verify() with a bogus signature under the bad key to
prove there is no crash/bypass path.
"""
import hashlib
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import arrowenvelope as ae

def _candidates():
    # y = 2 little-endian, sign bit 0 -- per the code's own comment, has no valid x
    y2 = (2).to_bytes(32, "little")
    # y = p (the field prime), non-canonical
    p = 2**255 - 19
    yp = p.to_bytes(32, "little")
    return [y2, yp]

def test_nonpoint_key_loads_but_verify_fails():
    sk = ae.generate()
    payload = b"hello"
    good_pk = ae.public_bytes(sk)
    env = ae.seal(sk, payload)
    for bad_pk in _candidates():
        assert len(bad_pk) == 32
        assert bad_pk != good_pk
        # from_public_bytes must not raise (that's the documented residual)
        pub = Ed25519PublicKey.from_public_bytes(bad_pk)
        # forging a signature under this key must fail verification, not crash or pass
        kid = hashlib.sha256(bad_pk).digest()[:8]
        signed = ae.VERSION + kid + hashlib.sha256(payload).digest()
        with pytest.raises(InvalidSignature):
            pub.verify(env[9:73], signed)
        # and ae.open() with this key registered must reject the envelope (not accept it)
        known = {kid: bad_pk}
        forged = ae.VERSION + kid + env[9:73] + payload
        with pytest.raises(ae.EnvelopeError):
            ae.open(forged, known)

def test_check_pk_accepts_the_y2_nonpoint():
    # y=2 is not on the small-order blacklist (it is not one of the 7 low-order
    # encodings), so _check_pk lets it through: confirms the residual is real for
    # at least one concrete non-point, and confirms verify() (tested above) is the
    # actual backstop, not _check_pk.
    y2 = (2).to_bytes(32, "little")
    ae._check_pk(y2)  # must not raise
