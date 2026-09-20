"""Prints the SPEC.md worked example. A port must reproduce these bytes exactly.

The private key is RFC 8032 section 7.1, test 1. It is public. Never use it for anything.
"""
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import arrowenvelope as ae

seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
payload = b"no internet here. all ok. next check 0900"

sk = Ed25519PrivateKey.from_private_bytes(seed)
pk = ae.public_bytes(sk)
kid = ae.key_id(pk)
digest = hashlib.sha256(payload).digest()
env = ae.seal(sk, payload)

for name, value in [
    ("private key (seed)", seed),
    ("public key", pk),
    ("key id", kid),
    ("payload", payload),
    ("sha256(payload)", digest),
    ("signed message = 0x01 || key id || sha256(payload)", ae.VERSION + kid + digest),
    ("signature", env[9:ae.HEADER]),
    ("envelope", env),
    ("announce", ae.announce(pk)),
]:
    print(f"{name}, {len(value)} bytes")
    print(f"  {value.hex()}")
