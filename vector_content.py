"""Prints the SPEC-CONTENT.md worked example. A port must reproduce these bytes exactly.

The tiny vector dictionary is the SPEC.md example shout repeated 4 times, so a port needs
no pack to check its bytes. The envelope key is the same RFC 8032 test key vector.py uses.
"""
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import arrowcontent as ac
import arrowenvelope as ae

seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
shout = b"no internet here. all ok. next check 0900"
dictionary = shout * 4
plaintext = b"all ok. next check 0900"  # a novel-ish reply, shares text with the dictionary

sk = Ed25519PrivateKey.from_private_bytes(seed)

frame_holds = ac.build_holds(ac.content_id(dictionary))
frame_compressed = ac.build_compressed(dictionary, plaintext)
frame_reference = ac.build_reference(dictionary, plaintext)  # dictionary doubles as the corpus here
envelope = ae.seal(sk, frame_compressed)
frame_compressed_padded = frame_compressed + b"\x00" * 8  # padded to a fixed 21-byte frame

for name, value in [
    ("dictionary bytes", dictionary),
    ("dictionary id", ac.content_id(dictionary)),
    ("plaintext", plaintext),
    ("0x04 dictionary-compressed frame", frame_compressed),
    ("0x04 frame padded to a fixed length", frame_compressed_padded),
    ("0x03 content-reference frame", frame_reference),
    ("0x05 holds frame", frame_holds),
    ("0x04 frame sealed in an envelope (RFC 8032 test key)", envelope),
]:
    print(f"{name}, {len(value)} bytes")
    print(f"  {value.hex()}")
