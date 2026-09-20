"""arrowenvelope: a signed, content-addressed envelope for open channels.

It authenticates. It does NOT encrypt, hide metadata, or detect replay.
Wire format and the worked example are in SPEC.md.
"""
import hashlib
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, load_der_private_key)

VERSION = b"\x01"
ANNOUNCE = b"\x02"
HEADER = 1 + 8 + 64  # version | key id | signature

# Ed25519 points of order 1, 2, 4 or 8. A signature under one of these verifies for
# anyone (R = identity, S = 0 passes cofactorless verify), so no honest party holds one.
# Blacklist copied from libsodium (ed25519_ref10.c, ge25519_has_small_order): 7 values
# compared with the sign bit of byte 31 masked, which covers the 14 encodings including
# the non-canonical y >= p forms that cryptography's from_public_bytes also accepts.
SMALL_ORDER = frozenset(bytes.fromhex(h) for h in (
    "00" * 32,
    "01" + "00" * 31,
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ec" + "ff" * 30 + "7f",
    "ed" + "ff" * 30 + "7f",
    "ee" + "ff" * 30 + "7f",
))


class EnvelopeError(ValueError):
    pass


def _small_order(point: bytes) -> bool:
    return point[:31] + bytes([point[31] & 0x7F]) in SMALL_ORDER


def _check_pk(pk_bytes: bytes) -> bytes:
    if len(pk_bytes) != 32:
        raise EnvelopeError("public key must be 32 bytes")
    if _small_order(pk_bytes):
        raise EnvelopeError("small-order key")
    return pk_bytes


def generate() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes_raw()


def key_id(pk_bytes: bytes) -> bytes:
    return hashlib.sha256(_check_pk(pk_bytes)).digest()[:8]


def _signed(kid: bytes, payload: bytes) -> bytes:
    return VERSION + kid + hashlib.sha256(payload).digest()


def seal(private_key: Ed25519PrivateKey, payload: bytes) -> bytes:
    kid = key_id(public_bytes(private_key))
    return VERSION + kid + private_key.sign(_signed(kid, payload)) + payload


def open(envelope: bytes, known_keys: dict[bytes, bytes]) -> bytes:  # shadows builtin, by spec
    if len(envelope) < HEADER:
        raise EnvelopeError("truncated")
    if envelope[:1] != VERSION:
        raise EnvelopeError("bad version")
    kid, sig, payload = envelope[1:9], envelope[9:HEADER], envelope[HEADER:]
    pk = known_keys.get(kid)
    if pk is None:
        raise EnvelopeError("unknown key")
    _check_pk(pk)
    if _small_order(sig[:32]):  # R; an honest signer never produces one, libsodium refuses it too
        raise EnvelopeError("bad signature")
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, _signed(kid, payload))
    except InvalidSignature:
        raise EnvelopeError("bad signature") from None
    return payload


def announce(pk_bytes: bytes) -> bytes:
    return ANNOUNCE + _check_pk(pk_bytes)


def parse_announce(frame: bytes) -> bytes:
    if len(frame) != 33 or frame[:1] != ANNOUNCE:
        raise EnvelopeError("not an announce frame")
    pk = _check_pk(frame[1:])
    # ponytail: from_public_bytes does not reject a non-point in cryptography 50.0.0
    # (measured: y=2, which has no valid x, loads without error). Kept as the asked-for
    # check; the control that actually holds is verify(), which raises InvalidSignature
    # under any non-point key. Upgrade path: decompress and check the curve equation.
    try:
        Ed25519PublicKey.from_public_bytes(pk)
    except Exception:
        raise EnvelopeError("not a valid Ed25519 point") from None
    return pk


# Keyring: one private key per file, created 0600, never overwritten (O_EXCL).
# The private file is PKCS#8 DER (RFC 5958, RFC 8410), 48 bytes; the public file is the
# raw 32 bytes the wire carries. Different lengths, so every entry point that takes one
# refuses the other: a private file is never announced, a public file never signs.
def save_key(private_key: Ed25519PrivateKey, path) -> None:
    # ponytail: 0600 is advisory on Windows, where NTFS ACLs inherit from the folder.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as f:
        f.write(private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()))


def load_key(path) -> Ed25519PrivateKey:
    try:
        sk = load_der_private_key(Path(path).read_bytes(), None)
    except ValueError:
        raise EnvelopeError(f"{path}: not a PKCS#8 private key file") from None
    if not isinstance(sk, Ed25519PrivateKey):
        raise EnvelopeError(f"{path}: not an Ed25519 key")
    return sk


USAGE = """usage: python -m arrowenvelope COMMAND [ARGS]
  keygen KEYFILE      write KEYFILE (private, PKCS#8 DER) and KEYFILE.pub (raw 32 bytes)
                      KEYFILE is 0600 on POSIX. On Windows it inherits its folder's
                      permissions: keep it in your user profile, out of synced folders.
  seal KEYFILE        stdin payload -> stdout envelope
  open PUBFILE...     stdin envelope -> stdout payload, or exit 1 with the reason
  announce            stdin raw public key -> stdout 33-byte announce frame
  id                  stdin raw public key -> stdout key id as 16 hex chars
Raw bytes on stdin and stdout, so a shell pipe can wrap any codec."""


def _main(argv: list[str]) -> None:
    cmd, args = (argv[1] if len(argv) > 1 else ""), argv[2:]
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    if cmd == "keygen" and len(args) == 1:
        sk = generate()
        save_key(sk, args[0])
        Path(args[0] + ".pub").write_bytes(public_bytes(sk))
    elif cmd == "seal" and len(args) == 1:
        stdout.write(seal(load_key(args[0]), stdin.read()))
    elif cmd == "open" and args:
        pks = [Path(p).read_bytes() for p in args]
        stdout.write(open(stdin.read(), {key_id(pk): pk for pk in pks}))
    elif cmd == "announce" and not args:
        stdout.write(announce(stdin.read()))
    elif cmd == "id" and not args:
        stdout.write(key_id(stdin.read()).hex().encode() + b"\n")
    else:
        sys.exit(USAGE)


if __name__ == "__main__":
    try:
        _main(sys.argv)
    except (EnvelopeError, OSError) as e:
        sys.exit(f"arrowenvelope: {e}")
