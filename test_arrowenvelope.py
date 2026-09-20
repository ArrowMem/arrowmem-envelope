import hashlib
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import arrowenvelope as ae
from examples import crosstalk_hook as hook

HERE = Path(__file__).parent
PAYLOAD = b"no internet here. all ok. next check 0900"
# RFC 8032 section 7.1, test 1: an independent anchor for a port's Ed25519.
RFC8032_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC8032_PK = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
# The 8 canonical small-order encodings plus the 6 non-canonical (y >= p or sign-bit) forms.
SMALL_ORDER_14 = [bytes.fromhex(h) for h in (
    "00" * 32, "00" * 31 + "80", "01" + "00" * 31, "01" + "00" * 30 + "80",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "ec" + "ff" * 30 + "7f", "ec" + "ff" * 31, "ed" + "ff" * 30 + "7f", "ed" + "ff" * 31,
    "ee" + "ff" * 30 + "7f", "ee" + "ff" * 31,
)]
IDENTITY_SIG = bytes.fromhex("01" + "00" * 31) + bytes(32)  # R = identity, S = 0


def flip(b: bytes, i: int) -> bytes:
    return b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]


def cli(*args, input=b"", check=True):
    return subprocess.run([sys.executable, "-m", "arrowenvelope", *args],
                          input=input, capture_output=True, cwd=HERE, check=check)


class EnvelopeTest(unittest.TestCase):
    def setUp(self):
        self.sk = ae.generate()
        self.pk = ae.public_bytes(self.sk)
        self.keys = {ae.key_id(self.pk): self.pk}
        self.env = ae.seal(self.sk, PAYLOAD)

    def test_round_trip(self):
        self.assertEqual(len(self.env), ae.HEADER + len(PAYLOAD))
        self.assertEqual(ae.open(self.env, self.keys), PAYLOAD)
        self.assertEqual(ae.open(ae.seal(self.sk, b""), self.keys), b"")

    def test_tamper_payload_byte(self):
        with self.assertRaisesRegex(ae.EnvelopeError, "bad signature"):
            ae.open(flip(self.env, ae.HEADER + 5), self.keys)

    def test_tamper_signature_byte(self):
        with self.assertRaisesRegex(ae.EnvelopeError, "bad signature"):
            ae.open(flip(self.env, 20), self.keys)

    def test_unknown_key(self):
        with self.assertRaisesRegex(ae.EnvelopeError, "unknown key"):
            ae.open(self.env, {})

    def test_truncated(self):
        for n in (0, 1, 9, ae.HEADER - 1):
            with self.assertRaisesRegex(ae.EnvelopeError, "truncated"):
                ae.open(self.env[:n], self.keys)

    def test_bad_version(self):
        with self.assertRaisesRegex(ae.EnvelopeError, "bad version"):
            ae.open(ae.announce(self.pk) + bytes(40), self.keys)

    def test_announce_round_trip(self):
        frame = ae.announce(self.pk)
        self.assertEqual(len(frame), 33)
        self.assertEqual(ae.parse_announce(frame), self.pk)
        for bad in (frame[:-1], b"\x01" + self.pk):
            with self.assertRaises(ae.EnvelopeError):
                ae.parse_announce(bad)

    def test_small_order_keys_refused(self):
        self.assertEqual(len(SMALL_ORDER_14), 14)
        for pk in SMALL_ORDER_14:
            kid = hashlib.sha256(pk).digest()[:8]  # by hand: key_id refuses these
            for payload in (PAYLOAD, b"", b"spoof 1", b"spoof 2", b"spoof 3"):
                with self.assertRaisesRegex(ae.EnvelopeError, "small-order key"):
                    ae.open(ae.VERSION + kid + IDENTITY_SIG + payload, {kid: pk})
            for fn in (ae.key_id, ae.announce):
                with self.assertRaisesRegex(ae.EnvelopeError, "small-order key"):
                    fn(pk)
            with self.assertRaisesRegex(ae.EnvelopeError, "small-order key"):
                ae.parse_announce(ae.ANNOUNCE + pk)
        # Small-order R under an honest key is refused before verify as well.
        kid = ae.key_id(self.pk)
        with self.assertRaisesRegex(ae.EnvelopeError, "bad signature"):
            ae.open(ae.VERSION + kid + IDENTITY_SIG + PAYLOAD, self.keys)

    def test_spec_vector(self):
        sk = Ed25519PrivateKey.from_private_bytes(RFC8032_SEED)
        self.assertEqual(ae.public_bytes(sk), RFC8032_PK)
        env = ae.seal(sk, PAYLOAD)
        self.assertEqual(env, ae.seal(sk, PAYLOAD))  # deterministic, same object every time
        self.assertIn(env.hex(), (HERE / "SPEC.md").read_text(encoding="utf-8"))

    def test_cli_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            key = str(Path(d) / "station.key")
            cli("keygen", key)
            pub = Path(key + ".pub").read_bytes()
            self.assertEqual(len(pub), 32)
            self.assertEqual(Path(key).stat().st_size, 48)  # PKCS#8 DER, never raw 32
            env = cli("seal", key, input=PAYLOAD).stdout
            self.assertEqual(cli("open", key + ".pub", input=env).stdout, PAYLOAD)
            self.assertEqual(cli("id", input=pub).stdout.strip(), ae.key_id(pub).hex().encode())
            self.assertEqual(ae.parse_announce(cli("announce", input=pub).stdout), pub)
            bad = cli("open", key + ".pub", input=flip(env, ae.HEADER + 1), check=False)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn(b"bad signature", bad.stderr)
            again = cli("keygen", key, check=False)  # never overwrite a private key
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(Path(key + ".pub").read_bytes(), pub)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(Path(key).stat().st_mode), 0o600)
            else:
                self.skipTest("0600 is a POSIX mode bit; Windows keyfiles inherit folder ACLs (README)")

    def test_cli_refuses_swapped_key_files(self):
        with tempfile.TemporaryDirectory() as d:
            key = str(Path(d) / "station.key")
            cli("keygen", key)
            private = Path(key).read_bytes()
            for args in (("announce",), ("id",), ("open", key)):  # private file where public expected
                r = cli(*args, input=private if args[0] != "open" else b"x" * ae.HEADER, check=False)
                self.assertNotEqual(r.returncode, 0, args)
                self.assertEqual(r.stdout, b"", args)
            r = cli("seal", key + ".pub", input=PAYLOAD, check=False)  # public file where private expected
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(r.stdout, b"")
            self.assertIn(b"not a PKCS#8 private key file", r.stderr)


class HookTest(unittest.TestCase):
    def setUp(self):
        hook.known.clear(); hook.signs.clear(); hook.mismatched.clear(); hook.seen.clear()
        self.delivered = []
        self.frames = {}
        hook.parse_inner_frame = lambda f: self.frames[f]
        hook.deliver = lambda hdr, text, signer, binding: self.delivered.append((hdr.origin, text, signer, binding))

    def frame(self, origin, type_, payload):
        f = f"{origin}/{type_}/{payload.hex()}".encode()
        self.frames[f] = (SimpleNamespace(type=type_, origin=origin), payload)
        return f

    def test_unsigned_frame_from_announced_station_is_marked_unverified(self):
        sk = ae.generate(); pk = ae.public_bytes(sk)
        hook.ingress(self.frame("VE3AAA", 0, b"hello before any key"))  # unsigned, no key yet: delivered, unverified
        self.assertEqual(self.delivered, [("VE3AAA", "hello before any key", None, None)])
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, ae.announce(pk)))
        hook.ingress(self.frame("VE3AAA", 0, b"spoof, unsigned"))  # origin now bound: still delivered, unverified
        self.assertEqual(self.delivered[-1], ("VE3AAA", "spoof, unsigned", None, None))
        self.assertEqual(len(self.delivered), 2)
        sealed = ae.seal(sk, (7).to_bytes(2, "big") + b"all ok")
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, sealed))
        self.assertEqual(self.delivered[-1], ("VE3AAA", "all ok", ae.key_id(pk), "bound"))
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, sealed))  # replay: dropped
        self.assertEqual(len(self.delivered), 3)

    def test_cross_origin_sealed_frame_delivered_with_mismatch_flag(self):
        # G1: attacker announces their own key under a different call sign, then seals a
        # frame whose header claims the victim's call sign. ORIGIN is unauthenticated
        # metadata; the signer reported is always the key that actually verified, never
        # suppressed to None, and the call sign mismatch is a separate advisory flag.
        sk_v = ae.generate(); pk_v = ae.public_bytes(sk_v)
        sk_a = ae.generate(); pk_a = ae.public_bytes(sk_a)
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, ae.announce(pk_v)))
        hook.ingress(self.frame("VE3ZZZ", hook.TYPE_ENVELOPE, ae.announce(pk_a)))
        spoof = ae.seal(sk_a, (1).to_bytes(2, "big") + b"VE3AAA is fine, no help needed")
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, spoof))
        origin, text, signer, binding = self.delivered[-1]
        self.assertEqual(origin, "VE3AAA")       # ORIGIN is unauthenticated metadata, shown as sent
        self.assertEqual(signer, ae.key_id(pk_a))  # the real, verified signer, disclosed rather than hidden
        self.assertEqual(binding, "mismatch")      # VE3AAA is bound to pk_v, not the key that signed this

    def test_second_announce_for_a_bound_origin_is_recorded_not_rebound(self):
        # G2: a second, different key announced under an already-bound call sign is
        # recorded as a mismatch flag. It is not refused (the key still enters `known`,
        # since identity is the key, never ORIGIN) and it is not rebound (`signs` keeps
        # the first key), so a sealed frame under the second key still verifies and
        # delivers, flagged mismatched rather than dropped.
        sk_v = ae.generate(); pk_v = ae.public_bytes(sk_v)
        sk_a = ae.generate(); pk_a = ae.public_bytes(sk_a)
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, ae.announce(pk_v)))
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, ae.announce(pk_a)))  # recorded, not refused
        self.assertEqual(hook.known, {ae.key_id(pk_v): pk_v, ae.key_id(pk_a): pk_a})
        self.assertEqual(hook.signs, {"VE3AAA": ae.key_id(pk_v)})  # not rebound
        self.assertEqual(hook.mismatched, {"VE3AAA"})
        spoof2 = ae.seal(sk_a, (2).to_bytes(2, "big") + b"spoof under second key")
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, spoof2))
        self.assertEqual(self.delivered, [("VE3AAA", "spoof under second key", ae.key_id(pk_a), "mismatch")])

    def test_forged_announce_replay_no_longer_mutes_the_station(self):
        # G3: replaying a victim's own public announce under another station's call sign
        # binds that call sign (TOFU cannot see the forgery), but must not silence it.
        sk_v = ae.generate(); pk_v = ae.public_bytes(sk_v)
        victim_announce = ae.announce(pk_v)
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, victim_announce))
        hook.ingress(self.frame("VE3BBB", 0, b"VE3BBB all ok"))
        hook.ingress(self.frame("VE3BBB", hook.TYPE_ENVELOPE, victim_announce))  # replayed, forged origin
        hook.ingress(self.frame("VE3BBB", 0, b"VE3BBB all ok, second check"))
        self.assertEqual(len(self.delivered), 2)  # both delivered, neither dropped
        self.assertEqual(self.delivered[-1], ("VE3BBB", "VE3BBB all ok, second check", None, None))

    def test_attacker_prebinds_call_sign_victim_seal_still_reports_victim_key(self):
        # Regression for the TOFU ruling: the attacker announces their own key under the
        # VICTIM's call sign first, winning the bind. The victim's own later announce for
        # that call sign is recorded as a mismatch, not refused, not rebound. When the
        # attacker seals under that call sign, TOFU-first-seen reads it as "bound" (the
        # inversion this ruling accepts: a call sign binding is metadata, not trust).
        # When the victim seals, the hook still reports signer=victim key id, never the
        # attacker's, with the call sign correctly flagged mismatch: the attacker is never
        # reported as a verified holder of the victim's key.
        sk_a = ae.generate(); pk_a = ae.public_bytes(sk_a)
        sk_v = ae.generate(); pk_v = ae.public_bytes(sk_v)
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, ae.announce(pk_a)))  # attacker binds first
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, ae.announce(pk_v)))  # victim: mismatch, not rebound
        self.assertEqual(hook.signs["VE3AAA"], ae.key_id(pk_a))
        self.assertEqual(hook.mismatched, {"VE3AAA"})

        attacker_frame = ae.seal(sk_a, (1).to_bytes(2, "big") + b"attacker under the bound key")
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, attacker_frame))
        self.assertEqual(self.delivered[-1], ("VE3AAA", "attacker under the bound key", ae.key_id(pk_a), "bound"))

        victim_frame = ae.seal(sk_v, (2).to_bytes(2, "big") + b"victim, the real station")
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, victim_frame))
        origin, text, signer, binding = self.delivered[-1]
        self.assertEqual(signer, ae.key_id(pk_v))   # the victim's frame is delivered under the victim's own key id
        self.assertNotEqual(signer, ae.key_id(pk_a))  # the attacker is never reported as holder of the victim's key
        self.assertEqual(binding, "mismatch")         # the call sign still reads bound to the attacker's key

    def test_two_honest_keys_same_body_are_two_frames(self):
        # Ed25519 is deterministic, so replay dedup on the whole envelope still catches a
        # true repeat, but two different keys sealing the identical body are two distinct
        # envelopes (different key id, different signature), not one replayed twice.
        sk1 = ae.generate(); pk1 = ae.public_bytes(sk1)
        sk2 = ae.generate(); pk2 = ae.public_bytes(sk2)
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, ae.announce(pk1)))
        hook.ingress(self.frame("VE3BBB", hook.TYPE_ENVELOPE, ae.announce(pk2)))
        body = (1).to_bytes(2, "big") + b"all ok"
        hook.ingress(self.frame("VE3AAA", hook.TYPE_ENVELOPE, ae.seal(sk1, body)))
        hook.ingress(self.frame("VE3BBB", hook.TYPE_ENVELOPE, ae.seal(sk2, body)))
        self.assertEqual(len(self.delivered), 2)
        self.assertEqual(self.delivered[0][2], ae.key_id(pk1))
        self.assertEqual(self.delivered[1][2], ae.key_id(pk2))

    def test_readme_discloses_unsigned_frames(self):
        readme = (HERE / "README.md").read_text(encoding="utf-8")
        self.assertIn("- Unsigned frames. The envelope cannot stop a frame that never carried one.", readme)
        self.assertIn("drop, or visibly mark as unverified, unsigned", readme)

    def test_readme_discloses_forged_binding_cannot_mute(self):
        readme = (HERE / "README.md").read_text(encoding="utf-8")
        self.assertIn("only the key id is proven", readme)
        self.assertIn("it cannot drop a sealed frame", readme)

    def test_small_order_announce_never_enters_trust_store(self):
        for pk in SMALL_ORDER_14:
            hook.ingress(self.frame("VE3BBB", hook.TYPE_ENVELOPE, ae.ANNOUNCE + pk))  # caught, no raise
        self.assertEqual(hook.known, {})
        self.assertEqual(hook.signs, {})
        self.assertEqual(self.delivered, [])

    def test_malformed_announce_never_raises_out_of_ingress(self):
        # Item 2 regression: the whole envelope-type branch, parse_announce included, is
        # one try/except so a hostile or malformed announce can never crash the RX loop.
        for bad in (
            ae.ANNOUNCE + bytes(33),                 # 0x02 + 33 bytes: wrong length
            ae.ANNOUNCE,                              # 0x02 alone: wrong length
            ae.ANNOUNCE + SMALL_ORDER_14[0],          # 0x02 + small-order key
            ae.ANNOUNCE + (2).to_bytes(32, "little"),  # 0x02 + a deterministic non-point (y=2 has no valid x)
        ):
            hook.ingress(self.frame("VE3CCC", hook.TYPE_ENVELOPE, bad))  # must not raise
        self.assertEqual(self.delivered, [])
        # Note: cryptography's from_public_bytes does not itself reject the non-point case
        # (measured: y=2 is accepted with no exception), so `known` may gain that one dead
        # entry. It can never verify anything: Ed25519.verify() under a non-point key always
        # raises InvalidSignature, the same outcome as any other bad signature (also
        # measured). Only the length and small-order cases keep `known` empty here.


if __name__ == "__main__":
    unittest.main()
