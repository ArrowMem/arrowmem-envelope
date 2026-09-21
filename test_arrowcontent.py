import unittest
import zlib
from pathlib import Path

import arrowcontent as ac

HERE = Path(__file__).parent
DICTIONARY = b"no internet here. all ok. next check 0900" * 4
PLAINTEXT = b"all ok. next check 0900"


class ReferenceTest(unittest.TestCase):
    def test_round_trip(self):
        frame = ac.build_reference(DICTIONARY, PLAINTEXT)
        self.assertEqual(len(frame), 41)
        cid, oid = ac.parse_reference(frame)
        self.assertEqual(cid, ac.content_id(DICTIONARY))
        self.assertEqual(oid, ac.object_id(PLAINTEXT))
        index = {ac.object_id(PLAINTEXT): PLAINTEXT}
        self.assertEqual(ac.resolve_reference(frame, DICTIONARY, index), PLAINTEXT)

    def test_reference_not_held_wrong_corpus(self):
        frame = ac.build_reference(DICTIONARY, PLAINTEXT)
        index = {ac.object_id(PLAINTEXT): PLAINTEXT}
        with self.assertRaisesRegex(ac.ContentError, "reference not held"):
            ac.resolve_reference(frame, b"a different corpus entirely", index)

    def test_reference_not_held_missing_object(self):
        frame = ac.build_reference(DICTIONARY, PLAINTEXT)
        with self.assertRaisesRegex(ac.ContentError, "reference not held"):
            ac.resolve_reference(frame, DICTIONARY, {})

    def test_not_a_reference_frame(self):
        with self.assertRaisesRegex(ac.ContentError, "not a reference frame"):
            ac.parse_reference(b"\x03" + bytes(39))  # one byte short of 41
        with self.assertRaisesRegex(ac.ContentError, "not a reference frame"):
            ac.parse_reference(b"\x04" + bytes(40))  # wrong type byte, right length


class CompressedTest(unittest.TestCase):
    def test_round_trip(self):
        frame = ac.build_compressed(DICTIONARY, PLAINTEXT)
        self.assertEqual(frame[:1], ac.COMPRESSED)
        did = frame[1:9]
        self.assertEqual(did, ac.content_id(DICTIONARY))
        self.assertEqual(ac.decode_compressed(frame, {did: DICTIONARY}), PLAINTEXT)

    def test_empty_plaintext_round_trip(self):
        frame = ac.build_compressed(DICTIONARY, b"")
        did = frame[1:9]
        self.assertEqual(ac.decode_compressed(frame, {did: DICTIONARY}), b"")

    def test_unknown_dictionary(self):
        frame = ac.build_compressed(DICTIONARY, PLAINTEXT)
        with self.assertRaisesRegex(ac.ContentError, "unknown dictionary"):
            ac.decode_compressed(frame, {})

    def test_bad_inflate(self):
        did = ac.content_id(DICTIONARY)
        garbage = ac.COMPRESSED + did + b"\xff\xff\xff\xff\xff\xff"
        with self.assertRaisesRegex(ac.ContentError, "bad inflate"):
            ac.decode_compressed(garbage, {did: DICTIONARY})

    def test_too_long_output_is_capped(self):
        big = b"x" * 10000
        frame = ac.build_compressed(DICTIONARY, big)
        did = frame[1:9]
        with self.assertRaisesRegex(ac.ContentError, "too long"):
            ac.decode_compressed(frame, {did: DICTIONARY}, cap=4096)
        # a cap that actually fits still decodes fine
        self.assertEqual(ac.decode_compressed(frame, {did: DICTIONARY}, cap=len(big)), big)

    def test_dictionary_too_large_refused_at_encode(self):
        with self.assertRaisesRegex(ac.ContentError, "dictionary too large"):
            ac.build_compressed(b"x" * (ac.MAX_DICTIONARY_BYTES + 1), PLAINTEXT)

    def test_decoder_accepts_any_conforming_deflate_stream(self):
        # Built with the stdlib compressor directly, not through build_compressed, to prove
        # the decoder is not coupled to its own encoder's exact byte output.
        did = ac.content_id(DICTIONARY)
        co = zlib.compressobj(6, zlib.DEFLATED, -15, zdict=DICTIONARY)  # different level
        raw = co.compress(PLAINTEXT) + co.flush()
        frame = ac.COMPRESSED + did + raw
        self.assertEqual(ac.decode_compressed(frame, {did: DICTIONARY}), PLAINTEXT)

    def test_each_chunk_independent_not_one_running_stream(self):
        # research section 5 / FLAMP: losing one compressed frame must not lose the next.
        a, b = b"first chunk of a reply", b"second chunk, unrelated content"
        fa, fb = ac.build_compressed(DICTIONARY, a), ac.build_compressed(DICTIONARY, b)
        did = fa[1:9]
        # decode fb without ever having touched fa: proves no shared running state
        self.assertEqual(ac.decode_compressed(fb, {did: DICTIONARY}), b)
        self.assertEqual(ac.decode_compressed(fa, {did: DICTIONARY}), a)

    def test_red_decoder_that_skips_dictionary_id_check_is_wrong(self):
        # RED FIRST: a decoder that ignores the frame's dictionary id and always inflates
        # against whatever dictionary it happens to hold, instead of the one the frame
        # names, must be caught. wrong_dict's own bytes as the plaintext forces the very
        # first LZ77 matches to reference the dictionary window (nothing has been emitted
        # yet to self-reference), so decoding against a DIFFERENT dictionary's bytes at
        # those same window distances produces silently wrong output, not an error.
        def broken_decode(frame):
            do = zlib.decompressobj(-15, zdict=DICTIONARY)  # ignores frame[1:9] entirely
            return do.decompress(frame[1 + ac.ID_LEN:]) + do.flush()

        wrong_dict = b"the survivor should stay with the vehicle and signal for help " * 20
        plaintext_from_wrong_dict = wrong_dict[:80]
        frame = ac.build_compressed(wrong_dict, plaintext_from_wrong_dict)
        # The real decoder must refuse: it does not hold wrong_dict's id.
        with self.assertRaisesRegex(ac.ContentError, "unknown dictionary"):
            ac.decode_compressed(frame, {ac.content_id(DICTIONARY): DICTIONARY})
        # The broken decoder silently substitutes DICTIONARY's bytes at those window
        # distances and returns the wrong content instead of refusing.
        self.assertNotEqual(broken_decode(frame), plaintext_from_wrong_dict)


class HoldsTest(unittest.TestCase):
    def test_round_trip(self):
        cid = ac.content_id(DICTIONARY)
        frame = ac.build_holds(cid)
        self.assertEqual(len(frame), 9)
        self.assertEqual(ac.parse_holds(frame), cid)

    def test_wrong_id_length_refused(self):
        with self.assertRaisesRegex(ac.ContentError, "id must be 8 bytes"):
            ac.build_holds(b"short")

    def test_not_a_holds_frame(self):
        with self.assertRaisesRegex(ac.ContentError, "not a holds frame"):
            ac.parse_holds(b"\x05" + bytes(7))  # one byte short
        with self.assertRaisesRegex(ac.ContentError, "not a holds frame"):
            ac.parse_holds(b"\x03" + bytes(8))  # wrong type byte, right length


class SpecVectorTest(unittest.TestCase):
    def test_vector_bytes_are_in_spec(self):
        spec = (HERE / "SPEC-CONTENT.md").read_text(encoding="utf-8")
        frame_compressed = ac.build_compressed(DICTIONARY, PLAINTEXT)
        frame_reference = ac.build_reference(DICTIONARY, PLAINTEXT)
        frame_holds = ac.build_holds(ac.content_id(DICTIONARY))
        self.assertIn(DICTIONARY.hex(), spec)
        self.assertIn(ac.content_id(DICTIONARY).hex(), spec)
        self.assertIn(frame_compressed.hex(), spec)
        self.assertIn(frame_reference.hex(), spec)
        self.assertIn(frame_holds.hex(), spec)

    def test_deterministic_same_bytes_same_output(self):
        self.assertEqual(ac.build_compressed(DICTIONARY, PLAINTEXT),
                          ac.build_compressed(DICTIONARY, PLAINTEXT))


if __name__ == "__main__":
    unittest.main()
