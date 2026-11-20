import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from cryptocore.cli import main
from cryptocore.mac import HMAC


class HmacVectorTests(unittest.TestCase):
    def test_rfc_4231_cases_1_to_4(self):
        vectors = [
            (
                bytes.fromhex("0b" * 20),
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                bytes.fromhex("aa" * 20),
                bytes.fromhex("dd" * 50),
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                bytes(range(1, 26)),
                bytes.fromhex("cd" * 50),
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
        ]

        for index, (key, data, expected) in enumerate(vectors, start=1):
            self.assertEqual(HMAC(key).compute(data), expected, f"RFC 4231 case {index}")

    def test_short_exact_and_long_keys(self):
        for size in (16, 64, 100):
            with self.subTest(size=size):
                first = HMAC(b"k" * size).compute(b"message")
                second = HMAC(b"k" * size).compute(b"message")
                self.assertEqual(first, second)
                self.assertEqual(len(first), 64)

    def test_streaming_matches_single_update(self):
        expected = HMAC(b"key").compute(b"first second third")
        streamed = HMAC(b"key")
        streamed.update(b"first ")
        streamed.update(b"second ")
        streamed.update(b"third")
        self.assertEqual(streamed.hexdigest(), expected)


class HmacCliTests(unittest.TestCase):
    def test_generate_and_verify(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            source = directory / "message.bin"
            mac_file = directory / "message.hmac"
            source.write_bytes(b"authenticated contents")

            self.assertEqual(main([
                "dgst", "--algorithm", "sha256", "--hmac", "--key", "00112233",
                "--input", str(source), "--output", str(mac_file),
            ]), 0)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main([
                    "dgst", "--algorithm", "sha256", "--hmac", "--key", "00112233",
                    "--input", str(source), "--verify", str(mac_file),
                ])
            self.assertEqual(code, 0)
            self.assertIn("[OK]", stdout.getvalue())

    def test_verify_detects_changed_file_and_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            source = directory / "message.bin"
            mac_file = directory / "message.hmac"
            source.write_bytes(b"original")
            main([
                "dgst", "--algorithm", "sha256", "--hmac", "--key", "aabb",
                "--input", str(source), "--output", str(mac_file),
            ])

            source.write_bytes(b"changed")
            with contextlib.redirect_stderr(io.StringIO()):
                changed_code = main([
                    "dgst", "--algorithm", "sha256", "--hmac", "--key", "aabb",
                    "--input", str(source), "--verify", str(mac_file),
                ])
                wrong_key_code = main([
                    "dgst", "--algorithm", "sha256", "--hmac", "--key", "ccdd",
                    "--input", str(source), "--verify", str(mac_file),
                ])
            self.assertEqual(changed_code, 1)
            self.assertEqual(wrong_key_code, 1)


if __name__ == "__main__":
    unittest.main()
