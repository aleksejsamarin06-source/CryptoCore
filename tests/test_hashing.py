import contextlib
import hashlib
import io
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptocore.cli import main
from cryptocore.hash import hash_file
from cryptocore.hash.sha256 import sha256_hex
from cryptocore.hash.sha3_256 import sha3_256_hex


class HashVectorTests(unittest.TestCase):
    def test_sha256_known_vectors(self):
        vectors = {
            b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        }

        for data, expected in vectors.items():
            with self.subTest(data=data):
                self.assertEqual(sha256_hex(data), expected)

    def test_sha3_256_known_vectors(self):
        self.assertEqual(
            sha3_256_hex(b""),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        )
        self.assertEqual(
            sha3_256_hex(b"abc"),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        )

    def test_hash_file_reads_chunks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "data.bin"
            data = (b"abc123" * 2000) + b"end"
            file_path.write_bytes(data)

            self.assertEqual(hash_file("sha256", str(file_path)), hashlib.sha256(data).hexdigest())
            self.assertEqual(hash_file("sha3-256", str(file_path)), hashlib.sha3_256(data).hexdigest())

    def test_avalanche_effect_for_sha256(self):
        first = sha256_hex(b"Hello, world!")
        second = sha256_hex(b"Hello, world?")
        first_bits = bin(int(first, 16))[2:].zfill(256)
        second_bits = bin(int(second, 16))[2:].zfill(256)
        changed = sum(a != b for a, b in zip(first_bits, second_bits))

        self.assertGreater(changed, 100)
        self.assertLess(changed, 156)


class DigestCliTests(unittest.TestCase):
    def test_dgst_prints_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "plain.txt"
            file_path.write_text("abc", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main([
                    "dgst",
                    "--algorithm", "sha256",
                    "--input", str(file_path),
                ])

            expected = hashlib.sha256(file_path.read_bytes()).hexdigest()
            self.assertEqual(code, 0)
            self.assertEqual(stdout.getvalue(), f"{expected}  {file_path}\n")

    def test_dgst_writes_output_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "plain.txt"
            output_path = Path(temp_dir) / "plain.sha3"
            file_path.write_text("abc", encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                code = main([
                    "dgst",
                    "--algorithm", "sha3-256",
                    "--input", str(file_path),
                    "--output", str(output_path),
                ])

            expected = hashlib.sha3_256(file_path.read_bytes()).hexdigest()
            self.assertEqual(code, 0)
            self.assertEqual(output_path.read_text(encoding="utf-8"), f"{expected}  {file_path}\n")

    def test_dgst_rejects_encrypt_options(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                main([
                    "dgst",
                    "--algorithm", "sha256",
                    "--input", "file.txt",
                    "--key", "00",
                ])

        self.assertEqual(error.exception.code, 2)


@unittest.skipUnless(shutil.which("sha256sum"), "sha256sum не найден")
class SystemHashTests(unittest.TestCase):
    def test_sha256_matches_sha256sum(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "plain.txt"
            file_path.write_bytes(b"system command compatibility")

            result = subprocess.run(
                ["sha256sum", str(file_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            system_hash = result.stdout.split()[0]

            self.assertEqual(hash_file("sha256", str(file_path)), system_hash)


if __name__ == "__main__":
    unittest.main()
