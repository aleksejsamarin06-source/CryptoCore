import contextlib
import io
import re
import tempfile
import unittest
from pathlib import Path

from cryptocore.cli import main
from cryptocore.csprng import generate_random_bytes


class CsprngTests(unittest.TestCase):
    def test_generate_random_bytes_length(self):
        self.assertEqual(len(generate_random_bytes(16)), 16)
        self.assertEqual(len(generate_random_bytes(32)), 32)

    def test_rejects_bad_size(self):
        with self.assertRaises(ValueError):
            generate_random_bytes(0)

    def test_1000_generated_keys_are_unique(self):
        keys = {generate_random_bytes(16).hex() for _ in range(1000)}

        self.assertEqual(len(keys), 1000)

    def test_hamming_weight_is_reasonable(self):
        data = b"".join(generate_random_bytes(16) for _ in range(1000))
        ones = sum(byte.bit_count() for byte in data)
        total_bits = len(data) * 8
        ratio = ones / total_bits

        self.assertGreater(ratio, 0.45)
        self.assertLess(ratio, 0.55)

    def test_cli_generates_key_for_encrypt(self):
        source_data = b"secret data for generated key"

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            plain_file = temp_path / "plain.txt"
            cipher_file = temp_path / "cipher.bin"
            decoded_file = temp_path / "decoded.txt"
            plain_file.write_bytes(source_data)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                encrypt_code = main([
                    "--algorithm", "aes",
                    "--mode", "ctr",
                    "--encrypt",
                    "--input", str(plain_file),
                    "--output", str(cipher_file),
                ])

            match = re.search(r"Сгенерирован случайный ключ: ([0-9a-f]{32})", stdout.getvalue())
            self.assertIsNotNone(match)
            generated_key = match.group(1)

            with contextlib.redirect_stdout(io.StringIO()):
                decrypt_code = main([
                    "--algorithm", "aes",
                    "--mode", "ctr",
                    "--decrypt",
                    "--key", generated_key,
                    "--input", str(cipher_file),
                    "--output", str(decoded_file),
                ])

            self.assertEqual(encrypt_code, 0)
            self.assertEqual(decrypt_code, 0)
            self.assertEqual(decoded_file.read_bytes(), source_data)

    def test_cli_warns_about_weak_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            plain_file = Path(temp_dir) / "plain.txt"
            cipher_file = Path(temp_dir) / "cipher.bin"
            plain_file.write_text("test", encoding="utf-8")

            stderr = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()):
                with contextlib.redirect_stderr(stderr):
                    code = main([
                        "--algorithm", "aes",
                        "--mode", "ecb",
                        "--encrypt",
                        "--key", "00000000000000000000000000000000",
                        "--input", str(plain_file),
                        "--output", str(cipher_file),
                    ])

            self.assertEqual(code, 0)
            self.assertIn("ключ выглядит слабым", stderr.getvalue())

    def test_cli_requires_key_for_decrypt(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cipher_file = Path(temp_dir) / "cipher.bin"
            cipher_file.write_bytes(b"0" * 32)

            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    main([
                        "--algorithm", "aes",
                        "--mode", "ecb",
                        "--decrypt",
                        "--input", str(cipher_file),
                    ])

            self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
