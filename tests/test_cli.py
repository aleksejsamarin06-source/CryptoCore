import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from cryptocore.cli import main


class CliTests(unittest.TestCase):
    def test_cli_full_cycle(self):
        key = "000102030405060708090a0b0c0d0e0f"
        source_data = b"file data\nwith two lines\n"

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            plain_file = temp_path / "plain.txt"
            cipher_file = temp_path / "cipher.bin"
            decoded_file = temp_path / "decoded.txt"
            plain_file.write_bytes(source_data)

            with contextlib.redirect_stdout(io.StringIO()):
                with contextlib.redirect_stderr(io.StringIO()):
                    encrypt_code = main([
                        "--algorithm", "aes",
                        "--mode", "ecb",
                        "--encrypt",
                        "--key", key,
                        "--input", str(plain_file),
                        "--output", str(cipher_file),
                    ])
                    decrypt_code = main([
                        "--algorithm", "aes",
                        "--mode", "ecb",
                        "--decrypt",
                        "--key", key,
                        "--input", str(cipher_file),
                        "--output", str(decoded_file),
                    ])

            self.assertEqual(encrypt_code, 0)
            self.assertEqual(decrypt_code, 0)
            self.assertEqual(decoded_file.read_bytes(), source_data)

    def test_cli_rejects_bad_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            plain_file = Path(temp_dir) / "plain.txt"
            plain_file.write_text("test", encoding="utf-8")

            with contextlib.redirect_stderr(io.StringIO()):
                code = main([
                    "--algorithm", "aes",
                    "--mode", "ecb",
                    "--encrypt",
                    "--key", "1234",
                    "--input", str(plain_file),
                ])

            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
