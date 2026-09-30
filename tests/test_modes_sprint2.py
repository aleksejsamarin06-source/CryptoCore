import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import AES

from cryptocore.cli import main
from cryptocore.modes.cbc import decrypt_cbc, encrypt_cbc
from cryptocore.modes.cfb import decrypt_cfb, encrypt_cfb
from cryptocore.modes.ctr import decrypt_ctr, encrypt_ctr
from cryptocore.modes.ofb import decrypt_ofb, encrypt_ofb
from cryptocore.padding import BLOCK_SIZE, add_pkcs7_padding


class Sprint2ModeTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        self.iv = bytes.fromhex("aabbccddeeff00112233445566778899")
        self.data = b"data for new modes, not aligned"

    def test_cbc_full_cycle(self):
        encrypted = encrypt_cbc(self.data, self.key, self.iv)
        decrypted = decrypt_cbc(encrypted, self.key, self.iv)

        self.assertEqual(decrypted, self.data)

    def test_cbc_matches_pycryptodome(self):
        expected = AES.new(self.key, AES.MODE_CBC, self.iv).encrypt(
            add_pkcs7_padding(self.data)
        )

        self.assertEqual(encrypt_cbc(self.data, self.key, self.iv), expected)

    def test_stream_modes_full_cycle_without_padding(self):
        modes = [
            (encrypt_cfb, decrypt_cfb),
            (encrypt_ofb, decrypt_ofb),
            (encrypt_ctr, decrypt_ctr),
        ]

        for encrypt_func, decrypt_func in modes:
            with self.subTest(mode=encrypt_func.__name__):
                encrypted = encrypt_func(self.data, self.key, self.iv)
                decrypted = decrypt_func(encrypted, self.key, self.iv)

                self.assertEqual(len(encrypted), len(self.data))
                self.assertEqual(decrypted, self.data)

    def test_cfb_matches_pycryptodome(self):
        expected = AES.new(
            self.key,
            AES.MODE_CFB,
            self.iv,
            segment_size=128,
        ).encrypt(self.data)

        self.assertEqual(encrypt_cfb(self.data, self.key, self.iv), expected)

    def test_ofb_matches_pycryptodome(self):
        expected = AES.new(self.key, AES.MODE_OFB, self.iv).encrypt(self.data)

        self.assertEqual(encrypt_ofb(self.data, self.key, self.iv), expected)

    def test_ctr_matches_pycryptodome(self):
        expected = AES.new(
            self.key,
            AES.MODE_CTR,
            nonce=b"",
            initial_value=int.from_bytes(self.iv, byteorder="big"),
        ).encrypt(self.data)

        self.assertEqual(encrypt_ctr(self.data, self.key, self.iv), expected)


class Sprint2CliTests(unittest.TestCase):
    def test_cli_full_cycle_for_all_modes(self):
        key = "000102030405060708090a0b0c0d0e0f"
        source_data = b"short file for all sprint two modes"

        for mode in ["ecb", "cbc", "cfb", "ofb", "ctr"]:
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_path = Path(temp_dir)
                    plain_file = temp_path / "plain.txt"
                    cipher_file = temp_path / "cipher.bin"
                    decoded_file = temp_path / "decoded.txt"
                    plain_file.write_bytes(source_data)

                    with contextlib.redirect_stdout(io.StringIO()):
                        encrypt_code = main([
                            "--algorithm", "aes",
                            "--mode", mode,
                            "--encrypt",
                            "--key", key,
                            "--input", str(plain_file),
                            "--output", str(cipher_file),
                        ])
                        decrypt_code = main([
                            "--algorithm", "aes",
                            "--mode", mode,
                            "--decrypt",
                            "--key", key,
                            "--input", str(cipher_file),
                            "--output", str(decoded_file),
                        ])

                    self.assertEqual(encrypt_code, 0)
                    self.assertEqual(decrypt_code, 0)
                    self.assertEqual(decoded_file.read_bytes(), source_data)

                    if mode != "ecb":
                        self.assertGreaterEqual(
                            len(cipher_file.read_bytes()),
                            BLOCK_SIZE + len(source_data),
                        )

    def test_cli_decrypt_with_explicit_iv(self):
        key = "000102030405060708090a0b0c0d0e0f"
        source_data = b"cbc file with explicit iv"

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            plain_file = temp_path / "plain.txt"
            cipher_file = temp_path / "cipher.bin"
            cipher_without_iv = temp_path / "cipher_without_iv.bin"
            decoded_file = temp_path / "decoded.txt"
            plain_file.write_bytes(source_data)

            with contextlib.redirect_stdout(io.StringIO()):
                encrypt_code = main([
                    "--algorithm", "aes",
                    "--mode", "cbc",
                    "--encrypt",
                    "--key", key,
                    "--input", str(plain_file),
                    "--output", str(cipher_file),
                ])

            encrypted_data = cipher_file.read_bytes()
            iv = encrypted_data[:BLOCK_SIZE].hex()
            cipher_without_iv.write_bytes(encrypted_data[BLOCK_SIZE:])

            with contextlib.redirect_stdout(io.StringIO()):
                decrypt_code = main([
                    "--algorithm", "aes",
                    "--mode", "cbc",
                    "--decrypt",
                    "--key", key,
                    "--iv", iv,
                    "--input", str(cipher_without_iv),
                    "--output", str(decoded_file),
                ])

            self.assertEqual(encrypt_code, 0)
            self.assertEqual(decrypt_code, 0)
            self.assertEqual(decoded_file.read_bytes(), source_data)

    def test_cli_rejects_iv_for_encrypt(self):
        key = "000102030405060708090a0b0c0d0e0f"

        with tempfile.TemporaryDirectory() as temp_dir:
            plain_file = Path(temp_dir) / "plain.txt"
            plain_file.write_text("test", encoding="utf-8")

            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    main([
                        "--algorithm", "aes",
                        "--mode", "cbc",
                        "--encrypt",
                        "--key", key,
                        "--iv", "aabbccddeeff00112233445566778899",
                        "--input", str(plain_file),
                    ])

            self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
