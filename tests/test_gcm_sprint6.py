import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import AES

from cryptocore.aead import EncryptThenMAC
from cryptocore.cli import main
from cryptocore.modes.gcm import AuthenticationError, GCM


class GcmVectorTests(unittest.TestCase):
    def test_nist_empty_plaintext(self):
        gcm = GCM(bytes(16), bytes(12))
        ciphertext, tag = gcm.encrypt_detached(b"")
        self.assertEqual(ciphertext, b"")
        self.assertEqual(tag.hex(), "58e2fccefa7e3061367f1d57a4e7455a")

    def test_nist_single_block(self):
        gcm = GCM(bytes(16), bytes(12))
        ciphertext, tag = gcm.encrypt_detached(bytes(16))
        self.assertEqual(ciphertext.hex(), "0388dace60b6a392f328c2b971b2fe78")
        self.assertEqual(tag.hex(), "ab6e47d42cec13bdf53a67b21257bddf")

    def test_nist_vector_with_aad(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39"
        )
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        expected_ciphertext = bytes.fromhex(
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091"
        )

        gcm = GCM(key, nonce)
        ciphertext, tag = gcm.encrypt_detached(plaintext, aad)
        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(tag.hex(), "5bc94fbc3221a5db94fae95ae7121a47")
        self.assertEqual(gcm.decrypt_detached(ciphertext, tag, aad), plaintext)

    def test_non_96_bit_nonce_round_trip(self):
        key = bytes.fromhex("00" * 16)
        nonce = bytes.fromhex("0102030405060708")
        gcm = GCM(key, nonce)
        encrypted = gcm.encrypt(b"message", b"aad")
        self.assertEqual(gcm.decrypt(encrypted, b"aad"), b"message")

        reference = AES.new(key, AES.MODE_GCM, nonce=nonce)
        reference.update(b"aad")
        reference_ciphertext, reference_tag = reference.encrypt_and_digest(b"message")
        self.assertEqual(encrypted[len(nonce):-16], reference_ciphertext)
        self.assertEqual(encrypted[-16:], reference_tag)


class GcmSecurityTests(unittest.TestCase):
    def test_wrong_aad_ciphertext_and_tag_fail(self):
        key = bytes.fromhex("00112233445566778899aabbccddeeff")
        encrypted = GCM(key, bytes(12)).encrypt(b"secret message", b"correct")

        with self.assertRaises(AuthenticationError):
            GCM(key, bytes(12)).decrypt(encrypted, b"wrong")

        for position in (12, len(encrypted) - 1):
            tampered = bytearray(encrypted)
            tampered[position] ^= 1
            with self.subTest(position=position):
                with self.assertRaises(AuthenticationError):
                    GCM(key, bytes(12)).decrypt(bytes(tampered), b"correct")

    def test_generated_nonces_are_unique(self):
        key = bytes(16)
        nonces = {GCM(key).nonce for _ in range(1000)}
        self.assertEqual(len(nonces), 1000)

    def test_empty_and_large_aad(self):
        key = bytes.fromhex("102030405060708090a0b0c0d0e0f000")
        for aad in (b"", b"large aad block" * 10000):
            with self.subTest(size=len(aad)):
                gcm = GCM(key)
                encrypted = gcm.encrypt(b"payload", aad)
                self.assertEqual(gcm.decrypt(encrypted, aad), b"payload")


class GcmCliTests(unittest.TestCase):
    def test_full_cycle_and_authentication_failure_does_not_write(self):
        key = "00112233445566778899aabbccddeeff"
        aad = "aabbccddeeff"
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            source = directory / "plain.bin"
            encrypted = directory / "cipher.bin"
            decrypted = directory / "decoded.bin"
            failed_output = directory / "must-not-exist.bin"
            source.write_bytes(b"GCM file payload")

            with contextlib.redirect_stdout(io.StringIO()):
                encrypt_code = main([
                    "--algorithm", "aes", "--mode", "gcm", "--encrypt", "--key", key,
                    "--aad", aad, "--input", str(source), "--output", str(encrypted),
                ])
                decrypt_code = main([
                    "--algorithm", "aes", "--mode", "gcm", "--decrypt", "--key", key,
                    "--aad", aad, "--input", str(encrypted), "--output", str(decrypted),
                ])

            self.assertEqual(encrypt_code, 0)
            self.assertEqual(decrypt_code, 0)
            self.assertEqual(decrypted.read_bytes(), source.read_bytes())
            self.assertEqual(len(encrypted.read_bytes()), 12 + len(source.read_bytes()) + 16)

            with contextlib.redirect_stderr(io.StringIO()):
                failure_code = main([
                    "--algorithm", "aes", "--mode", "gcm", "--decrypt", "--key", key,
                    "--aad", "00", "--input", str(encrypted), "--output", str(failed_output),
                ])
            self.assertEqual(failure_code, 1)
            self.assertFalse(failed_output.exists())


class EncryptThenMacTests(unittest.TestCase):
    def test_round_trip_and_key_separation(self):
        aead = EncryptThenMAC(b"master key material", "ctr")
        self.assertNotEqual(aead.encryption_key, aead.mac_key[:16])
        encrypted = aead.encrypt(b"protected", b"metadata")
        self.assertEqual(aead.decrypt(encrypted, b"metadata"), b"protected")

    def test_tampering_fails_before_decryption(self):
        aead = EncryptThenMAC(b"master key material", "ctr")
        encrypted = bytearray(aead.encrypt(b"protected", b"metadata"))
        encrypted[20] ^= 1
        with self.assertRaises(AuthenticationError):
            aead.decrypt(bytes(encrypted), b"metadata")
        with self.assertRaises(AuthenticationError):
            aead.decrypt(bytes(encrypted), b"other metadata")


if __name__ == "__main__":
    unittest.main()
