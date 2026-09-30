import unittest

from cryptocore.aes_block import encrypt_block
from cryptocore.modes.ecb import decrypt_ecb, encrypt_ecb


class EcbTests(unittest.TestCase):
    def test_aes_block_matches_known_vector(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        block = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        self.assertEqual(encrypt_block(block, key), expected)

    def test_encrypt_decrypt_text(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        data = "Пример текста для шифрования".encode("utf-8")

        encrypted = encrypt_ecb(data, key)
        decrypted = decrypt_ecb(encrypted, key)

        self.assertNotEqual(encrypted, data)
        self.assertEqual(decrypted, data)

    def test_encrypt_decrypt_binary_data(self):
        key = bytes.fromhex("00112233445566778899aabbccddeeff")
        data = bytes(range(256))

        encrypted = encrypt_ecb(data, key)
        decrypted = decrypt_ecb(encrypted, key)

        self.assertEqual(decrypted, data)

    def test_rejects_wrong_ciphertext_size(self):
        key = bytes.fromhex("00112233445566778899aabbccddeeff")

        with self.assertRaises(ValueError):
            decrypt_ecb(b"short", key)


if __name__ == "__main__":
    unittest.main()
