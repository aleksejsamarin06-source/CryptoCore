import unittest

from cryptocore.padding import add_pkcs7_padding, remove_pkcs7_padding


class PaddingTests(unittest.TestCase):
    def test_adds_full_block_for_aligned_data(self):
        data = b"1234567890abcdef"
        padded = add_pkcs7_padding(data)

        self.assertEqual(len(padded), 32)
        self.assertEqual(padded[-16:], bytes([16]) * 16)

    def test_removes_valid_padding(self):
        data = b"hello"
        padded = add_pkcs7_padding(data)

        self.assertEqual(remove_pkcs7_padding(padded), data)

    def test_rejects_bad_padding(self):
        with self.assertRaises(ValueError):
            remove_pkcs7_padding(b"1234567890abcde\x02")


if __name__ == "__main__":
    unittest.main()
