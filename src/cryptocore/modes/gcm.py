import secrets

from cryptocore.aes_block import check_key, encrypt_block
from cryptocore.csprng import generate_random_bytes

BLOCK_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
REDUCTION_CONSTANT = 0xE1000000000000000000000000000000


class AuthenticationError(ValueError):
    """Данные GCM не прошли проверку подлинности."""


class GCM:
    """AES-GCM по NIST SP 800-38D на основе AES-примитива проекта."""

    def __init__(self, key: bytes, nonce: bytes | None = None):
        check_key(key)
        if nonce is not None and not nonce:
            raise ValueError("Nonce не должен быть пустым")

        self.key = bytes(key)
        self.nonce = bytes(nonce) if nonce is not None else generate_random_bytes(NONCE_SIZE)
        self._hash_subkey = int.from_bytes(encrypt_block(bytes(BLOCK_SIZE), self.key), "big")

    @staticmethod
    def _iter_padded_blocks(data: bytes):
        view = memoryview(data)
        for offset in range(0, len(view), BLOCK_SIZE):
            block = bytes(view[offset:offset + BLOCK_SIZE])
            yield block.ljust(BLOCK_SIZE, b"\x00")

    @staticmethod
    def _mult_gf(x: int, y: int) -> int:
        """Умножение в GF(2^128) по x^128 + x^7 + x^2 + x + 1."""
        product = 0
        value = y
        for bit in range(127, -1, -1):
            if (x >> bit) & 1:
                product ^= value
            value = ((value >> 1) ^ REDUCTION_CONSTANT) if value & 1 else value >> 1
        return product

    def _ghash_blocks(self, blocks) -> bytes:
        result = 0
        for block in blocks:
            result = self._mult_gf(result ^ int.from_bytes(block, "big"), self._hash_subkey)
        return result.to_bytes(BLOCK_SIZE, "big")

    def _ghash(self, aad: bytes, ciphertext: bytes) -> bytes:
        aad = bytes(aad)
        ciphertext = bytes(ciphertext)

        def blocks():
            yield from self._iter_padded_blocks(aad)
            yield from self._iter_padded_blocks(ciphertext)
            yield (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")

        return self._ghash_blocks(blocks())

    def _initial_counter(self) -> bytes:
        if len(self.nonce) == NONCE_SIZE:
            return self.nonce + b"\x00\x00\x00\x01"

        def nonce_blocks():
            yield from self._iter_padded_blocks(self.nonce)
            yield bytes(8) + (len(self.nonce) * 8).to_bytes(8, "big")

        return self._ghash_blocks(nonce_blocks())

    @staticmethod
    def _increment_counter(counter: bytes) -> bytes:
        prefix = counter[:12]
        low = (int.from_bytes(counter[12:], "big") + 1) & 0xFFFFFFFF
        return prefix + low.to_bytes(4, "big")

    def _crypt(self, data: bytes, initial_counter: bytes) -> bytes:
        result = bytearray()
        counter = initial_counter
        view = memoryview(data)
        for offset in range(0, len(view), BLOCK_SIZE):
            counter = self._increment_counter(counter)
            block = view[offset:offset + BLOCK_SIZE]
            key_stream = encrypt_block(counter, self.key)
            result.extend(value ^ key_stream[index] for index, value in enumerate(block))
        return bytes(result)

    def encrypt_detached(self, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        initial_counter = self._initial_counter()
        ciphertext = self._crypt(bytes(plaintext), initial_counter)
        authentication = self._ghash(aad, ciphertext)
        encrypted_counter = encrypt_block(initial_counter, self.key)
        tag = bytes(left ^ right for left, right in zip(encrypted_counter, authentication))
        return ciphertext, tag

    def decrypt_detached(self, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        if len(tag) != TAG_SIZE:
            raise AuthenticationError("неверная длина тега GCM")

        initial_counter = self._initial_counter()
        authentication = self._ghash(aad, ciphertext)
        encrypted_counter = encrypt_block(initial_counter, self.key)
        expected_tag = bytes(left ^ right for left, right in zip(encrypted_counter, authentication))
        if not secrets.compare_digest(expected_tag, tag):
            raise AuthenticationError("AAD, шифртекст или тег были изменены")

        return self._crypt(bytes(ciphertext), initial_counter)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        ciphertext, tag = self.encrypt_detached(plaintext, aad)
        return self.nonce + ciphertext + tag

    def decrypt(self, data: bytes, aad: bytes = b"") -> bytes:
        data = bytes(data)
        if data.startswith(self.nonce) and len(data) >= len(self.nonce) + TAG_SIZE:
            data = data[len(self.nonce):]
        if len(data) < TAG_SIZE:
            raise AuthenticationError("входные данные не содержат полный тег GCM")
        return self.decrypt_detached(data[:-TAG_SIZE], data[-TAG_SIZE:], aad)
