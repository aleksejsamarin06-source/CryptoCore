import struct


MASK_32 = 0xFFFFFFFF

INITIAL_HASH = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

ROUND_CONSTANTS = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def rotate_right(value: int, bits: int) -> int:
    return ((value >> bits) | (value << (32 - bits))) & MASK_32


def sha256_hex(data: bytes) -> str:
    sha = SHA256()
    sha.update(data)
    return sha.hexdigest()


class SHA256:
    def __init__(self):
        self.hash_values = INITIAL_HASH.copy()
        self.buffer = b""
        self.message_length = 0

    def update(self, data: bytes) -> None:
        self.message_length += len(data)
        self.buffer += data

        while len(self.buffer) >= 64:
            self.process_block(self.buffer[:64])
            self.buffer = self.buffer[64:]

    def process_block(self, block: bytes) -> None:
        words = list(struct.unpack(">16I", block))

        for i in range(16, 64):
            s0 = rotate_right(words[i - 15], 7) ^ rotate_right(words[i - 15], 18) ^ (words[i - 15] >> 3)
            s1 = rotate_right(words[i - 2], 17) ^ rotate_right(words[i - 2], 19) ^ (words[i - 2] >> 10)
            words.append((words[i - 16] + s0 + words[i - 7] + s1) & MASK_32)

        a, b, c, d, e, f, g, h = self.hash_values

        for i in range(64):
            big_s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)
            choice = (e & f) ^ (~e & g)
            temp1 = (h + big_s1 + choice + ROUND_CONSTANTS[i] + words[i]) & MASK_32
            big_s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (big_s0 + majority) & MASK_32

            h = g
            g = f
            f = e
            e = (d + temp1) & MASK_32
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & MASK_32

        self.hash_values = [
            (old + new) & MASK_32
            for old, new in zip(self.hash_values, [a, b, c, d, e, f, g, h])
        ]

    def digest(self) -> bytes:
        copy = SHA256()
        copy.hash_values = self.hash_values.copy()
        copy.buffer = self.buffer
        copy.message_length = self.message_length

        bit_length = copy.message_length * 8
        copy.buffer += b"\x80"

        while len(copy.buffer) % 64 != 56:
            copy.buffer += b"\x00"

        copy.buffer += struct.pack(">Q", bit_length)

        while copy.buffer:
            copy.process_block(copy.buffer[:64])
            copy.buffer = copy.buffer[64:]

        return b"".join(struct.pack(">I", value) for value in copy.hash_values)

    def hexdigest(self) -> str:
        return self.digest().hex()
