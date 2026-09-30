from cryptocore.aes_block import encrypt_block
from cryptocore.bytes_utils import split_blocks, xor_bytes
from cryptocore.padding import BLOCK_SIZE


def encrypt_ofb(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен быть длиной 16 байт")

    result = []
    feedback = iv

    for block in split_blocks(data):
        feedback = encrypt_block(feedback, key)
        result.append(xor_bytes(block, feedback[:len(block)]))

    return b"".join(result)


def decrypt_ofb(data: bytes, key: bytes, iv: bytes) -> bytes:
    return encrypt_ofb(data, key, iv)
