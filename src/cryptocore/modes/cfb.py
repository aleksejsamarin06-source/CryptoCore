from cryptocore.aes_block import encrypt_block
from cryptocore.bytes_utils import split_blocks, xor_bytes
from cryptocore.padding import BLOCK_SIZE


def encrypt_cfb(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен быть длиной 16 байт")

    result = []
    previous_block = iv

    for block in split_blocks(data):
        encrypted_feedback = encrypt_block(previous_block, key)
        cipher_block = xor_bytes(block, encrypted_feedback[:len(block)])
        result.append(cipher_block)
        previous_block = cipher_block

    return b"".join(result)


def decrypt_cfb(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен быть длиной 16 байт")

    result = []
    previous_block = iv

    for block in split_blocks(data):
        encrypted_feedback = encrypt_block(previous_block, key)
        plain_block = xor_bytes(block, encrypted_feedback[:len(block)])
        result.append(plain_block)
        previous_block = block

    return b"".join(result)
