from cryptocore.aes_block import encrypt_block
from cryptocore.bytes_utils import split_blocks, xor_bytes
from cryptocore.padding import BLOCK_SIZE


def encrypt_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен быть длиной 16 байт")

    result = []
    counter = int.from_bytes(iv, byteorder="big")

    for block in split_blocks(data):
        counter_block = counter.to_bytes(BLOCK_SIZE, byteorder="big")
        key_stream = encrypt_block(counter_block, key)
        result.append(xor_bytes(block, key_stream[:len(block)]))
        counter = (counter + 1) % (1 << 128)

    return b"".join(result)


def decrypt_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    return encrypt_ctr(data, key, iv)
