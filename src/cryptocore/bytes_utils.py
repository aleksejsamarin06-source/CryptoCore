from cryptocore.padding import BLOCK_SIZE


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def xor_bytes(first: bytes, second: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(first, second))
