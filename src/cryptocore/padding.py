BLOCK_SIZE = 16


def add_pkcs7_padding(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len]) * padding_len


def remove_pkcs7_padding(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Некорректная длина данных с padding")

    padding_len = data[-1]
    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Некорректный PKCS#7 padding")

    padding = data[-padding_len:]
    if padding != bytes([padding_len]) * padding_len:
        raise ValueError("Некорректный PKCS#7 padding")

    return data[:-padding_len]
