from Crypto.Cipher import AES

from cryptocore.padding import BLOCK_SIZE


def check_key(key: bytes) -> None:
    if len(key) != BLOCK_SIZE:
        raise ValueError("Для AES-128 ключ должен быть длиной 16 байт")


def encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("Блок должен быть длиной 16 байт")
    check_key(key)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)


def decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("Блок должен быть длиной 16 байт")
    check_key(key)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)
