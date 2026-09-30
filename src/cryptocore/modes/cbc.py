from cryptocore.aes_block import decrypt_block, encrypt_block
from cryptocore.bytes_utils import split_blocks, xor_bytes
from cryptocore.padding import BLOCK_SIZE, add_pkcs7_padding, remove_pkcs7_padding


def encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен быть длиной 16 байт")

    result = []
    previous_block = iv
    padded_data = add_pkcs7_padding(data)

    for block in split_blocks(padded_data):
        mixed_block = xor_bytes(block, previous_block)
        encrypted_block = encrypt_block(mixed_block, key)
        result.append(encrypted_block)
        previous_block = encrypted_block

    return b"".join(result)


def decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен быть длиной 16 байт")
    if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Шифртекст для CBC должен быть кратен 16 байтам")

    result = []
    previous_block = iv

    for block in split_blocks(data):
        decrypted_block = decrypt_block(block, key)
        plain_block = xor_bytes(decrypted_block, previous_block)
        result.append(plain_block)
        previous_block = block

    return remove_pkcs7_padding(b"".join(result))
