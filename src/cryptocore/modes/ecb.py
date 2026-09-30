from cryptocore.aes_block import decrypt_block, encrypt_block
from cryptocore.bytes_utils import split_blocks
from cryptocore.padding import BLOCK_SIZE, add_pkcs7_padding, remove_pkcs7_padding


def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    padded_data = add_pkcs7_padding(data)
    encrypted_blocks = []

    for block in split_blocks(padded_data):
        encrypted_blocks.append(encrypt_block(block, key))

    return b"".join(encrypted_blocks)


def decrypt_ecb(data: bytes, key: bytes) -> bytes:
    if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Шифртекст для ECB должен быть кратен 16 байтам")

    decrypted_blocks = []
    for block in split_blocks(data):
        decrypted_blocks.append(decrypt_block(block, key))

    return remove_pkcs7_padding(b"".join(decrypted_blocks))
