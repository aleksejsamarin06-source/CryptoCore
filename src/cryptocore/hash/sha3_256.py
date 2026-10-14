import hashlib


def sha3_256_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()
