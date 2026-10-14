from cryptocore.hash.digest import hash_file
from cryptocore.hash.sha256 import SHA256, sha256_hex
from cryptocore.hash.sha3_256 import sha3_256_hex


SUPPORTED_HASHES = ("sha256", "sha3-256")

__all__ = [
    "SUPPORTED_HASHES",
    "SHA256",
    "sha256_hex",
    "sha3_256_hex",
    "hash_file",
]
