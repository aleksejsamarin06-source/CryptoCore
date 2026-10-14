from cryptocore.modes.cbc import decrypt_cbc, encrypt_cbc
from cryptocore.modes.cfb import decrypt_cfb, encrypt_cfb
from cryptocore.modes.ctr import decrypt_ctr, encrypt_ctr
from cryptocore.modes.ecb import decrypt_ecb, encrypt_ecb
from cryptocore.modes.ofb import decrypt_ofb, encrypt_ofb


SUPPORTED_MODES = ("ecb", "cbc", "cfb", "ofb", "ctr")

__all__ = [
    "SUPPORTED_MODES",
    "encrypt_ecb",
    "decrypt_ecb",
    "encrypt_cbc",
    "decrypt_cbc",
    "encrypt_cfb",
    "decrypt_cfb",
    "encrypt_ofb",
    "decrypt_ofb",
    "encrypt_ctr",
    "decrypt_ctr",
]
