import secrets

from cryptocore.csprng import generate_random_bytes
from cryptocore.mac import HMAC, hmac_sha256
from cryptocore.modes.cbc import decrypt_cbc, encrypt_cbc
from cryptocore.modes.cfb import decrypt_cfb, encrypt_cfb
from cryptocore.modes.ctr import decrypt_ctr, encrypt_ctr
from cryptocore.modes.gcm import AuthenticationError
from cryptocore.modes.ofb import decrypt_ofb, encrypt_ofb

IV_SIZE = 16
TAG_SIZE = 32
SUPPORTED_ETM_MODES = ("cbc", "cfb", "ofb", "ctr")

_ENCRYPTION_LABEL = b"CryptoCore Encrypt-then-MAC encryption key\x01"
_AUTHENTICATION_LABEL = b"CryptoCore Encrypt-then-MAC authentication key\x01"


class EncryptThenMAC:
    """Составная AEAD-схема Encrypt-then-MAC с HMAC-SHA-256."""

    def __init__(self, master_key: bytes, mode: str = "ctr"):
        if not master_key:
            raise ValueError("Master key не должен быть пустым")
        self.mode = self._validate_mode(mode)
        self.encryption_key = hmac_sha256(master_key, _ENCRYPTION_LABEL)[:16]
        self.mac_key = hmac_sha256(master_key, _AUTHENTICATION_LABEL)

    @classmethod
    def from_keys(cls, encryption_key: bytes, mac_key: bytes, mode: str = "ctr"):
        instance = cls.__new__(cls)
        if len(encryption_key) != 16:
            raise ValueError("Ключ шифрования AES-128 должен быть длиной 16 байт")
        if not mac_key:
            raise ValueError("Ключ MAC не должен быть пустым")
        instance.mode = cls._validate_mode(mode)
        instance.encryption_key = bytes(encryption_key)
        instance.mac_key = bytes(mac_key)
        return instance

    @staticmethod
    def _validate_mode(mode: str) -> str:
        if mode not in SUPPORTED_ETM_MODES:
            raise ValueError("Encrypt-then-MAC поддерживает cbc, cfb, ofb и ctr")
        return mode

    def _encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        functions = {
            "cbc": encrypt_cbc,
            "cfb": encrypt_cfb,
            "ofb": encrypt_ofb,
            "ctr": encrypt_ctr,
        }
        return functions[self.mode](plaintext, self.encryption_key, iv)

    def _decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        if not ciphertext and self.mode in ("cfb", "ofb", "ctr"):
            return b""
        functions = {
            "cbc": decrypt_cbc,
            "cfb": decrypt_cfb,
            "ofb": decrypt_ofb,
            "ctr": decrypt_ctr,
        }
        return functions[self.mode](ciphertext, self.encryption_key, iv)

    def encrypt(self, plaintext: bytes, aad: bytes = b"", iv: bytes | None = None) -> bytes:
        iv = generate_random_bytes(IV_SIZE) if iv is None else bytes(iv)
        if len(iv) != IV_SIZE:
            raise ValueError("IV должен быть длиной 16 байт")

        ciphertext = self._encrypt(bytes(plaintext), iv)
        authenticated_ciphertext = iv + ciphertext
        mac = HMAC(self.mac_key)
        mac.update(authenticated_ciphertext)
        mac.update(aad)
        tag = mac.digest()
        return authenticated_ciphertext + tag

    def decrypt(self, data: bytes, aad: bytes = b"") -> bytes:
        data = bytes(data)
        if len(data) < IV_SIZE + TAG_SIZE:
            raise AuthenticationError("входные данные Encrypt-then-MAC слишком короткие")

        authenticated_ciphertext = data[:-TAG_SIZE]
        supplied_tag = data[-TAG_SIZE:]
        mac = HMAC(self.mac_key)
        mac.update(authenticated_ciphertext)
        mac.update(aad)
        expected_tag = mac.digest()
        if not secrets.compare_digest(supplied_tag, expected_tag):
            raise AuthenticationError("AAD, IV, шифртекст или тег были изменены")

        iv = authenticated_ciphertext[:IV_SIZE]
        ciphertext = authenticated_ciphertext[IV_SIZE:]
        return self._decrypt(ciphertext, iv)


def encrypt_then_mac(
        plaintext: bytes,
        encryption_key: bytes,
        mac_key: bytes,
        aad: bytes = b"",
        iv: bytes | None = None,
        mode: str = "ctr",
) -> bytes:
    return EncryptThenMAC.from_keys(encryption_key, mac_key, mode).encrypt(plaintext, aad, iv)


def decrypt_then_verify(
        data: bytes,
        encryption_key: bytes,
        mac_key: bytes,
        aad: bytes = b"",
        mode: str = "ctr",
) -> bytes:
    return EncryptThenMAC.from_keys(encryption_key, mac_key, mode).decrypt(data, aad)
