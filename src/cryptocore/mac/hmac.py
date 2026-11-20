from pathlib import Path

from cryptocore.hash.sha256 import SHA256

BLOCK_SIZE = 64
CHUNK_SIZE = 8192


class HMAC:
    """Потоковая реализация HMAC-SHA-256 по RFC 2104."""

    block_size = BLOCK_SIZE
    digest_size = 32

    def __init__(self, key: bytes, hash_function: str = "sha256"):
        if hash_function != "sha256":
            raise ValueError("HMAC в CryptoCore поддерживает только sha256")

        normalized_key = self._process_key(bytes(key))
        self._key = normalized_key
        ipad = bytes(value ^ 0x36 for value in normalized_key)
        self._opad = bytes(value ^ 0x5C for value in normalized_key)
        self._inner = SHA256()
        self._inner.update(ipad)

    @staticmethod
    def _process_key(key: bytes) -> bytes:
        if len(key) > BLOCK_SIZE:
            hasher = SHA256()
            hasher.update(key)
            key = hasher.digest()
        return key.ljust(BLOCK_SIZE, b"\x00")

    def update(self, data: bytes) -> None:
        self._inner.update(bytes(data))

    def digest(self) -> bytes:
        outer = SHA256()
        outer.update(self._opad)
        outer.update(self._inner.digest())
        return outer.digest()

    def hexdigest(self) -> str:
        return self.digest().hex()

    def compute(self, message: bytes) -> str:
        one_shot = HMAC(self._key)
        one_shot.update(message)
        return one_shot.hexdigest()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    mac = HMAC(key)
    mac.update(message)
    return mac.digest()


def hmac_file(key: bytes, input_path: str) -> str:
    mac = HMAC(key)
    path = Path(input_path)

    try:
        with path.open("rb") as file:
            while chunk := file.read(CHUNK_SIZE):
                mac.update(chunk)
    except OSError as error:
        raise OSError(f"Не удалось прочитать файл '{input_path}': {error}") from error

    return mac.hexdigest()
