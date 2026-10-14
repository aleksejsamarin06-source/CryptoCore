import hashlib
from pathlib import Path

from cryptocore.hash.sha256 import SHA256


CHUNK_SIZE = 8192


def hash_file(algorithm: str, input_path: str) -> str:
    path = Path(input_path)

    if algorithm == "sha256":
        hasher = SHA256()
        update = hasher.update
        hexdigest = hasher.hexdigest
    elif algorithm == "sha3-256":
        hasher = hashlib.sha3_256()
        update = hasher.update
        hexdigest = hasher.hexdigest
    else:
        raise ValueError("Поддерживаются только sha256 и sha3-256")

    try:
        with path.open("rb") as file:
            while True:
                chunk = file.read(CHUNK_SIZE)
                if not chunk:
                    break
                update(chunk)
    except OSError as error:
        raise OSError(f"Не удалось прочитать файл '{input_path}': {error}") from error

    return hexdigest()
