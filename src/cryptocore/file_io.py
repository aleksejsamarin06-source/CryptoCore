from pathlib import Path


def read_file(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as error:
        raise OSError(f"Не удалось прочитать файл '{path}': {error}") from error


def write_file(path: str, data: bytes) -> None:
    try:
        Path(path).write_bytes(data)
    except OSError as error:
        raise OSError(f"Не удалось записать файл '{path}': {error}") from error
