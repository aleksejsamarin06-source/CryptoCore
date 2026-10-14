import os


def generate_random_bytes(num_bytes: int) -> bytes:
    if num_bytes <= 0:
        raise ValueError("Количество байт должно быть положительным")

    try:
        return os.urandom(num_bytes)
    except OSError as error:
        raise OSError(f"Не удалось получить случайные байты: {error}") from error
