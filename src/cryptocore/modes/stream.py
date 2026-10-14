from cryptocore.padding import BLOCK_SIZE


def check_stream_mode_input(data: bytes, iv: bytes) -> None:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен быть длиной 16 байт")
    if len(data) == 0:
        raise ValueError("Шифртекст для потокового режима не должен быть пустым")
