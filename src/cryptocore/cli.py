import argparse
import sys
from pathlib import Path

from cryptocore.csprng import generate_random_bytes
from cryptocore.file_io import read_file, write_file
from cryptocore.hash import SUPPORTED_HASHES, hash_file
from cryptocore.modes import SUPPORTED_MODES
from cryptocore.modes import decrypt_cbc, decrypt_cfb, decrypt_ctr, decrypt_ecb, decrypt_ofb
from cryptocore.modes import encrypt_cbc, encrypt_cfb, encrypt_ctr, encrypt_ecb, encrypt_ofb
from cryptocore.padding import BLOCK_SIZE


def setup_output_encoding() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass


class RussianArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"Ошибка аргументов: {message}\n")


def parse_key(key_hex: str) -> bytes:
    if len(key_hex) != 32:
        raise ValueError("Ключ должен быть hex-строкой длиной 32 символа")

    try:
        return bytes.fromhex(key_hex)
    except ValueError as error:
        raise ValueError("Ключ должен содержать только шестнадцатеричные символы") from error


def parse_iv(iv_hex: str) -> bytes:
    if len(iv_hex) != 32:
        raise ValueError("IV должен быть hex-строкой длиной 32 символа")

    try:
        return bytes.fromhex(iv_hex)
    except ValueError as error:
        raise ValueError("IV должен содержать только шестнадцатеричные символы") from error


def key_looks_weak(key: bytes) -> bool:
    if key == bytes(len(key)):
        return True

    sequential_up = bytes(range(len(key)))
    sequential_down = bytes(range(len(key) - 1, -1, -1))
    return key == sequential_up or key == sequential_down


def get_key_for_operation(args: argparse.Namespace, parser: argparse.ArgumentParser) -> bytes:
    if args.key:
        key = parse_key(args.key)
        if key_looks_weak(key):
            print("Предупреждение: ключ выглядит слабым", file=sys.stderr)
        return key

    if args.decrypt:
        parser.error("для расшифрования нужно указать --key")

    key = generate_random_bytes(BLOCK_SIZE)
    print(f"Сгенерирован случайный ключ: {key.hex()}")
    return key


def make_output_name(input_path: str, encrypt: bool) -> str:
    if encrypt:
        return f"{input_path}.enc"
    return f"{input_path}.dec"


def build_crypto_parser() -> argparse.ArgumentParser:
    parser = RussianArgumentParser(
        prog="cryptocore",
        description="Минимальная утилита для AES-128",
    )
    parser.add_argument("--algorithm", help="алгоритм, сейчас поддерживается aes")
    parser.add_argument("--mode", help="режим работы: ecb, cbc, cfb, ofb, ctr")
    parser.add_argument("--encrypt", action="store_true", help="зашифровать файл")
    parser.add_argument("--decrypt", action="store_true", help="расшифровать файл")
    parser.add_argument("--key", help="ключ AES-128 в hex-формате")
    parser.add_argument("--iv", help="IV в hex-формате для расшифрования")
    parser.add_argument("--input", help="путь к входному файлу")
    parser.add_argument("--output", help="путь к выходному файлу")
    return parser


def build_digest_parser() -> argparse.ArgumentParser:
    parser = RussianArgumentParser(
        prog="cryptocore dgst",
        description="Вычисление хеша файла",
    )
    parser.add_argument("--algorithm", choices=SUPPORTED_HASHES, required=True)
    parser.add_argument("--input", required=True, help="путь к входному файлу")
    parser.add_argument("--output", help="путь к файлу для записи результата")
    return parser


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.algorithm != "aes":
        parser.error("нужно указать --algorithm aes")

    if args.mode not in SUPPORTED_MODES:
        parser.error("нужно указать --mode ecb, cbc, cfb, ofb или ctr")

    if args.encrypt == args.decrypt:
        parser.error("нужно указать ровно один флаг: --encrypt или --decrypt")

    if args.encrypt and args.iv:
        parser.error("--iv нельзя указывать при шифровании")

    if args.mode == "ecb" and args.iv:
        parser.error("--iv не используется в режиме ecb")

    if not args.input:
        parser.error("нужно указать --input")


def encrypt_data(mode: str, data: bytes, key: bytes) -> bytes:
    if mode == "ecb":
        return encrypt_ecb(data, key)

    iv = generate_random_bytes(BLOCK_SIZE)

    if mode == "cbc":
        encrypted_data = encrypt_cbc(data, key, iv)
    elif mode == "cfb":
        encrypted_data = encrypt_cfb(data, key, iv)
    elif mode == "ofb":
        encrypted_data = encrypt_ofb(data, key, iv)
    elif mode == "ctr":
        encrypted_data = encrypt_ctr(data, key, iv)
    else:
        raise ValueError("Неподдерживаемый режим")

    return iv + encrypted_data


def split_iv_and_ciphertext(data: bytes) -> tuple[bytes, bytes]:
    if len(data) < BLOCK_SIZE:
        raise ValueError("Во входном файле нет полного IV")
    return data[:BLOCK_SIZE], data[BLOCK_SIZE:]


def decrypt_data(mode: str, data: bytes, key: bytes, iv_text: str | None) -> bytes:
    if mode == "ecb":
        return decrypt_ecb(data, key)

    if iv_text:
        iv = parse_iv(iv_text)
        ciphertext = data
    else:
        iv, ciphertext = split_iv_and_ciphertext(data)

    if mode == "cbc":
        return decrypt_cbc(ciphertext, key, iv)
    if mode == "cfb":
        return decrypt_cfb(ciphertext, key, iv)
    if mode == "ofb":
        return decrypt_ofb(ciphertext, key, iv)
    if mode == "ctr":
        return decrypt_ctr(ciphertext, key, iv)

    raise ValueError("Неподдерживаемый режим")


def run_digest(argv: list[str]) -> int:
    parser = build_digest_parser()
    args = parser.parse_args(argv)

    try:
        digest = hash_file(args.algorithm, args.input)
        result = f"{digest}  {args.input}\n"

        if args.output:
            try:
                Path(args.output).write_text(result, encoding="utf-8")
            except OSError as error:
                raise OSError(f"Не удалось записать файл '{args.output}': {error}") from error
        else:
            print(result, end="")

        return 0
    except (ValueError, OSError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    setup_output_encoding()

    if argv is None:
        argv = sys.argv[1:]

    if argv and argv[0] == "dgst":
        return run_digest(argv[1:])

    parser = build_crypto_parser()
    args = parser.parse_args(argv)
    validate_args(args, parser)

    try:
        key = get_key_for_operation(args, parser)
        input_data = read_file(args.input)

        if args.encrypt:
            output_data = encrypt_data(args.mode, input_data, key)
        else:
            output_data = decrypt_data(args.mode, input_data, key, args.iv)

        output_path = args.output or make_output_name(args.input, args.encrypt)
        write_file(output_path, output_data)
        print(f"Готово. Результат записан в файл: {output_path}")
        return 0
    except (ValueError, OSError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1
