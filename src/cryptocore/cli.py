import argparse
import secrets
import sys
from pathlib import Path
from typing import NoReturn

from cryptocore.csprng import generate_random_bytes
from cryptocore.file_io import read_file, write_file
from cryptocore.hash import SUPPORTED_HASHES, hash_file
from cryptocore.mac import hmac_file
from cryptocore.modes import AuthenticationError, GCM, SUPPORTED_MODES
from cryptocore.modes import decrypt_cbc, decrypt_cfb, decrypt_ctr, decrypt_ecb, decrypt_ofb
from cryptocore.modes import encrypt_cbc, encrypt_cfb, encrypt_ctr, encrypt_ecb, encrypt_ofb
from cryptocore.padding import BLOCK_SIZE


def setup_output_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            reconfigure = getattr(stream, "reconfigure")
        except AttributeError:
            continue
        reconfigure(encoding="utf-8")


class RussianArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
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


def parse_nonce(nonce_hex: str) -> bytes:
    if len(nonce_hex) != 24:
        raise ValueError("Nonce GCM должен быть hex-строкой длиной 24 символа")
    try:
        return bytes.fromhex(nonce_hex)
    except ValueError as error:
        raise ValueError("Nonce GCM должен содержать только шестнадцатеричные символы") from error


def parse_aad(aad_hex: str | None) -> bytes:
    if aad_hex is None:
        return b""
    try:
        return bytes.fromhex(aad_hex)
    except ValueError as error:
        raise ValueError("AAD должен быть шестнадцатеричной строкой") from error


def parse_hmac_key(key_hex: str) -> bytes:
    try:
        return bytes.fromhex(key_hex)
    except ValueError as error:
        raise ValueError("Ключ HMAC должен быть шестнадцатеричной строкой чётной длины") from error


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
    parser.add_argument("--mode", help="режим работы: ecb, cbc, cfb, ofb, ctr, gcm")
    parser.add_argument("--encrypt", action="store_true", help="зашифровать файл")
    parser.add_argument("--decrypt", action="store_true", help="расшифровать файл")
    parser.add_argument("--key", help="ключ AES-128 в hex-формате")
    parser.add_argument("--iv", help="IV в hex-формате для расшифрования")
    parser.add_argument("--nonce", help="nonce GCM в hex-формате (алиас --iv для GCM)")
    parser.add_argument("--aad", help="associated data в hex-формате для GCM")
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
    parser.add_argument("--hmac", action="store_true", help="вычислить HMAC-SHA-256")
    parser.add_argument("--key", help="ключ HMAC произвольной длины в hex-формате")
    parser.add_argument("--verify", help="проверить HMAC из указанного файла")
    return parser


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.algorithm != "aes":
        parser.error("нужно указать --algorithm aes")

    if args.mode not in SUPPORTED_MODES:
        parser.error("нужно указать --mode ecb, cbc, cfb, ofb, ctr или gcm")

    if args.encrypt == args.decrypt:
        parser.error("нужно указать ровно один флаг: --encrypt или --decrypt")

    if args.iv and args.nonce:
        parser.error("нужно указать только один из аргументов: --iv или --nonce")

    if args.encrypt and args.iv and args.mode != "gcm":
        parser.error("--iv нельзя указывать при шифровании этого режима")

    if args.nonce and args.mode != "gcm":
        parser.error("--nonce используется только в режиме gcm")

    if args.aad is not None and args.mode != "gcm":
        parser.error("--aad используется только в режиме gcm")

    if args.mode == "ecb" and args.iv:
        parser.error("--iv не используется в режиме ecb")

    if not args.input:
        parser.error("нужно указать --input")


def encrypt_data(
        mode: str,
        data: bytes,
        key: bytes,
        nonce_text: str | None = None,
        aad: bytes = b"",
) -> bytes:
    if mode == "ecb":
        return encrypt_ecb(data, key)

    if mode == "gcm":
        nonce = parse_nonce(nonce_text) if nonce_text else None
        return GCM(key, nonce).encrypt(data, aad)

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


def decrypt_data(
        mode: str,
        data: bytes,
        key: bytes,
        iv_text: str | None,
        aad: bytes = b"",
) -> bytes:
    if mode == "ecb":
        return decrypt_ecb(data, key)

    if mode == "gcm":
        if iv_text:
            nonce = parse_nonce(iv_text)
        else:
            if len(data) < 28:
                raise AuthenticationError("входной файл не содержит nonce и полный тег GCM")
            nonce = data[:12]
        return GCM(key, nonce).decrypt(data, aad)

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

    if args.hmac:
        if not args.key:
            parser.error("при использовании --hmac нужно указать --key")
        if args.algorithm != "sha256":
            parser.error("HMAC поддерживается только с алгоритмом sha256")
    elif args.key or args.verify:
        parser.error("аргументы --key и --verify используются только вместе с --hmac")

    try:
        if args.hmac:
            key = parse_hmac_key(args.key)
            digest = hmac_file(key, args.input)
        else:
            digest = hash_file(args.algorithm, args.input)
        result = f"{digest}  {args.input}\n"

        if args.verify:
            try:
                expected_text = Path(args.verify).read_text(encoding="utf-8")
            except OSError as error:
                raise OSError(f"Не удалось прочитать файл '{args.verify}': {error}") from error

            fields = expected_text.split()
            if not fields:
                raise ValueError("Файл с ожидаемым HMAC пуст")
            expected = fields[0].lower()
            try:
                valid_expected = len(expected) == 64 and len(bytes.fromhex(expected)) == 32
            except ValueError:
                valid_expected = False
            if not valid_expected or not secrets.compare_digest(digest, expected):
                print("[ERROR] HMAC verification failed", file=sys.stderr)
                return 1
            print("[OK] HMAC verification successful")
            return 0

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
        aad = parse_aad(args.aad)
        nonce_text = args.nonce or args.iv

        if args.encrypt:
            output_data = encrypt_data(args.mode, input_data, key, nonce_text, aad)
        else:
            output_data = decrypt_data(args.mode, input_data, key, nonce_text, aad)

        output_path = args.output or make_output_name(args.input, args.encrypt)
        write_file(output_path, output_data)
        print(f"Готово. Результат записан в файл: {output_path}")
        return 0
    except AuthenticationError as error:
        print(f"[ERROR] Authentication failed: {error}", file=sys.stderr)
        return 1
    except (ValueError, OSError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1
