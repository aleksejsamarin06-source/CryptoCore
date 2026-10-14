from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptocore.csprng import generate_random_bytes


def main():
    output_path = Path("nist_test_data.bin")
    total_size = 10_000_000
    written = 0

    with output_path.open("wb") as file:
        while written < total_size:
            chunk_size = min(8192, total_size - written)
            file.write(generate_random_bytes(chunk_size))
            written += chunk_size

    print(f"Сгенерировано {written} байт: {output_path}")


if __name__ == "__main__":
    main()
