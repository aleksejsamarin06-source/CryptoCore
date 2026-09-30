# CryptoCore

CryptoCore - консольная утилита для шифрования файлов с помощью AES-128.

Сам AES-примитив берется из `pycryptodome`. Режимы работы, разбиение на блоки, XOR, счетчик CTR, обработка IV и PKCS#7 padding реализованы в проекте.

## Зависимости

- Python 3.10 или новее
- pycryptodome

## Установка зависимостей

```bash
pip install -r requirements.txt
```

Для установки команды `cryptocore` в текущем окружении:

```bash
pip install -e .
```

Если проект не установлен как пакет, можно запускать через `main.py`:

```bash
python main.py --help
```

## Использование

Поддерживаемые режимы:

- `ecb`
- `cbc`
- `cfb`
- `ofb`
- `ctr`

Для `ecb` IV не используется.

Для `cbc`, `cfb`, `ofb`, `ctr` при шифровании IV генерируется автоматически и записывается в начало выходного файла. При расшифровании программа может взять IV из первых 16 байт входного файла. Также IV можно передать вручную через `--iv`.

Шифрование в режиме ECB:

```bash
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование в режиме ECB:

```bash
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Шифрование в режиме CBC:

```bash
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование в режиме CBC, если IV записан в начале файла:

```bash
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Расшифрование с IV, переданным вручную:

```bash
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv aabbccddeeff00112233445566778899 --input ciphertext_only.bin --output decrypted.txt
```

Ключ передается как hex-строка длиной 32 символа, то есть 16 байт для AES-128.

IV тоже передается как hex-строка длиной 32 символа, то есть 16 байт.

Если `--output` не указан, имя выходного файла создается автоматически:

- при шифровании: `<input>.enc`
- при расшифровании: `<input>.dec`

## Проверка полного цикла

PowerShell или терминал PyCharm:

```powershell
"Привет, это проверка CryptoCore" | Out-File -Encoding utf8 plain.txt
```

```powershell
.\.venv\Scripts\python.exe main.py --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plain.txt --output cipher.bin
```

```powershell
.\.venv\Scripts\python.exe main.py --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cipher.bin --output decoded.txt
```

Проверка:

```powershell
Compare-Object (Get-Content plain.txt) (Get-Content decoded.txt)
```

Если команда ничего не вывела, значит файлы совпадают.

Команды для Linux/macOS:

```bash
echo "test message" > plain.txt
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plain.txt --output cipher.bin
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cipher.bin --output decoded.txt
diff plain.txt decoded.txt
```

Если `diff` ничего не выводит, значит файлы совпадают.

## Проверка совместимости с OpenSSL

При шифровании в режимах с IV файл имеет формат:

```text
<16 байт IV><шифртекст>
```

Для проверки через OpenSSL нужно отделить первые 16 байт IV от остального шифртекста.

Пример для CBC в Linux/macOS:

```bash
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plain.txt --output cipher.bin
dd if=cipher.bin of=iv.bin bs=16 count=1
dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1
openssl enc -aes-128-cbc -d -K 000102030405060708090a0b0c0d0e0f -iv $(xxd -p iv.bin | tr -d '\n') -in ciphertext_only.bin -out decoded_openssl.txt
diff plain.txt decoded_openssl.txt
```

Для `cfb`, `ofb`, `ctr` в команде OpenSSL меняется только режим:

```bash
openssl enc -aes-128-cfb -d ...
openssl enc -aes-128-ofb -d ...
openssl enc -aes-128-ctr -d ...
```

## Тесты

```bash
python -m unittest discover -v
```
