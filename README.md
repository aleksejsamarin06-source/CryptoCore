# CryptoCore

CryptoCore - консольная утилита для шифрования и хеширования файлов.

Сам AES-примитив берется из `pycryptodome`. Режимы работы, включая GCM/GHASH, разбиение на блоки, XOR, счетчики, обработка IV/nonce, PKCS#7 padding, CSPRNG-обертка, SHA-256 и HMAC-SHA-256 реализованы в проекте. SHA3-256 используется через стандартный модуль `hashlib`.

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

Команды шифрования можно запускать в старом формате:

```bash
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Поддерживаемые режимы:

- `ecb`
- `cbc`
- `cfb`
- `ofb`
- `ctr`
- `gcm`

Для `ecb` IV не используется.

Для `cbc`, `cfb`, `ofb`, `ctr` при шифровании IV генерируется автоматически и записывается в начало выходного файла. При расшифровании программа может взять IV из первых 16 байт входного файла. Также IV можно передать вручную через `--iv`. Для GCM используется отдельный 12-байтный nonce; его можно передать через `--nonce` (или совместимый алиас `--iv`).

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

IV передается как hex-строка длиной 32 символа, то есть 16 байт. Nonce GCM имеет 24 hex-символа, то есть 12 байт.

Если при шифровании `--key` не указан, программа генерирует случайный ключ длиной 16 байт и выводит его в терминал:

```bash
cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
```

Пример вывода:

```text
Сгенерирован случайный ключ: 1a2b3c4d5e6f7890fedcba9876543210
Готово. Результат записан в файл: ciphertext.bin
```

Этот ключ не записывается в файл с шифртекстом. Его нужно сохранить отдельно, иначе файл нельзя будет расшифровать.

Для расшифрования `--key` обязателен:

```bash
cryptocore --algorithm aes --mode ctr --decrypt --key 1a2b3c4d5e6f7890fedcba9876543210 --input ciphertext.bin --output decrypted.txt
```

Если переданный ключ выглядит слабым, например состоит из одних нулей, программа выводит предупреждение в `stderr`.

Если `--output` не указан, имя выходного файла создается автоматически:

- при шифровании: `<input>.enc`
- при расшифровании: `<input>.dec`

## CSPRNG

Модуль CSPRNG находится в `src/cryptocore/csprng.py`.

Основная функция:

```python
generate_random_bytes(num_bytes: int) -> bytes
```

Она использует `os.urandom`, то есть криптографически стойкий источник случайности операционной системы. Эта функция применяется для генерации ключа, если `--key` не передан при шифровании, и для генерации IV в режимах `cbc`, `cfb`, `ofb`, `ctr`.

Для подготовки данных к NIST STS можно сгенерировать бинарный файл:

```bash
python scripts/generate_nist_data.py
```

Будет создан файл `nist_test_data.bin` размером 10 МБ. Его можно передать в NIST Statistical Test Suite. Сам набор NIST STS нужно скачать отдельно с сайта NIST и собрать по его документации:

```text
https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software
```

Общая процедура:

1. Скачать и собрать NIST STS.
2. Сгенерировать `nist_test_data.bin`.
3. Запустить `assess` из NIST STS.
4. Указать файл `nist_test_data.bin` как источник битов.
5. Проверить отчеты: большая часть тестов должна иметь `p-value >= 0.01`.

## Хеширование

Для вычисления хеша используется подкоманда `dgst`.

Поддерживаемые алгоритмы:

- `sha256` - собственная реализация SHA-256.
- `sha3-256` - реализация через `hashlib.sha3_256`.

Пример SHA-256:

```bash
cryptocore dgst --algorithm sha256 --input document.pdf
```

Формат вывода:

```text
HASH_VALUE  INPUT_FILE_PATH
```

Пример SHA3-256 с записью результата в файл:

```bash
cryptocore dgst --algorithm sha3-256 --input document.pdf --output document.sha3
```

Хеширование читает файл частями, поэтому не требует загружать весь файл в память.

## HMAC-SHA-256

Флаг `--hmac` переводит команду `dgst` в режим HMAC-SHA-256. В этом режиме обязателен `--key`: ключ задаётся hex-строкой и может иметь произвольную длину. Входной файл читается частями.

```bash
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt
```

Результат имеет стандартный формат:

```text
HMAC_VALUE  INPUT_FILE_PATH
```

Его можно записать в файл и затем проверить:

```bash
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --output message.hmac
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify message.hmac
```

При успешной проверке команда возвращает код `0`, при несовпадении — `1`. Сравнение выполняется константным по времени. Файл проверки может содержать имя файла после HMAC: при разборе используется первое поле.

HMAC строится по RFC 2104 как `H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ message))`. Длинный ключ сначала хешируется, короткий дополняется нулями до 64 байт. Секретный ключ защищает подлинность и целостность сообщения, но сам HMAC не шифрует данные. Реализация использует собственный SHA-256 проекта и проверяется векторами RFC 4231.

## AES-GCM и AAD

GCM объединяет шифрование и аутентификацию. AAD (associated data) не шифруется, но включается в проверку целостности. В CLI AAD передаётся как необязательная hex-строка; отсутствие `--aad` означает пустой AAD.

```bash
cryptocore --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --aad aabbccddeeff --input plain.txt --output cipher.gcm
cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --aad aabbccddeeff --input cipher.gcm --output decoded.txt
```

Формат файла GCM:

```text
<12 байт nonce><шифртекст><16 байт authentication tag>
```

Nonce по умолчанию генерируется заново для каждой операции. Для воспроизводимых тестовых векторов его можно указать явно:

```bash
cryptocore --algorithm aes --mode gcm --encrypt --key 00000000000000000000000000000000 --nonce 000000000000000000000000 --aad "" --input plain.bin --output cipher.gcm
```

Неверный AAD, изменённый шифртекст, nonce или тег вызывают полный отказ аутентификации: команда возвращает код `1` и не создаёт выходной файл с открытым текстом. Повторное использование одного nonce с тем же ключом GCM небезопасно.

Реализация `GCM` находится в `src/cryptocore/modes/gcm.py`: CTR-преобразование использует AES-примитив проекта, а GHASH содержит собственное умножение в `GF(2^128)` по многочлену `x^128 + x^7 + x^2 + x + 1`. Также в `src/cryptocore/aead/` доступна составная схема Encrypt-then-MAC. Она выводит разные ключи шифрования и MAC из master key, а тег HMAC проверяет до расшифрования.

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

Автоматические тесты совместимости запускаются вместе с остальными тестами, если команда `openssl` доступна в PATH. Проверить это можно так:

```powershell
openssl version
```

Если OpenSSL не установлен или не добавлен в PATH, эти тесты будут пропущены.

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

Если OpenSSL доступен в PATH, тесты совместимости с OpenSSL будут выполнены автоматически. Если системные команды `sha256sum` или аналоги недоступны, соответствующие системные тесты могут быть пропущены.
