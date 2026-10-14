# Проверка CryptoCore

## Автоматические тесты

Основной набор тестов запускается командой:

```bash
python -m unittest discover -v
```

На Windows перед запуском тестов совместимости с OpenSSL может понадобиться добавить OpenSSL в `PATH` текущего терминала:

```powershell
$env:PATH = 'C:\Program Files\FireDaemon OpenSSL 4\bin;' + $env:PATH
python -m unittest discover -v
```

Последний прогон:

```text
Ran 36 tests
OK (skipped=1)
```

Пропущенный тест относится к системной команде `sha256sum`, которой обычно нет в Windows. Тесты совместимости с OpenSSL выполнялись и прошли.

## NIST STS

Для проверки CSPRNG был сгенерирован файл:

```text
nist_test_data.bin
```

Команда генерации:

```bash
python scripts/generate_nist_data.py
```

Параметры запуска NIST Statistical Test Suite:

- файл данных: `/mnt/c/Users/Lecoo/PycharmProjects/crypto_2/nist_test_data.bin`
- длина одной последовательности: `1000000` бит
- количество последовательностей: `80`
- формат входа: Binary
- выбран запуск всех статистических тестов

Итоговый отчёт сохранён в:

```text
NIST_REPORT.txt
```

В отчёте указан минимальный проходной порог:

- `76/80` для основных тестов;
- `44/47` для Random Excursions и Random Excursions Variant.

Полученные результаты соответствуют этим порогам. Небольшие отклонения отдельных последовательностей допустимы для статистических тестов.
