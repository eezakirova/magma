# -*- coding: utf-8 -*-
import sys

# ==========================================================
# ПАРАМЕТРЫ АЛГОРИТМА
# ==========================================================

BLOCK_LEN = 8   # 64 бита
KEY_LEN = 32    # 256 бит

# ==========================================================
# S-БЛОКИ ГОСТ Р 34.12-2015 (Магма)
# ==========================================================

S_BOXES = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]
]

# ==========================================================
# РАБОТА С ФАЙЛАМИ
# ==========================================================

def read_plain_text(path):
    """Читает текстовый файл."""
    with open(path, "r", encoding="utf-8") as file:
        return file.read()

def print_text_file(title, path):
    """Выводит содержимое файла в консоль."""
    text = read_plain_text(path)
    print(f"{title} ({path}):")
    print(text if text else "[пустой файл]")
    print()

def hex_file_to_bytes(path):
    """Считывает hex-строку из файла и переводит в байты."""
    text = read_plain_text(path)
    hex_string = "".join(text.split())

    if not hex_string:
        return b""

    if len(hex_string) % 2 != 0:
        raise ValueError("Hex-строка должна содержать четное число символов.")

    return bytes.fromhex(hex_string)

def bytes_to_hex_file(path, data):
    """Сохраняет байты в файл как hex."""
    with open(path, "w", encoding="utf-8") as file:
        file.write(data.hex())

# ==========================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==========================================================

def bytes_xor(left, right):
    """XOR двух байтовых строк одинаковой длины."""
    return bytes(a ^ b for a, b in zip(left, right))

def apply_padding(data):
    """
    Добавляет PKCS#7 padding только если длина не кратна 8 байтам.
    Для контрольного примера ГОСТ padding не добавляется.
    """
    if len(data) % BLOCK_LEN == 0:
        return data

    pad = BLOCK_LEN - (len(data) % BLOCK_LEN)
    return data + bytes([pad] * pad)

def remove_padding(data):
    """Удаляет PKCS#7 padding, если он корректен."""
    if not data:
        return data

    pad = data[-1]

    if pad < 1 or pad > BLOCK_LEN:
        return data

    if data[-pad:] == bytes([pad] * pad):
        return data[:-pad]

    return data

# ==========================================================
# ОСНОВНЫЕ КРИПТОГРАФИЧЕСКИЕ ОПЕРАЦИИ
# ==========================================================

def rotate_11_bits(value):
    """Циклический сдвиг 32-битного числа влево на 11 бит."""
    return ((value << 11) | (value >> 21)) & 0xFFFFFFFF

def substitute_by_sboxes(value):
    """
    Подстановка по S-блокам.
    Обрабатываются 8 четырёхбитных полубайтов.
    """
    output = 0

    for i in range(8):
        part = (value >> (4 * i)) & 0xF
        replaced = S_BOXES[i][part]
        output |= replaced << (4 * i)

    return output

def magma_round_function(value, round_key):
    """
    Раундовая функция g[k](a):
    1) сложение по модулю 2^32
    2) подстановка S-блоками
    3) циклический сдвиг влево на 11 бит
    """
    temp = (value + round_key) & 0xFFFFFFFF
    temp = substitute_by_sboxes(temp)
    temp = rotate_11_bits(temp)
    return temp

# ==========================================================
# РАБОТА С БЛОКАМИ
# ==========================================================

def split_block(block):
    """Разделяет 8-байтный блок на две 32-битные половины."""
    left = int.from_bytes(block[:4], byteorder="big")
    right = int.from_bytes(block[4:], byteorder="big")
    return left, right

def merge_block(left, right):
    """Объединяет две 32-битные половины в 8-байтный блок."""
    return left.to_bytes(4, byteorder="big") + right.to_bytes(4, byteorder="big")

# ==========================================================
# ГЕНЕРАЦИЯ РАУНДОВЫХ КЛЮЧЕЙ
# ==========================================================

def prepare_round_keys(key):
    """
    Формирует 32 раундовых ключа:
    K1..K8 повторяются 3 раза, затем K8..K1.
    """
    if len(key) != KEY_LEN:
        raise ValueError("Ключ должен быть длиной 32 байта (64 hex-символа).")

    parts = [int.from_bytes(key[i:i + 4], byteorder="big") for i in range(0, KEY_LEN, 4)]
    return parts * 3 + parts[::-1]

# ==========================================================
# ШИФРОВАНИЕ / РАСШИФРОВАНИЕ ОДНОГО БЛОКА
# ==========================================================

def encrypt_block(block, round_keys):
    """
    Шифрование одного блока по ГОСТ Магма:
    EK1..K32(a) = G*[K32]G[K31]...G[K1](a1, a0)
    """
    a1, a0 = split_block(block)

    for i in range(31):
        a1, a0 = a0, magma_round_function(a0, round_keys[i]) ^ a1

    return merge_block(magma_round_function(a0, round_keys[31]) ^ a1, a0)

def decrypt_block(block, round_keys):
    """
    Расшифрование одного блока по ГОСТ Магма:
    DK1..K32(b) = G*[K1]G[K2]...G[K32](b1, b0)
    """
    rk = list(reversed(round_keys))
    a1, a0 = split_block(block)

    for i in range(31):
        a1, a0 = a0, magma_round_function(a0, rk[i]) ^ a1

    return merge_block(magma_round_function(a0, rk[31]) ^ a1, a0)

# ==========================================================
# РЕЖИМ ECB
# ==========================================================

def encrypt_ecb(data, round_keys):
    """Шифрование в режиме ECB."""
    result = bytearray()

    for i in range(0, len(data), BLOCK_LEN):
        block = data[i:i + BLOCK_LEN]
        result.extend(encrypt_block(block, round_keys))

    return bytes(result)

def decrypt_ecb(data, round_keys):
    """Расшифрование в режиме ECB."""
    result = bytearray()

    for i in range(0, len(data), BLOCK_LEN):
        block = data[i:i + BLOCK_LEN]
        result.extend(decrypt_block(block, round_keys))

    return bytes(result)

# ==========================================================
# РЕЖИМ CBC
# ==========================================================

def encrypt_cbc(data, round_keys, iv):
    """Шифрование в режиме CBC."""
    if len(iv) != BLOCK_LEN:
        raise ValueError("IV для режима CBC должен быть длиной 8 байт (16 hex-символов).")

    result = bytearray()
    previous = iv

    for i in range(0, len(data), BLOCK_LEN):
        block = data[i:i + BLOCK_LEN]
        mixed = bytes_xor(block, previous)
        encrypted = encrypt_block(mixed, round_keys)
        result.extend(encrypted)
        previous = encrypted

    return bytes(result)

def decrypt_cbc(data, round_keys, iv):
    """Расшифрование в режиме CBC."""
    if len(iv) != BLOCK_LEN:
        raise ValueError("IV для режима CBC должен быть длиной 8 байт (16 hex-символов).")

    result = bytearray()
    previous = iv

    for i in range(0, len(data), BLOCK_LEN):
        block = data[i:i + BLOCK_LEN]
        decrypted = decrypt_block(block, round_keys)
        plain = bytes_xor(decrypted, previous)
        result.extend(plain)
        previous = block

    return bytes(result)

# ==========================================================
# ПРОВЕРКИ
# ==========================================================

def check_key(key_hex):
    """Проверяет корректность ключа."""
    if len(key_hex) != 64:
        raise ValueError("Ключ должен содержать 64 hex-символа.")
    bytes.fromhex(key_hex)

def check_iv(iv_hex):
    """Проверяет корректность IV для CBC."""
    if len(iv_hex) != 16:
        raise ValueError("IV должен содержать 16 hex-символов.")
    bytes.fromhex(iv_hex)

# ==========================================================
# СПРАВКА
# ==========================================================

def print_help():
    """Показывает, как правильно запускать программу."""
    print()
    print("Использование:")
    print("  python magma.py encrypt <mode> <input_file> <output_file> <key_hex> [iv_hex]")
    print("  python magma.py decrypt <mode> <input_file> <output_file> <key_hex> [iv_hex]")
    print()
    print("Где:")
    print("  encrypt     - режим шифрования")
    print("  decrypt     - режим расшифрования")
    print("  mode        - ecb или cbc")
    print("  input_file  - текстовый файл с hex-данными")
    print("  output_file - файл для записи результата")
    print("  key_hex     - ключ длиной 64 hex-символа")
    print("  iv_hex      - IV для CBC, 16 hex-символов")
    print()

# ==========================================================
# ГЛАВНАЯ ФУНКЦИЯ
# ==========================================================

def main():
    if len(sys.argv) < 6:
        print("Ошибка: недостаточно аргументов.")
        print_help()
        return

    action = sys.argv[1].lower()
    mode = sys.argv[2].lower()
    input_file = sys.argv[3]
    output_file = sys.argv[4]
    key_hex = sys.argv[5]
    iv_hex = sys.argv[6] if len(sys.argv) == 7 else None

    try:
        if action not in ("encrypt", "decrypt"):
            raise ValueError("Первый аргумент должен быть encrypt или decrypt.")

        if mode not in ("ecb", "cbc"):
            raise ValueError("Режим должен быть 'ecb' или 'cbc'.")

        check_key(key_hex)

        if mode == "cbc":
            if iv_hex is None:
                raise ValueError("Для режима CBC необходимо указать IV.")
            check_iv(iv_hex)

        if mode == "ecb" and iv_hex is not None:
            print("Внимание: IV игнорируется в режиме ECB.")

        print("=" * 60)
        print_text_file("Входной файл", input_file)

        input_data = hex_file_to_bytes(input_file)

        round_keys = prepare_round_keys(bytes.fromhex(key_hex))

        if action == "encrypt":
            print(f"Режим: ЗАШИФРОВАНИЕ ({mode.upper()})")
            print()

            prepared_data = apply_padding(input_data)

            if mode == "ecb":
                result = encrypt_ecb(prepared_data, round_keys)
            else:
                iv = bytes.fromhex(iv_hex)
                result = encrypt_cbc(prepared_data, round_keys, iv)

        else:
            print(f"Режим: РАСШИФРОВАНИЕ ({mode.upper()})")
            print()

            if len(input_data) % BLOCK_LEN != 0:
                raise ValueError("Длина зашифрованных данных должна быть кратна 8 байтам.")

            if mode == "ecb":
                result = decrypt_ecb(input_data, round_keys)
            else:
                iv = bytes.fromhex(iv_hex)
                result = decrypt_cbc(input_data, round_keys, iv)

            result = remove_padding(result)

        bytes_to_hex_file(output_file, result)

        print_text_file("Выходной файл", output_file)
        print("Операция выполнена успешно.")
        print("=" * 60)

    except Exception as error:
        print("Ошибка:", error)

if __name__ == "__main__":
    main()