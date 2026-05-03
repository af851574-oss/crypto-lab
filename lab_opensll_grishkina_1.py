"""
Лабораторная работа по шифрованию данных
Выполняет студент: Анна Гришкина
Группа: БасБ252

Программа демонстрирует:
1. Симметричное шифрование (AES-256-CBC)
2. Асимметричное шифрование (RSA 2048)
3. Гибридное шифрование (RSA + AES)
"""

import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Цвета для красивого вывода в консоли (работает в Windows и Mac/Linux)
class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    """Печатает красивый заголовок"""
    print("\n" + "=" * 60)
    print(f"{Colors.BOLD}{Colors.BLUE}{text:^60}{Colors.RESET}")
    print("=" * 60)

def print_success(text):
    """Печатает сообщение об успехе"""
    print(f"{Colors.GREEN}✅ {text}{Colors.RESET}")

def print_info(text):
    """Печатает информационное сообщение"""
    print(f"{Colors.BLUE}📌 {text}{Colors.RESET}")

def print_warning(text):
    """Печатает предупреждение"""
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.RESET}")

def print_step(step_num, text):
    """Печатает шаг выполнения"""
    print(f"\n{Colors.BOLD}🔹 Шаг {step_num}:{Colors.RESET} {text}")

def wait_for_user():
    """Ждёт нажатия Enter (чтобы можно было читать вывод)"""
    input(f"\n{Colors.YELLOW}Нажмите Enter, чтобы продолжить...{Colors.RESET}")

# ============================================================
# ВСТУПЛЕНИЕ
# ============================================================
print_header("ЛАБОРАТОРНАЯ РАБОТА ПО ШИФРОВАНИЮ ДАННЫХ")
print(f"""
{Colors.BOLD}Добро пожаловать!{Colors.RESET}

Эта программа покажет вам, как работают разные виды шифрования:
  🔐 Симметричное шифрование — один ключ и для шифрования, и для расшифровки
  🔑 Асимметричное шифрование — публичный и приватный ключи
  🧬 Гибридное шифрование — комбинация обоих методов

Давайте начнём!
""")

wait_for_user()

# ============================================================
# ЧАСТЬ 1. Симметричное шифрование
# ============================================================
print_header("ЧАСТЬ 1. СИММЕТРИЧНОЕ ШИФРОВАНИЕ (AES-256-CBC)")
print_info("""
Что происходит?
- Мы создаём простой текстовый файл
- Генерируем случайный ключ (256 бит) и вектор инициализации (128 бит)
- Шифруем файл с помощью AES-256-CBC
- Расшифровываем и проверяем, что данные не изменились

Плюсы: быстро работает с большими файлами
Минусы: нужно безопасно передать клюдругому человеку
""")

# Функции для дополнения данных (PKCS7)
def pad(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

# Шаг 1.1: Создаём файл
print_step("1.1", "Создаём текстовый файл secret.txt")
with open('secret.txt', 'w', encoding='utf-8') as f:
    f.write("Это секретный текст для шифрования.\n")
    f.write("Вторая строка важной информации.\n")
    f.write("Третья строка для наглядности.\n")
print_success("Файл secret.txt создан")

# Шаг 1.2: Генерируем ключ и IV
print_step("1.2", "Генерируем случайный ключ и вектор инициализации (IV)")
key = os.urandom(32)   # 256 бит
iv = os.urandom(16)    # 128 бит

with open('key.hex', 'w') as f:
    f.write(key.hex())
with open('iv.hex', 'w') as f:
    f.write(iv.hex())

print_success(f"Ключ (первые 32 символа): {key.hex()[:32]}... (всего 64 символа)")
print_success(f"IV: {iv.hex()}")
print_info("Ключ и IV сохранены в файлах key.hex и iv.hex")

# Шаг 1.3: Шифруем
print_step("1.3", "Шифруем файл алгоритмом AES-256-CBC")
with open('secret.txt', 'rb') as f:
    plaintext = f.read()

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
padded_plaintext = pad(plaintext)
ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

with open('cipher.bin', 'wb') as f:
    f.write(ciphertext)

print_success(f"Файл зашифрован → cipher.bin (размер: {len(ciphertext)} байт)")
print_info("Исходный файл был дополнен до размера, кратного 16 байтам")

# Шаг 1.4: Расшифровываем
print_step("1.4", "Расшифровываем файл и проверяем целостность")
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
decrypted = unpad(decrypted_padded)

with open('decrypted.txt', 'wb') as f:
    f.write(decrypted)

print_success("Файл расшифрован → decrypted.txt")

# Проверка
with open('secret.txt', 'rb') as f1, open('decrypted.txt', 'rb') as f2:
    if f1.read() == f2.read():
        print_success("✅ Проверка пройдена! secret.txt и decrypted.txt совпадают")
    else:
        print_warning("Файлы не совпадают! Что-то пошло не так")

wait_for_user()

# ============================================================
# ЧАСТЬ 2. Асимметричное шифрование
# ============================================================
print_header("ЧАСТЬ 2. АСИММЕТРИЧНОЕ ШИФРОВАНИЕ (RSA 2048)")
print_info("""
Что происходит?
- Мы генерируем пару ключей: приватный (секретный) и публичный (можно делиться)
- Создаём короткое сообщение (RSA не может шифровать большие данные)
- Шифруем публичным ключом — только владелец приватного ключа сможет прочитать
- Расшифровываем приватным ключом

Плюсы: можно передавать публичный ключ по незащищённому каналу
Минусы: работает медленно, нельзя шифровать большие объёмы данных
""")

# Шаг 2.1: Генерация ключей
print_step("2.1", "Генерируем пару RSA-ключей (2048 бит)")
print_info("Это может занять несколько секунд...")

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

with open('private.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open('public.pem', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print_success("Приватный ключ сохранён → private.pem (НИКОМУ НЕ ПОКАЗЫВАТЬ!)")
print_success("Публичный ключ сохранён → public.pem (можно отправить кому угодно)")

# Шаг 2.2: Создаём сообщение
print_step("2.2", "Создаём короткое сообщение для шифрования")
message = b"RSA 2048 может зашифровать только сообщение до 190 байт. Это сообщение как раз подходит!"
with open('secret_rsa.txt', 'wb') as f:
    f.write(message)

print_success(f"Сообщение: {message[:50].decode()}...")
print_info(f"Размер сообщения: {len(message)} байт (максимум 190 для RSA 2048)")

# Шаг 2.3: Шифрование публичным ключом
print_step("2.3", "Шифруем сообщение ПУБЛИЧНЫМ ключом")
encrypted = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
with open('secret.enc', 'wb') as f:
    f.write(encrypted)

print_success(f"Сообщение зашифровано → secret.enc (размер: {len(encrypted)} байт)")

# Шаг 2.4: Расшифровка приватным ключом
print_step("2.4", "Расшифровываем сообщение ПРИВАТНЫМ ключом")
decrypted = private_key.decrypt(
    encrypted,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
with open('secret.dec.txt', 'wb') as f:
    f.write(decrypted)

print_success("Сообщение расшифровано → secret.dec.txt")

# Проверка
if message == decrypted:
    print_success("✅ Проверка пройдена! secret_rsa.txt и secret.dec.txt совпадают")
else:
    print_warning("Файлы не совпадают!")

wait_for_user()

# ============================================================
# ЧАСТЬ 3. Гибридное шифрование
# ============================================================
print_header("ЧАСТЬ 3. ГИБРИДНОЕ ШИФРОВАНИЕ (RSA + AES)")
print_info("""
Что происходит?
Гибридное шифрование объединяет лучшее из двух миров:
  1. Генерируем случайный симметричный ключ (AES, 256 бит)
  2. Шифруем БОЛЬШОЙ файл этим симметричным ключом (быстро!)
  3. Шифруем сам симметричный ключ RSA-ключом (безопасно!)
  
В результате:
  - Получатель расшифровывает симметричный ключ своим RSA-ключом
  - Затем расшифровывает большой файл симметричным ключом
  
Именно так работает HTTPS, PGP, шифрованные мессенджеры!
""")

# Шаг 3.1: Создаём большой файл
print_step("3.1", "Создаём большой файл для шифрования")
big_size = 10 * 1024 * 1024  # 10 МБ
print_info(f"Создаём файл размером {big_size // (1024*1024)} МБ...")
with open('bigdata.bin', 'wb') as f:
    f.write(os.urandom(big_size))

print_success("bigdata.bin создан (10 МБ случайных данных)")

# Шаг 3.2: Генерируем симметричный ключ
print_step("3.2", "Генерируем случайный симметричный ключ (AES-256)")
sym_key = os.urandom(32)
sym_iv = os.urandom(16)

with open('sym.key', 'wb') as f:
    f.write(sym_key)
with open('sym.iv', 'wb') as f:
    f.write(sym_iv)

print_success(f"Симметричный ключ: {sym_key.hex()[:32]}...")
print_success(f"IV: {sym_iv.hex()[:32]}...")

# Шаг 3.3: Шифруем большой файл симметрично
print_step("3.3", "Шифруем большой файл симметричным ключом (AES-256-CBC)")
with open('bigdata.bin', 'rb') as f:
    big_plaintext = f.read()

cipher = Cipher(algorithms.AES(sym_key), modes.CBC(sym_iv), backend=default_backend())
encryptor = cipher.encryptor()
padded_big = pad(big_plaintext)
big_ciphertext = encryptor.update(padded_big) + encryptor.finalize()

with open('bigdata.enc', 'wb') as f:
    f.write(big_ciphertext)

print_success(f"Большой файл зашифрован → bigdata.enc (размер: {len(big_ciphertext)} байт)")

# Шаг 3.4: Шифруем симметричный ключ RSA
print_step("3.4", "Шифруем симметричный ключ ПУБЛИЧНЫМ RSA-ключом")
encrypted_sym_key = public_key.encrypt(
    sym_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
with open('sym.key.enc', 'wb') as f:
    f.write(encrypted_sym_key)

print_success(f"Симметричный ключ зашифрован → sym.key.enc (размер: {len(encrypted_sym_key)} байт)")
print_info("Теперь у нас есть два файла: bigdata.enc (зашифрованные данные) и sym.key.enc (зашифрованный ключ)")

# Шаг 3.5: Расшифровка
print_step("3.5", "РАСШИФРОВКА (получатель данных)")

# a) Расшифровываем симметричный ключ
print_info("a) Расшифровываем симметричный ключ ПРИВАТНЫМ RSA-ключом")
decrypted_sym_key = private_key.decrypt(
    encrypted_sym_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print_success("Симметричный ключ расшифрован")

# b) Расшифровываем данные
print_info("б) Расшифровываем большой файл симметричным ключом")
cipher = Cipher(algorithms.AES(decrypted_sym_key), modes.CBC(sym_iv), backend=default_backend())
decryptor = cipher.decryptor()
decrypted_padded_big = decryptor.update(big_ciphertext) + decryptor.finalize()
decrypted_big = unpad(decrypted_padded_big)

with open('bigdata.dec.bin', 'wb') as f:
    f.write(decrypted_big)

print_success("Большой файл расшифрован → bigdata.dec.bin")

# Проверка
print_step("3.6", "Проверяем целостность данных")
with open('bigdata.bin', 'rb') as f1, open('bigdata.dec.bin', 'rb') as f2:
    if f1.read() == f2.read():
        print_success("✅ Проверка пройдена! bigdata.bin и bigdata.dec.bin совпадают")
    else:
        print_warning("Файлы не совпадают!")

# ============================================================
# ФИНАЛ
# ============================================================
print_header("ЛАБОРАТОРНАЯ РАБОТА ВЫПОЛНЕНА УСПЕШНО!")

print(f"""
{Colors.BOLD}Итоги:{Colors.RESET}

✅ Симметричное шифрование (AES-256-CBC):
   - Зашифрован и расшифрован файл secret.txt
   - Ключ и IV сохранены в key.hex и iv.hex

✅ Асимметричное шифрование (RSA 2048):
   - Сгенерирована пара ключей (private.pem, public.pem)
   - Сообщение зашифровано публичным и расшифровано приватным ключом

✅ Гибридное шифрование (RSA + AES):
   - Большой файл (10 МБ) зашифрован симметрично
   - Симметричный ключ зашифрован RSA
   - Успешно расшифровано!

{Colors.BOLD}Созданные файлы:{Colors.RESET}
""")

# Выводим список всех созданных файлов
files = []
for f in os.listdir('.'):
    if os.path.isfile(f) and any(f.endswith(ext) for ext in ('.txt', '.bin', '.enc', '.pem', '.key', '.hex', '.iv')):
        size = os.path.getsize(f)
        if size < 1024:
            size_str = f"{size} байт"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.1f} КБ"
        else:
            size_str = f"{size / (1024 * 1024):.1f} МБ"
        files.append(f"   • {f:25} ({size_str:>8})")

for f in sorted(files):
    print(f)

print(f"""
{Colors.BOLD}Отчёт готов!{Colors.RESET}
Вы можете сделать скриншоты этого окна и список файлов в папке проекта.
""")

input(f"\n{Colors.GREEN}Нажмите Enter, чтобы завершить...{Colors.RESET}")