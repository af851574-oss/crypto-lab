# coding: utf-8
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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

print("=" * 60)
print("ЛАБОРАТОРНАЯ РАБОТА ПО КРИПТОГРАФИИ")
print("Студентка: Анна Гришкина")
print("=" * 60)

# Функции для дополнения PKCS7
def pad(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

# ========== ЧАСТЬ 1. Симметричное шифрование ==========
print("\n[1] СИММЕТРИЧНОЕ ШИФРОВАНИЕ (AES-256-CBC)")

# Создаём файл
with open('secret.txt', 'w', encoding='utf-8') as f:
    f.write("Секретный текст для шифрования.\nВторая строка.\n")

# Генерируем ключ и IV
key = os.urandom(32)
iv = os.urandom(16)

with open('key.hex', 'w') as f:
    f.write(key.hex())
with open('iv.hex', 'w') as f:
    f.write(iv.hex())

print(f"  Ключ: {key.hex()[:32]}...")
print(f"  IV: {iv.hex()}")

# Шифрование
with open('secret.txt', 'rb') as f:
    plaintext = f.read()

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(pad(plaintext)) + encryptor.finalize()

with open('cipher.bin', 'wb') as f:
    f.write(ciphertext)
print("  Файл зашифрован -> cipher.bin")

# Расшифровка
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
decrypted = unpad(decrypted_padded)

with open('decrypted.txt', 'wb') as f:
    f.write(decrypted)
print("  Файл расшифрован -> decrypted.txt")

# Проверка
with open('secret.txt', 'rb') as f1, open('decrypted.txt', 'rb') as f2:
    if f1.read() == f2.read():
        print("  ✅ secret.txt и decrypted.txt совпадают!")
    else:
        print("  ❌ Ошибка!")

# ========== ЧАСТЬ 2. Асимметричное шифрование ==========
print("\n[2] АСИММЕТРИЧНОЕ ШИФРОВАНИЕ (RSA 2048)")

# Генерация ключей
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
print("  Ключи созданы: private.pem, public.pem")

# Шифрование короткого сообщения
message = b"RSA short message for encryption"
encrypted = public_key.encrypt(
    message,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
with open('secret.enc', 'wb') as f:
    f.write(encrypted)
print("  Сообщение зашифровано -> secret.enc")

# Расшифровка
decrypted = private_key.decrypt(
    encrypted,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
with open('secret.dec.txt', 'wb') as f:
    f.write(decrypted)
print("  Сообщение расшифровано -> secret.dec.txt")

if message == decrypted:
    print("  ✅ Исходный и расшифрованный файлы совпадают!")

# ========== ЧАСТЬ 3. Гибридное шифрование ==========
print("\n[3] ГИБРИДНОЕ ШИФРОВАНИЕ (RSA + AES)")

# Создаём большой файл (1 МБ для скорости, можно увеличить)
with open('bigdata.bin', 'wb') as f:
    f.write(os.urandom(1024 * 1024))  # 1 МБ
print("  Создан bigdata.bin (1 МБ)")

# Генерируем симметричный ключ
sym_key = os.urandom(32)
sym_iv = os.urandom(16)

with open('sym.key', 'wb') as f:
    f.write(sym_key)
with open('sym.iv', 'wb') as f:
    f.write(sym_iv)

# Шифруем большой файл симметрично
with open('bigdata.bin', 'rb') as f:
    big_data = f.read()

cipher = Cipher(algorithms.AES(sym_key), modes.CBC(sym_iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_big = encryptor.update(pad(big_data)) + encryptor.finalize()

with open('bigdata.enc', 'wb') as f:
    f.write(encrypted_big)
print("  Большой файл зашифрован -> bigdata.enc")

# Шифруем симметричный ключ RSA
encrypted_sym_key = public_key.encrypt(
    sym_key,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
with open('sym.key.enc', 'wb') as f:
    f.write(encrypted_sym_key)
print("  Симметричный ключ зашифрован RSA -> sym.key.enc")

# Расшифровка
decrypted_sym_key = private_key.decrypt(
    encrypted_sym_key,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

decryptor = cipher.decryptor()
decrypted_big_padded = decryptor.update(encrypted_big) + decryptor.finalize()
decrypted_big = unpad(decrypted_big_padded)

with open('bigdata.dec.bin', 'wb') as f:
    f.write(decrypted_big)
print("  Данные расшифрованы -> bigdata.dec.bin")

# Проверка
with open('bigdata.bin', 'rb') as f1, open('bigdata.dec.bin', 'rb') as f2:
    if f1.read() == f2.read():
        print("  ✅ bigdata.bin и bigdata.dec.bin совпадают!")

print("\n" + "=" * 60)
print("ЛАБОРАТОРНАЯ РАБОТА ВЫПОЛНЕНА УСПЕШНО!")
print("=" * 60)

# Список созданных файлов
print("\nСозданные файлы:")
for f in sorted(os.listdir('.')):
    if os.path.isfile(f):
        size = os.path.getsize(f)
        if size < 1024:
            print(f"  {f} ({size} байт)")
        elif size < 1024*1024:
            print(f"  {f} ({size/1024:.1f} КБ)")
        else:
            print(f"  {f} ({size/(1024*1024):.1f} МБ)")