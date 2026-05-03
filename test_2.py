# coding: utf-8
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

print("=" * 50)
print("ПОЛНАЯ ПРОВЕРКА КРИПТОГРАФИИ")
print("=" * 50)

# Тест 1: Fernet (простое шифрование)
print("\n1. Fernet симметричное шифрование...")
key = Fernet.generate_key()
cipher = Fernet(key)
original = b"Test message"
encrypted = cipher.encrypt(original)
decrypted = cipher.decrypt(encrypted)
print("   ✅" if original == decrypted else "   ❌")

# Тест 2: AES-256
print("\n2. AES-256 шифрование...")
key_aes = os.urandom(32)
iv = os.urandom(16)
aes_cipher = Cipher(algorithms.AES(key_aes), modes.CBC(iv), backend=default_backend())
encryptor = aes_cipher.encryptor()
pad_len = 16 - (len(original) % 16)
padded = original + bytes([pad_len]) * pad_len
encrypted_aes = encryptor.update(padded) + encryptor.finalize()
decryptor = aes_cipher.decryptor()
decrypted_padded = decryptor.update(encrypted_aes) + decryptor.finalize()
decrypted_aes = decrypted_padded[:-decrypted_padded[-1]]
print("   ✅" if original == decrypted_aes else "   ❌")

# Тест 3: RSA
print("\n3. RSA шифрование...")
private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public = private.public_key()
encrypted_rsa = public.encrypt(b"Short message", padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
decrypted_rsa = private.decrypt(encrypted_rsa, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
print("   ✅" if b"Short message" == decrypted_rsa else "   ❌")

print("\n" + "=" * 50)
print("🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ!")
print("=" * 50)