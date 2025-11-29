import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16

# Generate a 32-byte AES key (256-bit)
def generate_aes_key():
    return os.urandom(32)

def aes_encrypt(key, plaintext):
    iv = b'\x00'*16  # or a random 16-byte IV per message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE))

def aes_decrypt(key, ciphertext):
    iv = b'\x00'*16  # same IV as used in encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
