import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16

# ===============================================================
# generate_aes_key()
# ---------------------------------------------------------------
# Returns:
#   • A random 32-byte (256-bit) AES key
#
# Notes:
#   • AES-256 requires a 32-byte key.
#   • os.urandom() provides cryptographically secure randomness.
# ===============================================================
def generate_aes_key():
    return os.urandom(32)

# ===============================================================
# aes_encrypt(key, plaintext)
# ---------------------------------------------------------------
# Params:
#   key       → 32-byte AES key
#   plaintext → raw bytes to encrypt
#
# Returns:
#   • Ciphertext (bytes) after AES-CBC encryption + PKCS7 padding
#
# Notes:
#   • Uses AES CBC mode.
#   • IV is currently 16 zero-bytes (must match decrypt).
#   • Padding ensures plaintext length is a multiple of 16 bytes.
# ===============================================================
def aes_encrypt(key, plaintext):
    iv = b'\x00'*16  # or a random 16-byte IV per message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE))

# ===============================================================
# aes_decrypt(key, ciphertext)
# ---------------------------------------------------------------
# Params:
#   key        → AES key used for encryption
#   ciphertext → encrypted bytes
#
# Returns:
#   • Decrypted plaintext (bytes), after unpadding
#
# Notes:
#   • Uses same static IV as encryption.
#   • unpad() removes PKCS7 padding applied earlier.
# ===============================================================
def aes_decrypt(key, ciphertext):
    iv = b'\x00'*16  # same IV as used in encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
