"""
aes_utils.py - AES symmetric encryption utility functions
Provides functions for generating AES keys and encrypting/decrypting messages
using AES-256 in CBC mode. Used for fast symmetric encryption of chat messages.
"""
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES block size in bytes (16 bytes = 128 bits)
BLOCK_SIZE = 16

def generate_aes_key():
    """
    Generate a random 32-byte (256-bit) AES key for symmetric encryption.
    
    Returns:
        32-byte random key as bytes
    """
    return os.urandom(32)

def aes_encrypt(key, plaintext):
    """
    Encrypt plaintext using AES-256 in CBC mode.
    
    Args:
        key: 32-byte AES key
        plaintext: Plain text bytes to encrypt
        
    Returns:
        Encrypted ciphertext bytes (padded to block size)
    """
    # Note: Using zero IV for simplicity. In production, use random IV per message.
    iv = b'\x00'*16  # Initialization vector (16 bytes)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE))

def aes_decrypt(key, ciphertext):
    """
    Decrypt ciphertext using AES-256 in CBC mode.
    
    Args:
        key: 32-byte AES key (must match encryption key)
        ciphertext: Encrypted bytes to decrypt
        
    Returns:
        Decrypted plaintext bytes (padding removed)
    """
    # Must use same IV as encryption
    iv = b'\x00'*16  # Same IV as used in encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

