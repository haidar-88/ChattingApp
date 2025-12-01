"""
rsa_utils.py - RSA encryption utility functions
Provides functions for generating, saving, loading, and using RSA keypairs
for secure key exchange in the chat application.
"""
import rsa
import base64


# -----------------------------------------------------------
# Generate RSA keypair
# -----------------------------------------------------------
def generate_rsa_keypair(bits=2048):
    """
    Generate a new RSA public/private keypair.
    
    Args:
        bits: Key size in bits (default 2048 for good security)
        
    Returns:
        Tuple of (private_key, public_key) RSA key objects
    """
    public_key, private_key = rsa.newkeys(bits)
    return private_key, public_key


# -----------------------------------------------------------
# Save keys to disk
# -----------------------------------------------------------
def save_private_key(path, private_key):
    """
    Save RSA private key to a file in PKCS#1 format.
    
    Args:
        path: File path where the key will be saved
        private_key: RSA private key object to save
    """
    with open(path, "wb") as f:
        f.write(private_key.save_pkcs1())

def save_public_key(path, public_key):
    """
    Save RSA public key to a file in PKCS#1 format.
    
    Args:
        path: File path where the key will be saved
        public_key: RSA public key object to save
    """
    with open(path, "wb") as f:
        f.write(public_key.save_pkcs1())

# -----------------------------------------------------------
# Load keys
# -----------------------------------------------------------
def load_private_key(path):
    """
    Load RSA private key from a file.
    
    Args:
        path: File path to load the key from
        
    Returns:
        RSA private key object
    """
    with open(path, "rb") as f:
        return rsa.PrivateKey.load_pkcs1(f.read())

def load_public_key(path):
    """
    Load RSA public key from a file.
    
    Args:
        path: File path to load the key from
        
    Returns:
        RSA public key object
    """
    with open(path, "rb") as f:
        return rsa.PublicKey.load_pkcs1(f.read())

# -----------------------------------------------------------
# Encrypt message with PUBLIC KEY
# -----------------------------------------------------------
def rsa_encrypt(public_key, message_bytes):
    """
    Encrypt data using RSA public key encryption.
    
    Args:
        public_key: RSA public key object
        message_bytes: Bytes to encrypt
        
    Returns:
        Base64-encoded encrypted bytes (safe for transmission over TCP/JSON)
    """
    encrypted = rsa.encrypt(message_bytes, public_key)
    return base64.b64encode(encrypted)  # safe to send over TCP/JSON

# -----------------------------------------------------------
# Decrypt message with PRIVATE KEY
# -----------------------------------------------------------
def rsa_decrypt(private_key, encrypted_b64):
    """
    Decrypt data using RSA private key decryption.
    
    Args:
        private_key: RSA private key object
        encrypted_b64: Base64-encoded encrypted bytes
        
    Returns:
        Decrypted bytes
    """
    encrypted = base64.b64decode(encrypted_b64)
    return rsa.decrypt(encrypted, private_key)

def load_key_for_server(public_key_bytes):
    """
    Load RSA public key from raw bytes (used by server).
    
    Args:
        public_key_bytes: Raw bytes of the public key in PKCS#1 format
        
    Returns:
        RSA public key object
    """
    return rsa.PublicKey.load_pkcs1(public_key_bytes)
