# rsa_utils.py
import rsa
import base64


# -----------------------------------------------------------
# Generate RSA keypair
# -----------------------------------------------------------
def generate_rsa_keypair(bits=2048):
    """
    Generates a new RSA keypair.
    
    Args:
        bits (int): Key size (2048-bit recommended for security)

    Returns:
        (private_key, public_key): Tuple of RSA key objects
    """
    public_key, private_key = rsa.newkeys(bits)
    return private_key, public_key


# -----------------------------------------------------------
# Save keys to disk
# -----------------------------------------------------------
def save_private_key(path, private_key):
    """
    Saves a private key in PKCS#1 format to the specified file.
    """
    with open(path, "wb") as f:
        f.write(private_key.save_pkcs1())

def save_public_key(path, public_key):
    """
    Saves a public key in PKCS#1 format to the specified file.
    """
    with open(path, "wb") as f:
        f.write(public_key.save_pkcs1())

# -----------------------------------------------------------
# Load keys
# -----------------------------------------------------------
def load_private_key(path):
    """
    Loads a private key from a PKCS#1 formatted file.
    """
    with open(path, "rb") as f:
        return rsa.PrivateKey.load_pkcs1(f.read())

def load_public_key(path):
    """
    Loads a public key from a PKCS#1 formatted file.
    """
    with open(path, "rb") as f:
        return rsa.PublicKey.load_pkcs1(f.read())

# -----------------------------------------------------------
# Encrypt message with PUBLIC KEY
# -----------------------------------------------------------
def rsa_encrypt(public_key, message_bytes):
    """
    Encrypts raw bytes using an RSA public key.

    Args:
        public_key: rsa.PublicKey object
        message_bytes (bytes): plaintext to encrypt

    Returns:
        Base64-encoded encrypted ciphertext (bytes)
    """
    encrypted = rsa.encrypt(message_bytes, public_key)
    return base64.b64encode(encrypted)  # safe to send over TCP/JSON

# -----------------------------------------------------------
# Decrypt message with PRIVATE KEY
# -----------------------------------------------------------
def rsa_decrypt(private_key, encrypted_b64):
    """
    Decrypts a base64-encoded RSA ciphertext using a private key.

    Args:
        private_key: rsa.PrivateKey object
        encrypted_b64 (bytes): base64-encoded ciphertext

    Returns:
        Decrypted plaintext (bytes)
    """
    encrypted = base64.b64decode(encrypted_b64)
    return rsa.decrypt(encrypted, private_key)

# -----------------------------------------------------------
# Helper for loading a public key received from server
# (server sends the raw PKCS#1 bytes)
# -----------------------------------------------------------
def load_key_for_server(public_key_bytes):
    """
    Load a public key directly from PKCS#1 bytes received from server.

    Args:
        public_key_bytes (bytes): raw public key data

    Returns:
        rsa.PublicKey object
    """
    return rsa.PublicKey.load_pkcs1(public_key_bytes)