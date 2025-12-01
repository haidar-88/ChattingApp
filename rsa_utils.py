# rsa_utils.py
import rsa
import base64


# -----------------------------------------------------------
# Generate RSA keypair
# -----------------------------------------------------------
def generate_rsa_keypair(bits=2048):
    public_key, private_key = rsa.newkeys(bits)
    return private_key, public_key


# -----------------------------------------------------------
# Save keys to disk
# -----------------------------------------------------------
def save_private_key(path, private_key):
    with open(path, "wb") as f:
        f.write(private_key.save_pkcs1())

def save_public_key(path, public_key):
    with open(path, "wb") as f:
        f.write(public_key.save_pkcs1())

# -----------------------------------------------------------
# Load keys
# -----------------------------------------------------------
def load_private_key(path):
    with open(path, "rb") as f:
        return rsa.PrivateKey.load_pkcs1(f.read())

def load_public_key(path):
    with open(path, "rb") as f:
        return rsa.PublicKey.load_pkcs1(f.read())

# -----------------------------------------------------------
# Encrypt message with PUBLIC KEY
# -----------------------------------------------------------
def rsa_encrypt(public_key, message_bytes):
    encrypted = rsa.encrypt(message_bytes, public_key)
    return base64.b64encode(encrypted)  # safe to send over TCP/JSON

# -----------------------------------------------------------
# Decrypt message with PRIVATE KEY
# -----------------------------------------------------------
def rsa_decrypt(private_key, encrypted_b64):
    encrypted = base64.b64decode(encrypted_b64)
    return rsa.decrypt(encrypted, private_key)

def load_key_for_server(public_key_bytes):
    return rsa.PublicKey.load_pkcs1(public_key_bytes)