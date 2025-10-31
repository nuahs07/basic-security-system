from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

# This function creates a strong encryption key from a user's password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000, # Standard number of iterations
        backend=default_backend()
    )
    # Return a URL-safe base64 encoded key
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# --- "Clocking" (Encryption) Function ---
def encrypt_data(data_to_encrypt: str, password: str) -> tuple[bytes, bytes]:
    """Encrypts data. Returns (encrypted_data_bytes, salt_bytes)"""
    salt = os.urandom(16) # Generate a new, random salt for every encryption
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(data_to_encrypt.encode())
    return encrypted_data, salt

# --- "Un-Clocking" (Decryption) Function ---
def decrypt_data(encrypted_data: bytes, password: str, salt: bytes) -> str:
    """Decrypts data. Returns the original string or None if failed."""
    try:
        key = derive_key(password, salt)
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode()
    except Exception as e:
        print(f"Decryption failed (likely wrong password): {e}")
        return None