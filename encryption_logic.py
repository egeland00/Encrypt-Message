from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import re

# Constants
MIN_PASSWORD_LENGTH = 8
KDF_ITERATIONS = 100000

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

def encrypt_message(message, password):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    encryptor = cipher.encryptor()

    padded_data = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    
    return salt.hex() + iv.hex() + encrypted_message.hex()

def decrypt_message(message_with_salt_and_iv, password):
    salt = bytes.fromhex(message_with_salt_and_iv[:32])
    iv = bytes.fromhex(message_with_salt_and_iv[32:64])
    encrypted_message = message_with_salt_and_iv[64:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decryptor = cipher.decryptor()

    decrypted_message = decryptor.update(bytes.fromhex(encrypted_message)) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_message) + unpadder.finalize()

    return unpadded_data.decode()

def password_complexity_check(password):
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, "The private key must be at least 8 characters long."
    if not re.search("[a-z]", password):
        return False, "The private key must contain at least one lowercase letter."
    if not re.search("[A-Z]", password):
        return False, "The private key must contain at least one uppercase letter."
    if not re.search("[0-9]", password):
        return False, "The private key must contain at least one digit."
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "The private key must contain at least one special character."
    return True, ""
