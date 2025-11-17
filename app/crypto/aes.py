from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def generate_aes_key():
    """Generate random 128-bit AES key"""
    return os.urandom(16)  # 128 bits = 16 bytes

def generate_iv():
    """Generate random 128-bit IV for AES-CBC"""
    return os.urandom(16)

def aes_encrypt(key, plaintext):
    """
    Encrypt plaintext using AES-128-CBC
    Returns: (iv, ciphertext) as bytes
    """
    # Generate random IV
    iv = generate_iv()
    
    # Apply PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode() if isinstance(plaintext, str) else plaintext)
    padded_data += padder.finalize()
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv, ciphertext

def aes_decrypt(key, iv, ciphertext):
    """
    Decrypt ciphertext using AES-128-CBC
    Returns: plaintext as bytes
    """
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext