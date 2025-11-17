import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_nonce(length=32):
    """Generate cryptographic nonce"""
    return os.urandom(length)

def generate_salt(length=16):
    """Generate salt for password hashing"""
    return os.urandom(length)

def hash_password(password, salt):
    """Hash password with salt using SHA-256"""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(salt)
    digest.update(password.encode())
    return digest.finalize()

def verify_password_hash(password, salt, expected_hash):
    """Verify password against stored hash"""
    computed_hash = hash_password(password, salt)
    return computed_hash == expected_hash

def send_message(sock, message_bytes):
    """Send message with length prefix"""
    # Send 4-byte length prefix
    length = len(message_bytes)
    sock.sendall(length.to_bytes(4, byteorder='big'))
    # Send actual message
    sock.sendall(message_bytes)

def receive_message(sock):
    """Receive message with length prefix"""
    # Receive 4-byte length prefix
    length_bytes = sock.recv(4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, byteorder='big')
    
    # Receive actual message
    chunks = []
    bytes_received = 0
    while bytes_received < length:
        chunk = sock.recv(min(length - bytes_received, 4096))
        if not chunk:
            raise ConnectionError("Connection closed while receiving message")
        chunks.append(chunk)
        bytes_received += len(chunk)
    
    return b''.join(chunks)