import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def create_hello_message(cert_pem, nonce):
    """Create client hello message"""
    return {
        "type": "hello",
        "client_cert": cert_pem,
        "nonce": base64.b64encode(nonce).decode('utf-8')
    }

def create_server_hello_message(cert_pem, nonce):
    """Create server hello message"""
    return {
        "type": "server_hello",
        "server_cert": cert_pem,
        "nonce": base64.b64encode(nonce).decode('utf-8')
    }

def create_register_message(email, username, password, salt):
    """
    Create registration message with hashed password
    pwd = SHA256(salt || password)
    """
    # Hash password with salt
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(salt)
    digest.update(password.encode())
    pwd_hash = digest.finalize()
    
    return {
        "type": "register",
        "email": email,
        "username": username,
        "pwd": base64.b64encode(pwd_hash).decode('utf-8'),
        "salt": base64.b64encode(salt).decode('utf-8')
    }

def create_login_message(email, password, salt, nonce):
    """
    Create login message with hashed password
    pwd = SHA256(salt || password)
    """
    # Hash password with salt
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(salt)
    digest.update(password.encode())
    pwd_hash = digest.finalize()
    
    return {
        "type": "login",
        "email": email,
        "pwd": base64.b64encode(pwd_hash).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8')
    }

def create_dh_exchange_message(dh_public_key_bytes):
    """Create DH key exchange message"""
    return {
        "type": "dh_exchange",
        "public_key": base64.b64encode(dh_public_key_bytes).decode('utf-8')
    }

def create_dh_client_message(g, p, A):
    """
    Create DH client message with parameters
    { "type":"dh_client", "g": int, "p": int, "A": int }
    """
    return {
        "type": "dh_client",
        "g": g,
        "p": p,
        "A": A
    }

def create_dh_server_message(B):
    """
    Create DH server response message
    { "type":"dh_server", "B": int }
    """
    return {
        "type": "dh_server",
        "B": B
    }

def create_chat_message(seqno, timestamp, ciphertext_b64, signature_b64):
    """
    Create encrypted chat message with signature
    { "type":"msg", "seqno": n, "ts": unix_ms, "ct": base64, "sig": base64 }
    """
    return {
        "type": "msg",
        "seqno": seqno,
        "ts": timestamp,
        "ct": ciphertext_b64,
        "sig": signature_b64
    }

def create_receipt_message(peer, first_seq, last_seq, transcript_hash, signature_b64):
    """
    Create session receipt
    { "type":"receipt", "peer":"client|server", "first_seq":..., "last_seq":..., 
      "transcript_sha256":hex, "sig":base64 }
    """
    return {
        "type": "receipt",
        "peer": peer,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "transcript_sha256": transcript_hash,
        "sig": signature_b64
    }

def create_response_message(status, message, data=None):
    """Create generic response message"""
    response = {
        "type": "response",
        "status": status,
        "message": message
    }
    if data:
        response["data"] = data
    return response

def serialize_message(message):
    """Serialize message dictionary to JSON bytes"""
    return json.dumps(message).encode('utf-8')

def deserialize_message(message_bytes):
    """Deserialize JSON bytes to message dictionary"""
    return json.loads(message_bytes.decode('utf-8'))

def encrypt_message(message_dict, aes_key, aes_module):
    """Encrypt message using AES"""
    plaintext = serialize_message(message_dict)
    iv, ciphertext = aes_module.aes_encrypt(aes_key, plaintext)
    return {
        "encrypted": True,
        "iv": base64.b64encode(iv).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt_message(encrypted_dict, aes_key, aes_module):
    """Decrypt AES encrypted message"""
    iv = base64.b64decode(encrypted_dict["iv"])
    ciphertext = base64.b64decode(encrypted_dict["ciphertext"])
    plaintext = aes_module.aes_decrypt(aes_key, iv, ciphertext)
    return deserialize_message(plaintext)