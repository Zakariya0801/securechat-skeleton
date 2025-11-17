"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def sign_data(private_key, data):
    """
    Sign data using RSA private key with SHA-256
    Returns: signature as bytes
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, data, signature):
    """
    Verify RSA signature using public key and SHA-256
    Returns: True if valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def compute_sha256(data):
    """
    Compute SHA-256 hash of data
    Returns: hash digest as bytes
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    if isinstance(data, str):
        data = data.encode('utf-8')
    digest.update(data)
    return digest.finalize()

def compute_sha256_hex(data):
    """
    Compute SHA-256 hash and return as hex string
    """
    return compute_sha256(data).hex()
