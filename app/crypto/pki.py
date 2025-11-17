from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import datetime
import os

def load_certificate(cert_path):
    """Load X.509 certificate from PEM file"""
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert

def load_private_key(key_path, password=None):
    """Load private key from PEM file"""
    with open(key_path, 'rb') as f:
        key_data = f.read()
        key = serialization.load_pem_private_key(
            key_data,
            password=password,
            backend=default_backend()
        )
    return key

def load_ca_certificate(ca_cert_path):
    """Load CA certificate for verification"""
    return load_certificate(ca_cert_path)

def verify_certificate(cert, ca_cert):
    """
    Verify certificate against CA certificate
    Returns True if valid, False otherwise
    """
    try:
        # Check if certificate is expired
        now = datetime.datetime.utcnow()
        if now < cert.not_valid_before or now > cert.not_valid_after:
            return False
        
        # Verify signature using CA's public key
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return True
    except Exception as e:
        print(f"Certificate verification failed: {e}")
        return False

def get_certificate_pem(cert):
    """Convert certificate to PEM format string"""
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def parse_certificate_pem(pem_str):
    """Parse PEM string to certificate object"""
    cert = x509.load_pem_x509_certificate(pem_str.encode('utf-8'), default_backend())
    return cert

def get_subject_common_name(cert):
    """Extract common name from certificate subject"""
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        return cn
    except:
        return None

def generate_key_pair():
    """Generate RSA key pair for certificate"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def save_private_key(private_key, key_path, password=None):
    """Save private key to file"""
    encryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    
    with open(key_path, 'wb') as f:
        f.write(key_pem)