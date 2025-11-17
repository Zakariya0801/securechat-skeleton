from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import hashlib

# RFC 3526 - 2048-bit MODP Group
DH_PARAMETERS = dh.DHParameterNumbers(
    p=0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
    g=2
).parameters(default_backend())

# Standard DH parameters for the protocol
DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
DH_G = 2

def generate_dh_keypair():
    """Generate DH private and public key"""
    private_key = DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_dh_private():
    """Generate random DH private exponent (a or b)"""
    import secrets
    # Generate random private exponent (256 bits for security)
    return secrets.randbits(256)

def compute_dh_public(g, p, private):
    """
    Compute DH public value: A = g^a mod p or B = g^b mod p
    """
    return pow(g, private, p)

def compute_dh_shared_secret(public, private, p):
    """
    Compute shared secret: Ks = B^a mod p = A^b mod p
    """
    return pow(public, private, p)

def derive_session_key(shared_secret):
    """
    Derive AES-128 session key from shared secret
    K = Trunc16(SHA256(big-endian(Ks)))
    Returns: 16-byte AES key
    """
    # Convert shared secret to big-endian bytes
    # Determine byte length needed
    byte_length = (shared_secret.bit_length() + 7) // 8
    ks_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
    
    # Compute SHA-256 hash
    hash_digest = hashlib.sha256(ks_bytes).digest()
    
    # Truncate to 16 bytes for AES-128
    return hash_digest[:16]

def serialize_public_key(public_key):
    """Serialize DH public key to bytes"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    """Deserialize DH public key from bytes"""
    return serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

def compute_shared_secret(private_key, peer_public_key):
    """Compute shared secret from DH exchange"""
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret

def derive_aes_key(shared_secret, salt=None):
    """Derive AES-128 key from shared secret using HKDF-SHA256"""
    if salt is None:
        salt = b''
    
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # 128 bits for AES-128
        salt=salt,
        info=b'handshake data',
        backend=default_backend()
    )
    key = kdf.derive(shared_secret)
    return key