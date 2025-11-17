"""Create Root CA (RSA + self-signed X.509) using cryptography."""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import os

def generate_ca(ca_name="SecureChat Root CA", output_dir="certs"):
    """
    Generate self-signed root CA
    Creates:
    - ca_key.pem: CA private key
    - ca_cert.pem: CA self-signed certificate
    """
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    print("[*] Generating CA private key (2048-bit RSA)...")
    # Generate CA private key
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Save CA private key
    ca_key_path = os.path.join(output_dir, "ca_key.pem")
    with open(ca_key_path, 'wb') as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[+] CA private key saved to: {ca_key_path}")
    
    # Create CA certificate subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])
    
    print("[*] Creating self-signed CA certificate...")
    # Build CA certificate (self-signed)
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Valid for 10 years
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())
    
    # Save CA certificate
    ca_cert_path = os.path.join(output_dir, "ca_cert.pem")
    with open(ca_cert_path, 'wb') as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] CA certificate saved to: {ca_cert_path}")
    
    print("\n[+] Root CA created successfully!")
    print(f"    CA Name: {ca_name}")
    print(f"    Valid from: {ca_cert.not_valid_before}")
    print(f"    Valid until: {ca_cert.not_valid_after}")
    print(f"    Serial: {ca_cert.serial_number}")
    
    return ca_private_key, ca_cert

if __name__ == "__main__":
    import sys
    
    ca_name = "SecureChat Root CA"
    output_dir = "certs"
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        ca_name = sys.argv[1]
    if len(sys.argv) > 2:
        output_dir = sys.argv[2]
    
    print("="*60)
    print("SecureChat CA Generator")
    print("="*60)
    
    generate_ca(ca_name, output_dir)
    
    print("\n[!] IMPORTANT: Keep ca_key.pem private and secure!")
    print("[!] Do NOT commit ca_key.pem to version control!")
