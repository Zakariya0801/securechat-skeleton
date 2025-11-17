"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import os

def load_ca(ca_key_path="certs/ca_key.pem", ca_cert_path="certs/ca_cert.pem"):
    """Load CA private key and certificate"""
    # Load CA private key
    with open(ca_key_path, 'rb') as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    # Load CA certificate
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    return ca_key, ca_cert

def generate_certificate(common_name, cert_type="server", ca_key=None, ca_cert=None, 
                        output_dir="certs", validity_days=365):
    """
    Generate and sign certificate for server or client
    
    Args:
        common_name: Common Name (e.g., "localhost" for server, "client1" for client)
        cert_type: "server" or "client"
        ca_key: CA private key
        ca_cert: CA certificate
        output_dir: Output directory for generated files
        validity_days: Certificate validity period in days
    
    Creates:
        - {cert_type}_key.pem: Private key
        - {cert_type}_cert.pem: Signed certificate
    """
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    print(f"[*] Generating {cert_type} private key (2048-bit RSA)...")
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Save private key
    key_path = os.path.join(output_dir, f"{cert_type}_key.pem")
    with open(key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[+] {cert_type.capitalize()} private key saved to: {key_path}")
    
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    print(f"[*] Creating {cert_type} certificate...")
    # Build certificate
    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(common_name),
        ]),
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False,
    )
    
    # Add key usage based on certificate type
    if cert_type == "server":
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )
    else:  # client
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
    
    # Sign certificate with CA key
    cert = cert_builder.sign(ca_key, hashes.SHA256(), default_backend())
    
    # Save certificate
    cert_path = os.path.join(output_dir, f"{cert_type}_cert.pem")
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] {cert_type.capitalize()} certificate saved to: {cert_path}")
    
    print(f"\n[+] {cert_type.capitalize()} certificate created successfully!")
    print(f"    Common Name: {common_name}")
    print(f"    Valid from: {cert.not_valid_before}")
    print(f"    Valid until: {cert.not_valid_after}")
    print(f"    Serial: {cert.serial_number}")
    
    return private_key, cert

if __name__ == "__main__":
    import sys
    
    print("="*60)
    print("SecureChat Certificate Generator")
    print("="*60)
    
    # Default values
    cert_type = "server"
    common_name = "localhost"
    output_dir = "certs"
    ca_key_path = "certs/ca_key.pem"
    ca_cert_path = "certs/ca_cert.pem"
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        cert_type = sys.argv[1]  # "server" or "client"
    if len(sys.argv) > 2:
        common_name = sys.argv[2]
    if len(sys.argv) > 3:
        output_dir = sys.argv[3]
    
    # Check if CA exists
    if not os.path.exists(ca_key_path) or not os.path.exists(ca_cert_path):
        print("[!] Error: CA not found. Please run gen_ca.py first to create the CA.")
        sys.exit(1)
    
    # Load CA
    print("[*] Loading CA...")
    ca_key, ca_cert = load_ca(ca_key_path, ca_cert_path)
    print("[+] CA loaded successfully")
    
    # Generate certificate
    generate_certificate(common_name, cert_type, ca_key, ca_cert, output_dir)
    
    print(f"\n[*] To verify the certificate, run:")
    print(f"    openssl x509 -in {output_dir}/{cert_type}_cert.pem -text -noout")
