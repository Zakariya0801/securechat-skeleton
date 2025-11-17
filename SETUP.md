# SecureChat Setup Guide

## Prerequisites

1. **Python 3.8+** installed
2. **MySQL Server** installed and running
3. **pip** package manager

## Installation Steps

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

The required packages are:

- `cryptography` - For PKI, AES, RSA operations
- `mysql-connector-python` - For MySQL database connection

### 2. Setup MySQL Database

Start MySQL server and create a user:

```sql
-- Create database (will be created automatically by the app)
-- But ensure MySQL is running and accessible

-- Optional: Create dedicated user
CREATE USER 'securechat'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON securechat.* TO 'securechat'@'localhost';
FLUSH PRIVILEGES;
```

Update database credentials in `app/storage/db.py` if needed:

```python
db = DatabaseManager(host='localhost', user='root', password='your_password', database='securechat')
```

### 3. Generate PKI Infrastructure

#### Step 1: Generate Root CA

```bash
python scripts/gen_ca.py
```

This creates:

- `certs/ca_key.pem` - CA private key (keep secure!)
- `certs/ca_cert.pem` - CA certificate (trusted root)

#### Step 2: Generate Server Certificate

```bash
python scripts/gen_cert.py server localhost
```

This creates:

- `certs/server_key.pem` - Server private key
- `certs/server_cert.pem` - Server certificate signed by CA

#### Step 3: Generate Client Certificate

```bash
python scripts/gen_cert.py client client1
```

This creates:

- `certs/client_key.pem` - Client private key
- `certs/client_cert.pem` - Client certificate signed by CA

**Note:** The `certs/` directory should be in `.gitignore` to prevent committing private keys!

### 4. Verify Certificates (Optional)

```bash
# Inspect CA certificate
openssl x509 -in certs/ca_cert.pem -text -noout

# Inspect server certificate
openssl x509 -in certs/server_cert.pem -text -noout

# Verify server certificate against CA
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem

# Verify client certificate against CA
openssl verify -CAfile certs/ca_cert.pem certs/client_cert.pem
```

## Running the System

### Start the Server

```bash
python app/server.py [port]
```

Default port is 8888.

Example:

```bash
python app/server.py 8888
```

### Start the Client

```bash
python app/client.py [host] [port]
```

Example:

```bash
python app/client.py localhost 8888
```

## Usage Flow

### 1. Client Connection

- Client connects and exchanges certificates with server
- Mutual certificate verification occurs
- Both parties verify the certificate chain back to the CA

### 2. Authentication Phase

The client will be prompted to:

**Option 1: Register**

- Enter email, username, and password
- Password is hashed with salt: `SHA256(salt || password)`
- Credentials encrypted with temporary DH-derived AES key
- Stored securely in MySQL database

**Option 2: Login**

- Enter email and password
- Password verified against stored salted hash
- Authentication via encrypted channel

### 3. Session Key Establishment

- After authentication, full DH key exchange occurs
- Client sends: `{ "type":"dh_client", "g": int, "p": int, "A": int }`
- Server responds: `{ "type":"dh_server", "B": int }`
- Both compute: `Ks = A^b mod p = B^a mod p`
- Session key derived: `K = Trunc16(SHA256(big-endian(Ks)))`

### 4. Encrypted Chat

Once in chat mode:

- Type messages and press Enter to send
- Messages are:
  - Encrypted with AES-128-CBC using session key
  - Signed with RSA-SHA256 using sender's private key
  - Include sequence number and timestamp
- Each message format: `{ "type":"msg", "seqno": n, "ts": unix_ms, "ct": base64, "sig": base64 }`

Type `/quit` to exit.

### 5. Session Closure

- Both parties generate session receipt
- Transcript hash: `SHA256(concatenation of all messages)`
- Receipt signed with private key
- Provides non-repudiation evidence

## Directory Structure

```
securechat-skeleton/
├── app/
│   ├── client.py              # Client implementation
│   ├── server.py              # Server implementation
│   ├── crypto/
│   │   ├── aes.py            # AES-128-CBC encryption
│   │   ├── dh.py             # Diffie-Hellman key exchange
│   │   ├── pki.py            # Certificate handling
│   │   └── sign.py           # RSA signing/verification
│   ├── common/
│   │   ├── protocol.py       # Message format definitions
│   │   └── utils.py          # Utility functions
│   └── storage/
│       ├── db.py             # MySQL database operations
│       └── transcript.py     # Session transcript management
├── scripts/
│   ├── gen_ca.py             # Generate root CA
│   └── gen_cert.py           # Generate certificates
├── certs/                     # Generated certificates (not in git)
│   ├── ca_key.pem
│   ├── ca_cert.pem
│   ├── server_key.pem
│   ├── server_cert.pem
│   ├── client_key.pem
│   └── client_cert.pem
├── transcripts/               # Session transcripts and receipts
│   ├── client/
│   └── server/
└── requirements.txt

```

## Security Features Implemented

### 1. Confidentiality

- AES-128-CBC encryption for all message data
- Unique session key per chat session via DH
- Certificate-based identity verification

### 2. Integrity

- SHA-256 hashing of message content
- Signature verification prevents tampering
- Sequence numbers prevent replay attacks

### 3. Authenticity

- X.509 certificates signed by trusted CA
- RSA digital signatures on every message
- Mutual authentication (both client and server)

### 4. Non-Repudiation

- Append-only transcript logs
- Signed session receipts
- Cryptographic proof of participation

## Troubleshooting

### Certificate Verification Fails

- Ensure CA certificate is valid and not expired
- Check that all certificates are signed by the same CA
- Verify certificate paths are correct

### Database Connection Error

- Verify MySQL is running: `mysql -u root -p`
- Check database credentials in `app/storage/db.py`
- Ensure `securechat` database exists or app has permission to create it

### Import Errors

- Install all dependencies: `pip install -r requirements.txt`
- Verify Python version: `python --version` (should be 3.8+)

### Port Already in Use

- Change server port: `python app/server.py 9999`
- Kill existing process: `netstat -ano | findstr :8888` (Windows) or `lsof -i :8888` (Linux/Mac)

## Testing

### Test Certificate Chain

```bash
# Verify server certificate
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem

# Should output: certs/server_cert.pem: OK
```

### Test Database Connection

```bash
python -c "from app.storage.db import *; db = initialize_database(); print('DB OK' if db else 'DB Failed')"
```

### Test Encryption

```bash
python -c "from app.crypto.aes import *; key = generate_aes_key(); iv, ct = aes_encrypt(key, 'test'); print('AES OK')"
```

## Notes

- **Never commit private keys** (`*_key.pem` files) to version control
- Keep `ca_key.pem` especially secure - it can sign new certificates
- Transcripts contain encrypted messages - keep them secure
- Session receipts provide non-repudiation evidence for auditing

## Assignment Requirements Checklist

- [x] PKI Setup with self-signed CA
- [x] Certificate issuance and validation
- [x] Registration with salted password hashing
- [x] Login with credential verification
- [x] MySQL storage (no plaintext passwords)
- [x] Diffie-Hellman key exchange
- [x] AES-128-CBC encryption with PKCS#7 padding
- [x] RSA-SHA256 digital signatures
- [x] Sequence numbers and timestamps
- [x] Append-only transcript logs
- [x] Session receipts with signed transcript hash
- [x] Non-repudiation evidence
