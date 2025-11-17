# Manual Testing and Evidence Checklist

This document provides test scenarios to demonstrate the security properties of the SecureChat system.

## 🔐 Test Scenarios

### 1. Normal Operation Test

**Objective:** Verify system works correctly under normal conditions

**Steps:**

1. Start server: `python app/server.py`
2. Start client: `python app/client.py`
3. Client registers a new account
4. Client logs in
5. Exchange several messages
6. Type `/quit` to end session
7. Verify session receipts are generated

**Expected Results:**

- ✅ Certificate exchange succeeds
- ✅ Registration/login successful
- ✅ Messages encrypted and decrypted correctly
- ✅ Transcripts saved in `transcripts/` folder
- ✅ Session receipts generated with valid signatures

---

### 2. Encrypted Payload Test (Wireshark)

**Objective:** Verify all message payloads are encrypted (confidentiality)

**Steps:**

1. Start Wireshark capture on loopback interface
2. Filter: `tcp.port == 8888`
3. Run client-server chat session
4. Stop capture and analyze packets

**Expected Results:**

- ✅ No plaintext messages visible in packet data
- ✅ Only encrypted ciphertext and base64-encoded data visible
- ✅ Certificate exchange visible (PEM format)
- ✅ JSON structure visible but data encrypted

**Screenshot:** Include Wireshark capture showing encrypted payloads

---

### 3. BAD_CERT Test (Invalid Certificate)

**Objective:** Verify certificate validation rejects invalid certificates

**Test 3a: Self-Signed Certificate**

**Steps:**

1. Generate a self-signed certificate (not signed by CA):
   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout fake_key.pem -out fake_cert.pem -days 365 -nodes
   ```
2. Replace `certs/client_cert.pem` with `fake_cert.pem`
3. Start server and client
4. Attempt connection

**Expected Result:**

- ✅ Server rejects certificate with `BAD_CERT` error
- ✅ Connection terminated

**Test 3b: Expired Certificate**

**Steps:**

1. Modify certificate generation to create expired cert
2. Attempt connection

**Expected Result:**

- ✅ Certificate validation fails on expiry check
- ✅ Connection rejected

---

### 4. SIG_FAIL Test (Message Tampering)

**Objective:** Verify integrity checking detects tampered messages

**Steps:**

1. Modify `app/client.py` or `app/server.py` to flip a bit in ciphertext before sending:
   ```python
   # After encryption, tamper with ciphertext
   ct_bytes = base64.b64decode(ct_b64)
   tampered = bytearray(ct_bytes)
   tampered[0] ^= 0x01  # Flip one bit
   ct_b64 = base64.b64encode(bytes(tampered)).decode()
   ```
2. Send tampered message
3. Observe receiver's response

**Expected Result:**

- ✅ Signature verification fails
- ✅ Message rejected with signature error
- ✅ Receiver displays error: "Signature verification failed"

---

### 5. REPLAY Test (Sequence Number)

**Objective:** Verify replay attack protection

**Steps:**

1. Capture a valid message from client to server
2. Modify client to resend the same message (with same seqno)
3. Observe server response

**Expected Result:**

- ✅ Server detects duplicate/out-of-order sequence number
- ✅ Message rejected as replay attack
- ✅ Error logged: "REPLAY detected"

**Note:** Current implementation should enforce strictly increasing seqno

---

### 6. Non-Repudiation Test (Session Receipt)

**Objective:** Verify cryptographic proof of communication

**Steps:**

1. Complete a chat session with multiple messages
2. Locate transcript files:
   - `transcripts/client/*.txt`
   - `transcripts/server/*.txt`
3. Locate session receipt files:
   - `transcripts/client/*_receipt.txt`
   - `transcripts/server/*_receipt.txt`
4. Verify receipt contains:
   - Peer identification
   - First and last sequence numbers
   - SHA-256 hash of transcript
   - RSA signature

**Verification:**

1. Manually compute transcript hash:
   ```python
   import hashlib
   with open('transcripts/client/session.txt', 'r') as f:
       content = ''.join([line for line in f if not line.startswith('#')])
   computed_hash = hashlib.sha256(content.encode()).hexdigest()
   ```
2. Compare with receipt's `transcript_sha256` field
3. Verify signature using certificate's public key

**Expected Results:**

- ✅ Transcript hash matches receipt
- ✅ Signature verifies with participant's certificate
- ✅ Any modification to transcript invalidates receipt
- ✅ Provides non-repudiation evidence

---

### 7. Password Security Test

**Objective:** Verify passwords are never stored in plaintext

**Steps:**

1. Register user with password "test123"
2. Check MySQL database:
   ```sql
   USE securechat;
   SELECT email, username, HEX(salt), pwd_hash FROM users;
   ```
3. Verify stored values

**Expected Results:**

- ✅ `salt` is random 16-byte value (32 hex chars)
- ✅ `pwd_hash` is SHA-256 digest (64 hex chars)
- ✅ No plaintext password visible
- ✅ Hash = SHA256(salt || password)

---

### 8. Session Key Uniqueness Test

**Objective:** Verify each session has unique encryption key

**Steps:**

1. Complete session 1, note first message ciphertext
2. Disconnect and reconnect
3. Complete session 2, send same message
4. Compare ciphertexts

**Expected Results:**

- ✅ Different DH exchange each session
- ✅ Different session keys derived
- ✅ Same plaintext produces different ciphertext
- ✅ Demonstrates forward security

---

### 9. Certificate Chain Validation

**Objective:** Verify complete certificate chain

**Steps:**

```bash
# Verify CA is self-signed
openssl verify -CAfile certs/ca_cert.pem certs/ca_cert.pem

# Verify server cert signed by CA
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem

# Verify client cert signed by CA
openssl verify -CAfile certs/ca_cert.pem certs/client_cert.pem

# Inspect certificate details
openssl x509 -in certs/server_cert.pem -text -noout
```

**Expected Results:**

- ✅ All verifications succeed
- ✅ Certificate validity dates are correct
- ✅ Subject and Issuer fields correct
- ✅ Key usage extensions appropriate

---

## 📊 Evidence Documentation

For your report, include:

1. **Screenshots**:

   - Server and client console output during normal operation
   - Wireshark capture showing encrypted traffic
   - Certificate verification commands and output
   - Database showing hashed passwords

2. **Files**:

   - Sample transcript file
   - Session receipt file
   - Certificate inspection output

3. **Test Results**:

   - Table showing each test scenario result
   - Error messages for security violations
   - Proof of non-repudiation (verified receipts)

4. **Code Snippets**:
   - Key derivation implementation
   - Signature verification code
   - Certificate validation logic

---

## 🔍 Security Properties Demonstrated

| Property             | Test                   | Evidence               |
| -------------------- | ---------------------- | ---------------------- |
| **Confidentiality**  | Wireshark capture      | No plaintext visible   |
| **Integrity**        | Message tampering      | Signature fails        |
| **Authenticity**     | Certificate validation | BAD_CERT rejection     |
| **Non-Repudiation**  | Session receipt        | Signed transcript hash |
| **Freshness**        | Replay attack          | Sequence number check  |
| **Forward Security** | Session key uniqueness | Different ciphertexts  |

---

## 📝 Report Sections

Your test report should include:

1. **Setup**: Environment, tools, versions
2. **Test Execution**: Each scenario with steps
3. **Results**: Output, screenshots, observations
4. **Analysis**: Security properties demonstrated
5. **Conclusion**: System effectiveness

---

## ⚠️ Important Notes

- Always generate fresh certificates for testing
- Never reuse test certificates in production
- Keep private keys secure during testing
- Document any deviations from expected behavior
- Include timestamps in test evidence
- Verify all cryptographic operations manually

---

## 🎯 Grading Criteria

Tests must demonstrate:

- ✅ All security properties (CIANR)
- ✅ Correct protocol implementation
- ✅ Proper error handling
- ✅ Complete evidence documentation
- ✅ Clear analysis and explanation
