#!/usr/bin/env python3
"""
Verification script to test individual components
"""

import sys
import os

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

def test_aes():
    """Test AES encryption/decryption"""
    print("\n[*] Testing AES-128-CBC encryption...")
    try:
        from crypto import aes
        
        key = aes.generate_aes_key()
        plaintext = "Hello, SecureChat!"
        
        iv, ciphertext = aes.aes_encrypt(key, plaintext)
        decrypted = aes.aes_decrypt(key, iv, ciphertext)
        
        assert decrypted.decode() == plaintext, "Decryption failed"
        print("[+] AES test passed")
        return True
    except Exception as e:
        print(f"[!] AES test failed: {e}")
        return False

def test_dh():
    """Test Diffie-Hellman key exchange"""
    print("\n[*] Testing DH key exchange...")
    try:
        from crypto import dh
        
        # Simulate client and server
        a = dh.generate_dh_private()
        A = dh.compute_dh_public(dh.DH_G, dh.DH_P, a)
        
        b = dh.generate_dh_private()
        B = dh.compute_dh_public(dh.DH_G, dh.DH_P, b)
        
        # Both compute shared secret
        Ks_client = dh.compute_dh_shared_secret(B, a, dh.DH_P)
        Ks_server = dh.compute_dh_shared_secret(A, b, dh.DH_P)
        
        assert Ks_client == Ks_server, "Shared secrets don't match"
        
        # Derive keys
        key_client = dh.derive_session_key(Ks_client)
        key_server = dh.derive_session_key(Ks_server)
        
        assert key_client == key_server, "Derived keys don't match"
        assert len(key_client) == 16, "Key length should be 16 bytes"
        
        print(f"[+] DH test passed - Key: {key_client.hex()[:32]}...")
        return True
    except Exception as e:
        print(f"[!] DH test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_signing():
    """Test RSA signing and verification"""
    print("\n[*] Testing RSA signing...")
    try:
        from crypto import sign, pki
        
        # Generate a test keypair
        private_key = pki.generate_key_pair()
        public_key = private_key.public_key()
        
        data = b"Test message for signing"
        
        # Sign
        signature = sign.sign_data(private_key, data)
        print(f"[+] Signature generated: {len(signature)} bytes")
        
        # Verify
        valid = sign.verify_signature(public_key, data, signature)
        assert valid, "Signature verification failed"
        print("[+] Signature verified")
        
        # Test with tampered data
        tampered_data = b"Tampered message"
        invalid = sign.verify_signature(public_key, tampered_data, signature)
        assert not invalid, "Tampered data should fail verification"
        print("[+] Tampered data correctly rejected")
        
        print("[+] RSA signing test passed")
        return True
    except Exception as e:
        print(f"[!] RSA signing test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_certificates():
    """Test certificate loading and verification"""
    print("\n[*] Testing certificate operations...")
    try:
        from crypto import pki
        
        ca_cert_path = "certs/ca_cert.pem"
        server_cert_path = "certs/server_cert.pem"
        
        if not os.path.exists(ca_cert_path):
            print("[!] CA certificate not found. Run: python scripts/gen_ca.py")
            return False
        
        if not os.path.exists(server_cert_path):
            print("[!] Server certificate not found. Run: python scripts/gen_cert.py server localhost")
            return False
        
        # Load certificates
        ca_cert = pki.load_ca_certificate(ca_cert_path)
        server_cert = pki.load_certificate(server_cert_path)
        
        print(f"[+] CA: {pki.get_subject_common_name(ca_cert)}")
        print(f"[+] Server: {pki.get_subject_common_name(server_cert)}")
        
        # Verify server certificate
        valid = pki.verify_certificate(server_cert, ca_cert)
        if valid:
            print("[+] Server certificate verified against CA")
        else:
            print("[!] Server certificate verification failed")
            return False
        
        print("[+] Certificate test passed")
        return True
    except Exception as e:
        print(f"[!] Certificate test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_protocol():
    """Test protocol message creation"""
    print("\n[*] Testing protocol messages...")
    try:
        from common import protocol, utils
        import base64
        
        # Test hello message
        nonce = utils.generate_nonce()
        hello = protocol.create_hello_message("cert_pem_data", nonce)
        assert hello['type'] == 'hello'
        assert 'client_cert' in hello
        print("[+] Hello message created")
        
        # Test DH messages
        dh_client = protocol.create_dh_client_message(2, 23, 5)
        assert dh_client['type'] == 'dh_client'
        assert dh_client['g'] == 2
        print("[+] DH client message created")
        
        dh_server = protocol.create_dh_server_message(8)
        assert dh_server['type'] == 'dh_server'
        assert dh_server['B'] == 8
        print("[+] DH server message created")
        
        # Test chat message
        chat_msg = protocol.create_chat_message(1, 1234567890, "ct_data", "sig_data")
        assert chat_msg['type'] == 'msg'
        assert chat_msg['seqno'] == 1
        print("[+] Chat message created")
        
        # Test serialization
        msg_bytes = protocol.serialize_message(hello)
        msg_dict = protocol.deserialize_message(msg_bytes)
        assert msg_dict['type'] == 'hello'
        print("[+] Message serialization works")
        
        print("[+] Protocol test passed")
        return True
    except Exception as e:
        print(f"[!] Protocol test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_database():
    """Test database connection"""
    print("\n[*] Testing database connection...")
    try:
        from storage import db
        
        # Try to initialize database
        database = db.initialize_database()
        if not database:
            print("[!] Database initialization failed")
            print("[!] Make sure MySQL is running and credentials are correct")
            return False
        
        print("[+] Database connected successfully")
        database.disconnect()
        
        print("[+] Database test passed")
        return True
    except Exception as e:
        print(f"[!] Database test failed: {e}")
        print("[!] Make sure MySQL is running and credentials in app/storage/db.py are correct")
        return False

def main():
    print("="*60)
    print("SecureChat Component Verification")
    print("="*60)
    
    tests = [
        ("AES Encryption", test_aes),
        ("Diffie-Hellman", test_dh),
        ("RSA Signing", test_signing),
        ("Protocol Messages", test_protocol),
        ("Certificates", test_certificates),
        ("Database", test_database),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n[!] Unexpected error in {name}: {e}")
            results.append((name, False))
    
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    
    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {name}")
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    print(f"\n{passed}/{total} tests passed")
    
    if passed == total:
        print("\n✅ All tests passed! System is ready.")
    else:
        print("\n⚠️  Some tests failed. Check the output above.")

if __name__ == "__main__":
    main()
