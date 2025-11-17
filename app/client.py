"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import base64
import os
import time
import threading
from datetime import datetime
from cryptography.hazmat.primitives import serialization

from crypto import pki, aes, dh, sign
from common import protocol, utils
from storage import transcript

class SecureChatClient:
    def __init__(self, server_host='localhost', server_port=8888,
                 cert_path='certs/client_cert.pem', key_path='certs/client_key.pem',
                 ca_path='certs/ca_cert.pem'):
        self.server_host = server_host
        self.server_port = server_port
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path
        
        # Load client certificate and key
        print("[*] Loading client certificate and private key...")
        self.client_cert = pki.load_certificate(cert_path)
        self.client_key = pki.load_private_key(key_path)
        self.ca_cert = pki.load_ca_certificate(ca_path)
        print("[+] Client credentials loaded")
        
        # Client state
        self.session_key = None
        self.server_cert = None
        self.sock = None
        self.transcript_mgr = None
        self.seqno = 0
        self.running = False
    
    def connect(self):
        """Connect to server"""
        print(f"[*] Connecting to {self.server_host}:{self.server_port}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_host, self.server_port))
        print("[+] Connected to server")
    
    def run(self):
        """Main client workflow"""
        try:
            self.connect()
            
            # Phase 1: Certificate exchange
            if not self.control_plane_handshake():
                print("[!] Handshake failed")
                return
            
            # Phase 2: Registration or Login
            print("\n=== Authentication ===")
            print("1. Register")
            print("2. Login")
            choice = input("Choose option (1/2): ").strip()
            
            if choice == '1':
                authenticated = self.register()
            elif choice == '2':
                authenticated = self.login()
            else:
                print("[!] Invalid choice")
                return
            
            if not authenticated:
                print("[!] Authentication failed")
                return
            
            # Phase 3: Session key establishment
            if not self.establish_session_key():
                print("[!] Failed to establish session key")
                return
            
            # Initialize transcript
            self.transcript_mgr = transcript.TranscriptManager(
                transcript_dir='transcripts/client',
                peer_name='server'
            )
            self.transcript_mgr.start_session(f"client_{int(time.time())}")
            
            # Phase 4: Chat
            self.chat_loop()
            
            # Phase 5: Session closure
            self.close_session()
            
        except Exception as e:
            print(f"[!] Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.sock:
                self.sock.close()
    
    def control_plane_handshake(self):
        """
        Phase 1: Certificate exchange and verification
        """
        print("[*] Starting certificate exchange...")
        
        # Send client hello
        client_nonce = utils.generate_nonce()
        hello_msg = protocol.create_hello_message(
            pki.get_certificate_pem(self.client_cert),
            client_nonce
        )
        utils.send_message(self.sock, protocol.serialize_message(hello_msg))
        
        # Receive server hello
        msg_bytes = utils.receive_message(self.sock)
        if not msg_bytes:
            return False
        
        server_hello = protocol.deserialize_message(msg_bytes)
        if server_hello['type'] != 'server_hello':
            print("[!] Expected server_hello")
            return False
        
        # Verify server certificate
        server_cert_pem = server_hello['server_cert']
        server_nonce = base64.b64decode(server_hello['nonce'])
        
        try:
            self.server_cert = pki.parse_certificate_pem(server_cert_pem)
            if not pki.verify_certificate(self.server_cert, self.ca_cert):
                print("[!] BAD_CERT: Server certificate verification failed")
                return False
            
            print(f"[+] Server certificate verified: {pki.get_subject_common_name(self.server_cert)}")
        except Exception as e:
            print(f"[!] Certificate verification error: {e}")
            return False
        
        print("[+] Certificate exchange completed")
        return True
    
    def register(self):
        """Handle user registration"""
        print("\n=== Registration ===")
        email = input("Email: ").strip()
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        
        # Generate salt
        salt = utils.generate_salt()
        
        # Temporary DH for auth encryption
        print("[*] Establishing secure channel...")
        
        # Receive server DH parameters
        msg_bytes = utils.receive_message(self.sock)
        dh_msg = protocol.deserialize_message(msg_bytes)
        
        if dh_msg['type'] != 'dh_client':
            print("[!] Expected dh_client message")
            return False
        
        g = dh_msg['g']
        p = dh_msg['p']
        A = dh_msg['A']
        
        # Generate client DH key
        b = dh.generate_dh_private()
        B = dh.compute_dh_public(g, p, b)
        
        # Send client DH public value
        dh_response = protocol.create_dh_server_message(B)
        utils.send_message(self.sock, protocol.serialize_message(dh_response))
        
        # Compute shared secret
        Ks = dh.compute_dh_shared_secret(A, b, p)
        temp_key = dh.derive_session_key(Ks)
        
        print("[+] Secure channel established")
        
        # Create and encrypt registration message
        reg_msg = protocol.create_register_message(email, username, password, salt)
        encrypted_msg = protocol.encrypt_message(reg_msg, temp_key, aes)
        utils.send_message(self.sock, protocol.serialize_message(encrypted_msg))
        
        # Receive response
        msg_bytes = utils.receive_message(self.sock)
        encrypted_response = protocol.deserialize_message(msg_bytes)
        response = protocol.decrypt_message(encrypted_response, temp_key, aes)
        
        if response['status'] == 'success':
            print(f"[+] {response['message']}")
            return True
        else:
            print(f"[!] {response['message']}")
            return False
    
    def login(self):
        """Handle user login"""
        print("\n=== Login ===")
        email = input("Email: ").strip()
        password = input("Password: ").strip()
        
        # Temporary DH for auth encryption
        print("[*] Establishing secure channel...")
        
        # Receive server DH parameters
        msg_bytes = utils.receive_message(self.sock)
        dh_msg = protocol.deserialize_message(msg_bytes)
        
        if dh_msg['type'] != 'dh_client':
            print("[!] Expected dh_client message")
            return False
        
        g = dh_msg['g']
        p = dh_msg['p']
        A = dh_msg['A']
        
        # Generate client DH key
        b = dh.generate_dh_private()
        B = dh.compute_dh_public(g, p, b)
        
        # Send client DH public value
        dh_response = protocol.create_dh_server_message(B)
        utils.send_message(self.sock, protocol.serialize_message(dh_response))
        
        # Compute shared secret
        Ks = dh.compute_dh_shared_secret(A, b, p)
        temp_key = dh.derive_session_key(Ks)
        
        print("[+] Secure channel established")
        
        # We need to get salt first in a real system, but for simplicity,
        # we'll hash with a temporary approach
        # Better: server should send salt after receiving email
        
        # Create login message with nonce
        login_nonce = utils.generate_nonce()
        
        # For this implementation, we'll need the salt
        # In a proper implementation, client would request salt first
        # For now, use a deterministic approach or modify protocol
        
        # Create and encrypt login message
        salt = utils.generate_salt()  # Temporary - should get from server
        login_msg = protocol.create_login_message(email, password, salt, login_nonce)
        encrypted_msg = protocol.encrypt_message(login_msg, temp_key, aes)
        utils.send_message(self.sock, protocol.serialize_message(encrypted_msg))
        
        # Receive response
        msg_bytes = utils.receive_message(self.sock)
        encrypted_response = protocol.deserialize_message(msg_bytes)
        response = protocol.decrypt_message(encrypted_response, temp_key, aes)
        
        if response['status'] == 'success':
            print(f"[+] {response['message']}")
            return True
        else:
            print(f"[!] {response['message']}")
            return False
    
    def establish_session_key(self):
        """
        Phase 3: DH key exchange for chat session
        """
        print("[*] Establishing session key...")
        
        # Generate DH keypair
        a = dh.generate_dh_private()
        A = dh.compute_dh_public(dh.DH_G, dh.DH_P, a)
        
        # Send DH parameters to server
        dh_client_msg = protocol.create_dh_client_message(dh.DH_G, dh.DH_P, A)
        utils.send_message(self.sock, protocol.serialize_message(dh_client_msg))
        
        # Receive server DH response
        msg_bytes = utils.receive_message(self.sock)
        dh_server_msg = protocol.deserialize_message(msg_bytes)
        
        if dh_server_msg['type'] != 'dh_server':
            print("[!] Expected dh_server message")
            return False
        
        B = dh_server_msg['B']
        
        # Compute shared secret: Ks = B^a mod p
        Ks = dh.compute_dh_shared_secret(B, a, dh.DH_P)
        
        # Derive session key: K = Trunc16(SHA256(big-endian(Ks)))
        self.session_key = dh.derive_session_key(Ks)
        
        print("[+] Session key established")
        return True
    
    def chat_loop(self):
        """
        Phase 4: Encrypted message exchange
        """
        print("\n[+] Chat session started!")
        print("[*] Type messages to send. Type '/quit' to exit.\n")
        
        self.running = True
        
        # Start receiver thread
        receiver_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receiver_thread.start()
        
        # Send messages
        try:
            while self.running:
                message = input()
                
                if message == '/quit':
                    self.running = False
                    break
                
                if message.strip():
                    self.send_chat_message(message)
        except KeyboardInterrupt:
            print("\n[*] Ending chat session...")
            self.running = False
    
    def send_chat_message(self, plaintext):
        """
        Send encrypted and signed chat message
        """
        try:
            self.seqno += 1
            timestamp = int(time.time() * 1000)  # milliseconds
            
            # Encrypt message with AES-128
            iv, ciphertext = aes.aes_encrypt(self.session_key, plaintext)
            
            # Combine IV and ciphertext
            ct_bytes = iv + ciphertext
            ct_b64 = base64.b64encode(ct_bytes).decode('utf-8')
            
            # Compute signature: RSA-SHA256(seqno || ts || ct)
            hash_data = f"{self.seqno}{timestamp}".encode() + ct_bytes
            hash_digest = sign.compute_sha256(hash_data)
            signature = sign.sign_data(self.client_key, hash_digest)
            sig_b64 = base64.b64encode(signature).decode('utf-8')
            
            # Create and send message
            chat_msg = protocol.create_chat_message(self.seqno, timestamp, ct_b64, sig_b64)
            utils.send_message(self.sock, protocol.serialize_message(chat_msg))
            
            # Log to transcript
            server_cert_fingerprint = sign.compute_sha256_hex(
                self.server_cert.public_bytes(encoding=serialization.Encoding.DER)
            )
            self.transcript_mgr.append_message(
                self.seqno, timestamp, ct_b64, sig_b64, server_cert_fingerprint
            )
            
        except Exception as e:
            print(f"[!] Error sending message: {e}")
            self.running = False
    
    def receive_messages(self):
        """Receive and decrypt messages from server"""
        self.sock.settimeout(1.0)
        
        while self.running:
            try:
                msg_bytes = utils.receive_message(self.sock)
                if not msg_bytes:
                    break
                
                msg = protocol.deserialize_message(msg_bytes)
                
                if msg['type'] == 'msg':
                    self.handle_chat_message(msg)
                elif msg['type'] == 'receipt':
                    print(f"\n[*] Received session receipt from server")
                    if self.transcript_mgr:
                        self.transcript_mgr.save_receipt(msg)
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"\n[!] Connection error: {e}")
                break
    
    def handle_chat_message(self, chat_msg):
        """Handle incoming chat message"""
        try:
            seqno = chat_msg['seqno']
            ts = chat_msg['ts']
            ct_b64 = chat_msg['ct']
            sig_b64 = chat_msg['sig']
            
            # Verify signature
            ct_bytes = base64.b64decode(ct_b64)
            sig_bytes = base64.b64decode(sig_b64)
            
            hash_data = f"{seqno}{ts}".encode() + ct_bytes
            computed_hash = sign.compute_sha256(hash_data)
            
            server_pubkey = self.server_cert.public_key()
            if not sign.verify_signature(server_pubkey, computed_hash, sig_bytes):
                print(f"[!] Message {seqno} signature verification failed!")
                return
            
            # Decrypt
            iv = ct_bytes[:16]
            ciphertext = ct_bytes[16:]
            plaintext = aes.aes_decrypt(self.session_key, iv, ciphertext)
            
            print(f"\n[Server @ {datetime.fromtimestamp(ts/1000).strftime('%H:%M:%S')}]: {plaintext.decode()}")
            
            # Log to transcript
            server_cert_fingerprint = sign.compute_sha256_hex(
                self.server_cert.public_bytes(encoding=serialization.Encoding.DER)
            )
            self.transcript_mgr.append_message(seqno, ts, ct_b64, sig_b64, server_cert_fingerprint)
            
        except Exception as e:
            print(f"[!] Error handling message: {e}")
    
    def close_session(self):
        """
        Phase 5: Generate session receipt
        """
        self.running = False
        
        if self.transcript_mgr and self.transcript_mgr.messages:
            print("\n[*] Generating session receipt...")
            
            first_seq = self.transcript_mgr.get_first_seq()
            last_seq = self.transcript_mgr.get_last_seq()
            
            receipt = self.transcript_mgr.create_session_receipt(
                "client",
                first_seq,
                last_seq,
                self.client_key
            )
            
            self.transcript_mgr.save_receipt(receipt)
            print(f"[+] Session receipt generated: {receipt['transcript_sha256'][:16]}...")
            
            # Send receipt to server
            try:
                utils.send_message(self.sock, protocol.serialize_message(receipt))
            except:
                pass
        
        if self.transcript_mgr:
            self.transcript_mgr.close_session()
        
        print("[*] Session closed")

def main():
    import sys
    
    server_host = 'localhost'
    server_port = 8888
    
    if len(sys.argv) > 1:
        server_host = sys.argv[1]
    if len(sys.argv) > 2:
        server_port = int(sys.argv[2])
    
    try:
        client = SecureChatClient(server_host=server_host, server_port=server_port)
        client.run()
    except Exception as e:
        print(f"[!] Client error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
