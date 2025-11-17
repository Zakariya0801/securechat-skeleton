"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import base64
import os
import time
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import serialization

from crypto import pki, aes, dh, sign
from common import protocol, utils
from storage import db, transcript

class SecureChatServer:
    def __init__(self, host='0.0.0.0', port=8888, cert_path='certs/server_cert.pem',
                 key_path='certs/server_key.pem', ca_path='certs/ca_cert.pem'):
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path
        
        # Load server certificate and key
        print("[*] Loading server certificate and private key...")
        self.server_cert = pki.load_certificate(cert_path)
        self.server_key = pki.load_private_key(key_path)
        self.ca_cert = pki.load_ca_certificate(ca_path)
        print("[+] Server credentials loaded")
        
        # Initialize database
        print("[*] Initializing database...")
        self.db = db.initialize_database()
        if not self.db:
            raise Exception("Failed to initialize database")
        print("[+] Database initialized")
        
        # Server state
        self.session_key = None
        self.client_cert = None
        self.transcript_mgr = None
        self.seqno = 0
    
    def start(self):
        """Start the server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        
        print(f"[+] SecureChat Server listening on {self.host}:{self.port}")
        
        try:
            while True:
                client_sock, client_addr = sock.accept()
                print(f"\n[*] New connection from {client_addr}")
                self.handle_client(client_sock, client_addr)
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            sock.close()
            if self.db:
                self.db.disconnect()
    
    def handle_client(self, sock, addr):
        """Handle individual client connection"""
        try:
            # Phase 1: Certificate exchange and verification
            if not self.control_plane_handshake(sock):
                print("[!] Control plane handshake failed")
                sock.close()
                return
            
            # Phase 2: Registration/Login
            authenticated_user = self.handle_authentication(sock)
            if not authenticated_user:
                print("[!] Authentication failed")
                sock.close()
                return
            
            print(f"[+] User authenticated: {authenticated_user}")
            
            # Phase 3: DH Key Agreement for chat session
            if not self.establish_session_key(sock):
                print("[!] Session key establishment failed")
                sock.close()
                return
            
            # Initialize transcript
            self.transcript_mgr = transcript.TranscriptManager(
                transcript_dir='transcripts/server',
                peer_name=authenticated_user
            )
            self.transcript_mgr.start_session(f"server_{authenticated_user}_{int(time.time())}")
            
            # Phase 4: Encrypted chat loop
            self.chat_loop(sock)
            
            # Phase 5: Session closure and receipt generation
            self.close_session(sock)
            
        except Exception as e:
            print(f"[!] Error handling client: {e}")
            import traceback
            traceback.print_exc()
        finally:
            sock.close()
    
    def control_plane_handshake(self, sock):
        """
        Phase 1: Certificate exchange and mutual verification
        """
        print("[*] Starting control plane handshake...")
        
        # Receive client hello
        msg_bytes = utils.receive_message(sock)
        if not msg_bytes:
            return False
        
        hello_msg = protocol.deserialize_message(msg_bytes)
        if hello_msg['type'] != 'hello':
            print("[!] Expected hello message")
            return False
        
        # Extract and verify client certificate
        client_cert_pem = hello_msg['client_cert']
        client_nonce = base64.b64decode(hello_msg['nonce'])
        
        try:
            self.client_cert = pki.parse_certificate_pem(client_cert_pem)
            if not pki.verify_certificate(self.client_cert, self.ca_cert):
                print("[!] BAD_CERT: Client certificate verification failed")
                response = protocol.create_response_message("error", "BAD_CERT")
                utils.send_message(sock, protocol.serialize_message(response))
                return False
            
            print(f"[+] Client certificate verified: {pki.get_subject_common_name(self.client_cert)}")
        except Exception as e:
            print(f"[!] Certificate verification error: {e}")
            return False
        
        # Send server hello
        server_nonce = utils.generate_nonce()
        server_hello = protocol.create_server_hello_message(
            pki.get_certificate_pem(self.server_cert),
            server_nonce
        )
        utils.send_message(sock, protocol.serialize_message(server_hello))
        
        print("[+] Certificate exchange completed")
        return True
    
    def handle_authentication(self, sock):
        """
        Phase 2: Handle registration or login
        Uses temporary DH key for encrypting credentials
        """
        print("[*] Starting authentication phase...")
        
        # Temporary DH exchange for auth encryption
        temp_dh_private = dh.generate_dh_private()
        temp_dh_public = dh.compute_dh_public(dh.DH_G, dh.DH_P, temp_dh_private)
        
        # Send DH parameters to client
        dh_msg = protocol.create_dh_client_message(dh.DH_G, dh.DH_P, temp_dh_public)
        utils.send_message(sock, protocol.serialize_message(dh_msg))
        
        # Receive client's DH public value
        msg_bytes = utils.receive_message(sock)
        dh_response = protocol.deserialize_message(msg_bytes)
        
        if dh_response['type'] != 'dh_server':
            print("[!] Expected dh_server message")
            return None
        
        client_dh_public = dh_response['B']
        
        # Compute shared secret and derive AES key
        shared_secret = dh.compute_dh_shared_secret(client_dh_public, temp_dh_private, dh.DH_P)
        temp_aes_key = dh.derive_session_key(shared_secret)
        
        print("[+] Temporary encryption key established")
        
        # Receive encrypted auth message
        msg_bytes = utils.receive_message(sock)
        encrypted_msg = protocol.deserialize_message(msg_bytes)
        
        if not encrypted_msg.get('encrypted'):
            print("[!] Expected encrypted message")
            return None
        
        # Decrypt auth message
        auth_msg = protocol.decrypt_message(encrypted_msg, temp_aes_key, aes)
        
        if auth_msg['type'] == 'register':
            return self.handle_registration(sock, auth_msg, temp_aes_key)
        elif auth_msg['type'] == 'login':
            return self.handle_login(sock, auth_msg, temp_aes_key)
        else:
            print(f"[!] Unknown auth type: {auth_msg['type']}")
            return None
    
    def handle_registration(self, sock, reg_msg, temp_key):
        """Handle user registration"""
        email = reg_msg['email']
        username = reg_msg['username']
        pwd_hash = base64.b64decode(reg_msg['pwd'])
        salt = base64.b64decode(reg_msg['salt'])
        
        print(f"[*] Registration request: {email} ({username})")
        
        # Store in database (we receive the hash, so we need to hex it)
        # But the database expects password string to hash with salt
        # Actually, client sends SHA256(salt||password) already hashed
        # So we store the received hash directly
        
        try:
            # Check if user exists
            cursor = self.db.connection.cursor()
            check_query = "SELECT email FROM users WHERE email = %s OR username = %s"
            cursor.execute(check_query, (email, username))
            if cursor.fetchone():
                cursor.close()
                response = protocol.create_response_message("error", "User already exists")
                encrypted_response = protocol.encrypt_message(response, temp_key, aes)
                utils.send_message(sock, protocol.serialize_message(encrypted_response))
                return None
            
            # Insert user
            insert_query = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
            cursor.execute(insert_query, (email, username, salt, pwd_hash.hex()))
            self.db.connection.commit()
            cursor.close()
            
            print(f"[+] User registered: {username}")
            
            # Send success response
            response = protocol.create_response_message("success", "Registration successful")
            encrypted_response = protocol.encrypt_message(response, temp_key, aes)
            utils.send_message(sock, protocol.serialize_message(encrypted_response))
            
            return username
            
        except Exception as e:
            print(f"[!] Registration error: {e}")
            response = protocol.create_response_message("error", f"Registration failed: {e}")
            encrypted_response = protocol.encrypt_message(response, temp_key, aes)
            utils.send_message(sock, protocol.serialize_message(encrypted_response))
            return None
    
    def handle_login(self, sock, login_msg, temp_key):
        """Handle user login"""
        email = login_msg['email']
        pwd_hash = base64.b64decode(login_msg['pwd'])
        
        print(f"[*] Login request: {email}")
        
        try:
            # Retrieve user from database
            cursor = self.db.connection.cursor()
            query = "SELECT username, salt, pwd_hash FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            cursor.close()
            
            if not result:
                response = protocol.create_response_message("error", "User not found")
                encrypted_response = protocol.encrypt_message(response, temp_key, aes)
                utils.send_message(sock, protocol.serialize_message(encrypted_response))
                return None
            
            username, salt, stored_hash = result
            
            # Verify password hash
            if pwd_hash.hex() == stored_hash:
                print(f"[+] User logged in: {username}")
                response = protocol.create_response_message("success", "Login successful")
                encrypted_response = protocol.encrypt_message(response, temp_key, aes)
                utils.send_message(sock, protocol.serialize_message(encrypted_response))
                return username
            else:
                print("[!] Invalid password")
                response = protocol.create_response_message("error", "Invalid password")
                encrypted_response = protocol.encrypt_message(response, temp_key, aes)
                utils.send_message(sock, protocol.serialize_message(encrypted_response))
                return None
                
        except Exception as e:
            print(f"[!] Login error: {e}")
            response = protocol.create_response_message("error", f"Login failed: {e}")
            encrypted_response = protocol.encrypt_message(response, temp_key, aes)
            utils.send_message(sock, protocol.serialize_message(encrypted_response))
            return None
    
    def establish_session_key(self, sock):
        """
        Phase 3: DH key exchange for chat session
        """
        print("[*] Establishing session key...")
        
        # Receive client DH parameters
        msg_bytes = utils.receive_message(sock)
        dh_client_msg = protocol.deserialize_message(msg_bytes)
        
        if dh_client_msg['type'] != 'dh_client':
            print("[!] Expected dh_client message")
            return False
        
        g = dh_client_msg['g']
        p = dh_client_msg['p']
        A = dh_client_msg['A']
        
        # Generate server DH private key and compute public value
        b = dh.generate_dh_private()
        B = dh.compute_dh_public(g, p, b)
        
        # Send server DH public value
        dh_server_msg = protocol.create_dh_server_message(B)
        utils.send_message(sock, protocol.serialize_message(dh_server_msg))
        
        # Compute shared secret: Ks = A^b mod p
        Ks = dh.compute_dh_shared_secret(A, b, p)
        
        # Derive session key: K = Trunc16(SHA256(big-endian(Ks)))
        self.session_key = dh.derive_session_key(Ks)
        
        print("[+] Session key established")
        return True
    
    def chat_loop(self, sock):
        """
        Phase 4: Encrypted message exchange with signatures
        """
        print("[+] Entering chat mode...")
        print("[*] Type messages to send. Press Ctrl+C to end session.")
        
        sock.settimeout(0.5)  # Non-blocking for checking input
        
        try:
            while True:
                # Check for incoming messages
                try:
                    msg_bytes = utils.receive_message(sock)
                    if msg_bytes:
                        self.handle_chat_message(msg_bytes, sock)
                except socket.timeout:
                    pass
                except Exception as e:
                    if "connection" in str(e).lower():
                        print("\n[!] Client disconnected")
                        break
                
                # Check for server input (simulated - in real app would be separate thread)
                # For now, server just receives messages
                
        except KeyboardInterrupt:
            print("\n[*] Ending chat session...")
    
    def handle_chat_message(self, msg_bytes, sock):
        """Handle incoming encrypted chat message"""
        try:
            chat_msg = protocol.deserialize_message(msg_bytes)
            
            if chat_msg['type'] == 'msg':
                seqno = chat_msg['seqno']
                ts = chat_msg['ts']
                ct_b64 = chat_msg['ct']
                sig_b64 = chat_msg['sig']
                
                # Verify signature
                ct_bytes = base64.b64decode(ct_b64)
                sig_bytes = base64.b64decode(sig_b64)
                
                # Compute hash: SHA256(seqno || ts || ct)
                hash_data = f"{seqno}{ts}".encode() + ct_bytes
                computed_hash = sign.compute_sha256(hash_data)
                
                # Verify with client's public key
                client_pubkey = self.client_cert.public_key()
                if not sign.verify_signature(client_pubkey, computed_hash, sig_bytes):
                    print(f"[!] Message {seqno} signature verification failed!")
                    return
                
                # Decrypt message
                iv_and_ct = ct_bytes
                iv = iv_and_ct[:16]
                ciphertext = iv_and_ct[16:]
                plaintext = aes.aes_decrypt(self.session_key, iv, ciphertext)
                
                print(f"\n[Client @ {datetime.fromtimestamp(ts/1000).strftime('%H:%M:%S')}]: {plaintext.decode()}")
                
                # Log to transcript
                client_cert_fingerprint = sign.compute_sha256_hex(self.client_cert.public_bytes(
                    encoding=serialization.Encoding.DER
                ))
                self.transcript_mgr.append_message(seqno, ts, ct_b64, sig_b64, client_cert_fingerprint)
                
        except Exception as e:
            print(f"[!] Error handling message: {e}")
            import traceback
            traceback.print_exc()
    
    def close_session(self, sock):
        """
        Phase 5: Generate and exchange session receipt
        """
        if self.transcript_mgr and self.transcript_mgr.messages:
            print("\n[*] Generating session receipt...")
            
            first_seq = self.transcript_mgr.get_first_seq()
            last_seq = self.transcript_mgr.get_last_seq()
            
            receipt = self.transcript_mgr.create_session_receipt(
                "server",
                first_seq,
                last_seq,
                self.server_key
            )
            
            # Save receipt
            self.transcript_mgr.save_receipt(receipt)
            print(f"[+] Session receipt generated: {receipt['transcript_sha256'][:16]}...")
            
            # Send receipt to client
            try:
                utils.send_message(sock, protocol.serialize_message(receipt))
            except:
                pass
        
        if self.transcript_mgr:
            self.transcript_mgr.close_session()
        
        print("[*] Session closed")

def main():
    import sys
    
    # Parse command line arguments
    host = '0.0.0.0'
    port = 8888
    
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    
    try:
        server = SecureChatServer(host=host, port=port)
        server.start()
    except Exception as e:
        print(f"[!] Server error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
