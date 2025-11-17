"""Append-only transcript + TranscriptHash helpers."""
import os
import hashlib
from datetime import datetime
from ..crypto import sign

class TranscriptManager:
    """Manages append-only transcript logs and session receipts"""
    
    def __init__(self, transcript_dir='transcripts', peer_name='unknown'):
        """Initialize transcript manager"""
        self.transcript_dir = transcript_dir
        self.peer_name = peer_name
        self.transcript_file = None
        self.messages = []
        
        # Create transcripts directory if it doesn't exist
        if not os.path.exists(transcript_dir):
            os.makedirs(transcript_dir)
    
    def start_session(self, session_id):
        """Start new transcript session"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{session_id}_{timestamp}.txt"
        self.transcript_file = os.path.join(self.transcript_dir, filename)
        
        # Initialize empty transcript file
        with open(self.transcript_file, 'w') as f:
            f.write(f"# Transcript Session: {session_id}\n")
            f.write(f"# Peer: {self.peer_name}\n")
            f.write(f"# Started: {datetime.now().isoformat()}\n")
            f.write("# Format: seqno | timestamp | ciphertext | signature | peer_cert_fingerprint\n")
            f.write("#" + "="*80 + "\n")
    
    def append_message(self, seqno, timestamp, ciphertext_b64, signature_b64, peer_cert_fingerprint):
        """
        Append message to transcript (append-only)
        Format: seqno | ts | ct | sig | peer-cert-fingerprint
        """
        if not self.transcript_file:
            raise ValueError("No active transcript session")
        
        # Create transcript line
        line = f"{seqno}|{timestamp}|{ciphertext_b64}|{signature_b64}|{peer_cert_fingerprint}\n"
        
        # Append to file (append-only)
        with open(self.transcript_file, 'a') as f:
            f.write(line)
        
        # Keep in memory for hash computation
        self.messages.append(line.strip())
    
    def compute_transcript_hash(self):
        """
        Compute SHA-256 hash of entire transcript
        TranscriptHash = SHA256(concatenation of transcript lines)
        Returns: hash as hex string
        """
        # Read all message lines (skip header comments)
        transcript_content = ""
        
        if self.transcript_file and os.path.exists(self.transcript_file):
            with open(self.transcript_file, 'r') as f:
                for line in f:
                    if not line.startswith('#'):
                        transcript_content += line
        else:
            # Use in-memory messages
            transcript_content = '\n'.join(self.messages) + '\n'
        
        # Compute SHA-256
        return hashlib.sha256(transcript_content.encode()).hexdigest()
    
    def create_session_receipt(self, peer_type, first_seq, last_seq, private_key):
        """
        Create session receipt with signed transcript hash
        Returns: receipt dictionary
        """
        transcript_hash = self.compute_transcript_hash()
        
        # Sign the transcript hash
        signature = sign.sign_data(private_key, transcript_hash.encode())
        
        receipt = {
            "type": "receipt",
            "peer": peer_type,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": transcript_hash,
            "sig": signature.hex()
        }
        
        return receipt
    
    def verify_session_receipt(self, receipt, public_key):
        """
        Verify session receipt signature
        Returns: True if valid, False otherwise
        """
        try:
            transcript_hash = receipt["transcript_sha256"]
            signature = bytes.fromhex(receipt["sig"])
            
            # Verify signature
            return sign.verify_signature(public_key, transcript_hash.encode(), signature)
        except Exception as e:
            print(f"Receipt verification failed: {e}")
            return False
    
    def save_receipt(self, receipt):
        """Save session receipt to file"""
        if not self.transcript_file:
            return
        
        receipt_file = self.transcript_file.replace('.txt', '_receipt.txt')
        with open(receipt_file, 'w') as f:
            f.write(f"Session Receipt\n")
            f.write(f"Peer: {receipt['peer']}\n")
            f.write(f"First Sequence: {receipt['first_seq']}\n")
            f.write(f"Last Sequence: {receipt['last_seq']}\n")
            f.write(f"Transcript SHA256: {receipt['transcript_sha256']}\n")
            f.write(f"Signature: {receipt['sig']}\n")
    
    def get_first_seq(self):
        """Get first sequence number from transcript"""
        if not self.messages:
            return 0
        first_line = self.messages[0]
        return int(first_line.split('|')[0])
    
    def get_last_seq(self):
        """Get last sequence number from transcript"""
        if not self.messages:
            return 0
        last_line = self.messages[-1]
        return int(last_line.split('|')[0])
    
    def close_session(self):
        """Close transcript session"""
        if self.transcript_file:
            with open(self.transcript_file, 'a') as f:
                f.write("#" + "="*80 + "\n")
                f.write(f"# Session ended: {datetime.now().isoformat()}\n")
                f.write(f"# Total messages: {len(self.messages)}\n")
        
        self.transcript_file = None
