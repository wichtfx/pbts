#!/usr/bin/env python3
"""
Persistent BitTorrent Tracker System (PBTS)
"""

from flask import Flask, request, Response, jsonify
import bencoder
import hashlib
import time
import secrets
from dataclasses import dataclass, field
from typing import Dict, Set, Optional, List, Tuple
from collections import defaultdict
from urllib.parse import parse_qs, quote_from_bytes
import logging
import base64
import json

# BLS Signatures (BLS12-381 curve)
from py_ecc.bls import G2ProofOfPossession as bls

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# Cryptographic Helper Functions (BLS12-381)
# ============================================================================

def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate BLS keypair for signing/verification.
    Returns (private_key, public_key) as bytes.
    Uses BLS12-381 curve with G2 signatures (proof of possession).
    """
    # BLS12-381 curve order (private key must be in range [1, CURVE_ORDER))
    CURVE_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513
    
    # Generate a valid private key by reducing random bytes modulo curve order
    while True:
        private_key_bytes = secrets.token_bytes(32)
        private_key_int = int.from_bytes(private_key_bytes, 'big')
        
        # Reduce modulo curve order and ensure it's not zero
        private_key_int = private_key_int % CURVE_ORDER
        if private_key_int != 0:
            break
    
    # Convert back to bytes (ensure 32-byte representation)
    private_key_bytes = private_key_int.to_bytes(32, 'big')
    
    # Derive public key from private key
    public_key = bls.SkToPk(private_key_int)
    
    return private_key_bytes, public_key


def sign_message(private_key_bytes: bytes, message: bytes) -> bytes:
    """
    Sign a message with BLS private key.
    Returns signature (96 bytes).
    """
    # Convert bytes to integer for py-ecc
    private_key_int = int.from_bytes(private_key_bytes, 'big')
    signature = bls.Sign(private_key_int, message)
    return signature


def verify_signature(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify BLS signature. Returns True if valid, False otherwise.
    """
    try:
        return bls.Verify(public_key_bytes, message, signature)
    except Exception:
        return False


def aggregate_signatures(signatures: List[bytes]) -> bytes:
    """
    Aggregate multiple BLS signatures into one.
    This is the key advantage of BLS - constant size proof!
    """
    if not signatures:
        raise ValueError("Cannot aggregate empty signature list")
    return bls.Aggregate(signatures)


def aggregate_verify(
    public_keys: List[bytes],
    messages: List[bytes],
    aggregate_signature: bytes
) -> bool:
    """
    Verify an aggregate signature against multiple public keys and messages.
    This is MUCH faster than verifying each signature individually!
    
    Returns True if the aggregate signature is valid for all (pk, msg) pairs.
    """
    try:
        return bls.AggregateVerify(public_keys, messages, aggregate_signature)
    except Exception:
        return False


def hash_piece(piece_data: bytes) -> bytes:
    """SHA1 hash of a piece (standard BitTorrent)."""
    return hashlib.sha1(piece_data).digest()


# ============================================================================
# PBTS Attestation Functions (Algorithms from Paper)
# ============================================================================

def attest_piece_transfer(
    receiver_private_key: bytes,
    sender_public_key: bytes,
    piece_hash: bytes,
    piece_index: int,
    infohash: bytes,
    timestamp: int
) -> bytes:
    """
    Generate cryptographic receipt for piece transfer (Attest algorithm).
    
    Args:
        receiver_private_key: Receiver's BLS private key (32 bytes)
        sender_public_key: Sender's BLS public key (48 bytes)
        piece_hash: SHA1 hash of the piece
        piece_index: Index of the piece in the torrent
        infohash: SHA1 hash of the torrent
        timestamp: Unix timestamp of transfer
        
    Returns:
        BLS signature (receipt) as bytes (96 bytes)
    """
    # Construct message: infohash || sender_pk || piece_hash || index || timestamp
    message = infohash + sender_public_key + piece_hash + piece_index.to_bytes(4, 'big') + timestamp.to_bytes(8, 'big')
    
    # Sign with receiver's key
    receipt = sign_message(receiver_private_key, message)
    return receipt


def verify_receipt(
    receiver_public_key: bytes,
    sender_public_key: bytes,
    piece_hash: bytes,
    piece_index: int,
    infohash: bytes,
    timestamp: int,
    receipt: bytes
) -> bool:
    """
    Verify cryptographic receipt (Verify algorithm).
    
    Returns True if receipt is valid, False otherwise.
    """
    # Reconstruct the message that was signed
    message = infohash + sender_public_key + piece_hash + piece_index.to_bytes(4, 'big') + timestamp.to_bytes(8, 'big')
    
    # Verify BLS signature
    return verify_signature(receiver_public_key, message, receipt)


# ============================================================================
# PBTS Attestation Functions (Algorithms from Paper)
# ============================================================================

def attest_piece_transfer(
    receiver_private_key: bytes,
    sender_public_key: bytes,
    piece_hash: bytes,
    piece_index: int,
    infohash: bytes,
    timestamp: int
) -> bytes:
    """
    Generate cryptographic receipt for piece transfer (Attest algorithm).
    
    Args:
        receiver_private_key: Receiver's private key (PEM format)
        sender_public_key: Sender's public key (PEM format)
        piece_hash: SHA1 hash of the piece
        piece_index: Index of the piece in the torrent
        infohash: SHA1 hash of the torrent
        timestamp: Unix timestamp of transfer
        
    Returns:
        Signature (receipt) as bytes
    """
    # Construct message: infohash || sender_pk || piece_hash || index || timestamp
    message = infohash + sender_public_key + piece_hash + piece_index.to_bytes(4, 'big') + timestamp.to_bytes(8, 'big')
    
    # Sign with receiver's key
    receipt = sign_message(receiver_private_key, message)
    return receipt


def verify_receipt(
    receiver_public_key: bytes,
    sender_public_key: bytes,
    piece_hash: bytes,
    piece_index: int,
    infohash: bytes,
    timestamp: int,
    receipt: bytes
) -> bool:
    """
    Verify cryptographic receipt (Verify algorithm).
    
    Returns True if receipt is valid, False otherwise.
    """
    # Reconstruct the message that was signed
    message = infohash + sender_public_key + piece_hash + piece_index.to_bytes(4, 'big') + timestamp.to_bytes(8, 'big')
    
    # Verify signature
    return verify_signature(receiver_public_key, message, receipt)


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class Peer:
    """Represents a peer in the swarm"""
    peer_id: bytes
    ip: str
    port: int
    user_id: Optional[str] = None
    public_key: Optional[str] = None
    last_seen: float = field(default_factory=time.time)
    uploaded: int = 0
    downloaded: int = 0
    left: int = 0


@dataclass
class User:
    """Represents a registered user with reputation"""
    user_id: str
    public_key: str
    total_uploaded: int = 0
    total_downloaded: int = 0
    registered_at: float = field(default_factory=time.time)
    
    @property
    def ratio(self) -> float:
        """Calculate upload/download ratio"""
        if self.total_downloaded == 0:
            return float('inf') if self.total_uploaded > 0 else 1.0
        return self.total_uploaded / self.total_downloaded


class TrackerState:
    """Manages tracker state (in-memory, can be extended to use smart contracts)"""
    
    def __init__(self):
        # Swarms: infohash -> Set[Peer]
        self.swarms: Dict[bytes, Dict[str, Peer]] = defaultdict(dict)
        
        # Users: user_id -> User
        self.users: Dict[str, User] = {}
        
        # Receipt tracking for double-spend prevention
        # receipt_id -> timestamp of when it was used
        self.used_receipts: Dict[str, float] = {}
        
        # Receipt acceptance window (in seconds)
        self.receipt_window = 3600  # 1 hour
        
        # Garbage collection: remove old receipts periodically
        self.last_gc_time = time.time()
        self.gc_interval = 300  # 5 minutes
        
        # Instance ID (tracker identifier)
        self.instance_id = secrets.token_hex(32)
        
        # Signature verification disabled by default for backward compatibility
        # Enable with: POST /config {"verify_signatures": true}
        self.verify_signatures = False
        
    def add_peer(self, infohash: bytes, peer: Peer):
        """Add or update peer in swarm"""
        peer_key = f"{peer.ip}:{peer.port}"
        self.swarms[infohash][peer_key] = peer
        
    def remove_peer(self, infohash: bytes, peer_ip: str, peer_port: int):
        """Remove peer from swarm"""
        peer_key = f"{peer_ip}:{peer_port}"
        if infohash in self.swarms:
            self.swarms[infohash].pop(peer_key, None)
            
    def get_peers(self, infohash: bytes, max_peers: int = 50) -> List[Peer]:
        """Get list of peers for a torrent"""
        if infohash not in self.swarms:
            return []
        peers = list(self.swarms[infohash].values())
        # Filter out stale peers (not seen in 30 minutes)
        current_time = time.time()
        active_peers = [p for p in peers if current_time - p.last_seen < 1800]
        return active_peers[:max_peers]
    
    def register_user(self, user_id: str, public_key: str) -> bool:
        """Register a new user (implements Register algorithm)"""
        if user_id in self.users:
            return False
        self.users[user_id] = User(user_id=user_id, public_key=public_key)
        logger.info(f"Registered user: {user_id}")
        return True
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return self.users.get(user_id)
    
    def update_user_stats(self, user_id: str, uploaded_delta: int, downloaded_delta: int):
        """Update user statistics (implements Report algorithm)"""
        user = self.get_user(user_id)
        if user:
            user.total_uploaded += uploaded_delta
            user.total_downloaded += downloaded_delta
            logger.info(f"Updated stats for {user_id}: +{uploaded_delta}↑ +{downloaded_delta}↓ (ratio: {user.ratio:.2f})")
    
    def is_receipt_used(self, receipt_id: str) -> bool:
        """Check if a receipt has already been used."""
        return receipt_id in self.used_receipts
    
    def mark_receipt_used(self, receipt_id: str):
        """Mark a receipt as used with current timestamp."""
        self.used_receipts[receipt_id] = time.time()
        
    def garbage_collect_receipts(self):
        """Remove old receipts to prevent memory bloat."""
        current_time = time.time()
        
        # Only run GC periodically
        if current_time - self.last_gc_time < self.gc_interval:
            return
        
        self.last_gc_time = current_time
        
        # Remove receipts older than the acceptance window
        old_receipts = [
            rid for rid, timestamp in self.used_receipts.items()
            if current_time - timestamp > self.receipt_window * 2
        ]
        
        for rid in old_receipts:
            del self.used_receipts[rid]
        
        if old_receipts:
            logger.info(f"Garbage collected {len(old_receipts)} old receipts")


# Initialize tracker state
state = TrackerState()

# Flask app
app = Flask(__name__)
app.config['MIN_RATIO'] = 0.5  # Minimum ratio to download
app.config['MAX_PEERS'] = 50   # Maximum peers returned


def get_binary_param(param_name: bytes) -> bytes:
    """
    Extract binary parameter from request query string.
    BitTorrent uses raw binary data (not text!) for info_hash and peer_id.
    We parse the raw query string to preserve bytes without encoding conversions.
    """
    params = parse_qs(request.query_string)
    return params.get(param_name, [b''])[0]


# ============================================================================
# Standard BitTorrent Endpoints
# ============================================================================

@app.route('/announce')
def announce():
    """
    Standard BitTorrent announce endpoint with PBTS extensions
    Implements the Announce algorithm from the paper
    """
    try:
        # Parse binary parameters (info_hash and peer_id are 20-byte binary values)
        info_hash = get_binary_param(b'info_hash')
        peer_id = get_binary_param(b'peer_id')
        
        # Get regular text parameters
        port = int(request.args.get('port', 0))
        uploaded = int(request.args.get('uploaded', 0))
        downloaded = int(request.args.get('downloaded', 0))
        left = int(request.args.get('left', 0))
        event = request.args.get('event', '')
        compact = int(request.args.get('compact', 1))  # BEP 23: default to compact
        numwant = int(request.args.get('numwant', app.config['MAX_PEERS']))
        no_peer_id = int(request.args.get('no_peer_id', 0))
        
        # PBTS extensions (optional)
        user_id = request.args.get('user_id', '')
        public_key = request.args.get('public_key', '')
        signature = request.args.get('signature', '')
        
        # Validate required parameters
        if len(info_hash) != 20:
            return Response(bencoder.encode({b'failure reason': b'Invalid info_hash'}), mimetype='text/plain')
        
        if port <= 0 or port > 65535:
            return Response(bencoder.encode({b'failure reason': b'Invalid port'}), mimetype='text/plain')
        
        # Get client IP
        ip = request.headers.get('X-Real-IP', request.remote_addr)
        
        # Check ratio requirements for new downloads (PBTS feature)
        if event == 'started' and user_id:
            user = state.get_user(user_id)
            if user and user.ratio < app.config['MIN_RATIO']:
                failure_msg = f'Insufficient ratio: {user.ratio:.2f} < {app.config["MIN_RATIO"]}'.encode()
                return Response(bencoder.encode({b'failure reason': failure_msg}), mimetype='text/plain')
        
        # Create or update peer
        peer = Peer(
            peer_id=peer_id,
            ip=ip,
            port=port,
            user_id=user_id if user_id else None,
            public_key=public_key if public_key else None,
            uploaded=uploaded,
            downloaded=downloaded,
            left=left
        )
        
        # Handle events
        if event == 'stopped':
            state.remove_peer(info_hash, ip, port)
            logger.info(f"Peer stopped: {ip}:{port} for {info_hash.hex()[:8]}")
        else:
            state.add_peer(info_hash, peer)
            logger.info(f"Peer announced: {ip}:{port} for {info_hash.hex()[:8]} (event: {event or 'none'})")
        
        # Get peer list
        peers = state.get_peers(info_hash, numwant)
        
        # Build peer list based on compact parameter (BEP 23)
        if compact == 1:
            # Compact format: binary string of 6-byte peer entries (4-byte IP + 2-byte port)
            peer_bytes = b''
            for p in peers:
                if p.ip != ip or p.port != port:  # Exclude announcing peer
                    try:
                        # Convert IP address to 4 bytes
                        ip_parts = [int(x) for x in p.ip.split('.')]
                        if len(ip_parts) == 4:
                            ip_bytes = bytes(ip_parts)
                            port_bytes = p.port.to_bytes(2, 'big')
                            peer_bytes += ip_bytes + port_bytes
                    except (ValueError, AttributeError):
                        # Skip invalid IPs (e.g., IPv6 or malformed)
                        continue
            peer_list = peer_bytes
        else:
            # Dictionary format: list of peer dictionaries
            peer_list = []
            for p in peers:
                if p.ip != ip or p.port != port:  # Exclude announcing peer
                    peer_dict = {
                        b'ip': p.ip.encode(),
                        b'port': p.port
                    }
                    # Include peer_id unless no_peer_id is set
                    if not no_peer_id:
                        peer_dict[b'peer id'] = p.peer_id
                    peer_list.append(peer_dict)
        
        # Build response
        response = {
            b'interval': 1800,  # 30 minutes
            b'min interval': 900,  # 15 minutes
            b'tracker id': state.instance_id.encode(),
            b'complete': sum(1 for p in peers if p.left == 0),
            b'incomplete': sum(1 for p in peers if p.left > 0),
            b'peers': peer_list
        }
        
        return Response(bencoder.encode(response), mimetype='text/plain')
        
    except Exception as e:
        logger.error(f"Announce error: {e}", exc_info=True)
        return Response(bencoder.encode({b'failure reason': str(e).encode()}), mimetype='text/plain')


@app.route('/scrape')
def scrape():
    """Standard BitTorrent scrape endpoint"""
    try:
        # Parse binary info_hash parameters (can appear multiple times)
        params_bytes = parse_qs(request.query_string)
        info_hashes = params_bytes.get(b'info_hash', [])
        
        files = {}
        for info_hash in info_hashes:
            if len(info_hash) == 20:
                peers = state.get_peers(info_hash)
                files[info_hash] = {
                    b'complete': sum(1 for p in peers if p.left == 0),
                    b'incomplete': sum(1 for p in peers if p.left > 0),
                    b'downloaded': 0  # We don't track this
                }
        
        response = {b'files': files}
        return Response(bencoder.encode(response), mimetype='text/plain')
        
    except Exception as e:
        logger.error(f"Scrape error: {e}", exc_info=True)
        return Response(bencoder.encode({b'failure reason': str(e).encode()}), mimetype='text/plain')


# ============================================================================
# PBTS Extension Endpoints
# ============================================================================

@app.route('/register', methods=['POST'])
def register():
    """
    PBTS user registration endpoint
    Implements the Register algorithm from the paper
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        public_key = data.get('public_key')  # Base64-encoded PEM
        signature = data.get('signature')     # Base64-encoded signature
        
        if not user_id or not public_key:
            return jsonify({'success': False, 'error': 'Missing user_id or public_key'}), 400
        
        # Verify signature if provided and verification is enabled
        if signature and state.verify_signatures:
            try:
                public_key_bytes = base64.b64decode(public_key)
                signature_bytes = base64.b64decode(signature)
                
                # Construct message: "register" || instance_id || user_id
                message = b"register" + state.instance_id.encode() + user_id.encode()
                
                # Verify BLS signature
                if not verify_signature(public_key_bytes, message, signature_bytes):
                    return jsonify({'success': False, 'error': 'Invalid signature'}), 401
                
                logger.info(f"Verified BLS signature for user registration: {user_id}")
                
            except Exception as e:
                logger.error(f"Signature verification error: {e}")
                return jsonify({'success': False, 'error': 'Invalid signature format'}), 401
        elif state.verify_signatures and not signature:
            logger.warning(f"Registration without signature for {user_id} (verification enabled but no signature provided)")
        
        # If signature verification is disabled or no signature provided, allow registration
        # (public_key is stored as-is for future use)
        
        # Register user (store base64-encoded public key for convenience)
        success = state.register_user(user_id, public_key)
        
        if success:
            return jsonify({
                'success': True,
                'instance_id': state.instance_id,
                'message': 'User registered successfully'
            })
        else:
            return jsonify({'success': False, 'error': 'User already exists'}), 409
            
    except Exception as e:
        logger.error(f"Registration error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/report', methods=['POST'])
def report():
    """
    PBTS statistics reporting endpoint with receipt verification
    Implements the Report algorithm from the paper
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        public_key = data.get('public_key')  # Base64-encoded
        uploaded_delta = int(data.get('uploaded_delta', 0))
        downloaded_delta = int(data.get('downloaded_delta', 0))
        receipts = data.get('receipts', [])  # List of receipt objects
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Missing user_id'}), 400
        
        # Verify user exists
        user = state.get_user(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not registered'}), 404
        
        # Run garbage collection on old receipts
        state.garbage_collect_receipts()
        
        # Verify receipts if provided
        verified_upload = 0
        verified_download = 0
        
        if receipts and state.verify_signatures:
            try:
                # Try to decode sender's public key
                try:
                    sender_pk = base64.b64decode(public_key or user.public_key)
                except Exception as e:
                    logger.warning(f"Could not decode sender public key: {e}")
                    # Skip receipt verification if key can't be decoded
                    state.update_user_stats(user_id, uploaded_delta, downloaded_delta)
                    return jsonify({
                        'success': True,
                        'total_uploaded': user.total_uploaded,
                        'total_downloaded': user.total_downloaded,
                        'ratio': user.ratio,
                        'verified_receipts': 0,
                        'warning': 'Receipt verification skipped due to invalid key format'
                    })
                
                # Collect all receipts for batch verification
                valid_receipts = []
                public_keys_for_agg = []
                messages_for_agg = []
                signatures_for_agg = []
                
                for receipt_data in receipts:
                    # Extract receipt fields
                    receiver_pk_b64 = receipt_data.get('receiver_public_key')
                    piece_hash_hex = receipt_data.get('piece_hash')
                    piece_index = receipt_data.get('piece_index')
                    infohash_hex = receipt_data.get('infohash')
                    timestamp = receipt_data.get('timestamp')
                    receipt_sig_b64 = receipt_data.get('signature')
                    piece_size = receipt_data.get('piece_size', 16384)  # Default 16KB
                    
                    if not all([receiver_pk_b64, piece_hash_hex, piece_index is not None, 
                               infohash_hex, timestamp, receipt_sig_b64]):
                        logger.warning(f"Incomplete receipt data from {user_id}")
                        continue
                    
                    try:
                        # Decode receipt components
                        receiver_pk = base64.b64decode(receiver_pk_b64)
                        piece_hash = bytes.fromhex(piece_hash_hex)
                        infohash = bytes.fromhex(infohash_hex)
                        receipt_sig = base64.b64decode(receipt_sig_b64)
                        
                        # Check timestamp is recent (within acceptance window)
                        current_time = int(time.time())
                        if abs(current_time - timestamp) > state.receipt_window:
                            logger.warning(f"Receipt expired for {user_id}: {current_time - timestamp}s old")
                            continue
                        
                        # Generate receipt ID for double-spend check
                        receipt_id = hashlib.sha256(
                            infohash + sender_pk + receiver_pk + 
                            piece_hash + piece_index.to_bytes(4, 'big')
                        ).hexdigest()
                        
                        # Check if receipt already used
                        if state.is_receipt_used(receipt_id):
                            logger.warning(f"Receipt already used: {receipt_id[:16]}...")
                            continue
                        
                        # Reconstruct the message that was signed
                        message = infohash + sender_pk + piece_hash + piece_index.to_bytes(4, 'big') + timestamp.to_bytes(8, 'big')
                        
                        # Store for batch verification
                        valid_receipts.append({
                            'receipt_id': receipt_id,
                            'piece_size': piece_size
                        })
                        public_keys_for_agg.append(receiver_pk)
                        messages_for_agg.append(message)
                        signatures_for_agg.append(receipt_sig)
                        
                    except Exception as e:
                        logger.warning(f"Error processing receipt: {e}")
                        continue
                
                # Batch verify all receipts using BLS aggregate verification
                if valid_receipts:
                    try:
                        # Aggregate all signatures
                        aggregate_sig = aggregate_signatures(signatures_for_agg)
                        
                        # Verify all at once (MUCH faster than individual verification!)
                        if aggregate_verify(public_keys_for_agg, messages_for_agg, aggregate_sig):
                            # All receipts are valid!
                            for receipt_info in valid_receipts:
                                state.mark_receipt_used(receipt_info['receipt_id'])
                                verified_upload += receipt_info['piece_size']
                                verified_download += receipt_info['piece_size']
                            
                            logger.info(f"Batch verified {len(valid_receipts)} receipts for {user_id} "
                                      f"({verified_upload} bytes upload, {verified_download} bytes download)")
                        else:
                            logger.warning(f"Aggregate signature verification failed for {user_id}")
                            # Don't credit any receipts if aggregate verification fails
                    except Exception as e:
                        logger.error(f"Batch verification error: {e}", exc_info=True)
                
                # If receipts were provided, use only verified amounts
                if len(receipts) > 0:
                    uploaded_delta = verified_upload
                    downloaded_delta = verified_download
                    
            except Exception as e:
                logger.error(f"Receipt verification error: {e}", exc_info=True)
                return jsonify({'success': False, 'error': f'Receipt verification failed: {str(e)}'}), 400
        
        # Update user statistics
        state.update_user_stats(user_id, uploaded_delta, downloaded_delta)
        
        return jsonify({
            'success': True,
            'total_uploaded': user.total_uploaded,
            'total_downloaded': user.total_downloaded,
            'ratio': user.ratio,
            'verified_receipts': len(receipts) if receipts else 0
        })
        
    except Exception as e:
        logger.error(f"Report error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/stats')
def stats():
    """Get tracker statistics"""
    total_torrents = len(state.swarms)
    total_peers = sum(len(peers) for peers in state.swarms.values())
    total_users = len(state.users)
    
    return jsonify({
        'instance_id': state.instance_id,
        'total_torrents': total_torrents,
        'total_peers': total_peers,
        'total_users': total_users,
        'min_ratio': app.config['MIN_RATIO']
    })


@app.route('/user/<user_id>')
def get_user_info(user_id: str):
    """Get user information and reputation"""
    user = state.get_user(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'user_id': user.user_id,
        'public_key': user.public_key,
        'total_uploaded': user.total_uploaded,
        'total_downloaded': user.total_downloaded,
        'ratio': user.ratio,
        'registered_at': user.registered_at
    })


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy', 
        'instance_id': state.instance_id,
        'signature_verification': state.verify_signatures
    })


# ============================================================================
# PBTS Cryptographic API Endpoints
# ============================================================================

@app.route('/keygen', methods=['POST'])
def keygen():
    """
    Generate a new BLS keypair for testing.
    In production, clients should generate their own keys securely.
    
    BLS12-381 keys:
    - Private key: 32 bytes
    - Public key: 48 bytes  
    - Signature: 96 bytes
    """
    try:
        private_key, public_key = generate_keypair()
        
        return jsonify({
            'success': True,
            'private_key': base64.b64encode(private_key).decode(),
            'public_key': base64.b64encode(public_key).decode(),
            'key_type': 'BLS12-381',
            'private_key_size': len(private_key),
            'public_key_size': len(public_key),
            'warning': 'Store private key securely! Never share it!'
        })
    except Exception as e:
        logger.error(f"Keygen error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/attest', methods=['POST'])
def attest():
    """
    Generate a cryptographic receipt for piece transfer (Attest algorithm).
    This would typically be called by the receiving peer.
    """
    try:
        data = request.get_json()
        
        # Extract parameters
        receiver_private_key_b64 = data.get('receiver_private_key')
        sender_public_key_b64 = data.get('sender_public_key')
        piece_hash_hex = data.get('piece_hash')
        piece_index = data.get('piece_index')
        infohash_hex = data.get('infohash')
        timestamp = data.get('timestamp', int(time.time()))
        
        if not all([receiver_private_key_b64, sender_public_key_b64, 
                   piece_hash_hex, piece_index is not None, infohash_hex]):
            return jsonify({'success': False, 'error': 'Missing required parameters'}), 400
        
        # Decode parameters
        receiver_sk = base64.b64decode(receiver_private_key_b64)
        sender_pk = base64.b64decode(sender_public_key_b64)
        piece_hash = bytes.fromhex(piece_hash_hex)
        infohash = bytes.fromhex(infohash_hex)
        
        # Generate receipt
        receipt = attest_piece_transfer(
            receiver_sk, sender_pk, piece_hash, 
            piece_index, infohash, timestamp
        )
        
        return jsonify({
            'success': True,
            'receipt': base64.b64encode(receipt).decode(),
            'timestamp': timestamp,
            'message': 'Receipt generated successfully'
        })
        
    except Exception as e:
        logger.error(f"Attest error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/verify-receipt', methods=['POST'])
def verify_receipt_endpoint():
    """
    Verify a cryptographic receipt (Verify algorithm).
    This can be called by anyone to verify a receipt.
    """
    try:
        data = request.get_json()
        
        # Extract parameters
        receiver_public_key_b64 = data.get('receiver_public_key')
        sender_public_key_b64 = data.get('sender_public_key')
        piece_hash_hex = data.get('piece_hash')
        piece_index = data.get('piece_index')
        infohash_hex = data.get('infohash')
        timestamp = data.get('timestamp')
        receipt_b64 = data.get('receipt')
        
        if not all([receiver_public_key_b64, sender_public_key_b64, 
                   piece_hash_hex, piece_index is not None, 
                   infohash_hex, timestamp, receipt_b64]):
            return jsonify({'success': False, 'error': 'Missing required parameters'}), 400
        
        # Decode parameters
        receiver_pk = base64.b64decode(receiver_public_key_b64)
        sender_pk = base64.b64decode(sender_public_key_b64)
        piece_hash = bytes.fromhex(piece_hash_hex)
        infohash = bytes.fromhex(infohash_hex)
        receipt = base64.b64decode(receipt_b64)
        
        # Verify receipt
        is_valid = verify_receipt(
            receiver_pk, sender_pk, piece_hash, 
            piece_index, infohash, timestamp, receipt
        )
        
        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': 'Receipt is valid' if is_valid else 'Receipt is invalid'
        })
        
    except Exception as e:
        logger.error(f"Verify receipt error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/config', methods=['GET', 'POST'])
def config():
    """
    Get or update tracker configuration.
    POST to enable/disable signature verification (for testing).
    """
    if request.method == 'POST':
        try:
            data = request.get_json()
            if 'verify_signatures' in data:
                state.verify_signatures = bool(data['verify_signatures'])
                logger.info(f"Signature verification: {state.verify_signatures}")
            
            if 'receipt_window' in data:
                state.receipt_window = int(data['receipt_window'])
                logger.info(f"Receipt window: {state.receipt_window}s")
            
            return jsonify({
                'success': True,
                'message': 'Configuration updated'
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
    
    # GET request - return current config
    return jsonify({
        'instance_id': state.instance_id,
        'verify_signatures': state.verify_signatures,
        'receipt_window': state.receipt_window,
        'min_ratio': app.config['MIN_RATIO'],
        'max_peers': app.config['MAX_PEERS'],
        'used_receipts_count': len(state.used_receipts)
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)
