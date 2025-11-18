#!/usr/bin/env python3
"""
Persistent BitTorrent Tracker System (PBTS)
"""

from eth_account import Account
from web3 import Web3
from py_ecc.bls import G2ProofOfPossession as bls
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
import os

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()
load_dotenv('smartcontract/.env')

# Configure logging (must be before TEE import that uses logger)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# BLS Signatures (BLS12-381 curve)

# Web3 for smart contract interaction

# TEE Manager (optional - for TEE-backed operations)
try:
    from tee_manager import get_tee_manager, set_tee_mode, TEEMode, TEE_AVAILABLE

    # Read TEE mode from environment variable (default: disabled)
    tee_mode_str = os.getenv('TEE_MODE', 'disabled').lower()
    if tee_mode_str == 'enabled':
        tee_mode = TEEMode.ENABLED
    elif tee_mode_str == 'benchmark':
        tee_mode = TEEMode.BENCHMARK
    else:
        tee_mode = TEEMode.DISABLED

    tee_manager = get_tee_manager(tee_mode)
    # Note: TEE mode logging moved to main block to avoid confusion when imported as module
except ImportError:
    TEE_AVAILABLE = False
    tee_manager = None
    logger.warning("tee_manager not available - TEE features disabled")


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
    message = infohash + sender_public_key + piece_hash + \
        piece_index.to_bytes(4, 'big') + timestamp.to_bytes(8, 'big')

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
    message = infohash + sender_public_key + piece_hash + \
        piece_index.to_bytes(4, 'big') + timestamp.to_bytes(8, 'big')

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
    message = infohash + sender_public_key + piece_hash + \
        piece_index.to_bytes(4, 'big') + timestamp.to_bytes(8, 'big')

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
    message = infohash + sender_public_key + piece_hash + \
        piece_index.to_bytes(4, 'big') + timestamp.to_bytes(8, 'big')

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
            logger.info(
                f"Updated stats for {user_id}: +{uploaded_delta}↑ +{downloaded_delta}↓ (ratio: {user.ratio:.2f})")

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


# ============================================================================
# Smart Contract Configuration and Helper
# ============================================================================

class ContractManager:
    """Manages interaction with Reputation smart contracts"""

    def __init__(self):
        # Load configuration from environment variables
        # Default to local Anvil/Hardhat
        self.rpc_url = os.getenv('RPC', 'http://127.0.0.1:8545')
        self.factory_address = os.getenv(
            'FACTORY', '')  # ReputationFactory address

        # Initialize Web3
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))

        # Account setup - prefer TEE-derived key if available
        if TEE_AVAILABLE and tee_manager is not None and tee_manager.mode != TEEMode.DISABLED:
            try:
                # Get Ethereum account from TEE
                self.account = tee_manager.get_ethereum_account()
                self.private_key = ''  # Not stored when using TEE
                logger.info("Using TEE-derived Ethereum account")
            except Exception as e:
                logger.warning(
                    f"Failed to get TEE account, falling back to env var: {e}")
                self.private_key = os.getenv('PK0', '')
                if self.private_key:
                    self.account = Account.from_key(self.private_key)
                else:
                    self.account = None
        else:
            # Fallback to environment variable
            self.private_key = os.getenv('PK0', '')
            if self.private_key:
                self.account = Account.from_key(self.private_key)
            else:
                self.account = None

        # Current Reputation contract address (will be set after initialization)
        self.reputation_address = os.getenv('REPUTATION_ADDRESS', '')

        # Contract ABIs (simplified for prototype)
        self.factory_abi = [
            {
                "inputs": [
                    {"name": "_referrerReputation", "type": "address"},
                    {"name": "_attestation", "type": "bytes"}
                ],
                "name": "createReputation",
                "outputs": [{"name": "", "type": "address"}],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "anonymous": False,
                "inputs": [
                    {"indexed": False, "name": "newReputationAddress",
                        "type": "address"},
                    {"indexed": False, "name": "owner", "type": "address"},
                    {"indexed": False, "name": "referrer", "type": "address"},
                    {"indexed": False, "name": "attestation", "type": "bytes"}
                ],
                "name": "ReputationCreated",
                "type": "event"
            }
        ]

        self.reputation_abi = [
            {
                "inputs": [{"name": "_username", "type": "string"}],
                "name": "getUserData",
                "outputs": [{
                    "components": [
                        {"name": "username", "type": "string"},
                        {"name": "salt", "type": "string"},
                        {"name": "passwordHash", "type": "bytes32"},
                        {"name": "downloadSize", "type": "uint256"},
                        {"name": "uploadSize", "type": "uint256"}
                    ],
                    "name": "",
                    "type": "tuple"
                }],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {"name": "_username", "type": "string"},
                    {"name": "_salt", "type": "string"},
                    {"name": "_passwordHash", "type": "bytes32"},
                    {"name": "_downloadSize", "type": "uint256"},
                    {"name": "_uploadSize", "type": "uint256"}
                ],
                "name": "addUser",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [
                    {"name": "_username", "type": "string"},
                    {"name": "_downloadSize", "type": "uint256"},
                    {"name": "_uploadSize", "type": "uint256"}
                ],
                "name": "updateUser",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"name": "_username", "type": "string"}],
                "name": "migrateUserData",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "getOffchainDataUrl",
                "outputs": [{"name": "", "type": "string"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"name": "_offchainDataUrl", "type": "string"}],
                "name": "setOffchainDataUrl",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]

    def is_configured(self) -> bool:
        """Check if contract manager is properly configured"""
        has_account = self.account is not None
        has_factory = bool(self.factory_address)
        is_connected = self.w3.is_connected()

        logger.debug(
            f"is_configured check: account={has_account}, factory={has_factory}, connected={is_connected}")

        return has_account and has_factory and is_connected

    def create_reputation_contract(self, referrer_address: str = None) -> str:
        """Create a new Reputation contract via factory"""
        try:
            logger.info(">>> create_reputation_contract called")

            if not self.is_configured():
                raise Exception("Contract manager not configured")

            # Use zero address if no referrer specified
            if not referrer_address:
                referrer_address = "0x0000000000000000000000000000000000000000"

            logger.info(
                f"Creating factory contract instance at {self.factory_address}")

            # Create factory contract instance
            factory = self.w3.eth.contract(
                address=Web3.to_checksum_address(self.factory_address),
                abi=self.factory_abi
            )

            logger.info("Factory contract instance created")

            # Build transaction
            # Generate attestation - prefer TEE if available
            if TEE_AVAILABLE and tee_manager is not None and tee_manager.mode != TEEMode.DISABLED:
                try:
                    # Generate TEE attestation with contract creation details
                    payload = f"PBTS-Tracker-v1.0:factory={self.factory_address}:referrer={referrer_address}"
                    logger.info(
                        f"Generating TEE attestation for payload: {payload}")
                    attestation_report = tee_manager.generate_attestation(
                        payload)
                    attestation = attestation_report.quote.encode() if isinstance(
                        attestation_report.quote, str) else attestation_report.quote
                    logger.info(
                        f"Using TEE attestation (size: {attestation_report.quote_size_bytes} bytes)")
                except Exception as e:
                    logger.warning(
                        f"Failed to generate TEE attestation, using fallback: {e}")
                    attestation = b"PBTS-Tracker-v1.0"  # Simple attestation fallback
            else:
                logger.info(
                    "Using simple attestation (TEE disabled or unavailable)")
                attestation = b"PBTS-Tracker-v1.0"  # Simple attestation

            logger.info(
                f"Building transaction from account {self.account.address}")
            logger.info(
                f"Account balance: {self.w3.eth.get_balance(self.account.address)} wei")

            tx = factory.functions.createReputation(
                Web3.to_checksum_address(referrer_address),
                attestation
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 2000000,
                'gasPrice': self.w3.eth.gas_price
            })

            logger.info(
                f"Transaction built: gas={tx['gas']}, gasPrice={tx['gasPrice']}")

            # Sign and send transaction
            logger.info("Signing transaction...")
            signed_tx = self.account.sign_transaction(tx)

            logger.info("Sending raw transaction...")
            tx_hash = self.w3.eth.send_raw_transaction(
                signed_tx.raw_transaction)
            logger.info(f"Transaction sent: {tx_hash.hex()}")

            # Wait for transaction receipt
            logger.info("Waiting for transaction receipt...")
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            logger.info(
                f"Transaction receipt received: status={receipt['status']}")

            # Extract new contract address from event logs
            if receipt['logs'] and len(receipt['logs']) > 0:
                # Decode the ReputationCreated event
                event_log = receipt['logs'][0]
                decoded_event = factory.events.ReputationCreated().process_log(event_log)
                new_address = decoded_event['args']['newReputationAddress']

                # Update current reputation address
                self.reputation_address = new_address

                logger.info(
                    f"✅ Created Reputation contract at {new_address}, tx: {tx_hash.hex()}")

                return new_address
            else:
                raise Exception("No logs found in transaction receipt")

        except Exception as e:
            logger.error(
                f"❌ Error in create_reputation_contract: {e}", exc_info=True)
            raise

    def add_user_to_contract(self, username: str, salt: str, password_hash: str,
                             download_size: int = 0, upload_size: int = 0) -> str:
        """Add a new user to the Reputation contract"""
        if not self.reputation_address:
            raise Exception("No Reputation contract initialized")

        reputation = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.reputation_address),
            abi=self.reputation_abi
        )

        # Convert password hash to bytes32
        # Remove 0x prefix and validate hex string
        hash_hex = password_hash.replace('0x', '').replace('0X', '')

        # Validate that it's valid hex (only contains 0-9, a-f, A-F)
        try:
            # If shorter than 64 chars, pad with zeros on the left
            hash_hex = hash_hex.zfill(64)
            password_hash_bytes = bytes.fromhex(hash_hex)
        except ValueError as e:
            raise Exception(
                f"Invalid password_hash format. Must be a hex string (e.g., '0xabcdef123...'). Error: {e}")

        tx = reputation.functions.addUser(
            username,
            salt,
            password_hash_bytes,
            download_size,
            upload_size
        ).build_transaction({
            'from': self.account.address,
            'nonce': self.w3.eth.get_transaction_count(self.account.address),
            'gas': 500000,
            'gasPrice': self.w3.eth.gas_price
        })

        signed_tx = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        return tx_hash.hex()

    def get_user_from_contract(self, username: str) -> dict:
        """Get user data from Reputation contract"""
        if not self.reputation_address:
            raise Exception("No Reputation contract initialized")

        reputation = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.reputation_address),
            abi=self.reputation_abi
        )

        user_data = reputation.functions.getUserData(username).call()

        return {
            'username': user_data[0],
            'salt': user_data[1],
            'passwordHash': '0x' + user_data[2].hex(),
            'downloadSize': user_data[3],
            'uploadSize': user_data[4],
            'ratio': user_data[4] / user_data[3] if user_data[3] > 0 else float('inf')
        }

    def update_user_on_contract(self, username: str, download_size: int, upload_size: int) -> str:
        """Update user statistics on Reputation contract"""
        if not self.reputation_address:
            raise Exception("No Reputation contract initialized")

        reputation = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.reputation_address),
            abi=self.reputation_abi
        )

        tx = reputation.functions.updateUser(
            username,
            download_size,
            upload_size
        ).build_transaction({
            'from': self.account.address,
            'nonce': self.w3.eth.get_transaction_count(self.account.address),
            'gas': 200000,
            'gasPrice': self.w3.eth.gas_price
        })

        signed_tx = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        return tx_hash.hex()

    def migrate_user_data(self, username: str) -> str:
        """Migrate user data from referrer contract"""
        if not self.reputation_address:
            raise Exception("No Reputation contract initialized")

        reputation = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.reputation_address),
            abi=self.reputation_abi
        )

        tx = reputation.functions.migrateUserData(username).build_transaction({
            'from': self.account.address,
            'nonce': self.w3.eth.get_transaction_count(self.account.address),
            'gas': 300000,
            'gasPrice': self.w3.eth.gas_price
        })

        signed_tx = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        return tx_hash.hex()


# Initialize contract manager
contract_manager = ContractManager()

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
        # BEP 23: default to compact
        compact = int(request.args.get('compact', 1))
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
                failure_msg = f'Insufficient ratio: {user.ratio:.2f} < {app.config["MIN_RATIO"]}'.encode(
                )
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
            logger.info(
                f"Peer announced: {ip}:{port} for {info_hash.hex()[:8]} (event: {event or 'none'})")

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

                logger.info(
                    f"Verified BLS signature for user registration: {user_id}")

            except Exception as e:
                logger.error(f"Signature verification error: {e}")
                return jsonify({'success': False, 'error': 'Invalid signature format'}), 401
        elif state.verify_signatures and not signature:
            logger.warning(
                f"Registration without signature for {user_id} (verification enabled but no signature provided)")

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
                    state.update_user_stats(
                        user_id, uploaded_delta, downloaded_delta)
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
                    piece_size = receipt_data.get(
                        'piece_size', 16384)  # Default 16KB

                    if not all([receiver_pk_b64, piece_hash_hex, piece_index is not None,
                               infohash_hex, timestamp, receipt_sig_b64]):
                        logger.warning(
                            f"Incomplete receipt data from {user_id}")
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
                            logger.warning(
                                f"Receipt expired for {user_id}: {current_time - timestamp}s old")
                            continue

                        # Generate receipt ID for double-spend check
                        receipt_id = hashlib.sha256(
                            infohash + sender_pk + receiver_pk +
                            piece_hash + piece_index.to_bytes(4, 'big')
                        ).hexdigest()

                        # Check if receipt already used
                        if state.is_receipt_used(receipt_id):
                            logger.warning(
                                f"Receipt already used: {receipt_id[:16]}...")
                            continue

                        # Reconstruct the message that was signed
                        message = infohash + sender_pk + piece_hash + \
                            piece_index.to_bytes(
                                4, 'big') + timestamp.to_bytes(8, 'big')

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
                        aggregate_sig = aggregate_signatures(
                            signatures_for_agg)

                        # Verify all at once (MUCH faster than individual verification!)
                        if aggregate_verify(public_keys_for_agg, messages_for_agg, aggregate_sig):
                            # All receipts are valid!
                            for receipt_info in valid_receipts:
                                state.mark_receipt_used(
                                    receipt_info['receipt_id'])
                                verified_upload += receipt_info['piece_size']
                                verified_download += receipt_info['piece_size']

                            logger.info(f"Batch verified {len(valid_receipts)} receipts for {user_id} "
                                        f"({verified_upload} bytes upload, {verified_download} bytes download)")
                        else:
                            logger.warning(
                                f"Aggregate signature verification failed for {user_id}")
                            # Don't credit any receipts if aggregate verification fails
                    except Exception as e:
                        logger.error(
                            f"Batch verification error: {e}", exc_info=True)

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


@app.route('/keygen-tee', methods=['POST'])
def keygen_tee():
    """
    Generate a TEE-derived BLS keypair.
    Key is derived from TEE's root of trust using dstack_sdk.

    Returns same format as /keygen but with TEE attestation.
    """
    if not TEE_AVAILABLE or tee_manager is None:
        return jsonify({
            'success': False,
            'error': 'TEE not available - install dstack_sdk'
        }), 503

    try:
        # Generate TEE-derived keypair
        keypair = tee_manager.generate_keypair(tee_enabled=True)

        return jsonify({
            'success': True,
            'private_key': base64.b64encode(keypair.private_key).decode(),
            'public_key': base64.b64encode(keypair.public_key).decode(),
            'key_type': 'BLS12-381 (TEE-derived)',
            'private_key_size': len(keypair.private_key),
            'public_key_size': len(keypair.public_key),
            'tee_derived': True,
            'derivation_time_ms': keypair.derivation_time_ms,
            'warning': 'Store private key securely! Never share it!'
        })
    except Exception as e:
        logger.error(f"TEE keygen error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/generate-attestation', methods=['POST'])
def generate_attestation():
    """
    Generate TEE attestation report (TDX quote).

    Request JSON:
        {
            "payload": "data to attest (e.g., user_id, registration message)"
        }

    Response:
        {
            "success": true,
            "quote": "...",
            "generation_time_ms": 42.5,
            "payload": "...",
            "quote_size_bytes": 1234
        }
    """
    if not TEE_AVAILABLE or tee_manager is None:
        return jsonify({
            'success': False,
            'error': 'TEE not available - install dstack_sdk'
        }), 503

    try:
        data = request.get_json()
        payload = data.get('payload')

        if not payload:
            return jsonify({'success': False, 'error': 'Missing payload'}), 400

        # Generate attestation
        attestation = tee_manager.generate_attestation(payload)

        return jsonify({
            'success': True,
            'quote': attestation.quote,
            'generation_time_ms': attestation.generation_time_ms,
            'payload': attestation.payload,
            'quote_size_bytes': attestation.quote_size_bytes
        })

    except Exception as e:
        logger.error(f"Attestation generation error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/verify-attestation', methods=['POST'])
def verify_attestation():
    """
    Verify TEE attestation report using DCAP QVL.

    This endpoint performs full cryptographic verification of TDX/SGX quotes:
    - Validates Intel/AMD signature chains
    - Checks TCB (Trusted Computing Base) status
    - Verifies payload inclusion in report_data

    Request JSON:
        {
            "quote": "TDX/SGX quote (hex string or bytes)",
            "expected_payload": "expected payload in quote",
            "pccs_url": "optional PCCS URL for collateral (defaults to Intel PCS)"
        }

    Response:
        {
            "success": true,
            "is_valid": true/false,
            "verification_time_ms": 150.5
        }
    """
    if not TEE_AVAILABLE or tee_manager is None:
        return jsonify({
            'success': False,
            'error': 'TEE not available - install dstack_sdk'
        }), 503

    try:
        data = request.get_json()
        quote = data.get('quote')
        expected_payload = data.get('expected_payload')
        pccs_url = data.get('pccs_url')  # Optional

        if not quote or not expected_payload:
            return jsonify({'success': False, 'error': 'Missing quote or expected_payload'}), 400

        # Verify attestation using DCAP QVL
        is_valid, verification_time_ms = tee_manager.verify_attestation(
            quote, expected_payload, pccs_url)

        return jsonify({
            'success': True,
            'is_valid': is_valid,
            'verification_time_ms': verification_time_ms
        })

    except Exception as e:
        logger.error(f"Attestation verification error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/tee/status', methods=['GET'])
def tee_status():
    """
    Get TEE status and statistics.

    Returns:
        {
            "tee_available": true/false,
            "tee_mode": "disabled/enabled/benchmark",
            "statistics": {...}
        }
    """
    if not TEE_AVAILABLE or tee_manager is None:
        return jsonify({
            'tee_available': False,
            'tee_mode': 'unavailable',
            'error': 'dstack_sdk not installed'
        })

    try:
        stats = tee_manager.get_statistics()

        return jsonify({
            'tee_available': True,
            'tee_mode': tee_manager.mode.value,
            'statistics': stats
        })

    except Exception as e:
        logger.error(f"TEE status error: {e}", exc_info=True)
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
    POST to enable/disable signature verification (for testing) and TEE mode.
    """
    if request.method == 'POST':
        try:
            data = request.get_json()
            if 'verify_signatures' in data:
                state.verify_signatures = bool(data['verify_signatures'])
                logger.info(
                    f"Signature verification: {state.verify_signatures}")

            if 'receipt_window' in data:
                state.receipt_window = int(data['receipt_window'])
                logger.info(f"Receipt window: {state.receipt_window}s")

            # TEE mode configuration
            if 'tee_mode' in data and TEE_AVAILABLE:
                mode_str = data['tee_mode'].lower()
                if mode_str == 'disabled':
                    set_tee_mode(TEEMode.DISABLED)
                elif mode_str == 'enabled':
                    set_tee_mode(TEEMode.ENABLED)
                elif mode_str == 'benchmark':
                    set_tee_mode(TEEMode.BENCHMARK)
                else:
                    return jsonify({'success': False, 'error': f'Invalid tee_mode: {mode_str}'}), 400
                logger.info(f"TEE mode: {mode_str}")

            return jsonify({
                'success': True,
                'message': 'Configuration updated'
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    # GET request - return current config
    config_data = {
        'instance_id': state.instance_id,
        'verify_signatures': state.verify_signatures,
        'receipt_window': state.receipt_window,
        'min_ratio': app.config['MIN_RATIO'],
        'max_peers': app.config['MAX_PEERS'],
        'used_receipts_count': len(state.used_receipts),
        'tee_available': TEE_AVAILABLE
    }

    if TEE_AVAILABLE and tee_manager is not None:
        config_data['tee_mode'] = tee_manager.mode.value

    return jsonify(config_data)

# ============================================================================
# PBTS Interaction with Smart Contracts
# ============================================================================


@app.route('/contract/init', methods=['POST'])
def init_contract():
    """
    Initialize a new Reputation contract via factory.
    By default uses zero address (0x00) as referrer.
    """
    try:
        logger.info("=== Contract Init Request ===")
        logger.info(
            f"Contract manager configured: {contract_manager.is_configured()}")
        logger.info(f"Factory address: {contract_manager.factory_address}")
        logger.info(
            f"Account: {contract_manager.account.address if contract_manager.account else 'None'}")
        logger.info(f"Web3 connected: {contract_manager.w3.is_connected()}")

        if not contract_manager.is_configured():
            error_msg = 'Contract manager not configured. Set RPC_URL, PRIVATE_KEY, and FACTORY_ADDRESS environment variables.'
            logger.error(error_msg)
            return jsonify({
                'success': False,
                'error': error_msg
            }), 500

        data = request.get_json(silent=True) or {}
        # Optional referrer address
        referrer = data.get('referrer_address', None)

        logger.info(
            f"Creating Reputation contract with referrer: {referrer or 'None (0x00)'}")

        # Create new Reputation contract
        new_address = contract_manager.create_reputation_contract(referrer)

        logger.info(f"✅ Created new Reputation contract at {new_address}")

        return jsonify({
            'success': True,
            'reputation_address': new_address,
            'referrer_address': referrer or '0x0000000000000000000000000000000000000000',
            'message': 'Reputation contract initialized successfully'
        })

    except Exception as e:
        logger.error(f"❌ Contract init error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/contract/register', methods=['POST'])
def contract_register():
    """
    Register a new user on the Reputation smart contract.
    """
    try:
        if not contract_manager.reputation_address:
            return jsonify({
                'success': False,
                'error': 'No Reputation contract initialized. Call /contract/init first.'
            }), 400

        data = request.get_json(silent=True) or {}
        username = data.get('username')
        salt = data.get('salt', '')
        password_hash = data.get('password_hash')
        download_size = int(data.get('download_size', 0))
        upload_size = int(data.get('upload_size', 0))

        if not username or not password_hash:
            return jsonify({'success': False, 'error': 'Missing username or password_hash'}), 400

        # Add user to smart contract
        tx_hash = contract_manager.add_user_to_contract(
            username, salt, password_hash, download_size, upload_size
        )

        logger.info(f"Registered user {username} on contract. TX: {tx_hash}")

        return jsonify({
            'success': True,
            'username': username,
            'tx_hash': tx_hash,
            'message': 'User registered on smart contract'
        })

    except Exception as e:
        logger.error(f"Contract register error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/contract/user/<username>', methods=['GET'])
def contract_get_user(username: str):
    """
    Get user data and reputation from the Reputation smart contract.
    """
    try:
        if not contract_manager.reputation_address:
            return jsonify({
                'success': False,
                'error': 'No Reputation contract initialized'
            }), 400

        # Get user data from contract
        user_data = contract_manager.get_user_from_contract(username)

        return jsonify({
            'success': True,
            'user': user_data,
            'contract_address': contract_manager.reputation_address
        })

    except Exception as e:
        logger.error(f"Contract get user error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/contract/update', methods=['POST'])
def contract_update():
    """
    Update user statistics on the Reputation smart contract.
    """
    try:
        if not contract_manager.reputation_address:
            return jsonify({
                'success': False,
                'error': 'No Reputation contract initialized'
            }), 400

        data = request.get_json(silent=True) or {}
        username = data.get('username')
        download_size = int(data.get('download_size', 0))
        upload_size = int(data.get('upload_size', 0))

        if not username:
            return jsonify({'success': False, 'error': 'Missing username'}), 400

        # Update user on smart contract
        tx_hash = contract_manager.update_user_on_contract(
            username, download_size, upload_size)

        logger.info(f"Updated user {username} on contract. TX: {tx_hash}")

        return jsonify({
            'success': True,
            'username': username,
            'tx_hash': tx_hash,
            'download_size': download_size,
            'upload_size': upload_size,
            'message': 'User statistics updated on smart contract'
        })

    except Exception as e:
        logger.error(f"Contract update error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/contract/migrate', methods=['POST'])
def contract_migrate():
    """
    Migrate user data from a previous Reputation contract to the current one.
    """
    try:
        if not contract_manager.reputation_address:
            return jsonify({
                'success': False,
                'error': 'No Reputation contract initialized'
            }), 400

        data = request.get_json(silent=True) or {}
        username = data.get('username')

        if not username:
            return jsonify({'success': False, 'error': 'Missing username'}), 400

        # Migrate user data
        tx_hash = contract_manager.migrate_user_data(username)

        logger.info(f"Migrated user {username} data. TX: {tx_hash}")

        return jsonify({
            'success': True,
            'username': username,
            'tx_hash': tx_hash,
            'message': 'User data migrated from referrer contract'
        })

    except Exception as e:
        logger.error(f"Contract migrate error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/contract/status', methods=['GET'])
def contract_status():
    """
    Get the current status of smart contract integration.
    """
    return jsonify({
        'configured': contract_manager.is_configured(),
        'connected': contract_manager.w3.is_connected() if contract_manager.w3 else False,
        'rpc_url': contract_manager.rpc_url,
        'account_address': contract_manager.account.address if contract_manager.account else None,
        'factory_address': contract_manager.factory_address or None,
        'reputation_address': contract_manager.reputation_address or None
    })


if __name__ == '__main__':
    # Log configuration when tracker server starts (not when imported as module)
    logger.info("=" * 70)
    logger.info("PBTS Tracker Server Starting")
    logger.info("=" * 70)
    if TEE_AVAILABLE and tee_manager:
        logger.info(f"TEE Mode: {tee_manager.mode.value}")
        if tee_manager.mode != TEEMode.DISABLED:
            logger.info("TEE features: ENABLED")
        else:
            logger.info("TEE features: disabled (using standard BLS crypto)")
    else:
        logger.info("TEE Mode: disabled (dstack_sdk not available)")
    logger.info("=" * 70)

    app.run(host='0.0.0.0', port=8000, debug=False)
