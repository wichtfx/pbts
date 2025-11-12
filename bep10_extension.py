#!/usr/bin/env python3
"""
BEP 10: Extension Protocol for PBTS

Implements the BitTorrent Extension Protocol (BEP 10) for peer-to-peer
receipt exchange in PBTS. This replaces the centralized HTTP receipt
submission with P2P communication.

Reference: http://www.bittorrent.org/beps/bep_0010.html

Extension Message Flow:
1. Extended Handshake: Negotiate PBTS extension support
2. Receipt Exchange: Send/receive receipts for completed pieces
3. Batch Reporting: Aggregate receipts for tracker submission

PBTS Extension Messages:
- pbts_receipt: Send a signed receipt for a piece transfer
- pbts_receipt_batch: Send multiple receipts in one message
- pbts_request_receipt: Request receipt for a specific piece
"""

import struct
import hashlib
import time
import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
import bencoder

logger = logging.getLogger(__name__)

# BEP 10 Extension Protocol Constants
EXTENDED_MESSAGE_ID = 20  # BEP 10 extended message ID
HANDSHAKE_MESSAGE_ID = 0  # Extended handshake uses ID 0

# PBTS Extension Names (registered in extended handshake)
PBTS_EXTENSION_NAME = "pbts"
PBTS_RECEIPT_MSG = "pbts_receipt"
PBTS_RECEIPT_BATCH_MSG = "pbts_receipt_batch"
PBTS_REQUEST_RECEIPT_MSG = "pbts_request_receipt"


@dataclass
class ExtensionHandshake:
    """
    BEP 10 extended handshake data

    The handshake dictionary (bencoded) contains:
    - m: dict mapping extension names to message IDs
    - v: client version string (optional)
    - p: listening port (optional)
    - yourip: peer's external IP (optional)
    - metadata_size: for BEP 9 (optional)
    """
    supported_extensions: Dict[str, int] = field(default_factory=dict)
    client_version: Optional[str] = None
    listening_port: Optional[int] = None
    metadata_size: Optional[int] = None

    def to_dict(self) -> Dict[bytes, Any]:
        """Convert to bencoded dictionary format"""
        result = {b"m": self.supported_extensions}
        if self.client_version:
            result[b"v"] = self.client_version.encode() if isinstance(self.client_version, str) else self.client_version
        if self.listening_port:
            result[b"p"] = self.listening_port
        if self.metadata_size:
            result[b"metadata_size"] = self.metadata_size
        return result

    @classmethod
    def from_dict(cls, data: Dict[bytes, Any]) -> 'ExtensionHandshake':
        """Parse from bencoded dictionary"""
        return cls(
            supported_extensions=data.get(b"m", {}),
            client_version=data.get(b"v").decode() if data.get(b"v") else None,
            listening_port=data.get(b"p"),
            metadata_size=data.get(b"metadata_size")
        )


@dataclass
class PBTSReceipt:
    """
    PBTS Receipt exchanged via BEP 10

    Contains cryptographic proof of piece transfer:
    - infohash: torrent identifier (20 bytes)
    - sender_pk: sender's BLS public key (48 bytes)
    - receiver_pk: receiver's BLS public key (48 bytes)
    - piece_hash: SHA-256 hash of piece data (32 bytes)
    - piece_index: piece number in torrent
    - timestamp: Unix timestamp of transfer
    - t_epoch: time epoch for receipt window
    - signature: BLS signature by receiver (96 bytes)
    """
    infohash: bytes
    sender_pk: bytes
    receiver_pk: bytes
    piece_hash: bytes
    piece_index: int
    timestamp: float
    t_epoch: int
    signature: bytes

    def to_dict(self) -> Dict[bytes, Any]:
        """Convert to dictionary for bencoding"""
        return {
            b"infohash": self.infohash,
            b"sender_pk": self.sender_pk,
            b"receiver_pk": self.receiver_pk,
            b"piece_hash": self.piece_hash,
            b"piece_index": self.piece_index,
            b"timestamp": int(self.timestamp),
            b"t_epoch": self.t_epoch,
            b"signature": self.signature
        }

    @classmethod
    def from_dict(cls, data: Dict[bytes, Any]) -> 'PBTSReceipt':
        """Parse from bencoded dictionary"""
        return cls(
            infohash=data[b"infohash"],
            sender_pk=data[b"sender_pk"],
            receiver_pk=data[b"receiver_pk"],
            piece_hash=data[b"piece_hash"],
            piece_index=data[b"piece_index"],
            timestamp=float(data[b"timestamp"]),
            t_epoch=data[b"t_epoch"],
            signature=data[b"signature"]
        )

    def get_message(self) -> bytes:
        """
        Get the message that was signed (for verification)
        Format: infohash || sender_pk || piece_hash || piece_index || t_epoch
        """
        return (
            self.infohash +
            self.sender_pk +
            self.piece_hash +
            struct.pack(">I", self.piece_index) +
            struct.pack(">Q", self.t_epoch)
        )

    def receipt_id(self) -> str:
        """
        Generate unique receipt ID for double-spend prevention
        Format: infohash:sender:receiver:piece_hash:index:epoch
        """
        return (
            f"{self.infohash.hex()}:"
            f"{self.sender_pk.hex()}:"
            f"{self.receiver_pk.hex()}:"
            f"{self.piece_hash.hex()}:"
            f"{self.piece_index}:"
            f"{self.t_epoch}"
        )


class BEP10Handler:
    """
    Handles BEP 10 extended protocol messages for PBTS

    This class manages:
    - Extended handshake negotiation
    - Receipt message encoding/decoding
    - Receipt batch aggregation
    - Message ID mapping
    """

    def __init__(self, client_version: str = "PBTS 0.1.0"):
        self.client_version = client_version

        # Local message ID mapping (what we send)
        self.local_ext_ids: Dict[str, int] = {}

        # Remote message ID mapping (what peer sends)
        self.remote_ext_ids: Dict[str, int] = {}

        # Receipt storage for batching
        self.pending_receipts: List[PBTSReceipt] = []

        # Track whether peer supports PBTS
        self.peer_supports_pbts = False

    def create_handshake(self, listening_port: Optional[int] = None) -> bytes:
        """
        Create extended handshake message

        Returns: Complete message to send on wire (length prefix + ID + payload)
        """
        # Assign local message IDs for PBTS extensions
        self.local_ext_ids = {
            PBTS_RECEIPT_MSG: 1,
            PBTS_RECEIPT_BATCH_MSG: 2,
            PBTS_REQUEST_RECEIPT_MSG: 3
        }

        handshake = ExtensionHandshake(
            supported_extensions={
                PBTS_EXTENSION_NAME.encode(): {
                    b"receipt": self.local_ext_ids[PBTS_RECEIPT_MSG],
                    b"receipt_batch": self.local_ext_ids[PBTS_RECEIPT_BATCH_MSG],
                    b"request_receipt": self.local_ext_ids[PBTS_REQUEST_RECEIPT_MSG]
                }
            },
            client_version=self.client_version,
            listening_port=listening_port
        )

        # Bencode the handshake dictionary
        payload = bencoder.encode(handshake.to_dict())

        # Construct message: <length><id><payload>
        # length = 1 (extended ID) + 1 (handshake ID) + len(payload)
        message_length = 2 + len(payload)

        return (
            struct.pack(">I", message_length) +
            struct.pack("B", EXTENDED_MESSAGE_ID) +
            struct.pack("B", HANDSHAKE_MESSAGE_ID) +
            payload
        )

    def parse_handshake(self, payload: bytes) -> bool:
        """
        Parse extended handshake from peer

        Returns: True if peer supports PBTS, False otherwise
        """
        try:
            # Decode bencoded handshake
            data = bencoder.decode(payload)
            handshake = ExtensionHandshake.from_dict(data)

            # Check if peer supports PBTS extension
            extensions = handshake.supported_extensions
            pbts_key = PBTS_EXTENSION_NAME.encode()
            if pbts_key in extensions:
                pbts_msgs = extensions[pbts_key]

                # Map remote message IDs
                if isinstance(pbts_msgs, dict):
                    self.remote_ext_ids[PBTS_RECEIPT_MSG] = pbts_msgs.get(b"receipt", 0)
                    self.remote_ext_ids[PBTS_RECEIPT_BATCH_MSG] = pbts_msgs.get(b"receipt_batch", 0)
                    self.remote_ext_ids[PBTS_REQUEST_RECEIPT_MSG] = pbts_msgs.get(b"request_receipt", 0)

                    self.peer_supports_pbts = True
                    logger.info(f"Peer supports PBTS extension (IDs: {self.remote_ext_ids})")
                    return True

            logger.info("Peer does not support PBTS extension")
            return False

        except Exception as e:
            logger.error(f"Failed to parse extended handshake: {e}")
            return False

    def create_receipt_message(self, receipt: PBTSReceipt) -> bytes:
        """
        Create pbts_receipt extended message

        Message format:
        <length><ext_id><msg_id><bencoded_receipt>
        """
        if not self.peer_supports_pbts:
            raise ValueError("Peer does not support PBTS extension")

        msg_id = self.remote_ext_ids.get(PBTS_RECEIPT_MSG, 0)
        if msg_id == 0:
            raise ValueError("Receipt message ID not negotiated")

        # Bencode receipt data
        payload = bencoder.encode(receipt.to_dict())

        # Construct message
        message_length = 2 + len(payload)  # ext_id + msg_id + payload

        return (
            struct.pack(">I", message_length) +
            struct.pack("B", EXTENDED_MESSAGE_ID) +
            struct.pack("B", msg_id) +
            payload
        )

    def create_receipt_batch_message(self, receipts: List[PBTSReceipt]) -> bytes:
        """
        Create pbts_receipt_batch extended message

        Sends multiple receipts in one message for efficiency
        """
        if not self.peer_supports_pbts:
            raise ValueError("Peer does not support PBTS extension")

        msg_id = self.remote_ext_ids.get(PBTS_RECEIPT_BATCH_MSG, 0)
        if msg_id == 0:
            raise ValueError("Receipt batch message ID not negotiated")

        # Bencode list of receipts
        receipt_dicts = [r.to_dict() for r in receipts]
        payload = bencoder.encode({b"receipts": receipt_dicts})

        # Construct message
        message_length = 2 + len(payload)

        return (
            struct.pack(">I", message_length) +
            struct.pack("B", EXTENDED_MESSAGE_ID) +
            struct.pack("B", msg_id) +
            payload
        )

    def create_request_receipt_message(
        self,
        infohash: bytes,
        piece_index: int,
        piece_hash: bytes
    ) -> bytes:
        """
        Create pbts_request_receipt extended message

        Request receipt from peer for a specific piece we uploaded to them
        """
        if not self.peer_supports_pbts:
            raise ValueError("Peer does not support PBTS extension")

        msg_id = self.remote_ext_ids.get(PBTS_REQUEST_RECEIPT_MSG, 0)
        if msg_id == 0:
            raise ValueError("Request receipt message ID not negotiated")

        # Bencode request data
        payload = bencoder.encode({
            b"infohash": infohash,
            b"piece_index": piece_index,
            b"piece_hash": piece_hash
        })

        # Construct message
        message_length = 2 + len(payload)

        return (
            struct.pack(">I", message_length) +
            struct.pack("B", EXTENDED_MESSAGE_ID) +
            struct.pack("B", msg_id) +
            payload
        )

    def parse_message(self, message_id: int, payload: bytes) -> Optional[Any]:
        """
        Parse incoming extended message

        Returns: Parsed message object or None if unknown message
        """
        # Find message type by ID
        msg_type = None
        for name, mid in self.local_ext_ids.items():
            if mid == message_id:
                msg_type = name
                break

        if not msg_type:
            logger.warning(f"Unknown extended message ID: {message_id}")
            return None

        try:
            data = bencoder.decode(payload)

            if msg_type == PBTS_RECEIPT_MSG:
                return PBTSReceipt.from_dict(data)

            elif msg_type == PBTS_RECEIPT_BATCH_MSG:
                receipts = [PBTSReceipt.from_dict(r) for r in data[b"receipts"]]
                return receipts

            elif msg_type == PBTS_REQUEST_RECEIPT_MSG:
                return {
                    "infohash": data[b"infohash"],
                    "piece_index": data[b"piece_index"],
                    "piece_hash": data[b"piece_hash"]
                }

        except Exception as e:
            logger.error(f"Failed to parse {msg_type} message: {e}")
            return None

    def add_receipt(self, receipt: PBTSReceipt):
        """Add receipt to pending batch"""
        self.pending_receipts.append(receipt)

    def get_pending_receipts(self) -> List[PBTSReceipt]:
        """Get and clear pending receipts for batch submission"""
        receipts = self.pending_receipts.copy()
        self.pending_receipts.clear()
        return receipts

    def should_batch_report(self, threshold: int = 10) -> bool:
        """Check if we have enough receipts to send batch report"""
        return len(self.pending_receipts) >= threshold


def compute_piece_hash(piece_data: bytes) -> bytes:
    """
    Compute SHA-256 hash of piece data

    This is used in receipt generation to prove which piece was transferred
    """
    return hashlib.sha256(piece_data).digest()


def compute_time_epoch(timestamp: float, window: int = 3600) -> int:
    """
    Compute time epoch for receipt timestamp-based verification

    Args:
        timestamp: Unix timestamp
        window: Time window in seconds (default: 3600 = 1 hour)

    Returns: Epoch number (t_epoch = floor(t / W))
    """
    return int(timestamp // window)


# Example usage functions

def example_handshake_flow():
    """
    Example: How to perform extended handshake
    """
    print("=== BEP 10 Extended Handshake Example ===\n")

    # Create handler
    handler = BEP10Handler(client_version="PBTS Example 1.0")

    # Create handshake message to send
    handshake_msg = handler.create_handshake(listening_port=6881)
    print(f"Handshake message ({len(handshake_msg)} bytes):")
    print(f"  {handshake_msg.hex()}\n")

    # Simulate receiving handshake from peer
    # (In real implementation, this comes from socket)
    # For demo, parse our own handshake
    # Skip length prefix (4 bytes) + ext ID (1 byte) + handshake ID (1 byte)
    peer_handshake_payload = handshake_msg[6:]

    supports_pbts = handler.parse_handshake(peer_handshake_payload)
    print(f"Peer supports PBTS: {supports_pbts}")
    print(f"Remote message IDs: {handler.remote_ext_ids}\n")


def example_receipt_exchange():
    """
    Example: How to exchange receipts
    """
    print("=== PBTS Receipt Exchange Example ===\n")

    # Create handler (after handshake)
    handler = BEP10Handler()
    handler.peer_supports_pbts = True
    handler.remote_ext_ids = {
        PBTS_RECEIPT_MSG: 1,
        PBTS_RECEIPT_BATCH_MSG: 2,
        PBTS_REQUEST_RECEIPT_MSG: 3
    }
    handler.local_ext_ids = handler.remote_ext_ids.copy()

    # Create a receipt
    infohash = hashlib.sha1(b"example_torrent").digest()
    sender_pk = b"S" * 48  # Mock 48-byte BLS public key
    receiver_pk = b"R" * 48
    piece_data = b"This is piece data for testing"
    piece_hash = compute_piece_hash(piece_data)
    piece_index = 5
    timestamp = time.time()
    t_epoch = compute_time_epoch(timestamp)
    signature = b"X" * 96  # Mock 96-byte BLS signature

    receipt = PBTSReceipt(
        infohash=infohash,
        sender_pk=sender_pk,
        receiver_pk=receiver_pk,
        piece_hash=piece_hash,
        piece_index=piece_index,
        timestamp=timestamp,
        t_epoch=t_epoch,
        signature=signature
    )

    print(f"Receipt ID: {receipt.receipt_id()}")
    print(f"Piece index: {receipt.piece_index}")
    print(f"Time epoch: {receipt.t_epoch}\n")

    # Create receipt message
    receipt_msg = handler.create_receipt_message(receipt)
    print(f"Receipt message ({len(receipt_msg)} bytes)")
    print(f"  First 64 bytes: {receipt_msg[:64].hex()}...\n")

    # Parse receipt message (simulate receiving)
    # Skip length (4) + ext_id (1)
    msg_id = receipt_msg[5]
    payload = receipt_msg[6:]
    parsed = handler.parse_message(msg_id, payload)

    print(f"Parsed receipt:")
    print(f"  Piece index: {parsed.piece_index}")
    print(f"  Receipt ID: {parsed.receipt_id()}")


def example_batch_reporting():
    """
    Example: How to batch multiple receipts
    """
    print("\n=== PBTS Batch Receipt Reporting Example ===\n")

    handler = BEP10Handler()
    handler.peer_supports_pbts = True
    handler.remote_ext_ids = {
        PBTS_RECEIPT_MSG: 1,
        PBTS_RECEIPT_BATCH_MSG: 2,
        PBTS_REQUEST_RECEIPT_MSG: 3
    }
    handler.local_ext_ids = {
        PBTS_RECEIPT_MSG: 1,
        PBTS_RECEIPT_BATCH_MSG: 2,
        PBTS_REQUEST_RECEIPT_MSG: 3
    }

    # Create multiple receipts
    receipts = []
    infohash = hashlib.sha1(b"test_torrent").digest()
    timestamp = time.time()
    t_epoch = compute_time_epoch(timestamp)

    for i in range(5):
        receipt = PBTSReceipt(
            infohash=infohash,
            sender_pk=b"S" * 48,
            receiver_pk=b"R" * 48,
            piece_hash=hashlib.sha256(f"piece_{i}".encode()).digest(),
            piece_index=i,
            timestamp=timestamp,
            t_epoch=t_epoch,
            signature=b"X" * 96
        )
        receipts.append(receipt)
        handler.add_receipt(receipt)

    print(f"Created {len(receipts)} receipts")
    print(f"Should batch report: {handler.should_batch_report(threshold=3)}\n")

    # Create batch message
    batch_msg = handler.create_receipt_batch_message(receipts)
    print(f"Batch message ({len(batch_msg)} bytes)")
    print(f"  Contains {len(receipts)} receipts\n")

    # Parse batch message
    msg_id = batch_msg[5]
    payload = batch_msg[6:]
    parsed_receipts = handler.parse_message(msg_id, payload)

    print(f"Parsed {len(parsed_receipts)} receipts from batch")
    for r in parsed_receipts:
        print(f"  - Piece {r.piece_index}: {r.receipt_id()[:40]}...")


if __name__ == "__main__":
    # Run examples
    example_handshake_flow()
    print("\n" + "="*60 + "\n")
    example_receipt_exchange()
    example_batch_reporting()
