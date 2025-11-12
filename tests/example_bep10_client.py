#!/usr/bin/env python3
"""
Example BEP 10 Client for PBTS

This demonstrates how to integrate PBTS receipts into a BitTorrent client
using the BEP 10 extension protocol. In a real implementation, this would
be integrated into an actual BitTorrent client (e.g., libtorrent, transmission).

This example shows:
1. How to perform extended handshake
2. How to generate and send receipts after piece transfer
3. How to receive and verify receipts
4. How to batch receipts for tracker reporting
"""

import socket
import struct
import hashlib
import time
import logging
from typing import Optional, Dict, List
import base64

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: requests module not found. HTTP tracker submission will be disabled.")

from bep10_extension import (
    BEP10Handler,
    PBTSReceipt,
    compute_piece_hash,
    compute_time_epoch,
    EXTENDED_MESSAGE_ID,
    HANDSHAKE_MESSAGE_ID
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PBTSBitTorrentPeer:
    """
    Simulated BitTorrent peer with PBTS extension support

    In a real implementation, this would be part of a full BitTorrent client
    that handles the complete peer protocol (handshake, bitfield, pieces, etc.).

    This simplified version only demonstrates the PBTS-specific extensions.
    """

    def __init__(
        self,
        tracker_url: str,
        private_key: bytes,
        public_key: bytes,
        peer_id: bytes = None
    ):
        """
        Initialize PBTS peer

        Args:
            tracker_url: PBTS tracker HTTP endpoint
            private_key: BLS private key (32 bytes)
            public_key: BLS public key (48 bytes)
            peer_id: 20-byte BitTorrent peer ID
        """
        self.tracker_url = tracker_url
        self.private_key = private_key
        self.public_key = public_key
        self.peer_id = peer_id or self._generate_peer_id()

        # BEP 10 extension handler
        self.bep10 = BEP10Handler(client_version="PBTS Example Client 0.1")

        # Receipt tracking
        self.sent_receipts: List[PBTSReceipt] = []
        self.received_receipts: List[PBTSReceipt] = []

        # Configuration
        self.receipt_batch_threshold = 10
        self.receipt_window = 3600  # 1 hour

        logger.info(f"Initialized PBTS peer {self.peer_id.hex()[:16]}...")

    def _generate_peer_id(self) -> bytes:
        """Generate BitTorrent peer ID (20 bytes)"""
        # Format: -PBXXXX-<random>
        # PB = PBTS, XXXX = version
        prefix = b"-PB0100-"  # PBTS 01.00
        random = hashlib.sha1(self.public_key).digest()[:12]
        return prefix + random

    def connect_to_peer(self, peer_socket: socket.socket) -> bool:
        """
        Perform extended handshake with peer

        In a real client, this happens after the standard BitTorrent handshake.
        The standard handshake includes:
        - Protocol string: "BitTorrent protocol"
        - Reserved bytes (byte 5, bit 4 = 0x10 indicates extension support)
        - Info hash (20 bytes)
        - Peer ID (20 bytes)

        Args:
            peer_socket: Connected socket to peer

        Returns: True if peer supports PBTS extension
        """
        try:
            # Send extended handshake
            handshake_msg = self.bep10.create_handshake()
            peer_socket.send(handshake_msg)
            logger.info("Sent extended handshake to peer")

            # Receive extended handshake response
            # Read message length (4 bytes)
            length_data = peer_socket.recv(4)
            if len(length_data) < 4:
                logger.error("Failed to read message length")
                return False

            length = struct.unpack(">I", length_data)[0]

            # Read message ID and payload
            message_data = peer_socket.recv(length)
            if len(message_data) < length:
                logger.error("Failed to read complete message")
                return False

            msg_id = message_data[0]
            if msg_id != EXTENDED_MESSAGE_ID:
                logger.error(f"Expected extended message, got {msg_id}")
                return False

            ext_msg_id = message_data[1]
            if ext_msg_id != HANDSHAKE_MESSAGE_ID:
                logger.error(f"Expected handshake, got {ext_msg_id}")
                return False

            # Parse handshake payload
            payload = message_data[2:]
            supports_pbts = self.bep10.parse_handshake(payload)

            if supports_pbts:
                logger.info("Peer supports PBTS extension!")
            else:
                logger.info("Peer does not support PBTS extension")

            return supports_pbts

        except Exception as e:
            logger.error(f"Extended handshake failed: {e}")
            return False

    def generate_receipt_for_upload(
        self,
        infohash: bytes,
        receiver_pk: bytes,
        piece_index: int,
        piece_data: bytes
    ) -> Optional[PBTSReceipt]:
        """
        Request receipt from peer after uploading a piece

        In the PBTS protocol, the DOWNLOADER (receiver) signs the receipt,
        not the uploader. So we need to request the peer to sign and send
        us a receipt.

        Args:
            infohash: Torrent info hash
            receiver_pk: Peer's public key (who received the piece)
            piece_index: Index of piece we uploaded
            piece_data: The piece data we sent

        Returns: Receipt from peer (if received)
        """
        if not self.bep10.peer_supports_pbts:
            logger.warning("Cannot request receipt: peer doesn't support PBTS")
            return None

        # Compute piece hash
        piece_hash = compute_piece_hash(piece_data)

        # Create request receipt message
        request_msg = self.bep10.create_request_receipt_message(
            infohash=infohash,
            piece_index=piece_index,
            piece_hash=piece_hash
        )

        logger.info(f"Requesting receipt for piece {piece_index}")

        # In a real implementation, send this via the peer socket and wait for response
        # For this example, we'll simulate it
        # peer_socket.send(request_msg)

        return None  # Would receive receipt via parse_message()

    def create_receipt_for_download(
        self,
        infohash: bytes,
        sender_pk: bytes,
        piece_index: int,
        piece_data: bytes
    ) -> PBTSReceipt:
        """
        Create and sign receipt after downloading a piece

        This is called when we receive a piece from a peer.
        We (the downloader) sign the receipt to prove the transfer occurred.

        Args:
            infohash: Torrent info hash
            sender_pk: Peer's public key (who sent the piece)
            piece_index: Index of piece we downloaded
            piece_data: The piece data we received

        Returns: Signed receipt
        """
        # Compute piece hash
        piece_hash = compute_piece_hash(piece_data)

        # Get current timestamp and epoch
        timestamp = time.time()
        t_epoch = compute_time_epoch(timestamp, self.receipt_window)

        # Create receipt message to sign
        # Format: infohash || sender_pk || piece_hash || piece_index || t_epoch
        message = (
            infohash +
            sender_pk +
            piece_hash +
            struct.pack(">I", piece_index) +
            struct.pack(">Q", t_epoch)
        )

        # Sign with our private key
        # In a real implementation, use BLS signing from tracker.py
        from tracker import sign_message
        signature = sign_message(self.private_key, message)

        # Create receipt
        receipt = PBTSReceipt(
            infohash=infohash,
            sender_pk=sender_pk,
            receiver_pk=self.public_key,
            piece_hash=piece_hash,
            piece_index=piece_index,
            timestamp=timestamp,
            t_epoch=t_epoch,
            signature=signature
        )

        logger.info(f"Created receipt for piece {piece_index} from {sender_pk.hex()[:16]}...")

        return receipt

    def send_receipt_to_peer(self, receipt: PBTSReceipt, peer_socket: socket.socket):
        """
        Send receipt to peer via BEP 10 extended message

        Args:
            receipt: The receipt to send
            peer_socket: Connected socket to peer
        """
        if not self.bep10.peer_supports_pbts:
            logger.warning("Cannot send receipt: peer doesn't support PBTS")
            return

        try:
            # Create receipt message
            receipt_msg = self.bep10.create_receipt_message(receipt)

            # Send via socket
            peer_socket.send(receipt_msg)

            # Track sent receipt
            self.sent_receipts.append(receipt)

            logger.info(f"Sent receipt for piece {receipt.piece_index} to peer")

        except Exception as e:
            logger.error(f"Failed to send receipt: {e}")

    def receive_message(self, peer_socket: socket.socket) -> Optional[any]:
        """
        Receive and parse extended message from peer

        Returns: Parsed message (PBTSReceipt, list of receipts, or request dict)
        """
        try:
            # Read message length
            length_data = peer_socket.recv(4)
            if len(length_data) < 4:
                return None

            length = struct.unpack(">I", length_data)[0]

            # Read message
            message_data = peer_socket.recv(length)
            if len(message_data) < length:
                return None

            # Check if extended message
            msg_id = message_data[0]
            if msg_id != EXTENDED_MESSAGE_ID:
                return None  # Not an extended message

            # Parse extended message
            ext_msg_id = message_data[1]
            payload = message_data[2:]

            parsed = self.bep10.parse_message(ext_msg_id, payload)

            # Track received receipts
            if isinstance(parsed, PBTSReceipt):
                self.received_receipts.append(parsed)
                logger.info(f"Received receipt for piece {parsed.piece_index}")
            elif isinstance(parsed, list):  # Batch of receipts
                self.received_receipts.extend(parsed)
                logger.info(f"Received {len(parsed)} receipts in batch")

            return parsed

        except Exception as e:
            logger.error(f"Failed to receive message: {e}")
            return None

    def submit_receipts_to_tracker(self, receipts: Optional[List[PBTSReceipt]] = None):
        """
        Submit received receipts to tracker for reputation update

        This uses the HTTP API endpoint /report.
        In the P2P mode, this is the only time we contact the tracker
        (aside from periodic announces).

        Args:
            receipts: List of receipts to submit (default: all received receipts)
        """
        if receipts is None:
            receipts = self.received_receipts

        if not receipts:
            logger.info("No receipts to submit")
            return

        # Format receipts for tracker API
        receipts_data = []
        for r in receipts:
            receipts_data.append({
                "infohash": r.infohash.hex(),
                "sender_pk": base64.b64encode(r.sender_pk).decode(),
                "receiver_pk": base64.b64encode(r.receiver_pk).decode(),
                "piece_hash": r.piece_hash.hex(),
                "piece_index": r.piece_index,
                "t_epoch": r.t_epoch,
                "signature": base64.b64encode(r.signature).decode()
            })

        # Submit to tracker
        if not HAS_REQUESTS:
            logger.warning("Cannot submit receipts: requests module not available")
            return

        try:
            response = requests.post(
                f"{self.tracker_url}/report",
                json={
                    "user_id": self.peer_id.hex(),
                    "receipts": receipts_data
                },
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"Successfully submitted {len(receipts)} receipts to tracker")

                # Clear submitted receipts
                self.received_receipts = [
                    r for r in self.received_receipts if r not in receipts
                ]
            else:
                logger.error(f"Tracker rejected receipts: {response.text}")

        except Exception as e:
            logger.error(f"Failed to submit receipts: {e}")

    def should_batch_report(self) -> bool:
        """Check if we should submit receipts to tracker"""
        return len(self.received_receipts) >= self.receipt_batch_threshold


def simulate_piece_transfer():
    """
    Simulate a piece transfer between two PBTS peers

    This demonstrates the complete receipt flow:
    1. Peer A uploads piece to Peer B
    2. Peer B (downloader) creates and signs receipt
    3. Peer B sends receipt to Peer A via BEP 10
    4. Peer A submits receipt to tracker
    5. Tracker updates Peer A's upload ratio
    """
    print("=== PBTS Piece Transfer Simulation ===\n")

    # Import key generation from tracker
    from tracker import generate_keypair

    # Create two peers
    print("Creating peers...")
    peer_a_sk, peer_a_pk = generate_keypair()
    peer_b_sk, peer_b_pk = generate_keypair()

    peer_a = PBTSBitTorrentPeer(
        tracker_url="http://localhost:8000",
        private_key=peer_a_sk,
        public_key=peer_a_pk
    )

    peer_b = PBTSBitTorrentPeer(
        tracker_url="http://localhost:8000",
        private_key=peer_b_sk,
        public_key=peer_b_pk
    )

    print(f"Peer A: {peer_a.peer_id.hex()[:16]}...")
    print(f"Peer B: {peer_b.peer_id.hex()[:16]}...\n")

    # Simulate torrent info
    infohash = hashlib.sha1(b"example_torrent_content").digest()
    piece_index = 42
    piece_data = b"This is the piece data that Peer A is uploading to Peer B" * 100

    # Simulate extended handshake (would happen via sockets in real implementation)
    print("Performing extended handshake...")
    peer_a.bep10.peer_supports_pbts = True
    peer_a.bep10.remote_ext_ids = {
        "pbts_receipt": 1,
        "pbts_receipt_batch": 2,
        "pbts_request_receipt": 3
    }
    peer_b.bep10.peer_supports_pbts = True
    peer_b.bep10.remote_ext_ids = peer_a.bep10.remote_ext_ids
    print("Both peers support PBTS extension\n")

    # Step 1: Peer A uploads piece to Peer B
    print(f"Peer A uploading piece {piece_index} to Peer B...")
    print(f"Piece size: {len(piece_data)} bytes\n")

    # Step 2: Peer B creates receipt for the download
    print("Peer B creating receipt...")
    receipt = peer_b.create_receipt_for_download(
        infohash=infohash,
        sender_pk=peer_a.public_key,
        piece_index=piece_index,
        piece_data=piece_data
    )
    print(f"Receipt ID: {receipt.receipt_id()[:60]}...")
    print(f"Signature: {receipt.signature.hex()[:60]}...\n")

    # Step 3: Peer B sends receipt to Peer A (simulated)
    print("Peer B sending receipt to Peer A via BEP 10...")
    # In real implementation: peer_b.send_receipt_to_peer(receipt, peer_a_socket)
    # For simulation, directly add to peer_a's received receipts
    peer_a.received_receipts.append(receipt)
    print("Receipt received by Peer A\n")

    # Step 4: Check if should batch report
    print(f"Peer A has {len(peer_a.received_receipts)} receipts")
    print(f"Batch threshold: {peer_a.receipt_batch_threshold}")
    print(f"Should submit now: {peer_a.should_batch_report()}\n")

    # Step 5: Submit to tracker (would normally happen when threshold reached)
    print("Submitting receipts to tracker...")
    print("(Note: This requires the tracker to be running at http://localhost:8000)")
    # peer_a.submit_receipts_to_tracker()

    print("\n=== Simulation Complete ===")
    print(f"\nIn a real deployment:")
    print(f"1. Peer A would accumulate ~{peer_a.receipt_batch_threshold} receipts")
    print(f"2. Then submit batch to tracker via /report endpoint")
    print(f"3. Tracker would verify BLS signatures and update reputation")
    print(f"4. Peer A's upload ratio increases on-chain")


if __name__ == "__main__":
    simulate_piece_transfer()
