#!/usr/bin/env python3
"""
Simplified PBTS BitTorrent Client for E2E Testing

This client simulates BitTorrent piece transfer with real PBTS receipt generation and submission.
Downloads are simulated with sleep(), but receipt generation and tracker submission are real.
"""

import hashlib
import struct
import time
import base64
import json
import argparse
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: requests module required. Install with: pip install requests")
    exit(1)

try:
    import bencoder
except ImportError:
    print("ERROR: bencoder module required. Install with: pip install bencoder.pyx")
    exit(1)

# Import from project root
import sys
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from tracker import generate_keypair, sign_message, verify_signature
from bep10_extension import PBTSReceipt, compute_piece_hash, compute_time_epoch

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class TorrentInfo:
    """Parsed torrent file information"""
    announce: str
    infohash: bytes
    name: str
    piece_length: int
    pieces: List[bytes]  # List of piece hashes
    length: int
    num_pieces: int


class PBTSClient:
    """
    Simplified PBTS BitTorrent Client

    Simulates piece transfers with sleep(), but implements real:
    - BLS signature generation
    - Receipt creation and verification
    - Batch submission to tracker
    - Smart contract updates (optional)
    """

    def __init__(
        self,
        user_id: str,
        private_key: bytes,
        public_key: bytes,
        tracker_url: str = "http://localhost:8000",
        mode: str = "leecher",  # "seeder" or "leecher"
        data_file: Optional[Path] = None
    ):
        """
        Initialize PBTS client

        Args:
            user_id: User identifier for tracker
            private_key: BLS private key (32 bytes)
            public_key: BLS public key (48 bytes)
            tracker_url: Tracker HTTP endpoint
            mode: "seeder" (has complete file) or "leecher" (downloading)
            data_file: Path to file being seeded (for seeders)
        """
        self.user_id = user_id
        self.private_key = private_key
        self.public_key = public_key
        self.tracker_url = tracker_url
        self.mode = mode
        self.data_file = data_file

        # State
        self.torrent: Optional[TorrentInfo] = None
        self.peer_id = self._generate_peer_id()
        self.port = 6881  # Simulated port

        # Statistics
        self.downloaded = 0
        self.uploaded = 0
        self.left = 0

        # Receipt management
        self.receipts_to_submit: List[PBTSReceipt] = []  # Receipts for pieces I uploaded
        self.receipt_batch_threshold = 10
        self.receipt_window = 3600

        logger.info(f"Initialized PBTS client - User: {user_id}, Mode: {mode}")
        logger.info(f"  Peer ID: {self.peer_id.hex()[:16]}...")
        logger.info(f"  Public Key: {base64.b64encode(public_key).decode()[:32]}...")

    def _generate_peer_id(self) -> bytes:
        """Generate 20-byte BitTorrent peer ID"""
        prefix = b"-PB0100-"  # PBTS client version 01.00
        random_part = hashlib.sha1(self.public_key + self.user_id.encode()).digest()[:12]
        return prefix + random_part

    def load_torrent(self, torrent_path: Path) -> TorrentInfo:
        """
        Parse .torrent file

        Args:
            torrent_path: Path to .torrent file

        Returns:
            Parsed torrent information
        """
        logger.info(f"Loading torrent: {torrent_path}")

        with open(torrent_path, 'rb') as f:
            torrent_data = bencoder.decode(f.read())

        announce = torrent_data[b'announce'].decode('utf-8')
        info = torrent_data[b'info']

        # Calculate infohash
        infohash = hashlib.sha1(bencoder.encode(info)).digest()

        # Parse info dictionary
        name = info[b'name'].decode('utf-8')
        piece_length = info[b'piece length']
        pieces_data = info[b'pieces']
        length = info[b'length']

        # Split pieces into list of 20-byte hashes
        pieces = [pieces_data[i:i+20] for i in range(0, len(pieces_data), 20)]
        num_pieces = len(pieces)

        self.torrent = TorrentInfo(
            announce=announce,
            infohash=infohash,
            name=name,
            piece_length=piece_length,
            pieces=pieces,
            length=length,
            num_pieces=num_pieces
        )

        # Set initial stats
        if self.mode == "seeder":
            self.downloaded = length
            self.uploaded = 0
            self.left = 0
        else:  # leecher
            self.downloaded = 0
            self.uploaded = 0
            self.left = length

        logger.info(f"  Torrent: {name}")
        logger.info(f"  Info hash: {infohash.hex()}")
        logger.info(f"  Size: {length} bytes")
        logger.info(f"  Pieces: {num_pieces} x {piece_length} bytes")

        return self.torrent

    def announce_to_tracker(self, event: str = "started") -> Dict:
        """
        Send announce to tracker

        Args:
            event: "started", "completed", or "stopped"

        Returns:
            Tracker response
        """
        if not self.torrent:
            raise ValueError("No torrent loaded")

        params = {
            'info_hash': self.torrent.infohash,
            'peer_id': self.peer_id,
            'port': self.port,
            'uploaded': self.uploaded,
            'downloaded': self.downloaded,
            'left': self.left,
            'compact': 1,
            'event': event
        }

        logger.info(f"Announcing to tracker (event={event})...")

        try:
            response = requests.get(
                f"{self.tracker_url}/announce",
                params=params,
                timeout=10
            )

            if response.status_code != 200:
                logger.error(f"Announce failed: {response.status_code}")
                return {}

            # Parse bencoded response
            data = bencoder.decode(response.content)

            if b'failure reason' in data:
                logger.error(f"Tracker error: {data[b'failure reason'].decode()}")
                return {}

            interval = data.get(b'interval', 1800)
            peers_data = data.get(b'peers', b'')

            # Parse compact peers (6 bytes each: 4 IP + 2 port)
            num_peers = len(peers_data) // 6

            logger.info(f"  Announce successful - {num_peers} peers, interval={interval}s")

            return {
                'interval': interval,
                'num_peers': num_peers
            }

        except Exception as e:
            logger.error(f"Announce failed: {e}")
            return {}

    def simulate_download_from_peer(
        self,
        peer_user_id: str,
        peer_public_key: bytes,
        piece_index: int,
        simulate_delay: float = 0.1
    ) -> Optional[PBTSReceipt]:
        """
        Simulate downloading a piece from a peer

        This simulates the piece transfer with sleep() but generates a REAL receipt
        with BLS signature.

        Args:
            peer_user_id: Sender's user ID
            peer_public_key: Sender's BLS public key
            piece_index: Index of piece being downloaded
            simulate_delay: Seconds to sleep (simulating download time)

        Returns:
            Receipt signed by this client (downloader) to give to uploader
        """
        if not self.torrent:
            raise ValueError("No torrent loaded")

        if piece_index >= self.torrent.num_pieces:
            raise ValueError(f"Invalid piece index: {piece_index}")

        # Simulate downloading the piece
        logger.info(f"📥 Downloading piece {piece_index} from {peer_user_id}...")
        time.sleep(simulate_delay)

        # Simulate piece data (in real client, this would be actual data)
        # Use deterministic data so piece hash is consistent
        piece_data = f"piece_{piece_index}_data".encode() * 100
        piece_data = piece_data[:self.torrent.piece_length]  # Truncate to piece length

        # Compute piece hash
        piece_hash = compute_piece_hash(piece_data)

        # Verify piece hash matches torrent (in real client)
        # For simulation, we skip this check

        # Update stats
        self.downloaded += len(piece_data)
        self.left -= len(piece_data)

        # Generate receipt
        # As the DOWNLOADER, I sign the receipt to prove I received the piece
        timestamp = time.time()
        t_epoch = compute_time_epoch(timestamp, self.receipt_window)

        # Receipt message format (PBTS protocol):
        # infohash || sender_pk || piece_hash || piece_index || t_epoch
        message = (
            self.torrent.infohash +
            peer_public_key +
            piece_hash +
            struct.pack(">I", piece_index) +
            struct.pack(">Q", t_epoch)
        )

        # Sign with MY private key (receiver/downloader signs)
        signature = sign_message(self.private_key, message)

        receipt = PBTSReceipt(
            infohash=self.torrent.infohash,
            sender_pk=peer_public_key,
            receiver_pk=self.public_key,
            piece_hash=piece_hash,
            piece_index=piece_index,
            timestamp=timestamp,
            t_epoch=t_epoch,
            signature=signature
        )

        logger.info(f"  ✅ Downloaded piece {piece_index} ({len(piece_data)} bytes)")
        logger.info(f"  📝 Generated receipt: {receipt.receipt_id()[:32]}...")

        return receipt

    def simulate_upload_to_peer(
        self,
        peer_user_id: str,
        peer_public_key: bytes,
        piece_index: int,
        simulate_delay: float = 0.1
    ) -> Tuple[bytes, bytes]:
        """
        Simulate uploading a piece to a peer

        Args:
            peer_user_id: Receiver's user ID
            peer_public_key: Receiver's BLS public key
            piece_index: Index of piece being uploaded
            simulate_delay: Seconds to sleep (simulating upload time)

        Returns:
            (piece_data, piece_hash) for the uploaded piece
        """
        if not self.torrent:
            raise ValueError("No torrent loaded")

        if self.mode != "seeder":
            raise ValueError("Only seeders can upload")

        # Simulate reading piece from file
        logger.info(f"📤 Uploading piece {piece_index} to {peer_user_id}...")
        time.sleep(simulate_delay)

        # Simulate piece data (same as download simulation for consistency)
        piece_data = f"piece_{piece_index}_data".encode() * 100
        piece_data = piece_data[:self.torrent.piece_length]

        piece_hash = compute_piece_hash(piece_data)

        # Update stats
        self.uploaded += len(piece_data)

        logger.info(f"  ✅ Uploaded piece {piece_index} ({len(piece_data)} bytes)")

        return piece_data, piece_hash

    def receive_receipt_from_peer(self, receipt: PBTSReceipt):
        """
        Receive a receipt from a peer (for a piece we uploaded)

        In real BEP 10 protocol, this would be received via P2P message.
        Here we just add it to our collection for batch submission.

        Args:
            receipt: Receipt from downloader
        """
        # Verify receipt signature
        is_valid = verify_signature(
            receipt.receiver_pk,
            receipt.get_message(),
            receipt.signature
        )

        if not is_valid:
            logger.warning(f"⚠️  Received INVALID receipt for piece {receipt.piece_index}")
            return

        logger.info(f"  📥 Received valid receipt from peer for piece {receipt.piece_index}")

        # Add to collection
        self.receipts_to_submit.append(receipt)

        # Check if should submit batch
        if len(self.receipts_to_submit) >= self.receipt_batch_threshold:
            logger.info(f"  🔄 Receipt batch threshold reached ({len(self.receipts_to_submit)} receipts)")
            self.submit_receipts_to_tracker()

    def submit_receipts_to_tracker(self, update_contract: bool = True):
        """
        Submit accumulated receipts to tracker via HTTP API

        This is the real implementation - actually calls tracker /report endpoint

        Args:
            update_contract: Whether to also update smart contract
        """
        if not self.receipts_to_submit:
            logger.info("No receipts to submit")
            return

        logger.info(f"📤 Submitting {len(self.receipts_to_submit)} receipts to tracker...")

        # Format receipts for API
        receipts_data = []
        for r in self.receipts_to_submit:
            receipts_data.append({
                "infohash": r.infohash.hex(),
                "sender_pk": base64.b64encode(r.sender_pk).decode(),
                "receiver_pk": base64.b64encode(r.receiver_pk).decode(),
                "piece_hash": r.piece_hash.hex(),
                "piece_index": r.piece_index,
                "t_epoch": r.t_epoch,
                "signature": base64.b64encode(r.signature).decode()
            })

        try:
            # Submit to tracker
            response = requests.post(
                f"{self.tracker_url}/report",
                json={
                    "user_id": self.user_id,
                    "receipts": receipts_data
                },
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(f"  ✅ Receipts accepted by tracker")
                logger.info(f"     Stats updated: {result.get('stats_updated', {})}")

                # Clear submitted receipts
                submitted_count = len(self.receipts_to_submit)
                self.receipts_to_submit = []

                # Optionally update smart contract
                if update_contract:
                    self._update_smart_contract()

                return submitted_count
            else:
                logger.error(f"  ❌ Tracker rejected receipts: {response.text}")
                return 0

        except Exception as e:
            logger.error(f"  ❌ Failed to submit receipts: {e}")
            return 0

    def _update_smart_contract(self):
        """Update smart contract with current stats"""
        try:
            response = requests.post(
                f"{self.tracker_url}/contract/update",
                json={
                    "username": self.user_id,
                    "download_size": self.downloaded,
                    "upload_size": self.uploaded
                },
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"  ✅ Smart contract updated")
            else:
                logger.warning(f"  ⚠️  Contract update failed: {response.text}")

        except Exception as e:
            logger.warning(f"  ⚠️  Contract update error: {e}")

    def get_stats(self) -> Dict:
        """Get client statistics"""
        ratio = self.uploaded / self.downloaded if self.downloaded > 0 else 0.0

        return {
            "user_id": self.user_id,
            "mode": self.mode,
            "downloaded": self.downloaded,
            "uploaded": self.uploaded,
            "left": self.left,
            "ratio": ratio,
            "receipts_pending": len(self.receipts_to_submit)
        }

    def print_stats(self):
        """Print client statistics"""
        stats = self.get_stats()
        logger.info(f"📊 Client Stats for {stats['user_id']}:")
        logger.info(f"   Downloaded: {stats['downloaded']} bytes")
        logger.info(f"   Uploaded: {stats['uploaded']} bytes")
        logger.info(f"   Ratio: {stats['ratio']:.2f}")
        logger.info(f"   Pending receipts: {stats['receipts_pending']}")


def load_keys_from_file(keys_file: Path) -> Tuple[bytes, bytes]:
    """Load private and public keys from JSON file"""
    with open(keys_file, 'r') as f:
        keys_data = json.load(f)

    private_key = base64.b64decode(keys_data['private_key'])
    public_key = base64.b64decode(keys_data['public_key'])

    return private_key, public_key


def main():
    parser = argparse.ArgumentParser(description='PBTS BitTorrent Client for E2E Testing')
    parser.add_argument('--user-id', required=True, help='User ID for tracker')
    parser.add_argument('--keys', required=True, help='Path to keys JSON file')
    parser.add_argument('--torrent', required=True, help='Path to .torrent file')
    parser.add_argument('--mode', choices=['seeder', 'leecher'], required=True)
    parser.add_argument('--tracker', default='http://localhost:8000', help='Tracker URL')
    parser.add_argument('--data', help='Path to data file (for seeders)')

    args = parser.parse_args()

    # Load keys
    private_key, public_key = load_keys_from_file(Path(args.keys))

    # Create client
    client = PBTSClient(
        user_id=args.user_id,
        private_key=private_key,
        public_key=public_key,
        tracker_url=args.tracker,
        mode=args.mode,
        data_file=Path(args.data) if args.data else None
    )

    # Load torrent
    client.load_torrent(Path(args.torrent))

    # Announce to tracker
    client.announce_to_tracker(event="started")

    logger.info(f"Client ready - Press Ctrl+C to stop")

    try:
        # Keep client running
        while True:
            time.sleep(10)
            client.print_stats()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        client.announce_to_tracker(event="stopped")


if __name__ == "__main__":
    main()
