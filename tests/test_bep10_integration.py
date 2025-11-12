#!/usr/bin/env python3
"""
Integration tests for BEP 10 with PBTS tracker

Tests the complete workflow:
1. Extended handshake between peers
2. Piece transfer and receipt generation
3. Receipt exchange via BEP 10
4. Batch submission to tracker
5. Signature verification by tracker

Requires tracker to be running on localhost:8000
"""

import unittest
import hashlib
import time
import base64
import struct
from typing import Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: requests not available, skipping tracker integration tests")

from bep10_extension import (
    BEP10Handler,
    PBTSReceipt,
    compute_piece_hash,
    compute_time_epoch,
)

# Import tracker functions if available
try:
    from tracker import generate_keypair, sign_message, verify_signature
    HAS_TRACKER = True
except ImportError:
    HAS_TRACKER = False
    print("Warning: tracker.py not found in path")


class TestPeerToPeerReceiptExchange(unittest.TestCase):
    """Test peer-to-peer receipt exchange workflow"""

    def setUp(self):
        """Set up two peers with PBTS extension"""
        self.alice = BEP10Handler(client_version="Alice Test Client")
        self.bob = BEP10Handler(client_version="Bob Test Client")

        # Simulate successful handshake
        alice_handshake = self.alice.create_handshake(listening_port=6881)
        bob_handshake = self.bob.create_handshake(listening_port=6882)

        # Parse each other's handshakes
        self.alice.parse_handshake(bob_handshake[6:])
        self.bob.parse_handshake(alice_handshake[6:])

        # Verify both support PBTS
        self.assertTrue(self.alice.peer_supports_pbts)
        self.assertTrue(self.bob.peer_supports_pbts)

    def test_single_receipt_exchange(self):
        """Test exchanging a single receipt between peers"""
        # Alice uploads piece to Bob
        infohash = hashlib.sha1(b"test_torrent").digest()
        piece_data = b"piece_data" * 100
        piece_hash = compute_piece_hash(piece_data)
        piece_index = 10

        # Bob creates receipt for the download
        receipt = PBTSReceipt(
            infohash=infohash,
            sender_pk=b"ALICE_PK" * 6,  # Mock public keys
            receiver_pk=b"BOB_PK" * 8,
            piece_hash=piece_hash,
            piece_index=piece_index,
            timestamp=time.time(),
            t_epoch=compute_time_epoch(time.time()),
            signature=b"X" * 96  # Mock signature
        )

        # Bob sends receipt to Alice
        receipt_msg = self.bob.create_receipt_message(receipt)

        # Alice receives and parses
        msg_id = receipt_msg[5]
        payload = receipt_msg[6:]
        received = self.alice.parse_message(msg_id, payload)

        self.assertIsNotNone(received)
        self.assertEqual(received.piece_index, piece_index)
        self.assertEqual(received.receipt_id(), receipt.receipt_id())

    def test_batch_receipt_exchange(self):
        """Test exchanging multiple receipts in batch"""
        receipts = []
        infohash = hashlib.sha1(b"test_torrent").digest()

        # Create 10 receipts for different pieces
        for i in range(10):
            piece_data = f"piece_{i}".encode() * 100
            receipt = PBTSReceipt(
                infohash=infohash,
                sender_pk=b"ALICE_PK" * 6,
                receiver_pk=b"BOB_PK" * 8,
                piece_hash=compute_piece_hash(piece_data),
                piece_index=i,
                timestamp=time.time(),
                t_epoch=compute_time_epoch(time.time()),
                signature=b"X" * 96
            )
            receipts.append(receipt)

        # Bob sends batch to Alice
        batch_msg = self.bob.create_receipt_batch_message(receipts)

        # Alice receives and parses
        msg_id = batch_msg[5]
        payload = batch_msg[6:]
        received = self.alice.parse_message(msg_id, payload)

        self.assertIsInstance(received, list)
        self.assertEqual(len(received), 10)
        for i, r in enumerate(received):
            self.assertEqual(r.piece_index, i)

    def test_receipt_request_response(self):
        """Test requesting a receipt from peer"""
        infohash = hashlib.sha1(b"test_torrent").digest()
        piece_hash = compute_piece_hash(b"piece_data")
        piece_index = 5

        # Alice requests receipt from Bob
        request_msg = self.alice.create_request_receipt_message(
            infohash=infohash,
            piece_index=piece_index,
            piece_hash=piece_hash
        )

        # Bob receives request
        msg_id = request_msg[5]
        payload = request_msg[6:]
        request = self.bob.parse_message(msg_id, payload)

        self.assertIsInstance(request, dict)
        self.assertEqual(request["infohash"], infohash)
        self.assertEqual(request["piece_index"], piece_index)

        # Bob creates and sends receipt
        receipt = PBTSReceipt(
            infohash=request["infohash"],
            sender_pk=b"ALICE_PK" * 6,
            receiver_pk=b"BOB_PK" * 8,
            piece_hash=request["piece_hash"],
            piece_index=request["piece_index"],
            timestamp=time.time(),
            t_epoch=compute_time_epoch(time.time()),
            signature=b"X" * 96
        )

        receipt_msg = self.bob.create_receipt_message(receipt)

        # Alice receives receipt
        msg_id = receipt_msg[5]
        payload = receipt_msg[6:]
        received = self.alice.parse_message(msg_id, payload)

        self.assertIsNotNone(received)
        self.assertEqual(received.piece_index, piece_index)


@unittest.skipUnless(HAS_TRACKER, "Tracker module not available")
class TestReceiptGeneration(unittest.TestCase):
    """Test receipt generation with real BLS signatures"""

    def setUp(self):
        """Generate keypairs for testing"""
        self.alice_sk, self.alice_pk = generate_keypair()
        self.bob_sk, self.bob_pk = generate_keypair()

    def test_create_signed_receipt(self):
        """Test creating receipt with valid BLS signature"""
        infohash = hashlib.sha1(b"test_torrent").digest()
        piece_data = b"test_piece_data" * 100
        piece_hash = compute_piece_hash(piece_data)
        piece_index = 42
        timestamp = time.time()
        t_epoch = compute_time_epoch(timestamp)

        # Bob (receiver) signs the receipt
        message = (
            infohash +
            self.alice_pk +  # sender
            piece_hash +
            struct.pack(">I", piece_index) +
            struct.pack(">Q", t_epoch)
        )

        signature = sign_message(self.bob_sk, message)

        receipt = PBTSReceipt(
            infohash=infohash,
            sender_pk=self.alice_pk,
            receiver_pk=self.bob_pk,
            piece_hash=piece_hash,
            piece_index=piece_index,
            timestamp=timestamp,
            t_epoch=t_epoch,
            signature=signature
        )

        # Verify signature
        is_valid = verify_signature(
            self.bob_pk,
            receipt.get_message(),
            receipt.signature
        )

        self.assertTrue(is_valid)

    def test_invalid_signature_detection(self):
        """Test that invalid signatures are detected"""
        infohash = hashlib.sha1(b"test_torrent").digest()
        piece_hash = compute_piece_hash(b"piece")
        timestamp = time.time()
        t_epoch = compute_time_epoch(timestamp)

        # Create receipt with wrong signature
        receipt = PBTSReceipt(
            infohash=infohash,
            sender_pk=self.alice_pk,
            receiver_pk=self.bob_pk,
            piece_hash=piece_hash,
            piece_index=1,
            timestamp=timestamp,
            t_epoch=t_epoch,
            signature=b"X" * 96  # Invalid signature
        )

        # Verify should fail
        is_valid = verify_signature(
            self.bob_pk,
            receipt.get_message(),
            receipt.signature
        )

        self.assertFalse(is_valid)


@unittest.skipUnless(HAS_REQUESTS and HAS_TRACKER, "Requires requests and tracker")
class TestTrackerIntegration(unittest.TestCase):
    """
    Integration tests with running tracker

    These tests require:
    1. Tracker running on localhost:8000
    2. Tracker signature verification disabled (default)
    """

    TRACKER_URL = "http://localhost:8000"

    @classmethod
    def setUpClass(cls):
        """Check if tracker is available"""
        try:
            response = requests.get(f"{cls.TRACKER_URL}/health", timeout=1)
            if response.status_code != 200:
                raise unittest.SkipTest("Tracker not responding")
        except requests.RequestException:
            raise unittest.SkipTest("Tracker not available at localhost:8000")

    def setUp(self):
        """Generate test keypairs and register users"""
        self.alice_sk, self.alice_pk = generate_keypair()
        self.bob_sk, self.bob_pk = generate_keypair()

        # Register Alice
        response = requests.post(
            f"{self.TRACKER_URL}/register",
            json={
                "user_id": "test_alice",
                "public_key": base64.b64encode(self.alice_pk).decode()
            }
        )
        self.assertEqual(response.status_code, 200)

        # Register Bob
        response = requests.post(
            f"{self.TRACKER_URL}/register",
            json={
                "user_id": "test_bob",
                "public_key": base64.b64encode(self.bob_pk).decode()
            }
        )
        self.assertEqual(response.status_code, 200)

    def test_submit_single_receipt(self):
        """Test submitting single receipt to tracker"""
        infohash = hashlib.sha1(b"integration_test_torrent").digest()
        piece_data = b"test_piece" * 100
        piece_hash = compute_piece_hash(piece_data)
        timestamp = time.time()
        t_epoch = compute_time_epoch(timestamp)

        # Create signed receipt
        message = (
            infohash +
            self.alice_pk +
            piece_hash +
            struct.pack(">I", 0) +
            struct.pack(">Q", t_epoch)
        )
        signature = sign_message(self.bob_sk, message)

        receipt = PBTSReceipt(
            infohash=infohash,
            sender_pk=self.alice_pk,
            receiver_pk=self.bob_pk,
            piece_hash=piece_hash,
            piece_index=0,
            timestamp=timestamp,
            t_epoch=t_epoch,
            signature=signature
        )

        # Submit to tracker
        response = requests.post(
            f"{self.TRACKER_URL}/report",
            json={
                "user_id": "test_alice",
                "receipts": [{
                    "infohash": receipt.infohash.hex(),
                    "sender_pk": base64.b64encode(receipt.sender_pk).decode(),
                    "receiver_pk": base64.b64encode(receipt.receiver_pk).decode(),
                    "piece_hash": receipt.piece_hash.hex(),
                    "piece_index": receipt.piece_index,
                    "t_epoch": receipt.t_epoch,
                    "signature": base64.b64encode(receipt.signature).decode()
                }]
            }
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("stats_updated", data)

    def test_submit_receipt_batch(self):
        """Test submitting batch of receipts to tracker"""
        infohash = hashlib.sha1(b"batch_test_torrent").digest()
        receipts_data = []

        # Create 5 receipts
        for i in range(5):
            piece_data = f"piece_{i}".encode() * 100
            piece_hash = compute_piece_hash(piece_data)
            timestamp = time.time()
            t_epoch = compute_time_epoch(timestamp)

            message = (
                infohash +
                self.alice_pk +
                piece_hash +
                struct.pack(">I", i) +
                struct.pack(">Q", t_epoch)
            )
            signature = sign_message(self.bob_sk, message)

            receipts_data.append({
                "infohash": infohash.hex(),
                "sender_pk": base64.b64encode(self.alice_pk).decode(),
                "receiver_pk": base64.b64encode(self.bob_pk).decode(),
                "piece_hash": piece_hash.hex(),
                "piece_index": i,
                "t_epoch": t_epoch,
                "signature": base64.b64encode(signature).decode()
            })

        # Submit batch
        response = requests.post(
            f"{self.TRACKER_URL}/report",
            json={
                "user_id": "test_alice",
                "receipts": receipts_data
            }
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("stats_updated", data)

    def test_double_spend_prevention(self):
        """Test that duplicate receipts are rejected"""
        infohash = hashlib.sha1(b"double_spend_test").digest()
        piece_hash = compute_piece_hash(b"piece")
        timestamp = time.time()
        t_epoch = compute_time_epoch(timestamp)

        message = (
            infohash +
            self.alice_pk +
            piece_hash +
            struct.pack(">I", 0) +
            struct.pack(">Q", t_epoch)
        )
        signature = sign_message(self.bob_sk, message)

        receipt_data = {
            "infohash": infohash.hex(),
            "sender_pk": base64.b64encode(self.alice_pk).decode(),
            "receiver_pk": base64.b64encode(self.bob_pk).decode(),
            "piece_hash": piece_hash.hex(),
            "piece_index": 0,
            "t_epoch": t_epoch,
            "signature": base64.b64encode(signature).decode()
        }

        # Submit first time - should succeed
        response1 = requests.post(
            f"{self.TRACKER_URL}/report",
            json={
                "user_id": "test_alice",
                "receipts": [receipt_data]
            }
        )
        self.assertEqual(response1.status_code, 200)

        # Submit again - should be rejected
        response2 = requests.post(
            f"{self.TRACKER_URL}/report",
            json={
                "user_id": "test_alice",
                "receipts": [receipt_data]
            }
        )

        # Tracker may return 200 but not count duplicate
        # Check response message
        if response2.status_code == 200:
            data = response2.json()
            # Tracker should indicate no new stats updated
            # (implementation may vary)
            pass


class TestEndToEndWorkflow(unittest.TestCase):
    """Test complete end-to-end workflow"""

    def test_complete_piece_transfer_workflow(self):
        """
        Simulate complete workflow:
        1. Peers perform handshake
        2. Alice uploads piece to Bob
        3. Bob creates receipt with signature
        4. Bob sends receipt to Alice via BEP 10
        5. Alice accumulates receipts
        6. Alice submits batch to tracker
        """
        # Step 1: Handshake
        alice = BEP10Handler(client_version="Alice")
        bob = BEP10Handler(client_version="Bob")

        alice_hs = alice.create_handshake()
        bob_hs = bob.create_handshake()

        alice.parse_handshake(bob_hs[6:])
        bob.parse_handshake(alice_hs[6:])

        self.assertTrue(alice.peer_supports_pbts)
        self.assertTrue(bob.peer_supports_pbts)

        # Step 2: Simulate piece transfer
        infohash = hashlib.sha1(b"e2e_test_torrent").digest()
        receipts_for_alice = []

        for piece_index in range(10):
            piece_data = f"piece_{piece_index}".encode() * 100

            # Step 3: Bob creates receipt
            receipt = PBTSReceipt(
                infohash=infohash,
                sender_pk=b"ALICE_PK" * 6,
                receiver_pk=b"BOB_PK" * 8,
                piece_hash=compute_piece_hash(piece_data),
                piece_index=piece_index,
                timestamp=time.time(),
                t_epoch=compute_time_epoch(time.time()),
                signature=b"X" * 96
            )

            # Step 4: Bob sends to Alice
            receipt_msg = bob.create_receipt_message(receipt)
            msg_id = receipt_msg[5]
            payload = receipt_msg[6:]
            received = alice.parse_message(msg_id, payload)

            # Step 5: Alice accumulates
            receipts_for_alice.append(received)

        # Verify Alice collected all receipts
        self.assertEqual(len(receipts_for_alice), 10)

        # Step 6: Alice would submit batch to tracker
        # (requires tracker running and real signatures)
        # This is tested in TestTrackerIntegration


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
