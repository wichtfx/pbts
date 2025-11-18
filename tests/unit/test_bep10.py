#!/usr/bin/env python3
"""
Unit tests for BEP 10 Extension Protocol implementation

Tests cover:
- Extended handshake negotiation
- Receipt message encoding/decoding
- Batch receipt handling
- Message ID mapping
- Error handling
"""

import unittest
import hashlib
import time
import struct
from typing import List

from bep10_extension import (
    BEP10Handler,
    PBTSReceipt,
    ExtensionHandshake,
    compute_piece_hash,
    compute_time_epoch,
    EXTENDED_MESSAGE_ID,
    HANDSHAKE_MESSAGE_ID,
    PBTS_RECEIPT_MSG,
    PBTS_RECEIPT_BATCH_MSG,
    PBTS_REQUEST_RECEIPT_MSG,
    PBTS_EXTENSION_NAME
)


class TestExtensionHandshake(unittest.TestCase):
    """Test extended handshake creation and parsing"""

    def setUp(self):
        self.handler = BEP10Handler(client_version="Test Client 1.0")

    def test_create_handshake(self):
        """Test handshake message creation"""
        handshake_msg = self.handler.create_handshake(listening_port=6881)

        # Check message structure
        self.assertIsInstance(handshake_msg, bytes)
        self.assertGreater(len(handshake_msg), 20)

        # Check length prefix
        length = struct.unpack(">I", handshake_msg[:4])[0]
        self.assertEqual(length, len(handshake_msg) - 4)

        # Check message IDs
        ext_id = handshake_msg[4]
        handshake_id = handshake_msg[5]
        self.assertEqual(ext_id, EXTENDED_MESSAGE_ID)
        self.assertEqual(handshake_id, HANDSHAKE_MESSAGE_ID)

    def test_parse_handshake_with_pbts(self):
        """Test parsing handshake that supports PBTS"""
        # Create handshake
        handshake_msg = self.handler.create_handshake()

        # Extract payload (skip length + ext_id + handshake_id)
        payload = handshake_msg[6:]

        # Parse as peer
        peer_handler = BEP10Handler()
        supports_pbts = peer_handler.parse_handshake(payload)

        self.assertTrue(supports_pbts)
        self.assertTrue(peer_handler.peer_supports_pbts)
        self.assertIn(PBTS_RECEIPT_MSG, peer_handler.remote_ext_ids)
        self.assertIn(PBTS_RECEIPT_BATCH_MSG, peer_handler.remote_ext_ids)
        self.assertIn(PBTS_REQUEST_RECEIPT_MSG, peer_handler.remote_ext_ids)

    def test_parse_handshake_without_pbts(self):
        """Test parsing handshake without PBTS extension"""
        import bencoder

        # Create handshake without PBTS
        handshake = ExtensionHandshake(
            supported_extensions={b"ut_metadata": {b"msg_id": 1}},
            client_version="Other Client"
        )
        payload = bencoder.encode(handshake.to_dict())

        handler = BEP10Handler()
        supports_pbts = handler.parse_handshake(payload)

        self.assertFalse(supports_pbts)
        self.assertFalse(handler.peer_supports_pbts)

    def test_handshake_roundtrip(self):
        """Test complete handshake roundtrip"""
        # Alice creates handshake
        alice = BEP10Handler(client_version="Alice Client")
        alice_handshake = alice.create_handshake(listening_port=6881)

        # Bob receives and parses
        bob = BEP10Handler(client_version="Bob Client")
        bob_handshake = bob.create_handshake(listening_port=6882)

        alice_supports = bob.parse_handshake(alice_handshake[6:])
        bob_supports = alice.parse_handshake(bob_handshake[6:])

        self.assertTrue(alice_supports)
        self.assertTrue(bob_supports)
        self.assertEqual(alice.remote_ext_ids[PBTS_RECEIPT_MSG], 1)
        self.assertEqual(bob.remote_ext_ids[PBTS_RECEIPT_MSG], 1)


class TestPBTSReceipt(unittest.TestCase):
    """Test receipt data structure"""

    def setUp(self):
        self.infohash = hashlib.sha1(b"test_torrent").digest()
        self.sender_pk = b"S" * 48
        self.receiver_pk = b"R" * 48
        self.piece_data = b"piece_data_for_testing" * 100
        self.piece_hash = compute_piece_hash(self.piece_data)
        self.piece_index = 42
        self.timestamp = time.time()
        self.t_epoch = compute_time_epoch(self.timestamp)
        self.signature = b"X" * 96

    def test_receipt_creation(self):
        """Test creating a receipt"""
        receipt = PBTSReceipt(
            infohash=self.infohash,
            sender_pk=self.sender_pk,
            receiver_pk=self.receiver_pk,
            piece_hash=self.piece_hash,
            piece_index=self.piece_index,
            timestamp=self.timestamp,
            t_epoch=self.t_epoch,
            signature=self.signature
        )

        self.assertEqual(receipt.infohash, self.infohash)
        self.assertEqual(receipt.piece_index, self.piece_index)
        self.assertEqual(receipt.t_epoch, self.t_epoch)

    def test_receipt_to_dict(self):
        """Test receipt serialization to dict"""
        receipt = PBTSReceipt(
            infohash=self.infohash,
            sender_pk=self.sender_pk,
            receiver_pk=self.receiver_pk,
            piece_hash=self.piece_hash,
            piece_index=self.piece_index,
            timestamp=self.timestamp,
            t_epoch=self.t_epoch,
            signature=self.signature
        )

        data = receipt.to_dict()

        # Check all fields present with bytes keys
        self.assertIn(b"infohash", data)
        self.assertIn(b"sender_pk", data)
        self.assertIn(b"piece_hash", data)
        self.assertIn(b"piece_index", data)
        self.assertIn(b"timestamp", data)
        self.assertIn(b"t_epoch", data)
        self.assertIn(b"signature", data)

    def test_receipt_from_dict(self):
        """Test receipt deserialization from dict"""
        original = PBTSReceipt(
            infohash=self.infohash,
            sender_pk=self.sender_pk,
            receiver_pk=self.receiver_pk,
            piece_hash=self.piece_hash,
            piece_index=self.piece_index,
            timestamp=self.timestamp,
            t_epoch=self.t_epoch,
            signature=self.signature
        )

        data = original.to_dict()
        restored = PBTSReceipt.from_dict(data)

        self.assertEqual(restored.infohash, original.infohash)
        self.assertEqual(restored.sender_pk, original.sender_pk)
        self.assertEqual(restored.piece_index, original.piece_index)
        self.assertEqual(restored.t_epoch, original.t_epoch)

    def test_receipt_id_generation(self):
        """Test unique receipt ID generation"""
        receipt1 = PBTSReceipt(
            infohash=self.infohash,
            sender_pk=self.sender_pk,
            receiver_pk=self.receiver_pk,
            piece_hash=self.piece_hash,
            piece_index=self.piece_index,
            timestamp=self.timestamp,
            t_epoch=self.t_epoch,
            signature=self.signature
        )

        receipt2 = PBTSReceipt(
            infohash=self.infohash,
            sender_pk=self.sender_pk,
            receiver_pk=self.receiver_pk,
            piece_hash=self.piece_hash,
            piece_index=self.piece_index + 1,  # Different piece
            timestamp=self.timestamp,
            t_epoch=self.t_epoch,
            signature=self.signature
        )

        # Same piece should have same ID
        self.assertEqual(receipt1.receipt_id(), receipt1.receipt_id())

        # Different pieces should have different IDs
        self.assertNotEqual(receipt1.receipt_id(), receipt2.receipt_id())

    def test_get_message(self):
        """Test signed message generation"""
        receipt = PBTSReceipt(
            infohash=self.infohash,
            sender_pk=self.sender_pk,
            receiver_pk=self.receiver_pk,
            piece_hash=self.piece_hash,
            piece_index=self.piece_index,
            timestamp=self.timestamp,
            t_epoch=self.t_epoch,
            signature=self.signature
        )

        message = receipt.get_message()

        # Check message format
        self.assertIsInstance(message, bytes)
        expected_length = 20 + 48 + 32 + 4 + 8  # infohash + sender_pk + piece_hash + index + epoch
        self.assertEqual(len(message), expected_length)

        # Check components
        self.assertTrue(message.startswith(self.infohash))
        self.assertIn(self.sender_pk, message)
        self.assertIn(self.piece_hash, message)


class TestReceiptMessages(unittest.TestCase):
    """Test receipt message encoding/decoding"""

    def setUp(self):
        # Set up two handlers that have negotiated
        self.alice = BEP10Handler(client_version="Alice")
        self.bob = BEP10Handler(client_version="Bob")

        # Simulate handshake
        self.alice.peer_supports_pbts = True
        self.alice.remote_ext_ids = {
            PBTS_RECEIPT_MSG: 1,
            PBTS_RECEIPT_BATCH_MSG: 2,
            PBTS_REQUEST_RECEIPT_MSG: 3
        }
        self.alice.local_ext_ids = self.alice.remote_ext_ids.copy()

        self.bob.peer_supports_pbts = True
        self.bob.remote_ext_ids = self.alice.remote_ext_ids.copy()
        self.bob.local_ext_ids = self.alice.local_ext_ids.copy()

        # Create test receipt
        self.receipt = PBTSReceipt(
            infohash=hashlib.sha1(b"test").digest(),
            sender_pk=b"S" * 48,
            receiver_pk=b"R" * 48,
            piece_hash=hashlib.sha256(b"piece").digest(),
            piece_index=5,
            timestamp=time.time(),
            t_epoch=compute_time_epoch(time.time()),
            signature=b"X" * 96
        )

    def test_create_receipt_message(self):
        """Test single receipt message creation"""
        msg = self.alice.create_receipt_message(self.receipt)

        # Check structure
        self.assertIsInstance(msg, bytes)
        length = struct.unpack(">I", msg[:4])[0]
        self.assertEqual(length, len(msg) - 4)

        ext_id = msg[4]
        msg_id = msg[5]
        self.assertEqual(ext_id, EXTENDED_MESSAGE_ID)
        self.assertEqual(msg_id, 1)  # pbts_receipt

    def test_parse_receipt_message(self):
        """Test receipt message parsing"""
        msg = self.alice.create_receipt_message(self.receipt)

        # Bob receives and parses
        msg_id = msg[5]
        payload = msg[6:]
        parsed = self.bob.parse_message(msg_id, payload)

        self.assertIsInstance(parsed, PBTSReceipt)
        self.assertEqual(parsed.piece_index, self.receipt.piece_index)
        self.assertEqual(parsed.infohash, self.receipt.infohash)
        self.assertEqual(parsed.receipt_id(), self.receipt.receipt_id())

    def test_create_receipt_batch_message(self):
        """Test batch receipt message creation"""
        receipts = []
        for i in range(5):
            receipt = PBTSReceipt(
                infohash=hashlib.sha1(b"test").digest(),
                sender_pk=b"S" * 48,
                receiver_pk=b"R" * 48,
                piece_hash=hashlib.sha256(f"piece_{i}".encode()).digest(),
                piece_index=i,
                timestamp=time.time(),
                t_epoch=compute_time_epoch(time.time()),
                signature=b"X" * 96
            )
            receipts.append(receipt)

        msg = self.alice.create_receipt_batch_message(receipts)

        # Check structure
        self.assertIsInstance(msg, bytes)
        ext_id = msg[4]
        msg_id = msg[5]
        self.assertEqual(ext_id, EXTENDED_MESSAGE_ID)
        self.assertEqual(msg_id, 2)  # pbts_receipt_batch

    def test_parse_receipt_batch_message(self):
        """Test batch receipt message parsing"""
        receipts = []
        for i in range(5):
            receipt = PBTSReceipt(
                infohash=hashlib.sha1(b"test").digest(),
                sender_pk=b"S" * 48,
                receiver_pk=b"R" * 48,
                piece_hash=hashlib.sha256(f"piece_{i}".encode()).digest(),
                piece_index=i,
                timestamp=time.time(),
                t_epoch=compute_time_epoch(time.time()),
                signature=b"X" * 96
            )
            receipts.append(receipt)

        msg = self.alice.create_receipt_batch_message(receipts)

        # Bob receives and parses
        msg_id = msg[5]
        payload = msg[6:]
        parsed = self.bob.parse_message(msg_id, payload)

        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), 5)
        for i, r in enumerate(parsed):
            self.assertIsInstance(r, PBTSReceipt)
            self.assertEqual(r.piece_index, i)

    def test_create_request_receipt_message(self):
        """Test request receipt message creation"""
        infohash = hashlib.sha1(b"test").digest()
        piece_hash = hashlib.sha256(b"piece").digest()

        msg = self.alice.create_request_receipt_message(
            infohash=infohash,
            piece_index=10,
            piece_hash=piece_hash
        )

        # Check structure
        self.assertIsInstance(msg, bytes)
        ext_id = msg[4]
        msg_id = msg[5]
        self.assertEqual(ext_id, EXTENDED_MESSAGE_ID)
        self.assertEqual(msg_id, 3)  # pbts_request_receipt

    def test_parse_request_receipt_message(self):
        """Test request receipt message parsing"""
        infohash = hashlib.sha1(b"test").digest()
        piece_hash = hashlib.sha256(b"piece").digest()

        msg = self.alice.create_request_receipt_message(
            infohash=infohash,
            piece_index=10,
            piece_hash=piece_hash
        )

        # Bob receives and parses
        msg_id = msg[5]
        payload = msg[6:]
        parsed = self.bob.parse_message(msg_id, payload)

        self.assertIsInstance(parsed, dict)
        self.assertEqual(parsed["infohash"], infohash)
        self.assertEqual(parsed["piece_index"], 10)
        self.assertEqual(parsed["piece_hash"], piece_hash)

    def test_message_without_negotiation(self):
        """Test that messages fail without handshake"""
        handler = BEP10Handler()
        handler.peer_supports_pbts = False

        with self.assertRaises(ValueError):
            handler.create_receipt_message(self.receipt)


class TestBatchingLogic(unittest.TestCase):
    """Test receipt batching functionality"""

    def setUp(self):
        self.handler = BEP10Handler()

    def test_add_receipt(self):
        """Test adding receipts to pending batch"""
        receipt = PBTSReceipt(
            infohash=hashlib.sha1(b"test").digest(),
            sender_pk=b"S" * 48,
            receiver_pk=b"R" * 48,
            piece_hash=hashlib.sha256(b"piece").digest(),
            piece_index=0,
            timestamp=time.time(),
            t_epoch=compute_time_epoch(time.time()),
            signature=b"X" * 96
        )

        self.assertEqual(len(self.handler.pending_receipts), 0)
        self.handler.add_receipt(receipt)
        self.assertEqual(len(self.handler.pending_receipts), 1)

    def test_get_pending_receipts(self):
        """Test retrieving and clearing pending receipts"""
        for i in range(5):
            receipt = PBTSReceipt(
                infohash=hashlib.sha1(b"test").digest(),
                sender_pk=b"S" * 48,
                receiver_pk=b"R" * 48,
                piece_hash=hashlib.sha256(f"piece_{i}".encode()).digest(),
                piece_index=i,
                timestamp=time.time(),
                t_epoch=compute_time_epoch(time.time()),
                signature=b"X" * 96
            )
            self.handler.add_receipt(receipt)

        pending = self.handler.get_pending_receipts()
        self.assertEqual(len(pending), 5)
        self.assertEqual(len(self.handler.pending_receipts), 0)

    def test_should_batch_report(self):
        """Test batch threshold detection"""
        self.assertFalse(self.handler.should_batch_report(threshold=10))

        for i in range(5):
            receipt = PBTSReceipt(
                infohash=hashlib.sha1(b"test").digest(),
                sender_pk=b"S" * 48,
                receiver_pk=b"R" * 48,
                piece_hash=hashlib.sha256(f"piece_{i}".encode()).digest(),
                piece_index=i,
                timestamp=time.time(),
                t_epoch=compute_time_epoch(time.time()),
                signature=b"X" * 96
            )
            self.handler.add_receipt(receipt)

        self.assertFalse(self.handler.should_batch_report(threshold=10))
        self.assertTrue(self.handler.should_batch_report(threshold=3))


class TestHelperFunctions(unittest.TestCase):
    """Test utility functions"""

    def test_compute_piece_hash(self):
        """Test piece hash computation"""
        piece_data = b"test_piece_data"
        hash1 = compute_piece_hash(piece_data)

        self.assertIsInstance(hash1, bytes)
        self.assertEqual(len(hash1), 32)  # SHA-256

        # Same data should produce same hash
        hash2 = compute_piece_hash(piece_data)
        self.assertEqual(hash1, hash2)

        # Different data should produce different hash
        hash3 = compute_piece_hash(b"different_data")
        self.assertNotEqual(hash1, hash3)

    def test_compute_time_epoch(self):
        """Test time epoch computation"""
        timestamp = 7200.0  # 2 hours
        window = 3600  # 1 hour

        epoch = compute_time_epoch(timestamp, window)
        self.assertEqual(epoch, 2)

        # Test edge case
        epoch2 = compute_time_epoch(3599.0, window)
        self.assertEqual(epoch2, 0)

        epoch3 = compute_time_epoch(3600.0, window)
        self.assertEqual(epoch3, 1)

    def test_time_epoch_consistency(self):
        """Test that time epochs are deterministic"""
        timestamp = time.time()
        window = 3600

        epoch1 = compute_time_epoch(timestamp, window)
        epoch2 = compute_time_epoch(timestamp, window)

        self.assertEqual(epoch1, epoch2)


class TestErrorHandling(unittest.TestCase):
    """Test error conditions"""

    def test_invalid_handshake(self):
        """Test handling of invalid handshake data"""
        handler = BEP10Handler()

        # Invalid bencoded data
        result = handler.parse_handshake(b"invalid_data")
        self.assertFalse(result)

    def test_unknown_message_id(self):
        """Test handling of unknown message IDs"""
        handler = BEP10Handler()
        handler.local_ext_ids = {PBTS_RECEIPT_MSG: 1}

        # Unknown message ID
        result = handler.parse_message(99, b"payload")
        self.assertIsNone(result)

    def test_message_without_peer_support(self):
        """Test error when peer doesn't support PBTS"""
        handler = BEP10Handler()
        handler.peer_supports_pbts = False

        receipt = PBTSReceipt(
            infohash=hashlib.sha1(b"test").digest(),
            sender_pk=b"S" * 48,
            receiver_pk=b"R" * 48,
            piece_hash=hashlib.sha256(b"piece").digest(),
            piece_index=0,
            timestamp=time.time(),
            t_epoch=compute_time_epoch(time.time()),
            signature=b"X" * 96
        )

        with self.assertRaises(ValueError):
            handler.create_receipt_message(receipt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
