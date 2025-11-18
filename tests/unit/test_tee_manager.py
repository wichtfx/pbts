#!/usr/bin/env python3
"""
Unit tests for TEE Manager

Tests cover:
- TEE mode configuration
- Keypair generation (baseline and TEE-derived)
- Attestation generation and verification
- Statistics tracking
- Error handling
- Graceful degradation when TEE unavailable
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import unittest
import time
from unittest.mock import Mock, patch, MagicMock
from tee_manager import (
    TEEManager,
    TEEMode,
    TEEKeyPair,
    AttestationReport,
    get_tee_manager,
    set_tee_mode,
    TEE_AVAILABLE
)
from py_ecc.bls import G2ProofOfPossession as bls


class TestTEEMode(unittest.TestCase):
    """Test TEE mode enumeration"""

    def test_modes_exist(self):
        """Test that all modes are defined"""
        self.assertEqual(TEEMode.DISABLED.value, "disabled")
        self.assertEqual(TEEMode.ENABLED.value, "enabled")
        self.assertEqual(TEEMode.BENCHMARK.value, "benchmark")


class TestTEEManagerBaseline(unittest.TestCase):
    """Test TEE Manager in baseline mode (no TEE required)"""

    def setUp(self):
        """Initialize manager in disabled mode"""
        self.manager = TEEManager(mode=TEEMode.DISABLED)

    def test_initialization(self):
        """Test manager initializes correctly"""
        self.assertEqual(self.manager.mode, TEEMode.DISABLED)
        self.assertIsNotNone(self.manager.stats)
        self.assertEqual(self.manager.stats['key_generations'], 0)

    def test_generate_baseline_keypair(self):
        """Test baseline BLS keypair generation"""
        keypair = self.manager.generate_keypair(tee_enabled=False)

        # Verify keypair structure
        self.assertIsInstance(keypair, TEEKeyPair)
        self.assertEqual(len(keypair.private_key), 32)
        self.assertEqual(len(keypair.public_key), 48)
        self.assertFalse(keypair.tee_derived)
        self.assertIsNotNone(keypair.derivation_time_ms)
        self.assertGreater(keypair.derivation_time_ms, 0)

    def test_keypair_is_valid_bls(self):
        """Test that generated keypair is valid BLS12-381"""
        keypair = self.manager.generate_keypair(tee_enabled=False)

        # Verify public key matches private key
        sk_int = int.from_bytes(keypair.private_key, 'big')
        expected_pk = bls.SkToPk(sk_int)

        # bls.SkToPk returns bytes directly (48 bytes for BLS12-381)
        self.assertEqual(keypair.public_key, expected_pk)

    def test_keypair_uniqueness(self):
        """Test that each keypair is unique"""
        keypair1 = self.manager.generate_keypair(tee_enabled=False)
        keypair2 = self.manager.generate_keypair(tee_enabled=False)

        self.assertNotEqual(keypair1.private_key, keypair2.private_key)
        self.assertNotEqual(keypair1.public_key, keypair2.public_key)

    def test_statistics_tracking(self):
        """Test that statistics are tracked correctly"""
        # Initial state
        self.assertEqual(self.manager.stats['key_generations'], 0)

        # Generate keypairs
        keypair1 = self.manager.generate_keypair(tee_enabled=False)
        self.assertEqual(self.manager.stats['key_generations'], 1)

        keypair2 = self.manager.generate_keypair(tee_enabled=False)
        self.assertEqual(self.manager.stats['key_generations'], 2)

        # Verify total time is sum of individual times
        expected_total = keypair1.derivation_time_ms + keypair2.derivation_time_ms
        self.assertAlmostEqual(
            self.manager.stats['total_key_gen_time_ms'],
            expected_total,
            delta=0.001
        )

    def test_get_statistics(self):
        """Test statistics retrieval"""
        # Generate some keypairs
        for _ in range(5):
            self.manager.generate_keypair(tee_enabled=False)

        stats = self.manager.get_statistics()

        self.assertEqual(stats['key_generations'], 5)
        self.assertGreater(stats['avg_key_gen_time_ms'], 0)
        self.assertEqual(stats['attestations_generated'], 0)
        self.assertEqual(stats['avg_attestation_time_ms'], 0)

    def test_reset_statistics(self):
        """Test statistics reset"""
        # Generate some data
        self.manager.generate_keypair(tee_enabled=False)
        self.assertEqual(self.manager.stats['key_generations'], 1)

        # Reset
        self.manager.reset_statistics()

        # Verify reset
        self.assertEqual(self.manager.stats['key_generations'], 0)
        self.assertEqual(self.manager.stats['total_key_gen_time_ms'], 0)

    def test_tee_mode_disabled_prevents_tee_ops(self):
        """Test that TEE operations fail when mode is DISABLED"""
        with self.assertRaises(RuntimeError):
            self.manager.generate_keypair(tee_enabled=True)


@unittest.skipIf(not TEE_AVAILABLE, "TEE SDK not available")
class TestTEEManagerWithTEE(unittest.TestCase):
    """Test TEE Manager with TEE enabled (requires dstack_sdk)"""

    def setUp(self):
        """Initialize manager in enabled mode"""
        self.manager = TEEManager(mode=TEEMode.ENABLED)

    def test_tee_keypair_generation(self):
        """Test TEE-derived keypair generation"""
        keypair = self.manager.generate_keypair(tee_enabled=True)

        # Verify keypair structure
        self.assertIsInstance(keypair, TEEKeyPair)
        self.assertEqual(len(keypair.private_key), 32)
        self.assertEqual(len(keypair.public_key), 48)
        self.assertTrue(keypair.tee_derived)
        self.assertGreater(keypair.derivation_time_ms, 0)

    def test_attestation_generation(self):
        """Test TDX attestation generation"""
        payload = "test_user_registration"
        attestation = self.manager.generate_attestation(payload)

        # Verify attestation structure
        self.assertIsInstance(attestation, AttestationReport)
        self.assertIsNotNone(attestation.quote)
        self.assertEqual(attestation.payload, payload)
        self.assertGreater(attestation.generation_time_ms, 0)
        self.assertGreater(attestation.quote_size_bytes, 0)

    def test_attestation_with_large_payload(self):
        """Test attestation with payload > 64 bytes (should hash it)"""
        large_payload = "x" * 1000
        attestation = self.manager.generate_attestation(large_payload)

        # Should succeed despite large payload
        self.assertIsNotNone(attestation.quote)

    def test_attestation_statistics(self):
        """Test attestation statistics tracking"""
        self.assertEqual(self.manager.stats['attestations_generated'], 0)

        attestation = self.manager.generate_attestation("test")
        self.assertEqual(self.manager.stats['attestations_generated'], 1)
        self.assertAlmostEqual(
            self.manager.stats['total_attestation_time_ms'],
            attestation.generation_time_ms,
            delta=0.001
        )

    def test_verify_attestation_stub(self):
        """Test attestation verification (stub implementation)"""
        # Generate attestation
        payload = "verification_test"
        attestation = self.manager.generate_attestation(payload)

        # Verify (currently a stub that returns True)
        is_valid, duration_ms = self.manager.verify_attestation(
            attestation.quote,
            payload
        )

        # Stub should return True
        self.assertTrue(is_valid)
        self.assertGreater(duration_ms, 0)

    def test_get_ethereum_account(self):
        """Test Ethereum account derivation from TEE"""
        account = self.manager.get_ethereum_account(
            path="test/ethereum/path",
            purpose="testing"
        )

        # Verify account has required attributes
        self.assertIsNotNone(account)
        self.assertIsNotNone(account.address)
        # Account should have Web3.py account interface


class TestTEEManagerMocked(unittest.TestCase):
    """Test TEE Manager with mocked dstack SDK (no hardware required)"""

    @patch('tee_manager.TEE_AVAILABLE', True)
    @patch('tee_manager.DstackClient')
    def test_tee_keypair_with_mock(self, mock_dstack_client):
        """Test TEE keypair generation with mocked SDK"""
        # Setup mock
        mock_key_response = Mock()
        mock_key_response.decode_key.return_value = b'\x42' * 32  # Mock 32-byte key
        mock_dstack_client.return_value.get_key.return_value = mock_key_response

        # Test
        manager = TEEManager(mode=TEEMode.ENABLED)
        keypair = manager.generate_keypair(tee_enabled=True)

        # Verify SDK was called
        mock_dstack_client.return_value.get_key.assert_called_once()
        call_args = mock_dstack_client.return_value.get_key.call_args[0]
        self.assertIn('pbts/bls/', call_args[0])  # Path
        self.assertEqual(call_args[1], 'signature')  # Purpose

        # Verify keypair
        self.assertTrue(keypair.tee_derived)
        self.assertEqual(len(keypair.private_key), 32)

    @patch('tee_manager.TEE_AVAILABLE', True)
    @patch('tee_manager.DstackClient')
    def test_attestation_with_mock(self, mock_dstack_client):
        """Test attestation generation with mocked SDK"""
        # Setup mock
        mock_quote_response = Mock()
        mock_quote_response.quote = b'MOCK_TDX_QUOTE_DATA_' * 50
        mock_dstack_client.return_value.get_quote.return_value = mock_quote_response

        # Test
        manager = TEEManager(mode=TEEMode.ENABLED)
        attestation = manager.generate_attestation("test_payload")

        # Verify SDK was called
        mock_dstack_client.return_value.get_quote.assert_called_once()

        # Verify attestation
        self.assertEqual(attestation.quote, b'MOCK_TDX_QUOTE_DATA_' * 50)
        self.assertEqual(attestation.payload, "test_payload")


class TestTEEManagerSingleton(unittest.TestCase):
    """Test singleton pattern for TEE manager"""

    def setUp(self):
        """Reset singleton before each test"""
        import tee_manager
        tee_manager._tee_manager_instance = None

    def test_get_tee_manager_creates_instance(self):
        """Test that get_tee_manager creates instance"""
        manager = get_tee_manager(TEEMode.DISABLED)
        self.assertIsNotNone(manager)
        self.assertEqual(manager.mode, TEEMode.DISABLED)

    def test_get_tee_manager_returns_same_instance(self):
        """Test that get_tee_manager returns singleton"""
        manager1 = get_tee_manager(TEEMode.DISABLED)
        manager2 = get_tee_manager(TEEMode.BENCHMARK)  # Mode ignored

        self.assertIs(manager1, manager2)

    def test_set_tee_mode_creates_new_instance(self):
        """Test that set_tee_mode creates new instance"""
        manager1 = get_tee_manager(TEEMode.DISABLED)
        set_tee_mode(TEEMode.DISABLED)
        manager2 = get_tee_manager()

        self.assertIsNot(manager1, manager2)


class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases"""

    def test_tee_mode_enabled_without_sdk(self):
        """Test that ENABLED mode fails without SDK"""
        if not TEE_AVAILABLE:
            with self.assertRaises(RuntimeError) as ctx:
                TEEManager(mode=TEEMode.ENABLED)
            self.assertIn("dstack_sdk not available", str(ctx.exception))

    def test_attestation_without_tee(self):
        """Test that attestation fails without TEE"""
        manager = TEEManager(mode=TEEMode.DISABLED)

        with self.assertRaises(RuntimeError) as ctx:
            manager.generate_attestation("test")
        self.assertIn("TEE not available", str(ctx.exception))

    def test_ethereum_account_without_tee(self):
        """Test that Ethereum derivation fails without TEE"""
        manager = TEEManager(mode=TEEMode.DISABLED)

        with self.assertRaises(RuntimeError) as ctx:
            manager.get_ethereum_account()
        self.assertIn("TEE not available", str(ctx.exception))


def run_tests():
    """Run all tests"""
    unittest.main(verbosity=2)


if __name__ == '__main__':
    run_tests()
