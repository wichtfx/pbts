"""
TEE Manager for PBTS Tracker

Provides abstraction layer for TEE operations using Phala's dstack_sdk.
Supports both TEE-enabled and fallback modes for benchmarking.
"""

import time
import logging
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass
from enum import Enum

# Import will be optional - graceful degradation if not available
try:
    from dstack_sdk import DstackClient, AsyncDstackClient
    from dstack_sdk.ethereum import to_account_secure
    TEE_AVAILABLE = True
except ImportError:
    TEE_AVAILABLE = False
    logging.warning("dstack_sdk not available - TEE features disabled")

from py_ecc.bls import G2ProofOfPossession as bls
import secrets


class TEEMode(Enum):
    """TEE operation modes"""
    DISABLED = "disabled"      # No TEE, use regular crypto
    ENABLED = "enabled"        # Use TEE for all operations
    BENCHMARK = "benchmark"    # TEE available but measure both modes


@dataclass
class TEEKeyPair:
    """Container for TEE-derived or regular keypair"""
    private_key: bytes
    public_key: bytes
    tee_derived: bool
    derivation_time_ms: Optional[float] = None


@dataclass
class AttestationReport:
    """TEE attestation report"""
    quote: str
    generation_time_ms: float
    payload: str
    quote_size_bytes: int


class TEEManager:
    """
    Manages TEE operations for PBTS tracker.

    Supports three modes:
    - DISABLED: Regular BLS crypto only
    - ENABLED: Always use TEE
    - BENCHMARK: Measure both for comparison
    """

    def __init__(self, mode: TEEMode = TEEMode.DISABLED):
        self.mode = mode
        self.tee_available = TEE_AVAILABLE

        if mode != TEEMode.DISABLED and not TEE_AVAILABLE:
            raise RuntimeError(
                "TEE mode requested but dstack_sdk not available")

        self.logger = logging.getLogger(__name__)

        # Statistics tracking
        self.stats = {
            'key_generations': 0,
            'attestations_generated': 0,
            'total_key_gen_time_ms': 0,
            'total_attestation_time_ms': 0,
        }

    def generate_keypair(self, tee_enabled: bool = None) -> TEEKeyPair:
        """
        Generate keypair - either TEE-derived or regular BLS.

        Args:
            tee_enabled: Override mode setting. If None, uses self.mode

        Returns:
            TEEKeyPair with timing information
        """
        use_tee = tee_enabled if tee_enabled is not None else (
            self.mode == TEEMode.ENABLED)

        if use_tee:
            if self.mode == TEEMode.DISABLED:
                raise RuntimeError("TEE requested but mode is DISABLED")
            if not self.tee_available:
                raise RuntimeError("TEE requested but not available")

        start_time = time.perf_counter()

        # BLS12-381 curve order (private key must be in range [1, CURVE_ORDER))
        CURVE_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513

        if use_tee:
            # TEE-derived key using dstack_sdk
            # get_key() returns a GetKeyResponse with the key derivation
            path = f"pbts/bls/{secrets.token_hex(16)}"
            purpose = "signature"
            key_response = DstackClient().get_key(path, purpose)
            private_key_bytes = key_response.decode_key()  # Returns 32 bytes

            # Ensure private key is in valid range for BLS12-381
            private_key_int = int.from_bytes(private_key_bytes, 'big')
            private_key_int = private_key_int % CURVE_ORDER
            if private_key_int == 0:
                private_key_int = 1  # Ensure non-zero
            private_key = private_key_int.to_bytes(32, 'big')

            # bls.SkToPk returns bytes directly (48 bytes for BLS12-381 public key)
            public_key = bls.SkToPk(private_key_int)
        else:
            # Regular BLS key generation
            # Generate a valid private key by reducing random bytes modulo curve order
            while True:
                private_key_bytes = secrets.token_bytes(32)
                private_key_int = int.from_bytes(private_key_bytes, 'big')

                # Reduce modulo curve order and ensure it's not zero
                private_key_int = private_key_int % CURVE_ORDER
                if private_key_int != 0:
                    break

            # Convert back to bytes (ensure 32-byte representation)
            private_key = private_key_int.to_bytes(32, 'big')

            # bls.SkToPk returns bytes directly (48 bytes for BLS12-381 public key)
            public_key = bls.SkToPk(private_key_int)

        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000

        # Update stats
        self.stats['key_generations'] += 1
        self.stats['total_key_gen_time_ms'] += duration_ms

        return TEEKeyPair(
            private_key=private_key,
            public_key=public_key,
            tee_derived=use_tee,
            derivation_time_ms=duration_ms
        )

    def generate_attestation(self, payload: str) -> AttestationReport:
        """
        Generate TEE attestation report (TDX quote).

        Args:
            payload: Data to include in attestation (e.g., user_id, registration message)
                    Note: Max 64 bytes for report_data

        Returns:
            AttestationReport with quote and timing
        """
        if self.mode == TEEMode.DISABLED or not self.tee_available:
            raise RuntimeError("TEE not available for attestation")

        start_time = time.perf_counter()

        # Prepare report data (max 64 bytes)
        report_data = payload.encode('utf-8')
        if len(report_data) > 64:
            # Hash the payload if it's too long
            import hashlib
            report_data = hashlib.sha256(report_data).digest()[:64]

        # Generate TDX quote using new API
        quote_response = DstackClient().get_quote(report_data)
        tdx_quote = quote_response.quote

        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000

        # Calculate quote size
        quote_size = len(tdx_quote) if isinstance(
            tdx_quote, bytes) else len(str(tdx_quote).encode('utf-8'))

        # Update stats
        self.stats['attestations_generated'] += 1
        self.stats['total_attestation_time_ms'] += duration_ms

        return AttestationReport(
            quote=tdx_quote,
            generation_time_ms=duration_ms,
            payload=payload,
            quote_size_bytes=quote_size
        )

    def verify_attestation(self, quote: str, expected_payload: str) -> Tuple[bool, float]:
        """
        Verify TEE attestation report.

        NOTE: This is a STUB for the user to implement.
        Actual verification requires:
        - Parsing TDX quote structure
        - Verifying Intel/AMD signatures
        - Checking measurements (RTMR values)
        - Validating payload inclusion

        Args:
            quote: TDX quote to verify
            expected_payload: Expected payload that should be in quote

        Returns:
            (is_valid, verification_time_ms)
        """
        start_time = time.perf_counter()

        # TODO: Implement actual verification
        # This requires:
        # 1. Parse quote structure
        # 2. Verify Intel/AMD signature chain
        # 3. Check RTMR measurements match expected code hash
        # 4. Verify payload is included in report data

        # Placeholder: always return True for now
        is_valid = True

        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000

        self.logger.warning(
            "verify_attestation is a stub - implement actual verification")

        return is_valid, duration_ms

    def get_ethereum_account(self, path: str = "ethereum/pbts", purpose: str = "tracker"):
        """
        Get Ethereum account derived from TEE.

        Args:
            path: Path for key derivation (default: "ethereum/pbts")
            purpose: Purpose of the key (default: "tracker")

        Returns:
            Web3 Account object (using secure derivation)
        """
        if self.mode == TEEMode.DISABLED or not self.tee_available:
            raise RuntimeError("TEE not available")

        key_response = DstackClient().get_key(path, purpose)
        account = to_account_secure(key_response)
        return account

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get performance statistics.

        Returns:
            Dictionary with timing statistics
        """
        stats = self.stats.copy()

        # Calculate averages
        if stats['key_generations'] > 0:
            stats['avg_key_gen_time_ms'] = (
                stats['total_key_gen_time_ms'] / stats['key_generations']
            )
        else:
            stats['avg_key_gen_time_ms'] = 0

        if stats['attestations_generated'] > 0:
            stats['avg_attestation_time_ms'] = (
                stats['total_attestation_time_ms'] /
                stats['attestations_generated']
            )
        else:
            stats['avg_attestation_time_ms'] = 0

        return stats

    def reset_statistics(self):
        """Reset performance counters"""
        self.stats = {
            'key_generations': 0,
            'attestations_generated': 0,
            'total_key_gen_time_ms': 0,
            'total_attestation_time_ms': 0,
        }


# Singleton instance for use in tracker
_tee_manager_instance: Optional[TEEManager] = None


def get_tee_manager(mode: TEEMode = None) -> TEEManager:
    """
    Get or create TEE manager singleton.

    Args:
        mode: TEE mode (only used on first call)

    Returns:
        TEEManager instance
    """
    global _tee_manager_instance

    if _tee_manager_instance is None:
        if mode is None:
            mode = TEEMode.DISABLED
        _tee_manager_instance = TEEManager(mode)

    return _tee_manager_instance


def set_tee_mode(mode: TEEMode):
    """
    Set TEE mode (creates new manager instance).

    Args:
        mode: New TEE mode
    """
    global _tee_manager_instance
    _tee_manager_instance = TEEManager(mode)
