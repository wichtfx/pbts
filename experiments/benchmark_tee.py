#!/usr/bin/env python3
"""
TEE Attestation Benchmark

Measures overhead of:
- TEE-derived key generation vs regular key generation
- TEE attestation generation
- TEE attestation verification
- Comparison with non-TEE baseline
"""
import sys
import time
import statistics
from pathlib import Path
from typing import Dict

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tee_manager import TEEManager, TEEMode, TEE_AVAILABLE


class TEEBenchmark:
    """Benchmark for TEE operations"""

    def __init__(self, num_iterations: int = 100):
        """
        Initialize TEE benchmark

        Args:
            num_iterations: Number of iterations (note: TEE ops are slower, use fewer iterations)
        """
        self.num_iterations = num_iterations
        self.results = {}
        self.tee_available = TEE_AVAILABLE

        if not TEE_AVAILABLE:
            print(
                "WARNING: TEE not available. Will compare regular vs benchmark mode only.")

    def benchmark_key_generation_comparison(self) -> Dict[str, Dict[str, float]]:
        """Compare TEE-derived vs regular key generation"""
        print(
            f"\n[1/3] Benchmarking key generation comparison ({self.num_iterations} iterations)...")

        results = {}

        # Regular key generation
        print("  Testing regular key generation...")
        manager_regular = TEEManager(mode=TEEMode.DISABLED)
        times_regular = []

        for i in range(self.num_iterations):
            keypair = manager_regular.generate_keypair(tee_enabled=False)
            times_regular.append(keypair.derivation_time_ms)

            if (i + 1) % 10 == 0:
                print(f"    Progress: {i + 1}/{self.num_iterations}")

        results['regular'] = {
            'mean_ms': statistics.mean(times_regular),
            'median_ms': statistics.median(times_regular),
            'stdev_ms': statistics.stdev(times_regular) if len(times_regular) > 1 else 0,
            'min_ms': min(times_regular),
            'max_ms': max(times_regular)
        }

        # TEE key generation (if available)
        if self.tee_available:
            print("  Testing TEE-derived key generation...")
            manager_tee = TEEManager(mode=TEEMode.ENABLED)
            times_tee = []

            for i in range(self.num_iterations):
                keypair = manager_tee.generate_keypair(tee_enabled=True)
                times_tee.append(keypair.derivation_time_ms)

                if (i + 1) % 10 == 0:
                    print(f"    Progress: {i + 1}/{self.num_iterations}")

            results['tee'] = {
                'mean_ms': statistics.mean(times_tee),
                'median_ms': statistics.median(times_tee),
                'stdev_ms': statistics.stdev(times_tee) if len(times_tee) > 1 else 0,
                'min_ms': min(times_tee),
                'max_ms': max(times_tee),
                'overhead_vs_regular': statistics.mean(times_tee) - statistics.mean(times_regular),
                'overhead_percent': ((statistics.mean(times_tee) / statistics.mean(times_regular)) - 1) * 100
            }
        else:
            results['tee'] = None

        return results

    def benchmark_attestation_generation(self) -> Dict[str, float]:
        """Benchmark TEE attestation generation"""
        print(
            f"\n[2/3] Benchmarking attestation generation ({self.num_iterations} iterations)...")

        if not self.tee_available:
            print("  Skipped: TEE not available")
            return None

        manager = TEEManager(mode=TEEMode.ENABLED)
        times = []

        for i in range(self.num_iterations):
            payload = f"test_payload_{i}"

            start = time.perf_counter()
            attestation = manager.generate_attestation(payload)
            end = time.perf_counter()

            duration_ms = (end - start) * 1000
            times.append(duration_ms)

            # Verify the attestation report is populated
            assert attestation.quote is not None
            assert attestation.quote_size_bytes > 0

            if (i + 1) % 10 == 0:
                print(f"  Progress: {i + 1}/{self.num_iterations}")

        return {
            'mean_ms': statistics.mean(times),
            'median_ms': statistics.median(times),
            'stdev_ms': statistics.stdev(times) if len(times) > 1 else 0,
            'min_ms': min(times),
            'max_ms': max(times),
            'total_ms': sum(times)
        }

    def benchmark_attestation_verification(self, num_verify: int = 10) -> Dict[str, float]:
        """
        Benchmark TEE attestation verification

        Args:
            num_verify: Number of verifications (note: verification is VERY slow due to network calls)
        """
        print(
            f"\n[3/3] Benchmarking attestation verification ({num_verify} iterations)...")
        print("  NOTE: This may take several minutes due to DCAP collateral retrieval...")

        if not self.tee_available:
            print("  Skipped: TEE not available")
            return None

        manager = TEEManager(mode=TEEMode.ENABLED)

        # Generate attestation to verify
        payload = "test_verification_payload"
        attestation = manager.generate_attestation(payload)

        times = []
        success_count = 0

        for i in range(num_verify):
            print(f"  Verification {i + 1}/{num_verify}...")

            try:
                start = time.perf_counter()
                is_valid, verification_time = manager.verify_attestation(
                    quote=attestation.quote,
                    expected_payload=payload,
                    check_payload=False  # Skip payload check for benchmark
                )
                end = time.perf_counter()

                duration_ms = (end - start) * 1000
                times.append(duration_ms)

                if is_valid:
                    success_count += 1

                print(
                    f"    Result: {'VALID' if is_valid else 'INVALID'}, Time: {duration_ms:.2f} ms")

            except Exception as e:
                print(f"    Error: {e}")
                continue

        if not times:
            print("  No successful verifications")
            return None

        return {
            'mean_ms': statistics.mean(times),
            'median_ms': statistics.median(times),
            'stdev_ms': statistics.stdev(times) if len(times) > 1 else 0,
            'min_ms': min(times),
            'max_ms': max(times),
            'success_rate': success_count / num_verify,
            'num_attempts': num_verify,
            'num_successful': success_count
        }

    def run_all(self, verify_iterations: int = 10) -> Dict:
        """Run all benchmarks and return results"""
        print("=" * 70)
        print("TEE OPERATIONS BENCHMARK")
        print("=" * 70)

        if not self.tee_available:
            print("\nWARNING: TEE not available (dstack_sdk not installed)")
            print("Only comparing regular key generation modes\n")

        self.results = {
            'tee_available': self.tee_available,
            'key_generation': self.benchmark_key_generation_comparison(),
            'attestation_generation': self.benchmark_attestation_generation(),
            'attestation_verification': self.benchmark_attestation_verification(num_verify=verify_iterations)
        }

        return self.results

    def print_results(self):
        """Print formatted results"""
        print("\n" + "=" * 70)
        print("RESULTS SUMMARY")
        print("=" * 70)

        # Key generation comparison
        print("\n1. Key Generation Comparison:")
        kg = self.results['key_generation']

        print("\n   Regular (Non-TEE):")
        print(f"     Mean: {kg['regular']['mean_ms']:.4f} ms")
        print(f"     Median: {kg['regular']['median_ms']:.4f} ms")
        print(f"     Std Dev: {kg['regular']['stdev_ms']:.4f} ms")
        print(
            f"     Range: [{kg['regular']['min_ms']:.4f}, {kg['regular']['max_ms']:.4f}] ms")

        if kg['tee'] is not None:
            print("\n   TEE-Derived:")
            print(f"     Mean: {kg['tee']['mean_ms']:.4f} ms")
            print(f"     Median: {kg['tee']['median_ms']:.4f} ms")
            print(f"     Std Dev: {kg['tee']['stdev_ms']:.4f} ms")
            print(
                f"     Range: [{kg['tee']['min_ms']:.4f}, {kg['tee']['max_ms']:.4f}] ms")
            print(
                f"\n     Overhead: +{kg['tee']['overhead_vs_regular']:.4f} ms ({kg['tee']['overhead_percent']:.2f}%)")
        else:
            print("\n   TEE-Derived: Not available")

        # Attestation generation
        if self.results['attestation_generation'] is not None:
            print("\n2. Attestation Generation:")
            ag = self.results['attestation_generation']
            print(f"   Mean: {ag['mean_ms']:.4f} ms")
            print(f"   Median: {ag['median_ms']:.4f} ms")
            print(f"   Std Dev: {ag['stdev_ms']:.4f} ms")
            print(f"   Range: [{ag['min_ms']:.4f}, {ag['max_ms']:.4f}] ms")
        else:
            print("\n2. Attestation Generation: Not available (TEE not enabled)")

        # Attestation verification
        if self.results['attestation_verification'] is not None:
            print("\n3. Attestation Verification:")
            av = self.results['attestation_verification']
            print(f"   Mean: {av['mean_ms']:.4f} ms")
            print(f"   Median: {av['median_ms']:.4f} ms")
            print(f"   Std Dev: {av['stdev_ms']:.4f} ms")
            print(f"   Range: [{av['min_ms']:.4f}, {av['max_ms']:.4f}] ms")
            print(
                f"   Success Rate: {av['success_rate']*100:.1f}% ({av['num_successful']}/{av['num_attempts']})")
        else:
            print("\n3. Attestation Verification: Not available (TEE not enabled)")

        print("\n" + "=" * 70)
        print("INTERPRETATION")
        print("=" * 70)

        print("\nKey Observations:")

        # Key generation overhead
        if kg['tee'] is not None:
            print(
                f"1. TEE key derivation overhead: +{kg['tee']['overhead_vs_regular']:.2f} ms ({kg['tee']['overhead_percent']:.1f}%)")
        else:
            print("1. TEE key derivation: Not measured (TEE not available)")

        # Attestation overhead
        if self.results['attestation_generation'] is not None:
            ag = self.results['attestation_generation']
            print(
                f"2. Attestation generation overhead: ~{ag['mean_ms']:.2f} ms per attestation")
        else:
            print("2. Attestation generation: Not measured (TEE not available)")

        if self.results['attestation_verification'] is not None:
            av = self.results['attestation_verification']
            print(
                f"3. Attestation verification overhead: ~{av['mean_ms']:.2f} ms per verification")
            print(
                f"   NOTE: Verification includes network calls to Intel PCS for collateral")
        else:
            print("3. Attestation verification: Not measured (TEE not available)")

        print("\n" + "=" * 70)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Benchmark TEE operations')
    parser.add_argument('--iterations', type=int, default=100,
                        help='Number of iterations for key generation and attestation generation (default: 100)')
    parser.add_argument('--verify-iterations', type=int, default=10,
                        help='Number of iterations for attestation verification (default: 10, slower)')
    parser.add_argument('--output', type=str,
                        help='Output JSON file for results')

    args = parser.parse_args()

    # Check if TEE is available
    if not TEE_AVAILABLE:
        print("\n" + "=" * 70)
        print("WARNING: TEE not available")
        print("=" * 70)
        print("\nTo enable TEE benchmarks, install dstack-sdk:")
        print("  pip install dstack-sdk==0.5.3")
        print("  pip install dcap-qvl")
        print("\nProceeding with available benchmarks...\n")

    # Run benchmark
    benchmark = TEEBenchmark(num_iterations=args.iterations)
    results = benchmark.run_all(verify_iterations=args.verify_iterations)
    benchmark.print_results()

    # Save results to JSON if requested
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
