#!/usr/bin/env python3
"""
Receipt Creation and Verification Benchmark

Measures overhead of:
- BLS keypair generation
- Receipt creation (signing)
- Individual receipt verification
- Aggregate receipt verification (batch)
"""
import sys
import time
import hashlib
import statistics
from pathlib import Path
from typing import List, Dict

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tracker import (
    generate_keypair,
    verify_signature,
    aggregate_signatures,
    aggregate_verify,
    attest_piece_transfer,
    verify_receipt
)


class ReceiptBenchmark:
    """Benchmark for receipt operations"""

    def __init__(self, num_iterations: int = 10, batch_sizes: List[int] = None):
        self.num_iterations = num_iterations
        self.batch_sizes = batch_sizes or [10, 25, 50]  # Global batch size config
        self.results = {}

    def benchmark_keypair_generation(self) -> Dict[str, float]:
        """Benchmark BLS keypair generation"""
        print(
            f"\n[1/5] Benchmarking keypair generation ({self.num_iterations} iterations)...")

        times = []
        for i in range(self.num_iterations):
            start = time.perf_counter()
            sk, pk = generate_keypair()
            end = time.perf_counter()
            times.append((end - start) * 1000)  # Convert to ms

            if (i + 1) % 100 == 0:
                print(f"  Progress: {i + 1}/{self.num_iterations}")

        return {
            'mean_ms': statistics.mean(times),
            'median_ms': statistics.median(times),
            'stdev_ms': statistics.stdev(times) if len(times) > 1 else 0,
            'min_ms': min(times),
            'max_ms': max(times),
            'total_ms': sum(times)
        }

    def benchmark_receipt_creation(self) -> Dict[str, float]:
        """Benchmark receipt creation (signing)"""
        print(
            f"\n[2/5] Benchmarking receipt creation ({self.num_iterations} iterations)...")

        # Prepare test data
        receiver_sk, receiver_pk = generate_keypair()
        sender_sk, sender_pk = generate_keypair()
        infohash = hashlib.sha1(b"test_torrent").digest()
        piece_hash = hashlib.sha256(b"test_piece_data").digest()

        times = []
        for i in range(self.num_iterations):
            piece_index = i % 100
            timestamp = int(time.time())

            start = time.perf_counter()
            receipt = attest_piece_transfer(
                receiver_private_key=receiver_sk,
                sender_public_key=sender_pk,
                piece_hash=piece_hash,
                piece_index=piece_index,
                infohash=infohash,
                timestamp=timestamp
            )
            end = time.perf_counter()
            times.append((end - start) * 1000)

            if (i + 1) % 100 == 0:
                print(f"  Progress: {i + 1}/{self.num_iterations}")

        return {
            'mean_ms': statistics.mean(times),
            'median_ms': statistics.median(times),
            'stdev_ms': statistics.stdev(times) if len(times) > 1 else 0,
            'min_ms': min(times),
            'max_ms': max(times),
            'total_ms': sum(times)
        }

    def benchmark_receipt_verification(self) -> Dict[str, float]:
        """Benchmark individual receipt verification"""
        print(
            f"\n[3/5] Benchmarking receipt verification ({self.num_iterations} iterations)...")

        # Prepare test data
        receiver_sk, receiver_pk = generate_keypair()
        sender_sk, sender_pk = generate_keypair()
        infohash = hashlib.sha1(b"test_torrent").digest()
        piece_hash = hashlib.sha256(b"test_piece_data").digest()
        piece_index = 0
        timestamp = int(time.time())

        # Create receipt
        receipt = attest_piece_transfer(
            receiver_private_key=receiver_sk,
            sender_public_key=sender_pk,
            piece_hash=piece_hash,
            piece_index=piece_index,
            infohash=infohash,
            timestamp=timestamp
        )

        times = []
        for i in range(self.num_iterations):
            start = time.perf_counter()
            valid = verify_receipt(
                receiver_public_key=receiver_pk,
                sender_public_key=sender_pk,
                piece_hash=piece_hash,
                piece_index=piece_index,
                infohash=infohash,
                timestamp=timestamp,
                receipt=receipt
            )
            end = time.perf_counter()
            times.append((end - start) * 1000)

            assert valid, "Receipt should be valid"

            if (i + 1) % 100 == 0:
                print(f"  Progress: {i + 1}/{self.num_iterations}")

        return {
            'mean_ms': statistics.mean(times),
            'median_ms': statistics.median(times),
            'stdev_ms': statistics.stdev(times) if len(times) > 1 else 0,
            'min_ms': min(times),
            'max_ms': max(times),
            'total_ms': sum(times)
        }

    def benchmark_aggregate_creation(self) -> Dict[int, Dict[str, float]]:
        """Benchmark aggregate signature creation for different batch sizes"""
        print(f"\n[4/5] Benchmarking aggregate signature creation...")

        results = {}
        for batch_size in self.batch_sizes:
            print(f"  Batch size: {batch_size}...")

            # Create test receipts
            receiver_sk, receiver_pk = generate_keypair()
            sender_sk, sender_pk = generate_keypair()
            infohash = hashlib.sha1(b"test_torrent").digest()

            receipts = []
            for i in range(batch_size):
                piece_hash = hashlib.sha256(f"piece_{i}".encode()).digest()
                timestamp = int(time.time())
                receipt = attest_piece_transfer(
                    receiver_private_key=receiver_sk,
                    sender_public_key=sender_pk,
                    piece_hash=piece_hash,
                    piece_index=i,
                    infohash=infohash,
                    timestamp=timestamp
                )
                receipts.append(receipt)

            # Benchmark aggregation
            times = []
            # Adjust runs based on batch size
            num_runs = max(10, 1000 // batch_size)
            for _ in range(num_runs):
                start = time.perf_counter()
                agg_sig = aggregate_signatures(receipts)
                end = time.perf_counter()
                times.append((end - start) * 1000)

            results[batch_size] = {
                'mean_ms': statistics.mean(times),
                'median_ms': statistics.median(times),
                'stdev_ms': statistics.stdev(times) if len(times) > 1 else 0,
                'min_ms': min(times),
                'max_ms': max(times),
                'num_runs': num_runs
            }

        return results

    def benchmark_aggregate_verification(self) -> Dict[int, Dict[str, float]]:
        """
        Benchmark aggregate signature verification for different batch sizes

        NOTE: BLS aggregate verification is slow due to expensive pairing operations.
        Larger batch sizes (>25) may take several minutes per verification.
        """
        print(f"\n[5/5] Benchmarking aggregate signature verification...")
        print("  NOTE: This is slow due to pairing operations. Please be patient...")

        results = {}
        for batch_size in self.batch_sizes:
            print(f"\n  Batch size: {batch_size}...")

            # Create test data
            # NOTE: Use different receivers for each receipt (more realistic and much faster)
            # This simulates an uploader collecting receipts from multiple downloaders
            sender_sk, sender_pk = generate_keypair()
            infohash = hashlib.sha1(b"test_torrent").digest()

            receipts = []
            public_keys = []
            messages = []

            for i in range(batch_size):
                # Generate a different receiver for each receipt
                receiver_sk, receiver_pk = generate_keypair()

                piece_hash = hashlib.sha256(f"piece_{i}".encode()).digest()
                timestamp = int(time.time())
                piece_index = i

                receipt = attest_piece_transfer(
                    receiver_private_key=receiver_sk,
                    sender_public_key=sender_pk,
                    piece_hash=piece_hash,
                    piece_index=piece_index,
                    infohash=infohash,
                    timestamp=timestamp
                )
                receipts.append(receipt)

                # Reconstruct message for verification
                message = infohash + sender_pk + piece_hash + \
                    piece_index.to_bytes(4, 'big') + \
                    timestamp.to_bytes(8, 'big')
                messages.append(message)
                public_keys.append(receiver_pk)

            # Aggregate signatures
            agg_sig = aggregate_signatures(receipts)

            # Benchmark aggregate verification
            times = []
            # Very few runs due to slowness
            num_runs = max(3, 50 // batch_size)
            print(
                f"    Running {num_runs} aggregate verifications (may take a while)...", end='', flush=True)
            for _ in range(num_runs):
                start = time.perf_counter()
                valid = aggregate_verify(public_keys, messages, agg_sig)
                end = time.perf_counter()
                times.append((end - start) * 1000)
                assert valid, "Aggregate signature should be valid"
            print(" done")

            # Also benchmark individual verification for comparison
            individual_times = []
            print(
                f"    Running {num_runs} individual verifications...", end='', flush=True)
            for _ in range(num_runs):
                start = time.perf_counter()
                for i in range(batch_size):
                    verify_signature(public_keys[i], messages[i], receipts[i])
                end = time.perf_counter()
                individual_times.append((end - start) * 1000)
            print(" done")

            results[batch_size] = {
                'aggregate_mean_ms': statistics.mean(times),
                'aggregate_median_ms': statistics.median(times),
                'aggregate_stdev_ms': statistics.stdev(times) if len(times) > 1 else 0,
                'individual_mean_ms': statistics.mean(individual_times),
                'speedup': statistics.mean(individual_times) / statistics.mean(times),
                'num_runs': num_runs
            }

        return results

    def run_all(self) -> Dict:
        """Run all benchmarks and return results"""
        print("=" * 70)
        print("RECEIPT OPERATIONS BENCHMARK")
        print("=" * 70)

        self.results = {
            'keypair_generation': self.benchmark_keypair_generation(),
            'receipt_creation': self.benchmark_receipt_creation(),
            'receipt_verification': self.benchmark_receipt_verification(),
            'aggregate_creation': self.benchmark_aggregate_creation(),
            'aggregate_verification': self.benchmark_aggregate_verification()
        }

        return self.results

    def print_results(self):
        """Print formatted results"""
        print("\n" + "=" * 70)
        print("RESULTS SUMMARY")
        print("=" * 70)

        # Keypair generation
        print("\n1. Keypair Generation:")
        kp = self.results['keypair_generation']
        print(f"   Mean: {kp['mean_ms']:.4f} ms")
        print(f"   Median: {kp['median_ms']:.4f} ms")
        print(f"   Std Dev: {kp['stdev_ms']:.4f} ms")
        print(f"   Range: [{kp['min_ms']:.4f}, {kp['max_ms']:.4f}] ms")

        # Receipt creation
        print("\n2. Receipt Creation (Signing):")
        rc = self.results['receipt_creation']
        print(f"   Mean: {rc['mean_ms']:.4f} ms")
        print(f"   Median: {rc['median_ms']:.4f} ms")
        print(f"   Std Dev: {rc['stdev_ms']:.4f} ms")
        print(f"   Range: [{rc['min_ms']:.4f}, {rc['max_ms']:.4f}] ms")

        # Receipt verification
        print("\n3. Receipt Verification:")
        rv = self.results['receipt_verification']
        print(f"   Mean: {rv['mean_ms']:.4f} ms")
        print(f"   Median: {rv['median_ms']:.4f} ms")
        print(f"   Std Dev: {rv['stdev_ms']:.4f} ms")
        print(f"   Range: [{rv['min_ms']:.4f}, {rv['max_ms']:.4f}] ms")

        # Aggregate creation
        print("\n4. Aggregate Signature Creation:")
        for batch_size, stats in self.results['aggregate_creation'].items():
            print(f"   Batch size {batch_size}:")
            print(f"     Mean: {stats['mean_ms']:.4f} ms")
            print(f"     Median: {stats['median_ms']:.4f} ms")

        # Aggregate verification
        print("\n5. Aggregate Signature Verification:")
        print(
            f"   {'Batch Size':<12} {'Aggregate (ms)':<15} {'Individual (ms)':<16} {'Speedup':<10}")
        print(f"   {'-'*12} {'-'*15} {'-'*16} {'-'*10}")
        for batch_size, stats in self.results['aggregate_verification'].items():
            print(
                f"   {batch_size:<12} {stats['aggregate_mean_ms']:<15.4f} {stats['individual_mean_ms']:<16.4f} {stats['speedup']:<10.2f}x")

        print("\n" + "=" * 70)
        print("INTERPRETATION")
        print("=" * 70)
        print("\nKey Observations:")
        print("1. Receipt creation overhead: ~{:.2f} ms per receipt".format(
            self.results['receipt_creation']['mean_ms']))
        print("2. Receipt verification overhead: ~{:.2f} ms per receipt".format(
            self.results['receipt_verification']['mean_ms']))

        # Calculate aggregate efficiency (use largest batch size available)
        if self.results.get('aggregate_verification'):
            largest_batch = max(self.results['aggregate_verification'].keys())
            agg_data = self.results['aggregate_verification'][largest_batch]
            print(f"3. Aggregate verification for {largest_batch} receipts:")
            print(
                f"   - Aggregate: {agg_data['aggregate_mean_ms']:.2f} ms total ({agg_data['aggregate_mean_ms']/largest_batch:.4f} ms per receipt)")
            print(
                f"   - Individual: {agg_data['individual_mean_ms']:.2f} ms total ({agg_data['individual_mean_ms']/largest_batch:.4f} ms per receipt)")
            print(f"   - Speedup: {agg_data['speedup']:.2f}x faster")

        print("\n" + "=" * 70)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Benchmark receipt operations')
    parser.add_argument('--iterations', type=int, default=10,
                        help='Number of iterations for basic benchmarks (default: 10)')
    parser.add_argument('--batch-sizes', type=int, nargs='+', default=[10, 25, 50],
                        help='Batch sizes for aggregate benchmarks (default: 10 25 50)')
    parser.add_argument('--output', type=str,
                        help='Output JSON file for results')

    args = parser.parse_args()

    # Run benchmark
    benchmark = ReceiptBenchmark(num_iterations=args.iterations, batch_sizes=args.batch_sizes)
    results = benchmark.run_all()
    benchmark.print_results()

    # Save results to JSON if requested
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
