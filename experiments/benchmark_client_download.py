#!/usr/bin/env python3
"""
Client Download Simulation Benchmark

Measures receipt generation overhead in realistic download scenarios:
- Simulates downloading at various speeds (1-100 MB/s)
- Tests different piece sizes (256 KB - 4 MB)
- Calculates overhead as percentage of download time
- Shows impact on overall download throughput

This answers: "How much does PBTS receipt generation slow down my downloads?"
"""
import sys
import time
import hashlib
import statistics
from pathlib import Path
from typing import List
from dataclasses import dataclass

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tracker import generate_keypair, attest_piece_transfer


@dataclass
class DownloadScenario:
    """Represents a download scenario"""
    download_speed_mbps: float  # MB/s
    piece_size_kb: int  # KB
    num_pieces: int  # Total pieces to download
    batch_size: int = 1  # Number of pieces per receipt (1 = receipt per piece)

    @property
    def piece_size_bytes(self) -> int:
        return self.piece_size_kb * 1024

    @property
    def total_size_mb(self) -> float:
        return (self.piece_size_kb * self.num_pieces) / 1024

    @property
    def download_time_per_piece_ms(self) -> float:
        """Time to download one piece at given speed (ms)"""
        return (self.piece_size_kb / 1024) / self.download_speed_mbps * 1000

    @property
    def num_receipts(self) -> int:
        """Total number of receipts to generate"""
        return (self.num_pieces + self.batch_size - 1) // self.batch_size


@dataclass
class DownloadBenchmarkResult:
    """Results for a download scenario"""
    scenario: DownloadScenario

    # Receipt generation times
    mean_receipt_time_ms: float
    median_receipt_time_ms: float
    stdev_receipt_time_ms: float

    # Download simulation (total for entire file)
    total_download_time_sec: float
    total_receipt_gen_time_sec: float
    total_overhead_percent: float  # total_receipt_gen_time / total_download_time * 100

    # Throughput impact
    baseline_throughput_mbps: float
    actual_throughput_mbps: float
    throughput_reduction_percent: float

    # Total download time with receipts
    baseline_total_time_sec: float
    actual_total_time_sec: float
    total_overhead_sec: float


class ClientDownloadBenchmark:
    """Benchmark receipt generation overhead in download scenarios"""

    def __init__(self, warmup_iterations: int = 10, measure_iterations: int = 100):
        self.warmup_iterations = warmup_iterations
        self.measure_iterations = measure_iterations
        self.results: List[DownloadBenchmarkResult] = []

    def run_scenario(self, scenario: DownloadScenario) -> DownloadBenchmarkResult:
        """Run benchmark for a single scenario"""
        print(f"\n{'='*80}")
        print(f"Scenario: {scenario.download_speed_mbps} MB/s, "
              f"{scenario.piece_size_kb} KB pieces, "
              f"{scenario.num_pieces} pieces ({scenario.total_size_mb:.2f} MB total), "
              f"batch_size={scenario.batch_size} ({scenario.num_receipts} receipts)")
        print(f"{'='*80}")

        # Setup keys
        receiver_sk, receiver_pk = generate_keypair()
        sender_sk, sender_pk = generate_keypair()
        infohash = hashlib.sha1(b"benchmark_torrent").digest()

        # Warmup
        print(f"  Warmup: {self.warmup_iterations} iterations...")
        for i in range(self.warmup_iterations):
            piece_data = b"x" * scenario.piece_size_bytes
            piece_hash = hashlib.sha256(piece_data).digest()
            receipt = attest_piece_transfer(
                receiver_private_key=receiver_sk,
                sender_public_key=sender_pk,
                piece_hash=piece_hash,
                piece_index=i,
                infohash=infohash,
                timestamp=int(time.time())
            )

        # Measurement
        print(f"  Measuring: {self.measure_iterations} iterations...")
        receipt_times = []

        for i in range(self.measure_iterations):
            # Simulate receiving a piece
            piece_data = b"x" * scenario.piece_size_bytes
            piece_hash = hashlib.sha256(piece_data).digest()

            # Measure receipt generation time
            start = time.perf_counter()
            receipt = attest_piece_transfer(
                receiver_private_key=receiver_sk,
                sender_public_key=sender_pk,
                piece_hash=piece_hash,
                piece_index=i,
                infohash=infohash,
                timestamp=int(time.time())
            )
            end = time.perf_counter()

            receipt_times.append((end - start) * 1000)  # ms

        # Calculate statistics
        mean_receipt_time = statistics.mean(receipt_times)
        median_receipt_time = statistics.median(receipt_times)
        stdev_receipt_time = statistics.stdev(
            receipt_times) if len(receipt_times) > 1 else 0

        # Calculate total overhead: total_receipt_gen_time / total_download_transmission_time
        total_download_time_sec = scenario.total_size_mb / scenario.download_speed_mbps  # seconds
        total_receipt_gen_time_sec = (mean_receipt_time / 1000) * scenario.num_receipts  # seconds
        total_overhead_percent = (total_receipt_gen_time_sec / total_download_time_sec * 100) if total_download_time_sec > 0 else float('inf')

        # Calculate throughput impact
        baseline_throughput = scenario.download_speed_mbps

        # Actual throughput accounts for receipt generation time
        actual_total_time = total_download_time_sec + total_receipt_gen_time_sec  # seconds
        actual_throughput = scenario.total_size_mb / actual_total_time  # MB/s

        throughput_reduction = ((baseline_throughput - actual_throughput) /
                                baseline_throughput * 100) if baseline_throughput > 0 else 0

        # Total download time for entire file
        baseline_total_time = total_download_time_sec
        total_overhead = total_receipt_gen_time_sec

        result = DownloadBenchmarkResult(
            scenario=scenario,
            mean_receipt_time_ms=mean_receipt_time,
            median_receipt_time_ms=median_receipt_time,
            stdev_receipt_time_ms=stdev_receipt_time,
            total_download_time_sec=total_download_time_sec,
            total_receipt_gen_time_sec=total_receipt_gen_time_sec,
            total_overhead_percent=total_overhead_percent,
            baseline_throughput_mbps=baseline_throughput,
            actual_throughput_mbps=actual_throughput,
            throughput_reduction_percent=throughput_reduction,
            baseline_total_time_sec=baseline_total_time,
            actual_total_time_sec=actual_total_time,
            total_overhead_sec=total_overhead
        )

        self.results.append(result)
        return result

    def run_all(self, scenarios: List[DownloadScenario]) -> List[DownloadBenchmarkResult]:
        """Run all scenarios"""
        print("\n" + "="*80)
        print(" CLIENT DOWNLOAD SIMULATION BENCHMARK")
        print("="*80)
        print(f"\nConfiguration:")
        print(f"  - Warmup iterations: {self.warmup_iterations}")
        print(f"  - Measurement iterations: {self.measure_iterations}")
        print(f"  - Total scenarios: {len(scenarios)}")

        for i, scenario in enumerate(scenarios, 1):
            print(f"\n[{i}/{len(scenarios)}] Running scenario...")
            self.run_scenario(scenario)

        return self.results

    def print_results(self):
        """Print formatted results"""
        if not self.results:
            print("\nNo results to display.")
            return

        print("\n" + "="*80)
        print(" RESULTS SUMMARY")
        print("="*80)

        # Per-scenario results
        print("\nPER-SCENARIO BREAKDOWN:")
        print("-"*80)

        for result in self.results:
            s = result.scenario
            print(
                f"\nScenario: {s.download_speed_mbps} MB/s, {s.piece_size_kb} KB pieces, batch_size={s.batch_size}")
            print(f"  Receipt generation time:")
            print(f"    Mean:   {result.mean_receipt_time_ms:.3f} ms per receipt")
            print(f"    Median: {result.median_receipt_time_ms:.3f} ms per receipt")
            print(f"    Stdev:  {result.stdev_receipt_time_ms:.3f} ms")
            print(f"  Download simulation ({s.total_size_mb:.2f} MB, {s.num_receipts} receipts):")
            print(
                f"    Total download time: {result.total_download_time_sec:.3f} sec")
            print(
                f"    Total receipt gen time: {result.total_receipt_gen_time_sec:.3f} sec")
            print(
                f"    Overhead: {result.total_overhead_percent:.2f}% (receipt_gen / download)")
            print(f"  Throughput:")
            print(f"    Baseline: {result.baseline_throughput_mbps:.2f} MB/s")
            print(f"    Actual:   {result.actual_throughput_mbps:.2f} MB/s")
            print(f"    Reduction: {result.throughput_reduction_percent:.2f}%")
            print(f"  Total download time with receipts:")
            print(f"    Baseline: {result.baseline_total_time_sec:.2f} sec")
            print(f"    With receipts:   {result.actual_total_time_sec:.2f} sec")
            print(
                f"    Overhead: {result.total_overhead_sec:.2f} sec")

        # Summary table
        print("\n" + "="*80)
        print(" OVERHEAD SUMMARY TABLE")
        print("="*80)
        print(
            f"\n{'Speed':>8} {'Piece':>8} {'Batch':>8} {'Receipts':>10} {'Receipt Time':>15} {'Total OH':>12} {'Throughput':>15}")
        print(
            f"{'(MB/s)':>8} {'(KB)':>8} {'Size':>8} {'#':>10} {'(ms)':>15} {'(%)':>12} {'Reduction (%)':>15}")
        print("-"*80)

        for result in self.results:
            s = result.scenario
            print(f"{s.download_speed_mbps:>8.1f} {s.piece_size_kb:>8} {s.batch_size:>8} {s.num_receipts:>10} "
                  f"{result.mean_receipt_time_ms:>15.3f} {result.total_overhead_percent:>12.2f} "
                  f"{result.throughput_reduction_percent:>15.2f}")

        # Key insights
        print("\n" + "="*80)
        print(" KEY INSIGHTS")
        print("="*80)

        # Find best and worst scenarios
        min_overhead_result = min(
            self.results, key=lambda r: r.total_overhead_percent)
        max_overhead_result = max(
            self.results, key=lambda r: r.total_overhead_percent)

        print(f"\nBest case (lowest overhead):")
        print(f"  {min_overhead_result.scenario.download_speed_mbps} MB/s, "
              f"{min_overhead_result.scenario.piece_size_kb} KB pieces, "
              f"batch_size={min_overhead_result.scenario.batch_size}")
        print(
            f"  Total overhead: {min_overhead_result.total_overhead_percent:.2f}% of download time")
        print(
            f"  Throughput reduction: {min_overhead_result.throughput_reduction_percent:.2f}%")

        print(f"\nWorst case (highest overhead):")
        print(f"  {max_overhead_result.scenario.download_speed_mbps} MB/s, "
              f"{max_overhead_result.scenario.piece_size_kb} KB pieces, "
              f"batch_size={max_overhead_result.scenario.batch_size}")
        print(
            f"  Total overhead: {max_overhead_result.total_overhead_percent:.2f}% of download time")
        print(
            f"  Throughput reduction: {max_overhead_result.throughput_reduction_percent:.2f}%")

        # Average overhead across all scenarios
        avg_overhead = statistics.mean(
            [r.total_overhead_percent for r in self.results])
        avg_throughput_reduction = statistics.mean(
            [r.throughput_reduction_percent for r in self.results])

        print(f"\nAverage across all scenarios:")
        print(f"  Total overhead: {avg_overhead:.2f}% of download time")
        print(f"  Throughput reduction: {avg_throughput_reduction:.2f}%")

        print("\n" + "="*80)


def create_default_scenarios() -> List[DownloadScenario]:
    """Create realistic download scenarios"""
    scenarios = []

    # Typical BitTorrent configurations
    download_speeds = [1, 5, 10, 25, 50, 100]  # MB/s
    piece_sizes = [256, 512, 1024, 2048]  # KB

    # Test all combinations
    for speed in download_speeds:
        for piece_size in piece_sizes:
            # Simulate downloading 100 MB (adjust number of pieces accordingly)
            num_pieces = int(100 * 1024 / piece_size)  # 100 MB
            scenarios.append(DownloadScenario(
                download_speed_mbps=speed,
                piece_size_kb=piece_size,
                num_pieces=num_pieces
            ))

    return scenarios


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Client download simulation benchmark")
    parser.add_argument('--warmup', type=int, default=10,
                        help='Warmup iterations (default: 10)')
    parser.add_argument('--iterations', type=int, default=10,
                        help='Measurement iterations per scenario (default: 10)')
    parser.add_argument('--speeds', type=float, nargs='+',
                        default=[1, 5, 10, 20],
                        help='Download speeds in MB/s (default: 1 5 10 20)')
    parser.add_argument('--piece-sizes', type=int, nargs='+',
                        default=[256, 512, 1024, 2048, 4096],
                        help='Piece sizes in KB (default: 256 512 1024 2048 4096)')
    parser.add_argument('--file-size-mb', type=float, default=1000,
                        help='Simulated file size in MB (default: 1000)')
    parser.add_argument('--batch-size', type=int, default=10,
                        help='Number of pieces per receipt (default: 10, i.e., one receipt per 10 pieces)')
    parser.add_argument('--output', type=str,
                        help='Save results to JSON file')

    args = parser.parse_args()

    # Create scenarios
    scenarios = []
    for speed in args.speeds:
        for piece_size in args.piece_sizes:
            num_pieces = int(args.file_size_mb * 1024 / piece_size)
            scenarios.append(DownloadScenario(
                download_speed_mbps=speed,
                piece_size_kb=piece_size,
                num_pieces=num_pieces,
                batch_size=args.batch_size
            ))

    # Run benchmark
    benchmark = ClientDownloadBenchmark(
        warmup_iterations=args.warmup,
        measure_iterations=args.iterations
    )

    results = benchmark.run_all(scenarios)
    benchmark.print_results()

    # Save to JSON if requested
    if args.output:
        output_data = {
            'config': {
                'warmup_iterations': args.warmup,
                'measure_iterations': args.iterations,
                'file_size_mb': args.file_size_mb
            },
            'results': [
                {
                    'scenario': {
                        'download_speed_mbps': r.scenario.download_speed_mbps,
                        'piece_size_kb': r.scenario.piece_size_kb,
                        'num_pieces': r.scenario.num_pieces,
                        'batch_size': r.scenario.batch_size,
                        'num_receipts': r.scenario.num_receipts,
                        'total_size_mb': r.scenario.total_size_mb
                    },
                    'receipt_time': {
                        'mean_ms': r.mean_receipt_time_ms,
                        'median_ms': r.median_receipt_time_ms,
                        'stdev_ms': r.stdev_receipt_time_ms
                    },
                    'overhead': {
                        'total_download_time_sec': r.total_download_time_sec,
                        'total_receipt_gen_time_sec': r.total_receipt_gen_time_sec,
                        'total_overhead_percent': r.total_overhead_percent
                    },
                    'throughput': {
                        'baseline_mbps': r.baseline_throughput_mbps,
                        'actual_mbps': r.actual_throughput_mbps,
                        'reduction_percent': r.throughput_reduction_percent
                    },
                    'total_download': {
                        'baseline_time_sec': r.baseline_total_time_sec,
                        'actual_time_sec': r.actual_total_time_sec,
                        'overhead_sec': r.total_overhead_sec
                    }
                }
                for r in results
            ]
        }

        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)

        print(f"\n✓ Results saved to {args.output}")


if __name__ == '__main__':
    main()
