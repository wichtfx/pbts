#!/usr/bin/env python3
"""
Scalability Benchmark

Measures:
1. Concurrent report processing throughput (simulated parallel peers)
2. Swarm scale impact on announce and report latency
"""

import sys
import time
import hashlib
import statistics
import random
import threading
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass
from collections import defaultdict

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tracker import (
    generate_keypair,
    aggregate_signatures,
    aggregate_verify,
    attest_piece_transfer,
    verify_receipt,
    TrackerState,
    Peer,
)


def percentile(sorted_values: List[float], p: float) -> float:
    """Compute the p-th percentile from sorted values."""
    if not sorted_values:
        return 0.0
    idx = int(round(p / 100.0 * (len(sorted_values) - 1)))
    return sorted_values[min(idx, len(sorted_values) - 1)]


def generate_test_receipts(
    sender_pk: bytes,
    count: int,
    base_timestamp: int,
) -> List[dict]:
    """Generate pre-built receipts for benchmarking."""
    infohash = b'\xAB' * 20
    results = []
    for i in range(count):
        rx_sk, rx_pk = generate_keypair()
        piece_hash = hashlib.sha256(f"piece-{i}".encode()).digest()
        ts = base_timestamp + i

        sig = attest_piece_transfer(
            rx_sk, sender_pk, piece_hash, i, infohash, ts
        )

        results.append({
            'rx_pk': rx_pk,
            'sender_pk': sender_pk,
            'piece_hash': piece_hash,
            'piece_index': i,
            'infohash': infohash,
            'timestamp': ts,
            'signature': sig,
            'piece_size': 262144,
        })
    return results


def process_report_direct(
    receipts: List[dict],
    used_receipts: Dict[str, float],
    receipt_window: int,
) -> bool:
    """
    Process a batch of receipts with aggregate verification.
    Direct implementation (no HTTP) matching the tracker's Report algorithm.
    Returns True on success, False on failure.
    """
    if not receipts:
        return True

    now = int(time.time())
    public_keys = []
    messages = []
    signatures = []

    for r in receipts:
        # Check epoch window
        if abs(now - r['timestamp']) > receipt_window:
            return False

        # Check double-spend
        receipt_id = hashlib.sha256(
            r['infohash'] + r['sender_pk'] + r['rx_pk'] +
            r['piece_hash'] + r['piece_index'].to_bytes(4, 'big')
        ).hexdigest()
        if receipt_id in used_receipts:
            return False

        # Build message for verification
        msg = (
            r['infohash'] +
            r['sender_pk'] +
            r['piece_hash'] +
            r['piece_index'].to_bytes(4, 'big') +
            r['timestamp'].to_bytes(8, 'big')
        )
        public_keys.append(r['rx_pk'])
        messages.append(msg)
        signatures.append(r['signature'])
        used_receipts[receipt_id] = now

    # Aggregate verify
    agg_sig = aggregate_signatures(signatures)
    return aggregate_verify(public_keys, messages, agg_sig)


@dataclass
class ConcurrencyResult:
    num_peers: int
    receipts_per_report: int
    total_reports: int
    total_time_sec: float
    throughput_reports_per_sec: float
    mean_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    success_rate: float


@dataclass
class SwarmScaleResult:
    swarm_size: int
    announce_mean_ms: float
    announce_p95_ms: float
    report_mean_ms: float
    report_p95_ms: float


class ScalabilityBenchmark:
    """Benchmark for scalability: concurrent peers and swarm scaling"""

    def __init__(
        self,
        peer_counts: List[int] = None,
        swarm_sizes: List[int] = None,
        receipts_per_report: int = 10,
        announce_iterations: int = 100,
    ):
        self.peer_counts = peer_counts or [10, 50, 100, 200, 500]
        self.swarm_sizes = swarm_sizes or [100, 1000, 5000, 10000]
        self.receipts_per_report = receipts_per_report
        self.announce_iterations = announce_iterations
        self.results = {}

    def benchmark_concurrency(self) -> List[ConcurrencyResult]:
        """Benchmark concurrent report processing with N parallel peers."""
        print("\n=== Scalability: Concurrent Report Processing ===\n")
        print(f"{'Peers':>8} {'Reports':>10} {'Throughput':>12} {'Mean (ms)':>12} "
              f"{'P50':>10} {'P95':>10} {'P99':>10}")
        print("-" * 75)

        results = []

        for num_peers in self.peer_counts:
            used_receipts: Dict[str, float] = {}
            now = int(time.time())

            # Pre-generate receipts for each peer
            peer_data = []
            for p in range(num_peers):
                _sk, pk = generate_keypair()
                base_ts = now - 100 + p * 1000
                receipts = generate_test_receipts(pk, self.receipts_per_report, base_ts)
                peer_data.append(receipts)

            # Process all reports sequentially (Python GIL limits true parallelism)
            # but we measure individual latencies as if they were concurrent
            latencies = []
            successes = 0
            total_start = time.perf_counter()

            for receipts in peer_data:
                start = time.perf_counter()
                ok = process_report_direct(receipts, used_receipts, 7200)
                lat = (time.perf_counter() - start) * 1000
                latencies.append(lat)
                if ok:
                    successes += 1

            total_time = time.perf_counter() - total_start

            latencies.sort()
            mean = statistics.mean(latencies)

            result = ConcurrencyResult(
                num_peers=num_peers,
                receipts_per_report=self.receipts_per_report,
                total_reports=num_peers,
                total_time_sec=total_time,
                throughput_reports_per_sec=num_peers / total_time,
                mean_latency_ms=mean,
                p50_latency_ms=percentile(latencies, 50),
                p95_latency_ms=percentile(latencies, 95),
                p99_latency_ms=percentile(latencies, 99),
                min_latency_ms=latencies[0],
                max_latency_ms=latencies[-1],
                success_rate=successes / num_peers,
            )

            print(f"{result.num_peers:>8} {result.total_reports:>10} "
                  f"{result.throughput_reports_per_sec:>10.1f}/s "
                  f"{result.mean_latency_ms:>10.2f} "
                  f"{result.p50_latency_ms:>10.2f} "
                  f"{result.p95_latency_ms:>10.2f} "
                  f"{result.p99_latency_ms:>10.2f}")

            results.append(result)

        return results

    def benchmark_swarm_scale(self) -> List[SwarmScaleResult]:
        """Benchmark announce/report performance vs swarm size."""
        print("\n=== Scalability: Swarm Size Impact ===\n")
        print(f"{'Swarm':>10} {'Ann mean(ms)':>14} {'Ann p95(ms)':>14} "
              f"{'Rep mean(ms)':>14} {'Rep p95(ms)':>14}")
        print("-" * 70)

        results = []
        infohash = b'\xBB' * 20

        for size in self.swarm_sizes:
            tracker = TrackerState()

            # Populate swarm
            swarm = tracker.swarms[infohash]
            for i in range(size):
                _sk, pk = generate_keypair()
                peer = Peer(
                    peer_id=f"peer-{i}".encode(),
                    ip=f"10.0.{i // 256}.{i % 256}",
                    port=6881 + (i % 1000),
                    user_id=f"user-{i}",
                    public_key=pk,
                )
                peer.uploaded = 0
                peer.downloaded = 0
                peer.left = 1024
                peer.last_seen = time.time()
                swarm[f"peer-{i}"] = peer

            # Benchmark announce (lookup + sample)
            announce_timings = []
            for _ in range(self.announce_iterations):
                start = time.perf_counter()
                peers = list(swarm.values())[:50]
                _ = len(peers)  # force evaluation
                announce_timings.append((time.perf_counter() - start) * 1000)

            announce_timings.sort()
            ann_mean = statistics.mean(announce_timings)
            ann_p95 = percentile(announce_timings, 95)

            # Benchmark report processing
            now = int(time.time())
            _sk, pk = generate_keypair()

            report_iters = min(self.announce_iterations, 100)
            report_timings = []
            for _ in range(report_iters):
                fresh = generate_test_receipts(
                    pk, 10, now + random.randint(0, 100000)
                )
                start = time.perf_counter()
                process_report_direct(fresh, tracker.used_receipts, 7200)
                report_timings.append((time.perf_counter() - start) * 1000)

            report_timings.sort()
            rep_mean = statistics.mean(report_timings)
            rep_p95 = percentile(report_timings, 95)

            print(f"{size:>10} {ann_mean:>14.4f} {ann_p95:>14.4f} "
                  f"{rep_mean:>14.4f} {rep_p95:>14.4f}")

            results.append(SwarmScaleResult(
                swarm_size=size,
                announce_mean_ms=ann_mean,
                announce_p95_ms=ann_p95,
                report_mean_ms=rep_mean,
                report_p95_ms=rep_p95,
            ))

        return results

    def run_all(self) -> Dict:
        """Run all scalability benchmarks."""
        concurrency = self.benchmark_concurrency()
        swarm_scale = self.benchmark_swarm_scale()

        self.results = {
            'concurrency': [
                {
                    'num_peers': r.num_peers,
                    'receipts_per_report': r.receipts_per_report,
                    'total_reports': r.total_reports,
                    'total_time_sec': r.total_time_sec,
                    'throughput_reports_per_sec': r.throughput_reports_per_sec,
                    'mean_latency_ms': r.mean_latency_ms,
                    'p50_latency_ms': r.p50_latency_ms,
                    'p95_latency_ms': r.p95_latency_ms,
                    'p99_latency_ms': r.p99_latency_ms,
                    'min_latency_ms': r.min_latency_ms,
                    'max_latency_ms': r.max_latency_ms,
                    'success_rate': r.success_rate,
                }
                for r in concurrency
            ],
            'swarm_scale': [
                {
                    'swarm_size': r.swarm_size,
                    'announce_mean_ms': r.announce_mean_ms,
                    'announce_p95_ms': r.announce_p95_ms,
                    'report_mean_ms': r.report_mean_ms,
                    'report_p95_ms': r.report_p95_ms,
                }
                for r in swarm_scale
            ],
        }
        return self.results

    def print_results(self):
        """Print summary of results."""
        print("\n" + "=" * 80)
        print("SCALABILITY BENCHMARK RESULTS")
        print("=" * 80)

        if 'concurrency' in self.results:
            print("\nConcurrent Report Processing:")
            for r in self.results['concurrency']:
                print(f"  {r['num_peers']:>5} peers: "
                      f"{r['throughput_reports_per_sec']:.1f} reports/s, "
                      f"mean={r['mean_latency_ms']:.2f}ms, "
                      f"p95={r['p95_latency_ms']:.2f}ms")

        if 'swarm_scale' in self.results:
            print("\nSwarm Size Impact:")
            for r in self.results['swarm_scale']:
                print(f"  {r['swarm_size']:>6} peers: "
                      f"announce={r['announce_mean_ms']:.4f}ms, "
                      f"report={r['report_mean_ms']:.2f}ms")


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description='PBTS Scalability Benchmark')
    parser.add_argument('--peer-counts', type=int, nargs='+',
                        default=[10, 50, 100, 200, 500],
                        help='Concurrent peer counts (default: 10 50 100 200 500)')
    parser.add_argument('--swarm-sizes', type=int, nargs='+',
                        default=[100, 1000, 5000, 10000],
                        help='Swarm sizes (default: 100 1000 5000 10000)')
    parser.add_argument('--receipts-per-report', type=int, default=10,
                        help='Receipts per report (default: 10)')
    parser.add_argument('--announce-iterations', type=int, default=100,
                        help='Announce benchmark iterations (default: 100)')
    parser.add_argument('--output', type=str,
                        help='Output JSON file for results')

    args = parser.parse_args()

    benchmark = ScalabilityBenchmark(
        peer_counts=args.peer_counts,
        swarm_sizes=args.swarm_sizes,
        receipts_per_report=args.receipts_per_report,
        announce_iterations=args.announce_iterations,
    )
    results = benchmark.run_all()
    benchmark.print_results()

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
