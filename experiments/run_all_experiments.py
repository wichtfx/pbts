#!/usr/bin/env python3
"""
Run All PBTS Experiments

Comprehensive experiment runner that:
1. Runs all benchmarks (receipts, TEE, on-chain, load test)
2. Generates comparison reports
3. Saves results to JSON and generates summary
"""

import sys
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import benchmark modules
from experiments.benchmark_receipts import ReceiptBenchmark
from experiments.benchmark_tee import TEEBenchmark
from experiments.benchmark_client_download import ClientDownloadBenchmark, DownloadScenario
from experiments.benchmark_tracker_overhead import TrackerOverheadBenchmark
from experiments.benchmark_scalability import ScalabilityBenchmark
from experiments.benchmark_gas import GasBenchmark

from tee_manager import TEE_AVAILABLE


class ExperimentRunner:
    """Runs all experiments and generates reports"""

    def __init__(
        self,
        output_dir: Path = None,
        receipt_iterations: int = 1000,
        receipt_batch_sizes: list = None,
        tee_iterations: int = 100,
        tee_verify_iterations: int = 5,
        client_download_speeds: list = None,
        client_piece_sizes: list = None,
        tracker_overhead_iterations: int = 100,
        skip_tee: bool = False,
        skip_client_download: bool = False,
        skip_tracker_overhead: bool = False,
        **kwargs
    ):
        self.output_dir = output_dir or Path("/tmp/pbts_experiments")
        self.output_dir.mkdir(exist_ok=True, parents=True)

        self.receipt_iterations = receipt_iterations
        self.receipt_batch_sizes = receipt_batch_sizes or [10, 25, 50]
        self.tee_iterations = tee_iterations
        self.tee_verify_iterations = tee_verify_iterations
        self.client_download_speeds = client_download_speeds or [1, 5, 10, 20]
        self.client_piece_sizes = client_piece_sizes or [256, 512, 1024, 2048]
        self.tracker_overhead_iterations = tracker_overhead_iterations

        self.skip_tee = skip_tee or not TEE_AVAILABLE
        self.skip_client_download = skip_client_download
        self.skip_tracker_overhead = skip_tracker_overhead
        self.skip_scalability = kwargs.get('skip_scalability', False)
        self.skip_gas = kwargs.get('skip_gas', False)

        self.scalability_peer_counts = kwargs.get('scalability_peer_counts', [10, 50, 100, 200, 500])
        self.scalability_swarm_sizes = kwargs.get('scalability_swarm_sizes', [100, 1000, 5000, 10000])
        self.gas_num_users = kwargs.get('gas_num_users', 100)

        self.results = {}
        self.start_time = None
        self.end_time = None

    def run_all(self):
        """Run all experiments"""
        print("=" * 80)
        print(" " * 25 + "PBTS EXPERIMENTS")
        print("=" * 80)
        print(f"\nOutput directory: {self.output_dir}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        self.start_time = time.time()

        # 1. Receipt Benchmarks
        print("\n\n" + "=" * 80)
        print("EXPERIMENT 1/6: RECEIPT OPERATIONS")
        print("=" * 80)
        self.run_receipt_benchmarks()

        # 2. TEE Benchmarks (if available)
        if not self.skip_tee:
            print("\n\n" + "=" * 80)
            print("EXPERIMENT 2/6: TEE OPERATIONS")
            print("=" * 80)
            self.run_tee_benchmarks()
        else:
            print("\n\n" + "=" * 80)
            print("EXPERIMENT 2/6: TEE OPERATIONS - SKIPPED")
            print("=" * 80)
            if not TEE_AVAILABLE:
                print("\nTEE not available (dstack_sdk not installed)")
            self.results['tee'] = None

        # 3. Client Download Benchmarks
        if not self.skip_client_download:
            print("\n\n" + "=" * 80)
            print("EXPERIMENT 3/6: CLIENT DOWNLOAD SIMULATION")
            print("=" * 80)
            self.run_client_download_benchmarks()
        else:
            print("\n\n" + "=" * 80)
            print("EXPERIMENT 3/6: CLIENT DOWNLOAD SIMULATION - SKIPPED")
            print("=" * 80)
            self.results['client_download'] = None

        # 4. Tracker Overhead Benchmarks
        if not self.skip_tracker_overhead:
            print("\n\n" + "=" * 80)
            print("EXPERIMENT 4/6: TRACKER OVERHEAD BREAKDOWN")
            print("=" * 80)
            self.run_tracker_overhead_benchmarks()
        else:
            print("\n\n" + "=" * 80)
            print("EXPERIMENT 4/6: TRACKER OVERHEAD BREAKDOWN - SKIPPED")
            print("=" * 80)
            self.results['tracker_overhead'] = None

        # 5. Scalability Benchmarks
        if not self.skip_scalability:
            print("\n\n" + "=" * 80)
            print("EXPERIMENT 5/6: SCALABILITY")
            print("=" * 80)
            self.run_scalability_benchmarks()
        else:
            print("\n\n" + "=" * 80)
            print("EXPERIMENT 5/6: SCALABILITY - SKIPPED")
            print("=" * 80)
            self.results['scalability'] = None

        # 6. Gas Cost Benchmarks
        if not self.skip_gas:
            print("\n\n" + "=" * 80)
            print("EXPERIMENT 6/6: SMART CONTRACT GAS COSTS")
            print("=" * 80)
            self.run_gas_benchmarks()
        else:
            print("\n\n" + "=" * 80)
            print("EXPERIMENT 6/6: SMART CONTRACT GAS COSTS - SKIPPED")
            print("=" * 80)
            self.results['gas'] = None

        self.end_time = time.time()

        # Generate reports
        self.generate_reports()

    def run_receipt_benchmarks(self):
        """Run receipt operation benchmarks"""
        benchmark = ReceiptBenchmark(
            num_iterations=self.receipt_iterations,
            batch_sizes=self.receipt_batch_sizes
        )
        results = benchmark.run_all()
        benchmark.print_results()

        self.results['receipts'] = results

        # Save to JSON
        output_file = self.output_dir / "receipts.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {output_file}")

    def run_tee_benchmarks(self):
        """Run TEE operation benchmarks"""
        benchmark = TEEBenchmark(num_iterations=self.tee_iterations)
        results = benchmark.run_all(verify_iterations=self.tee_verify_iterations)
        benchmark.print_results()

        self.results['tee'] = results

        # Save to JSON
        output_file = self.output_dir / "tee.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {output_file}")

    def run_client_download_benchmarks(self):
        """Run client download simulation benchmarks"""
        # Create scenarios
        scenarios = []
        for speed in self.client_download_speeds:
            for piece_size in self.client_piece_sizes:
                num_pieces = int(100 * 1024 / piece_size)  # 100 MB file
                scenarios.append(DownloadScenario(
                    download_speed_mbps=speed,
                    piece_size_kb=piece_size,
                    num_pieces=num_pieces,
                    batch_size=1  # One receipt per piece
                ))

        benchmark = ClientDownloadBenchmark(
            warmup_iterations=10,
            measure_iterations=100
        )
        results = benchmark.run_all(scenarios)
        benchmark.print_results()

        # Convert results to JSON-serializable format
        self.results['client_download'] = {
            'scenarios': [
                {
                    'download_speed_mbps': r.scenario.download_speed_mbps,
                    'piece_size_kb': r.scenario.piece_size_kb,
                    'batch_size': r.scenario.batch_size,
                    'mean_receipt_time_ms': r.mean_receipt_time_ms,
                    'total_overhead_percent': r.total_overhead_percent,
                    'throughput_reduction_percent': r.throughput_reduction_percent
                }
                for r in results
            ]
        }

        # Save to JSON
        output_file = self.output_dir / "client_download.json"
        with open(output_file, 'w') as f:
            json.dump(self.results['client_download'], f, indent=2)
        print(f"\nResults saved to {output_file}")

    def run_tracker_overhead_benchmarks(self):
        """Run tracker overhead breakdown benchmarks"""
        print("\nNote: Tracker overhead benchmark requires running tracker...")
        print("Skipping for now. Run benchmark_tracker_overhead.py separately.")
        self.results['tracker_overhead'] = None

    def run_scalability_benchmarks(self):
        """Run scalability benchmarks"""
        benchmark = ScalabilityBenchmark(
            peer_counts=self.scalability_peer_counts,
            swarm_sizes=self.scalability_swarm_sizes,
        )
        results = benchmark.run_all()
        benchmark.print_results()

        self.results['scalability'] = results

        output_file = self.output_dir / "scalability.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {output_file}")

    def run_gas_benchmarks(self):
        """Run smart contract gas cost benchmarks"""
        benchmark = GasBenchmark(num_users=self.gas_num_users)
        results = benchmark.run_all()
        benchmark.print_results()

        self.results['gas'] = results if results else None

        if results:
            output_file = self.output_dir / "gas.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to {output_file}")

    def generate_reports(self):
        """Generate summary reports"""
        print("\n\n" + "=" * 80)
        print("GENERATING REPORTS")
        print("=" * 80)

        # Save all results
        all_results_file = self.output_dir / "all_results.json"
        with open(all_results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nAll results saved to {all_results_file}")

        # Generate summary report
        self.generate_summary_report()

        # Generate comparison tables
        self.generate_comparison_tables()

        total_time = self.end_time - self.start_time
        print(f"\n\nTotal experiment time: {total_time:.2f} seconds")
        print(f"Output directory: {self.output_dir}")

    def generate_summary_report(self):
        """Generate summary report in text format"""
        report_file = self.output_dir / "SUMMARY.txt"

        with open(report_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write(" " * 25 + "PBTS EXPERIMENT SUMMARY\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total time: {self.end_time - self.start_time:.2f} seconds\n\n")

            # Receipt operations
            if 'receipts' in self.results:
                f.write("\n" + "-" * 80 + "\n")
                f.write("1. RECEIPT OPERATIONS\n")
                f.write("-" * 80 + "\n\n")

                r = self.results['receipts']

                f.write(f"Keypair Generation:       {r['keypair_generation']['mean_ms']:.4f} ms (mean)\n")
                f.write(f"Receipt Creation:         {r['receipt_creation']['mean_ms']:.4f} ms (mean)\n")
                f.write(f"Receipt Verification:     {r['receipt_verification']['mean_ms']:.4f} ms (mean)\n\n")

                f.write("Aggregate Verification Speedup:\n")
                for batch_size, stats in r['aggregate_verification'].items():
                    f.write(f"  {batch_size:>3} receipts: {stats['speedup']:.2f}x faster\n")

            # TEE operations
            if 'tee' in self.results and self.results['tee'] is not None:
                f.write("\n" + "-" * 80 + "\n")
                f.write("2. TEE OPERATIONS\n")
                f.write("-" * 80 + "\n\n")

                t = self.results['tee']

                kg = t['key_generation']
                f.write(f"Regular Key Generation:   {kg['regular']['mean_ms']:.4f} ms (mean)\n")
                if kg['tee'] is not None:
                    f.write(f"TEE Key Generation:       {kg['tee']['mean_ms']:.4f} ms (mean)\n")
                    f.write(f"TEE Overhead:             +{kg['tee']['overhead_vs_regular']:.4f} ms ({kg['tee']['overhead_percent']:.2f}%)\n\n")

                if t['attestation_generation'] is not None:
                    ag = t['attestation_generation']
                    f.write(f"Attestation Generation:   {ag['mean_ms']:.2f} ms (mean)\n")

                if t['attestation_verification'] is not None:
                    av = t['attestation_verification']
                    f.write(f"Attestation Verification: {av['mean_ms']:.2f} ms (mean)\n")

            # Client download simulations
            if 'client_download' in self.results and self.results['client_download'] is not None:
                f.write("\n" + "-" * 80 + "\n")
                f.write("3. CLIENT DOWNLOAD SIMULATION\n")
                f.write("-" * 80 + "\n\n")

                cd = self.results['client_download']
                if cd['scenarios']:
                    # Show summary statistics
                    avg_overhead = sum(s['total_overhead_percent'] for s in cd['scenarios']) / len(cd['scenarios'])
                    avg_throughput_reduction = sum(s['throughput_reduction_percent'] for s in cd['scenarios']) / len(cd['scenarios'])

                    f.write(f"Average overhead:         {avg_overhead:.2f}% of download time\n")
                    f.write(f"Average throughput loss:  {avg_throughput_reduction:.2f}%\n")

            # Tracker overhead
            if 'tracker_overhead' in self.results and self.results['tracker_overhead'] is not None:
                f.write("\n" + "-" * 80 + "\n")
                f.write("4. TRACKER OVERHEAD BREAKDOWN\n")
                f.write("-" * 80 + "\n\n")

                f.write("See tracker_overhead.json for detailed breakdown\n")

            f.write("\n" + "=" * 80 + "\n")

        print(f"\nSummary report saved to {report_file}")

    def generate_comparison_tables(self):
        """Generate comparison tables"""
        tables_file = self.output_dir / "COMPARISON.txt"

        with open(tables_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write(" " * 25 + "OVERHEAD COMPARISON\n")
            f.write("=" * 80 + "\n\n")

            # Operation overhead comparison
            f.write("OPERATION OVERHEAD (compared to baseline)\n")
            f.write("-" * 80 + "\n\n")

            if 'receipts' in self.results:
                r = self.results['receipts']
                baseline_ms = 0.1  # Assume 0.1ms for baseline (no crypto)

                f.write(f"{'Operation':<30} {'Time (ms)':<15} {'Overhead vs Baseline':<20}\n")
                f.write(f"{'-'*30} {'-'*15} {'-'*20}\n")

                f.write(f"{'Receipt Creation':<30} {r['receipt_creation']['mean_ms']:<15.4f} {r['receipt_creation']['mean_ms']/baseline_ms:.1f}x\n")
                f.write(f"{'Receipt Verification':<30} {r['receipt_verification']['mean_ms']:<15.4f} {r['receipt_verification']['mean_ms']/baseline_ms:.1f}x\n")

            if 'tee' in self.results and self.results['tee'] is not None:
                t = self.results['tee']
                if t['key_generation']['tee'] is not None:
                    tee_overhead = t['key_generation']['tee']['overhead_percent']
                    f.write(f"{'TEE Key Generation':<30} {f'+{tee_overhead:.2f}':<15} {f'+{tee_overhead:.1f}%':<20}\n")

            f.write("\n\n")

            # Extension overhead summary
            f.write("EXTENSION OVERHEAD SUMMARY\n")
            f.write("-" * 80 + "\n\n")

            f.write("Per-operation overhead introduced by PBTS extensions:\n\n")

            if 'receipts' in self.results:
                r = self.results['receipts']
                f.write(f"1. BEP10 Receipt Exchange:\n")
                f.write(f"   - Receipt creation:    ~{r['receipt_creation']['mean_ms']:.2f} ms per receipt\n")
                f.write(f"   - Receipt verification: ~{r['receipt_verification']['mean_ms']:.2f} ms per receipt\n")

                # Find largest batch size available
                if 'aggregate_verification' in r and r['aggregate_verification']:
                    max_batch = max(r['aggregate_verification'].keys())
                    agg_data = r['aggregate_verification'][max_batch]
                    f.write(f"   - Aggregate verification ({max_batch}): ~{agg_data['aggregate_mean_ms']/max_batch:.4f} ms per receipt\n")
                    f.write(f"   - Speedup with aggregation: {agg_data['speedup']:.2f}x\n\n")

            if 'tee' in self.results and self.results['tee'] is not None:
                t = self.results['tee']
                if t['attestation_generation'] is not None:
                    f.write(f"2. TEE Attestation:\n")
                    f.write(f"   - Attestation generation: ~{t['attestation_generation']['mean_ms']:.2f} ms\n")
                    if t['attestation_verification'] is not None:
                        f.write(f"   - Attestation verification: ~{t['attestation_verification']['mean_ms']:.2f} ms\n\n")

            if 'client_download' in self.results and self.results['client_download'] is not None:
                cd = self.results['client_download']
                if cd['scenarios']:
                    avg_overhead = sum(s['total_overhead_percent'] for s in cd['scenarios']) / len(cd['scenarios'])
                    f.write(f"3. Client Download Overhead:\n")
                    f.write(f"   - Average overhead: ~{avg_overhead:.2f}% of download time\n\n")

            f.write("\n" + "=" * 80 + "\n")

        print(f"Comparison tables saved to {tables_file}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Run all PBTS experiments',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--output-dir', type=str,
                        help='Output directory for results (default: /tmp/pbts_experiments)')
    parser.add_argument('--receipt-iterations', type=int, default=10,
                        help='Iterations for receipt benchmarks (default: 10)')
    parser.add_argument('--receipt-batch-sizes', type=int, nargs='+', default=[10, 25, 50],
                        help='Batch sizes for aggregate benchmarks (default: 10 25 50)')
    parser.add_argument('--tee-iterations', type=int, default=10,
                        help='Iterations for TEE benchmarks (default: 10)')
    parser.add_argument('--tee-verify-iterations', type=int, default=5,
                        help='Iterations for TEE verification (default: 5, slow)')
    parser.add_argument('--skip-tee', action='store_true',
                        help='Skip TEE benchmarks')
    parser.add_argument('--skip-client-download', action='store_true',
                        help='Skip client download simulation benchmarks')
    parser.add_argument('--skip-tracker-overhead', action='store_true',
                        help='Skip tracker overhead benchmarks (requires running tracker)')
    parser.add_argument('--skip-scalability', action='store_true',
                        help='Skip scalability benchmarks')
    parser.add_argument('--skip-gas', action='store_true',
                        help='Skip gas cost benchmarks (requires Foundry)')
    parser.add_argument('--scalability-peers', type=int, nargs='+',
                        default=[10, 50, 100, 200, 500],
                        help='Peer counts for scalability benchmark')
    parser.add_argument('--scalability-swarm-sizes', type=int, nargs='+',
                        default=[100, 1000, 5000, 10000],
                        help='Swarm sizes for scalability benchmark')
    parser.add_argument('--gas-users', type=int, default=100,
                        help='Number of users for gas benchmark batch test')

    args = parser.parse_args()

    output_dir = Path(args.output_dir) if args.output_dir else None

    runner = ExperimentRunner(
        output_dir=output_dir,
        receipt_iterations=args.receipt_iterations,
        receipt_batch_sizes=args.receipt_batch_sizes,
        tee_iterations=args.tee_iterations,
        tee_verify_iterations=args.tee_verify_iterations,
        skip_tee=args.skip_tee,
        skip_client_download=args.skip_client_download,
        skip_tracker_overhead=args.skip_tracker_overhead,
        skip_scalability=args.skip_scalability,
        skip_gas=args.skip_gas,
        scalability_peer_counts=args.scalability_peers,
        scalability_swarm_sizes=args.scalability_swarm_sizes,
        gas_num_users=args.gas_users,
    )

    runner.run_all()

    print("\n\n" + "=" * 80)
    print("EXPERIMENTS COMPLETE!")
    print("=" * 80)
    print(f"\nAll results saved to: {runner.output_dir}")
    print("\nGenerated files:")
    print(f"  - all_results.json: Complete results in JSON format")
    print(f"  - SUMMARY.txt: Human-readable summary")
    print(f"  - COMPARISON.txt: Overhead comparison tables")
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
