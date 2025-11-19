#!/usr/bin/env python3
"""
Tracker Overhead Breakdown Benchmark

Measures and compares overhead from different tracker components:
1. Baseline (no extensions)
2. TEE operations (key derivation, attestation)
3. Receipt verification (individual and aggregate)
4. On-chain operations (registration, updates)
5. Combined (all extensions enabled)

This answers: "Which component is the bottleneck in the tracker?"
"""
from web3 import Web3
import requests
import sys
import time
import hashlib
import statistics
import base64
import subprocess
import atexit
from pathlib import Path
from typing import List, Dict
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tracker import generate_keypair, attest_piece_transfer, aggregate_signatures


@dataclass
class ComponentOverhead:
    """Overhead measurement for a specific component"""
    component_name: str
    mean_ms: float
    median_ms: float
    stdev_ms: float
    min_ms: float
    max_ms: float
    p95_ms: float
    p99_ms: float
    overhead_vs_baseline_ms: float
    overhead_vs_baseline_percent: float


class TrackerOverheadBenchmark:
    """Benchmark tracker overhead by component"""

    def __init__(
        self,
        tracker_url: str = "http://localhost:8000",
        iterations: int = 100,
        warmup: int = 10,
        auto_start: bool = True
    ):
        self.tracker_url = tracker_url
        self.iterations = iterations
        self.warmup = warmup
        self.auto_start = auto_start
        self.anvil_url = "http://localhost:8545"

        self.results: Dict[str, ComponentOverhead] = {}
        self.baseline_latency_ms: float = 0

        # Process management
        self.anvil_process = None
        self.tracker_process = None

    def cleanup(self):
        """Cleanup processes"""
        if self.anvil_process:
            print("\nStopping Anvil...")
            self.anvil_process.terminate()
            self.anvil_process.wait(timeout=5)

        if self.tracker_process:
            print("Stopping tracker...")
            self.tracker_process.terminate()
            self.tracker_process.wait(timeout=5)

    def start_anvil(self):
        """Start Anvil blockchain"""
        print("\nStarting Anvil...")
        self.anvil_process = subprocess.Popen(
            ['anvil', '--silent'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(2)  # Wait for Anvil to start

    def deploy_contracts(self):
        """Deploy smart contracts"""
        print("Deploying smart contracts...")
        deploy_script = project_root / 'deploy_factory.sh'

        if not deploy_script.exists():
            print(f"  ⚠ Deploy script not found: {deploy_script}")
            print("  Skipping contract deployment (on-chain features will be unavailable)")
            return False

        result = subprocess.run(
            [str(deploy_script)],
            cwd=project_root,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"  ⚠ Contract deployment failed: {result.stderr}")
            print("  On-chain features will be unavailable")
            return False

        print("  ✓ Contracts deployed successfully")
        time.sleep(2)
        return True

    def start_tracker(self):
        """Start PBTS tracker"""
        print("Starting PBTS tracker...")
        self.tracker_process = subprocess.Popen(
            ['python', 'tracker.py'],
            cwd=project_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(3)  # Wait for tracker to start

    def wait_for_tracker(self, timeout: int = 30):
        """Wait for tracker to be ready"""
        print("Waiting for tracker to be ready...")
        start = time.time()

        while time.time() - start < timeout:
            try:
                response = requests.get(
                    f"{self.tracker_url}/health", timeout=2)
                if response.status_code == 200:
                    print("✓ Tracker is ready")
                    return True
            except requests.exceptions.RequestException:
                pass
            time.sleep(1)

        raise RuntimeError("Tracker failed to start within timeout")

    def setup(self):
        """Setup test environment"""
        if self.auto_start:
            # Register cleanup handler
            atexit.register(self.cleanup)

            # Start services
            self.start_anvil()
            self.deploy_contracts()
            self.start_tracker()
            self.wait_for_tracker()

    def _initialize_contract(self):
        """Initialize smart contract"""
        print("\nInitializing smart contract...")
        try:
            response = requests.post(
                f"{self.tracker_url}/contract/init", timeout=10)
            if response.status_code != 200:
                print(f"  ⚠ Contract init failed: {response.text}")
                print("  On-chain benchmarks will be skipped")
                return False
            print("  ✓ Contract initialized successfully")
            return True
        except Exception as e:
            print(f"  ⚠ Contract init exception: {e}")
            print("  On-chain benchmarks will be skipped")
            return False

    def fund_tee_account(self):
        """Fund TEE-derived account with ETH from Anvil's pre-funded account"""
        print("\nFunding TEE-derived account...")

        # 1. Get TEE-derived account address from tracker
        response = requests.get(
            f"{self.tracker_url}/contract/status", timeout=5)
        status = response.json()
        tracker_address = status.get('account_address')

        if not tracker_address:
            raise RuntimeError(
                "Could not get TEE-derived account from tracker")

        print(f"  TEE-derived account: {tracker_address}")

        # 2. Connect to Anvil
        w3 = Web3(Web3.HTTPProvider(self.anvil_url))
        if not w3.is_connected():
            raise ConnectionError(
                f"Failed to connect to Anvil at {self.anvil_url}")

        # 3. Get pre-funded Anvil account
        anvil_accounts = w3.eth.accounts
        if not anvil_accounts:
            raise RuntimeError("No accounts found in Anvil")
        funder_account = anvil_accounts[0]
        print(f"  Funder account (Anvil): {funder_account}")

        # 4. Send transaction
        print("  Transferring 10 ETH from Anvil account to TEE account...")
        tx_hash = w3.eth.send_transaction({
            'from': funder_account,
            'to': tracker_address,
            'value': w3.to_wei(10, 'ether')
        })

        # 5. Wait for confirmation
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)

        if receipt.status == 1:
            print(f"  ✓ Funding successful (tx: {tx_hash.hex()})")
        else:
            raise Exception("Failed to fund TEE account")

    def measure_latency(self, operation_func, warmup: int = 10) -> List[float]:
        """Measure latency of an operation"""
        # Warmup
        for _ in range(warmup):
            try:
                operation_func()
            except Exception as e:
                print(f"  Warning: Warmup failed: {e}")

        # Measurement
        latencies = []
        for i in range(self.iterations):
            start = time.perf_counter()
            try:
                operation_func()
                end = time.perf_counter()
                latencies.append((end - start) * 1000)  # ms
            except Exception as e:
                print(f"  Warning: Iteration {i} failed: {e}")

        return latencies

    def calculate_stats(self, latencies: List[float], component_name: str, baseline: float = 0) -> ComponentOverhead:
        """Calculate statistics from latency measurements"""
        if not latencies:
            raise ValueError(
                f"No successful measurements for {component_name}")

        mean_lat = statistics.mean(latencies)
        median_lat = statistics.median(latencies)
        stdev_lat = statistics.stdev(latencies) if len(latencies) > 1 else 0
        min_lat = min(latencies)
        max_lat = max(latencies)

        # Calculate percentiles
        sorted_lat = sorted(latencies)
        p95_lat = sorted_lat[int(len(sorted_lat) * 0.95)]
        p99_lat = sorted_lat[int(len(sorted_lat) * 0.99)]

        overhead_ms = mean_lat - baseline
        overhead_percent = (overhead_ms / baseline *
                            100) if baseline > 0 else 0

        return ComponentOverhead(
            component_name=component_name,
            mean_ms=mean_lat,
            median_ms=median_lat,
            stdev_ms=stdev_lat,
            min_ms=min_lat,
            max_ms=max_lat,
            p95_ms=p95_lat,
            p99_ms=p99_lat,
            overhead_vs_baseline_ms=overhead_ms,
            overhead_vs_baseline_percent=overhead_percent
        )

    def benchmark_baseline(self):
        """Benchmark baseline announce (no extensions)"""
        print("\n[1/6] Benchmarking baseline announce (no extensions)...")

        # Disable all extensions
        requests.post(
            f"{self.tracker_url}/config",
            json={"verify_signatures": False, "tee_mode": "disabled"},
            timeout=5
        )

        # Test data
        infohash = hashlib.sha1(b"baseline_test").digest()
        peer_id = hashlib.sha1(b"peer_baseline").digest()

        def announce_operation():
            requests.get(
                f"{self.tracker_url}/announce",
                params={
                    'info_hash': infohash,
                    'peer_id': peer_id,
                    'port': 6881,
                    'uploaded': 0,
                    'downloaded': 0,
                    'left': 1000000,
                    'event': 'started'
                },
                timeout=5
            )

        latencies = self.measure_latency(announce_operation, self.warmup)
        result = self.calculate_stats(latencies, "Baseline (announce only)")
        self.baseline_latency_ms = result.mean_ms
        self.results['baseline'] = result

        print(f"  Mean latency: {result.mean_ms:.3f} ms")

    def benchmark_tee_operations(self):
        """Benchmark TEE operations"""
        print("\n[2/6] Benchmarking TEE operations...")

        # Check if TEE is available
        try:
            response = requests.get(
                f"{self.tracker_url}/tee/status", timeout=5)
            tee_status = response.json()
            if not tee_status.get('tee_available', False):
                print("  ⚠ TEE not available, skipping TEE benchmark")
                return
        except Exception as e:
            print(f"  ⚠ Failed to check TEE status: {e}, skipping")
            return

        # Enable TEE mode
        requests.post(
            f"{self.tracker_url}/config",
            json={"tee_mode": "enabled"},
            timeout=5
        )

        # Benchmark 1: TEE key generation
        print("  Testing TEE key generation...")

        def tee_keygen():
            response = requests.post(
                f"{self.tracker_url}/keygen-tee",
                json={"salt": f"test_{time.time_ns()}"},
                timeout=10
            )
            return response.json()

        latencies_keygen = self.measure_latency(tee_keygen, self.warmup)
        result_keygen = self.calculate_stats(
            latencies_keygen, "TEE key generation", self.baseline_latency_ms)
        self.results['tee_keygen'] = result_keygen

        print(
            f"    Mean latency: {result_keygen.mean_ms:.3f} ms (overhead: +{result_keygen.overhead_vs_baseline_ms:.3f} ms)")

        # Benchmark 2: TEE attestation generation
        print("  Testing TEE attestation generation...")

        def tee_attestation():
            # Generate a key first
            keygen_response = requests.post(
                f"{self.tracker_url}/keygen-tee",
                json={"salt": f"test_{time.time_ns()}"},
                timeout=10
            )
            key_data = keygen_response.json()

            # Generate attestation
            response = requests.post(
                f"{self.tracker_url}/generate-attestation",
                json={"public_key": key_data['public_key']},
                timeout=10
            )
            return response.json()

        latencies_attestation = self.measure_latency(
            tee_attestation, max(5, self.warmup // 2))  # Fewer warmup (slow)
        result_attestation = self.calculate_stats(
            latencies_attestation, "TEE attestation generation", self.baseline_latency_ms)
        self.results['tee_attestation'] = result_attestation

        print(
            f"    Mean latency: {result_attestation.mean_ms:.3f} ms (overhead: +{result_attestation.overhead_vs_baseline_ms:.3f} ms)")

        # Disable TEE for other tests
        requests.post(
            f"{self.tracker_url}/config",
            json={"tee_mode": "disabled"},
            timeout=5
        )

    def benchmark_receipt_verification(self):
        """Benchmark receipt verification (individual and aggregate)"""
        print("\n[3/6] Benchmarking receipt verification...")

        # Enable signature verification
        requests.post(
            f"{self.tracker_url}/config",
            json={"verify_signatures": True},
            timeout=5
        )

        # Setup users
        receiver_sk, receiver_pk = generate_keypair()
        sender_sk, sender_pk = generate_keypair()

        user_id = f"bench_receiver_{int(time.time())}"
        requests.post(
            f"{self.tracker_url}/register",
            json={
                "user_id": user_id,
                "public_key": base64.b64encode(receiver_pk).decode()
            },
            timeout=5
        )

        infohash = hashlib.sha1(b"receipt_test").digest()

        # Benchmark 1: Individual receipt verification
        print("  Testing individual receipt verification...")

        def verify_single_receipt():
            # Create receipt
            piece_hash = hashlib.sha256(b"test_piece_data").digest()
            timestamp = int(time.time())
            signature = attest_piece_transfer(
                receiver_private_key=receiver_sk,
                sender_public_key=sender_pk,
                piece_hash=piece_hash,
                piece_index=0,
                infohash=infohash,
                timestamp=timestamp
            )

            # Construct JSON-serializable receipt
            receipt_data = {
                "receiver_public_key": base64.b64encode(receiver_pk).decode(),
                "sender_pk": base64.b64encode(sender_pk).decode(),
                "piece_hash": piece_hash.hex(),
                "piece_index": 0,
                "infohash": infohash.hex(),
                "timestamp": timestamp,
                "signature": base64.b64encode(signature).decode()
            }

            # Submit to tracker
            response = requests.post(
                f"{self.tracker_url}/report",
                json={
                    "user_id": user_id,
                    "receipts": [receipt_data]
                },
                timeout=5
            )
            return response.json()

        latencies_single = self.measure_latency(
            verify_single_receipt, self.warmup)
        result_single = self.calculate_stats(
            latencies_single, "Receipt verification (1 receipt)", self.baseline_latency_ms)
        self.results['receipt_single'] = result_single

        print(
            f"    Mean latency: {result_single.mean_ms:.3f} ms (overhead: +{result_single.overhead_vs_baseline_ms:.3f} ms)")

        # Benchmark 2: Aggregate verification (different batch sizes)
        for batch_size in [10, 50]:
            print(
                f"  Testing aggregate verification ({batch_size} receipts)...")

            # Pre-create receipts ONCE (not in measurement loop)
            print(f"    Creating {batch_size} receipts...")
            receipt_data_list = []

            for i in range(batch_size):
                piece_hash = hashlib.sha256(
                    f"piece_{i}_{time.time_ns()}".encode()).digest()
                timestamp = int(time.time())
                signature = attest_piece_transfer(
                    receiver_private_key=receiver_sk,
                    sender_public_key=sender_pk,
                    piece_hash=piece_hash,
                    piece_index=i,
                    infohash=infohash,
                    timestamp=timestamp
                )
                # Each receipt keeps its individual signature
                # The tracker will aggregate them server-side for efficient verification
                receipt_data_list.append({
                    "receiver_public_key": base64.b64encode(receiver_pk).decode(),
                    "sender_pk": base64.b64encode(sender_pk).decode(),
                    "piece_hash": piece_hash.hex(),
                    "piece_index": i,
                    "infohash": infohash.hex(),
                    "timestamp": timestamp,
                    "signature": base64.b64encode(signature).decode()
                })

            # Now measure only the submission and verification time
            def verify_batch():
                response = requests.post(
                    f"{self.tracker_url}/report",
                    json={
                        "user_id": user_id,
                        "receipts": receipt_data_list
                    },
                    timeout=30
                )
                return response.json()

            # Fewer iterations for large batches
            batch_iterations = max(10, self.iterations // (batch_size // 10))
            latencies_batch = self.measure_latency(
                verify_batch, max(2, self.warmup // 5))
            result_batch = self.calculate_stats(
                latencies_batch, f"Receipt verification ({batch_size} receipts)", self.baseline_latency_ms)
            self.results[f'receipt_batch_{batch_size}'] = result_batch

            # Calculate per-receipt overhead
            per_receipt_ms = result_batch.mean_ms / batch_size
            print(
                f"    Mean latency: {result_batch.mean_ms:.3f} ms ({per_receipt_ms:.3f} ms/receipt)")

        # Disable verification for other tests
        requests.post(
            f"{self.tracker_url}/config",
            json={"verify_signatures": False},
            timeout=5
        )

    def benchmark_onchain_operations(self):
        """Benchmark on-chain operations"""
        print("\n[4/6] Benchmarking on-chain operations...")

        # Check contract status
        try:
            response = requests.get(
                f"{self.tracker_url}/contract/status", timeout=5)
            contract_status = response.json()
            if not contract_status.get('configured', False):
                print("  ⚠ Contract not initialized, skipping on-chain benchmark")
                return
        except Exception as e:
            print(f"  ⚠ Failed to check contract status: {e}, skipping")
            return

        # Benchmark 1: User registration on-chain
        print("  Testing on-chain user registration...")

        user_counter = 0

        def register_user_onchain():
            nonlocal user_counter
            user_id = f"onchain_user_{user_counter}_{time.time_ns()}"
            user_counter += 1

            sk, pk = generate_keypair()

            # Register on tracker first
            requests.post(
                f"{self.tracker_url}/register",
                json={
                    "user_id": user_id,
                    "public_key": base64.b64encode(pk).decode()
                },
                timeout=5
            )

            # Register on blockchain
            response = requests.post(
                f"{self.tracker_url}/contract/register",
                json={
                    "user_id": user_id,
                    "password": "test_password"
                },
                timeout=30
            )
            return response.json()

        latencies_register = self.measure_latency(
            register_user_onchain, max(2, self.warmup // 5))
        result_register = self.calculate_stats(
            latencies_register, "On-chain user registration", self.baseline_latency_ms)
        self.results['onchain_register'] = result_register

        print(
            f"    Mean latency: {result_register.mean_ms:.3f} ms (overhead: +{result_register.overhead_vs_baseline_ms:.3f} ms)")

        # Benchmark 2: Reputation update on-chain
        print("  Testing on-chain reputation update...")

        # Create a test user first
        test_user = f"update_user_{time.time_ns()}"
        sk, pk = generate_keypair()

        requests.post(
            f"{self.tracker_url}/register",
            json={
                "user_id": test_user,
                "public_key": base64.b64encode(pk).decode()
            },
            timeout=5
        )

        requests.post(
            f"{self.tracker_url}/contract/register",
            json={
                "user_id": test_user,
                "password": "test_password"
            },
            timeout=30
        )

        update_counter = 0

        def update_user_onchain():
            nonlocal update_counter
            update_counter += 1

            response = requests.post(
                f"{self.tracker_url}/contract/update",
                json={
                    "user_id": test_user,
                    "uploaded": update_counter * 1000000,
                    "downloaded": update_counter * 500000
                },
                timeout=30
            )
            return response.json()

        latencies_update = self.measure_latency(
            update_user_onchain, max(2, self.warmup // 5))
        result_update = self.calculate_stats(
            latencies_update, "On-chain reputation update", self.baseline_latency_ms)
        self.results['onchain_update'] = result_update

        print(
            f"    Mean latency: {result_update.mean_ms:.3f} ms (overhead: +{result_update.overhead_vs_baseline_ms:.3f} ms)")

    def benchmark_combined_overhead(self):
        """Benchmark combined overhead (receipts + on-chain)"""
        print("\n[5/6] Benchmarking combined overhead (receipts + on-chain)...")

        # Enable receipt verification
        requests.post(
            f"{self.tracker_url}/config",
            json={"verify_signatures": True},
            timeout=5
        )

        # Setup user
        user_id = f"combined_user_{time.time_ns()}"
        receiver_sk, receiver_pk = generate_keypair()

        requests.post(
            f"{self.tracker_url}/register",
            json={
                "user_id": user_id,
                "public_key": base64.b64encode(receiver_pk).decode()
            },
            timeout=5
        )

        # Register on-chain
        try:
            requests.post(
                f"{self.tracker_url}/contract/register",
                json={
                    "user_id": user_id,
                    "password": "test_password"
                },
                timeout=30
            )
        except Exception as e:
            print(f"  ⚠ On-chain registration failed: {e}")

        sender_sk, sender_pk = generate_keypair()
        infohash = hashlib.sha1(b"combined_test").digest()

        def combined_operation():
            # Submit receipts
            receipts = []
            for i in range(10):
                piece_hash = hashlib.sha256(
                    f"combined_piece_{i}_{time.time_ns()}".encode()).digest()
                timestamp = int(time.time())
                signature = attest_piece_transfer(
                    receiver_private_key=receiver_sk,
                    sender_public_key=sender_pk,
                    piece_hash=piece_hash,
                    piece_index=i,
                    infohash=infohash,
                    timestamp=timestamp
                )
                receipts.append({
                    "receiver_public_key": base64.b64encode(receiver_pk).decode(),
                    "sender_pk": base64.b64encode(sender_pk).decode(),
                    "piece_hash": piece_hash.hex(),
                    "piece_index": i,
                    "infohash": infohash.hex(),
                    "timestamp": timestamp,
                    "signature": base64.b64encode(signature).decode()
                })

            # Submit to tracker (verifies receipts)
            requests.post(
                f"{self.tracker_url}/report",
                json={
                    "user_id": user_id,
                    "receipts": receipts
                },
                timeout=30
            )

            # Update on-chain
            try:
                requests.post(
                    f"{self.tracker_url}/contract/update",
                    json={
                        "user_id": user_id,
                        "uploaded": 10000000,
                        "downloaded": 5000000
                    },
                    timeout=30
                )
            except Exception:
                pass  # On-chain may not be available

        latencies_combined = self.measure_latency(
            combined_operation, max(2, self.warmup // 5))
        result_combined = self.calculate_stats(
            latencies_combined, "Combined (10 receipts + on-chain update)", self.baseline_latency_ms)
        self.results['combined'] = result_combined

        print(
            f"    Mean latency: {result_combined.mean_ms:.3f} ms (overhead: +{result_combined.overhead_vs_baseline_ms:.3f} ms)")

    def benchmark_parallel_load(self):
        """Benchmark parallel request handling"""
        print("\n[6/6] Benchmarking parallel load (10 concurrent clients)...")

        # Disable extensions for baseline comparison
        requests.post(
            f"{self.tracker_url}/config",
            json={"verify_signatures": False},
            timeout=5
        )

        infohash = hashlib.sha1(b"parallel_test").digest()

        def parallel_announces(num_clients: int):
            """Execute parallel announces"""
            def announce():
                peer_id = hashlib.sha1(
                    f"peer_{time.time_ns()}".encode()).digest()
                start = time.perf_counter()
                requests.get(
                    f"{self.tracker_url}/announce",
                    params={
                        'info_hash': infohash,
                        'peer_id': peer_id,
                        'port': 6881,
                        'uploaded': 0,
                        'downloaded': 0,
                        'left': 1000000
                    },
                    timeout=5
                )
                end = time.perf_counter()
                return (end - start) * 1000

            with ThreadPoolExecutor(max_workers=num_clients) as executor:
                futures = [executor.submit(announce)
                           for _ in range(num_clients)]
                latencies = [f.result() for f in futures]

            return latencies

        # Warmup
        for _ in range(2):
            parallel_announces(10)

        # Measure
        all_latencies = []
        for _ in range(max(10, self.iterations // 10)):
            latencies = parallel_announces(10)
            all_latencies.extend(latencies)

        result_parallel = self.calculate_stats(
            all_latencies, "Parallel load (10 clients)", self.baseline_latency_ms)
        self.results['parallel_baseline'] = result_parallel

        print(f"    Mean latency: {result_parallel.mean_ms:.3f} ms")

    def run_all(self):
        """Run all benchmarks"""
        print("\n" + "="*80)
        print(" TRACKER OVERHEAD BREAKDOWN BENCHMARK")
        print("="*80)
        print(f"\nConfiguration:")
        print(f"  - Tracker URL: {self.tracker_url}")
        print(f"  - Iterations: {self.iterations}")
        print(f"  - Warmup: {self.warmup}")
        print(f"  - Auto-start: {self.auto_start}")

        self.setup()

        # Fund TEE account if TEE mode is enabled and auto_start is True
        tee_mode_enabled = False
        try:
            response = requests.get(
                f"{self.tracker_url}/tee/status", timeout=5)
            tee_status = response.json()
            if tee_status.get('tee_mode') == "enabled":
                tee_mode_enabled = True
        except Exception:
            pass  # TEE might not be available or tracker not fully up yet

        if self.auto_start and tee_mode_enabled:
            self.fund_tee_account()

        # Try to initialize contract (optional for benchmarking)
        contract_initialized = self._initialize_contract()
        if not contract_initialized:
            print("\n⚠ Note: Smart contract features not available")
            print("  Some benchmarks (on-chain operations) will be skipped\n")

        self.benchmark_baseline()
        self.benchmark_tee_operations()
        self.benchmark_receipt_verification()
        self.benchmark_onchain_operations()
        self.benchmark_combined_overhead()
        self.benchmark_parallel_load()

        print("\n✓ All benchmarks completed")

    def print_results(self):
        """Print formatted results"""
        if not self.results:
            print("\nNo results to display.")
            return

        print("\n" + "="*80)
        print(" RESULTS SUMMARY")
        print("="*80)

        # Component breakdown
        print("\nCOMPONENT OVERHEAD BREAKDOWN:")
        print("-"*80)
        print(
            f"{'Component':<45} {'Mean (ms)':>12} {'Overhead (ms)':>15} {'Overhead (%)':>12}")
        print("-"*80)

        for key, result in self.results.items():
            print(f"{result.component_name:<45} {result.mean_ms:>12.3f} "
                  f"{result.overhead_vs_baseline_ms:>15.3f} {result.overhead_vs_baseline_percent:>12.1f}%")

        # Key insights
        print("\n" + "="*80)
        print(" KEY INSIGHTS")
        print("="*80)

        baseline = self.results.get('baseline')
        if baseline:
            print(f"\nBaseline latency: {baseline.mean_ms:.3f} ms")

        # Find highest overhead components
        overhead_results = [(k, v)
                            for k, v in self.results.items() if k != 'baseline']
        overhead_results.sort(
            key=lambda x: x[1].overhead_vs_baseline_ms, reverse=True)

        print(f"\nTop overhead contributors:")
        for i, (key, result) in enumerate(overhead_results[:5], 1):
            print(f"  {i}. {result.component_name}")
            print(
                f"     Overhead: +{result.overhead_vs_baseline_ms:.3f} ms ({result.overhead_vs_baseline_percent:.1f}%)")

        # Receipt verification efficiency (use largest available batch size)
        if 'receipt_single' in self.results:
            single = self.results['receipt_single']

            # Find largest batch result
            batch_keys = [k for k in self.results.keys() if k.startswith('receipt_batch_')]
            if batch_keys:
                # Extract batch sizes and find max
                batch_sizes = []
                for k in batch_keys:
                    try:
                        size = int(k.split('_')[-1])
                        batch_sizes.append(size)
                    except ValueError:
                        pass

                if batch_sizes:
                    max_batch_size = max(batch_sizes)
                    batch_key = f'receipt_batch_{max_batch_size}'
                    batch = self.results[batch_key]
                    per_receipt_batch = batch.mean_ms / max_batch_size
                    speedup = single.mean_ms / per_receipt_batch

                    print(f"\nReceipt verification efficiency:")
                    print(
                        f"  Individual verification: {single.mean_ms:.3f} ms/receipt")
                    print(
                        f"  Batch verification ({max_batch_size}): {per_receipt_batch:.3f} ms/receipt")
                    print(f"  Speedup with batching: {speedup:.2f}x")

        # On-chain overhead
        if 'onchain_register' in self.results and 'onchain_update' in self.results:
            register = self.results['onchain_register']
            update = self.results['onchain_update']

            print(f"\nOn-chain operations:")
            print(
                f"  Registration: {register.mean_ms:.3f} ms ({register.overhead_vs_baseline_percent:.1f}% overhead)")
            print(
                f"  Update: {update.mean_ms:.3f} ms ({update.overhead_vs_baseline_percent:.1f}% overhead)")

        print("\n" + "="*80)


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Tracker overhead breakdown benchmark")
    parser.add_argument('--tracker-url', type=str, default='http://localhost:8000',
                        help='Tracker URL (default: http://localhost:8000)')
    parser.add_argument('--iterations', type=int, default=10,
                        help='Measurement iterations (default: 10)')
    parser.add_argument('--warmup', type=int, default=10,
                        help='Warmup iterations (default: 10)')
    parser.add_argument('--no-auto-start', action='store_true',
                        help='Don\'t auto-start Anvil/tracker (use existing)')
    parser.add_argument('--output', type=str,
                        help='Save results to JSON file')

    args = parser.parse_args()

    # Run benchmark
    benchmark = TrackerOverheadBenchmark(
        tracker_url=args.tracker_url,
        iterations=args.iterations,
        warmup=args.warmup,
        auto_start=not args.no_auto_start
    )

    try:
        benchmark.run_all()
        benchmark.print_results()

        # Save to JSON if requested
        if args.output:
            output_data = {
                'config': {
                    'tracker_url': args.tracker_url,
                    'iterations': args.iterations,
                    'warmup': args.warmup
                },
                'baseline_latency_ms': benchmark.baseline_latency_ms,
                'results': {
                    key: {
                        'component_name': result.component_name,
                        'mean_ms': result.mean_ms,
                        'median_ms': result.median_ms,
                        'stdev_ms': result.stdev_ms,
                        'min_ms': result.min_ms,
                        'max_ms': result.max_ms,
                        'p95_ms': result.p95_ms,
                        'p99_ms': result.p99_ms,
                        'overhead_vs_baseline_ms': result.overhead_vs_baseline_ms,
                        'overhead_vs_baseline_percent': result.overhead_vs_baseline_percent
                    }
                    for key, result in benchmark.results.items()
                }
            }

            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)

            print(f"\n✓ Results saved to {args.output}")

    finally:
        if not args.no_auto_start:
            benchmark.cleanup()


if __name__ == '__main__':
    main()
