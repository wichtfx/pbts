#!/usr/bin/env python3
"""
PBTS End-to-End Test

Complete workflow test:
1. Deploy smart contracts (ReputationFactory + Reputation)
2. Start tracker with contract integration
3. Register users (Alice as seeder, Bob as leecher)
4. Create test torrent
5. Simulate piece transfers with receipt generation
6. Submit receipts to tracker
7. Verify contract state updates

This tests the complete PBTS system including:
- BLS signature generation
- Receipt creation and verification
- Tracker receipt batch verification
- Smart contract integration
"""

import subprocess
import time
import sys
import signal
import json
import base64
import hashlib
import argparse
from pathlib import Path
from typing import Optional, Dict, Tuple
import requests

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from tracker import generate_keypair, sign_message
from tests.e2e.pbts_client import PBTSClient
from tests.utils.torrent_generator import create_torrent, generate_test_data


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_header(text: str):
    """Print section header"""
    print(f"\n{Colors.HEADER}{'=' * 70}")
    print(f"  {text}")
    print(f"{'=' * 70}{Colors.ENDC}\n")


def print_success(text: str):
    """Print success message"""
    print(f"{Colors.OKGREEN}✅ {text}{Colors.ENDC}")


def print_error(text: str):
    """Print error message"""
    print(f"{Colors.FAIL}❌ {text}{Colors.ENDC}")


def print_info(text: str):
    """Print info message"""
    print(f"{Colors.OKCYAN}ℹ️  {text}{Colors.ENDC}")


def print_warning(text: str):
    """Print warning message"""
    print(f"{Colors.WARNING}⚠️  {text}{Colors.ENDC}")


class E2ETestOrchestrator:
    """Orchestrates the complete E2E test"""

    def __init__(
        self,
        skip_anvil: bool = False,
        skip_contracts: bool = False,
        tracker_url: str = "http://localhost:8000",
        anvil_port: int = 8545,
        tracker_port: int = 8000
    ):
        """
        Initialize E2E test orchestrator

        Args:
            skip_anvil: Skip starting Anvil (assume already running)
            skip_contracts: Skip contract deployment (assume already deployed)
            tracker_url: Tracker HTTP endpoint
            anvil_port: Anvil RPC port
            tracker_port: Tracker HTTP port
        """
        self.skip_anvil = skip_anvil
        self.skip_contracts = skip_contracts
        self.tracker_url = tracker_url
        self.anvil_port = anvil_port
        self.tracker_port = tracker_port

        # Process management
        self.anvil_process: Optional[subprocess.Popen] = None
        self.tracker_process: Optional[subprocess.Popen] = None

        # Test data
        self.temp_dir = Path("/tmp/pbts_e2e_test")
        self.temp_dir.mkdir(exist_ok=True)

        # User keys
        self.alice_sk: Optional[bytes] = None
        self.alice_pk: Optional[bytes] = None
        self.bob_sk: Optional[bytes] = None
        self.bob_pk: Optional[bytes] = None

        # Test artifacts
        self.data_file: Optional[Path] = None
        self.torrent_file: Optional[Path] = None
        self.infohash: Optional[str] = None

        # Clients
        self.alice_client: Optional[PBTSClient] = None
        self.bob_client: Optional[PBTSClient] = None

    def cleanup(self):
        """Clean up all resources"""
        print_header("Cleaning Up")

        # Stop processes
        if self.tracker_process:
            print_info("Stopping tracker...")
            self.tracker_process.terminate()
            try:
                self.tracker_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.tracker_process.kill()

        if self.anvil_process:
            print_info("Stopping Anvil...")
            self.anvil_process.terminate()
            try:
                self.anvil_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.anvil_process.kill()

        print_success("Cleanup complete")

    def start_anvil(self):
        """Start Anvil local blockchain"""
        if self.skip_anvil:
            print_info("Skipping Anvil start (assume already running)")
            return

        print_header("Starting Anvil")

        try:
            # Check if already running
            response = requests.post(
                f"http://127.0.0.1:{self.anvil_port}",
                json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
                timeout=1
            )
            if response.status_code == 200:
                print_warning("Anvil already running, using existing instance")
                return
        except:
            pass

        # Start Anvil
        self.anvil_process = subprocess.Popen(
            ["anvil", "--port", str(self.anvil_port), "--silent"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Wait for Anvil to be ready
        print_info("Waiting for Anvil to start...")
        for i in range(10):
            time.sleep(1)
            try:
                response = requests.post(
                    f"http://127.0.0.1:{self.anvil_port}",
                    json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
                    timeout=1
                )
                if response.status_code == 200:
                    print_success(f"Anvil started on port {self.anvil_port}")
                    return
            except:
                continue

        raise Exception("Failed to start Anvil")

    def deploy_contracts(self):
        """Deploy smart contracts"""
        if self.skip_contracts:
            print_info("Skipping contract deployment")
            return

        print_header("Deploying Smart Contracts")

        # Check if contracts already deployed
        try:
            response = requests.get(f"{self.tracker_url}/contract/status", timeout=2)
            if response.status_code == 200:
                status = response.json()
                if status.get('factory_address') and status.get('reputation_address'):
                    print_warning("Contracts already deployed, using existing")
                    return
        except:
            pass

        # Deploy factory
        print_info("Deploying ReputationFactory...")
        project_root = Path(__file__).parent.parent.parent
        result = subprocess.run(
            ["./deploy_factory.sh"],
            capture_output=True,
            text=True,
            cwd=project_root
        )

        if result.returncode != 0:
            print_error(f"Factory deployment failed: {result.stderr}")
            raise Exception("Contract deployment failed")

        print_success("ReputationFactory deployed")

    def init_reputation_contract(self):
        """Initialize Reputation contract via tracker"""
        if self.skip_contracts:
            return

        print_header("Initializing Reputation Contract")

        # Initialize Reputation contract
        print_info("Initializing Reputation contract...")
        response = requests.post(f"{self.tracker_url}/contract/init", timeout=30)

        if response.status_code != 200:
            print_error(f"Contract init failed: {response.text}")
            raise Exception("Contract initialization failed")

        result = response.json()
        if not result.get('success'):
            print_error(f"Contract init failed: {result.get('error')}")
            raise Exception("Contract initialization failed")

        reputation_addr = result['reputation_address']
        print_success(f"Reputation contract: {reputation_addr}")

    def start_tracker(self):
        """Start PBTS tracker"""
        print_header("Starting PBTS Tracker")

        # Kill any existing tracker processes to ensure clean state
        subprocess.run(["pkill", "-f", "tracker.py"], capture_output=True)
        time.sleep(1)

        # Start tracker (use uv run to ensure dependencies are available)
        self.tracker_process = subprocess.Popen(
            ["uv", "run", "python", "tracker.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=Path(__file__).parent.parent.parent  # Project root
        )

        # Wait for tracker to be ready
        print_info("Waiting for tracker to start...")
        for i in range(15):
            time.sleep(1)
            try:
                response = requests.get(f"{self.tracker_url}/health", timeout=1)
                if response.status_code == 200:
                    print_success(f"Tracker started on port {self.tracker_port}")
                    return
            except:
                continue

        raise Exception("Failed to start tracker")

    def generate_user_keys(self):
        """Generate keypairs for Alice and Bob"""
        print_header("Generating User Keypairs")

        # Alice (seeder)
        self.alice_sk, self.alice_pk = generate_keypair()
        print_success(f"Alice public key: {base64.b64encode(self.alice_pk).decode()[:32]}...")

        # Save keys
        alice_keys_file = self.temp_dir / "alice_keys.json"
        with open(alice_keys_file, 'w') as f:
            json.dump({
                'private_key': base64.b64encode(self.alice_sk).decode(),
                'public_key': base64.b64encode(self.alice_pk).decode()
            }, f)

        # Bob (leecher)
        self.bob_sk, self.bob_pk = generate_keypair()
        print_success(f"Bob public key: {base64.b64encode(self.bob_pk).decode()[:32]}...")

        # Save keys
        bob_keys_file = self.temp_dir / "bob_keys.json"
        with open(bob_keys_file, 'w') as f:
            json.dump({
                'private_key': base64.b64encode(self.bob_sk).decode(),
                'public_key': base64.b64encode(self.bob_pk).decode()
            }, f)

    def register_users(self):
        """Register Alice and Bob with tracker and smart contract"""
        print_header("Registering Users")

        # Register Alice with tracker
        print_info("Registering Alice with tracker...")
        response = requests.post(
            f"{self.tracker_url}/register",
            json={
                "user_id": "alice",
                "public_key": base64.b64encode(self.alice_pk).decode()
            }
        )
        if response.status_code != 200:
            raise Exception(f"Failed to register Alice: {response.text}")
        print_success("Alice registered with tracker")

        # Register Alice with smart contract
        print_info("Registering Alice with smart contract...")
        response = requests.post(
            f"{self.tracker_url}/contract/register",
            json={
                "username": "alice",
                "salt": "salt_alice_e2e",
                "password_hash": "0x" + hashlib.sha256(b"alice_password").hexdigest(),
                "download_size": 0,
                "upload_size": 0
            }
        )
        if response.status_code != 200:
            raise Exception(f"Failed to register Alice on contract: {response.text}")
        print_success("Alice registered on smart contract")

        # Register Bob
        print_info("Registering Bob with tracker...")
        response = requests.post(
            f"{self.tracker_url}/register",
            json={
                "user_id": "bob",
                "public_key": base64.b64encode(self.bob_pk).decode()
            }
        )
        if response.status_code != 200:
            raise Exception(f"Failed to register Bob: {response.text}")
        print_success("Bob registered with tracker")

        print_info("Registering Bob with smart contract...")
        response = requests.post(
            f"{self.tracker_url}/contract/register",
            json={
                "username": "bob",
                "salt": "salt_bob_e2e",
                "password_hash": "0x" + hashlib.sha256(b"bob_password").hexdigest(),
                "download_size": 0,
                "upload_size": 0
            }
        )
        if response.status_code != 200:
            raise Exception(f"Failed to register Bob on contract: {response.text}")
        print_success("Bob registered on smart contract")

    def create_test_torrent(self, file_size: int = 102400):
        """Create test torrent file"""
        print_header("Creating Test Torrent")

        # Generate test data
        self.data_file = self.temp_dir / "test_data.dat"
        generate_test_data(file_size, self.data_file)
        print_success(f"Test data: {self.data_file} ({file_size} bytes)")

        # Create torrent
        self.torrent_file = self.temp_dir / "test.torrent"
        self.infohash = create_torrent(
            data_file=self.data_file,
            tracker_url=f"{self.tracker_url}/announce",
            output_path=self.torrent_file,
            piece_length=16384
        )
        print_success(f"Torrent: {self.torrent_file}")
        print_success(f"Info hash: {self.infohash}")

    def initialize_clients(self):
        """Initialize Alice and Bob clients"""
        print_header("Initializing Clients")

        # Alice (seeder)
        self.alice_client = PBTSClient(
            user_id="alice",
            private_key=self.alice_sk,
            public_key=self.alice_pk,
            tracker_url=self.tracker_url,
            mode="seeder",
            data_file=self.data_file
        )
        self.alice_client.load_torrent(self.torrent_file)
        self.alice_client.announce_to_tracker(event="started")
        print_success("Alice client initialized (seeder)")

        # Bob (leecher)
        self.bob_client = PBTSClient(
            user_id="bob",
            private_key=self.bob_sk,
            public_key=self.bob_pk,
            tracker_url=self.tracker_url,
            mode="leecher"
        )
        self.bob_client.load_torrent(self.torrent_file)
        self.bob_client.announce_to_tracker(event="started")
        print_success("Bob client initialized (leecher)")

    def simulate_piece_transfers(self, num_pieces: int = 5):
        """Simulate piece transfers between Alice and Bob"""
        print_header(f"Simulating {num_pieces} Piece Transfers")

        for piece_index in range(num_pieces):
            print(f"\n  📦 Transferring piece {piece_index}...")

            # Alice uploads to Bob
            piece_data, piece_hash = self.alice_client.simulate_upload_to_peer(
                peer_user_id="bob",
                peer_public_key=self.bob_pk,
                piece_index=piece_index,
                simulate_delay=0.1
            )

            # Bob downloads and creates receipt
            receipt = self.bob_client.simulate_download_from_peer(
                peer_user_id="alice",
                peer_public_key=self.alice_pk,
                piece_index=piece_index,
                simulate_delay=0.1
            )

            # Bob sends receipt to Alice (in real P2P via BEP 10)
            # Here we simulate it by directly calling Alice's handler
            self.alice_client.receive_receipt_from_peer(receipt)

            print_success(f"  Piece {piece_index} transferred with receipt")

        print_success(f"\nAll {num_pieces} pieces transferred")

    def submit_receipts(self):
        """Submit accumulated receipts to tracker"""
        print_header("Submitting Receipts to Tracker")

        # Alice submits receipts for pieces she uploaded
        submitted = self.alice_client.submit_receipts_to_tracker(update_contract=True)
        print_success(f"Alice submitted {submitted} receipts")

        # Bob also needs to update his download stats on the contract
        print_info("Bob updating contract with download stats...")
        self.bob_client._update_smart_contract()
        print_success("Bob updated contract with download stats")

    def verify_contract_state(self):
        """Verify smart contract state"""
        print_header("Verifying Smart Contract State")

        # Query Alice's stats
        response = requests.get(f"{self.tracker_url}/contract/user/alice")
        if response.status_code != 200:
            raise Exception(f"Failed to query Alice: {response.text}")

        alice_stats = response.json()['user']
        print(f"  Alice:")
        print(f"    Upload: {alice_stats['uploadSize']} bytes")
        print(f"    Download: {alice_stats['downloadSize']} bytes")
        print(f"    Ratio: {alice_stats['ratio']:.2f}")

        # Query Bob's stats
        response = requests.get(f"{self.tracker_url}/contract/user/bob")
        if response.status_code != 200:
            raise Exception(f"Failed to query Bob: {response.text}")

        bob_stats = response.json()['user']
        print(f"  Bob:")
        print(f"    Upload: {bob_stats['uploadSize']} bytes")
        print(f"    Download: {bob_stats['downloadSize']} bytes")
        print(f"    Ratio: {bob_stats['ratio']:.2f}")

        # Verify Alice has upload
        if alice_stats['uploadSize'] == 0:
            raise Exception("❌ Alice should have upload data!")

        # Verify Bob has download
        if bob_stats['downloadSize'] == 0:
            raise Exception("❌ Bob should have download data!")

        print_success("Contract state verified correctly!")

    def run(self):
        """Run complete E2E test"""
        try:
            print(f"\n{Colors.BOLD}PBTS End-to-End Test{Colors.ENDC}")
            print(f"Tracker: {self.tracker_url}")
            print(f"Temp dir: {self.temp_dir}")

            # Setup phase
            self.start_anvil()
            self.deploy_contracts()  # Deploy factory (writes FACTORY to .env)
            self.start_tracker()  # Start tracker so it loads FACTORY from .env
            self.init_reputation_contract()  # Initialize Reputation contract via tracker

            # User setup
            self.generate_user_keys()
            self.register_users()

            # Torrent creation
            self.create_test_torrent(file_size=102400)  # 100KB

            # Client initialization
            self.initialize_clients()

            # Simulate transfers
            self.simulate_piece_transfers(num_pieces=5)

            # Submit receipts
            self.submit_receipts()

            # Verify results
            self.verify_contract_state()

            # Final stats
            print_header("Final Client Statistics")
            self.alice_client.print_stats()
            self.bob_client.print_stats()

            print(f"\n{Colors.OKGREEN}{Colors.BOLD}{'=' * 70}")
            print(f"  ✅ E2E TEST PASSED!")
            print(f"{'=' * 70}{Colors.ENDC}\n")

            return True

        except Exception as e:
            print_error(f"E2E Test Failed: {e}")
            import traceback
            traceback.print_exc()
            return False

        finally:
            if not args.no_cleanup:
                self.cleanup()


def main():
    global args
    parser = argparse.ArgumentParser(
        description='PBTS End-to-End Test',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--skip-anvil',
        action='store_true',
        help='Skip starting Anvil (assume already running)'
    )
    parser.add_argument(
        '--skip-contracts',
        action='store_true',
        help='Skip contract deployment (assume already deployed)'
    )
    parser.add_argument(
        '--tracker-url',
        default='http://localhost:8000',
        help='Tracker URL (default: http://localhost:8000)'
    )
    parser.add_argument(
        '--no-cleanup',
        action='store_true',
        help='Do not clean up processes after test'
    )

    args = parser.parse_args()

    # Create orchestrator
    orchestrator = E2ETestOrchestrator(
        skip_anvil=args.skip_anvil,
        skip_contracts=args.skip_contracts,
        tracker_url=args.tracker_url
    )

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print("\n\nInterrupted! Cleaning up...")
        orchestrator.cleanup()
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)

    # Run test
    success = orchestrator.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
