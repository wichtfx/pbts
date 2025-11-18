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
import os
import signal
import json
import base64
import hashlib
import argparse
from pathlib import Path
from typing import Optional, Dict, Tuple
import requests
from web3 import Web3

# Add project root to path BEFORE importing local modules
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Now import local modules
from tracker import generate_keypair
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
        tracker_port: int = 8000,
        tee_mode: str = "disabled"
    ):
        """
        Initialize E2E test orchestrator

        Args:
            skip_anvil: Skip starting Anvil (assume already running)
            skip_contracts: Skip contract deployment (assume already deployed)
            tracker_url: Tracker HTTP endpoint
            anvil_port: Anvil RPC port
            tracker_port: Tracker HTTP port
            tee_mode: TEE mode (disabled/enabled/benchmark)
        """
        self.skip_anvil = skip_anvil
        self.skip_contracts = skip_contracts
        self.tracker_url = tracker_url
        self.anvil_port = anvil_port
        self.tracker_port = tracker_port
        self.tee_mode = tee_mode

        # Process management
        self.anvil_process: Optional[subprocess.Popen] = None
        self.tracker_process: Optional[subprocess.Popen] = None
        self.tracker_log_file: Optional[Path] = None

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

    def print_tracker_log(self, num_lines: int = 50):
        """Print last N lines of tracker log"""
        if self.tracker_log_file and self.tracker_log_file.exists():
            print_error(f"Last {num_lines} lines of tracker log:")
            try:
                with open(self.tracker_log_file, 'r') as f:
                    lines = f.readlines()
                    print(''.join(lines[-num_lines:]))
            except Exception as e:
                print_warning(f"Could not read log file: {e}")
        else:
            print_warning("Tracker log file not available")

    def cleanup(self):
        """Clean up all resources"""
        print_header("Cleaning Up")

        # Stop processes
        if self.tracker_process:
            print_info("Stopping tracker...")

            # Check if process already terminated
            if self.tracker_process.poll() is not None:
                print_warning(
                    f"Tracker already terminated with code {self.tracker_process.returncode}")
                self.print_tracker_log()

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
                json={"jsonrpc": "2.0", "method": "eth_blockNumber",
                      "params": [], "id": 1},
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
                    json={"jsonrpc": "2.0", "method": "eth_blockNumber",
                          "params": [], "id": 1},
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
            response = requests.get(
                f"{self.tracker_url}/contract/status", timeout=2)
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

        # Check if tracker is still running
        if self.tracker_process and self.tracker_process.poll() is not None:
            print_error(
                f"Tracker terminated unexpectedly with code {self.tracker_process.returncode}")
            self.print_tracker_log()
            raise Exception("Tracker process terminated before contract init")

        # Initialize Reputation contract
        print_info("Initializing Reputation contract...")
        try:
            response = requests.post(
                f"{self.tracker_url}/contract/init", timeout=30)
        except requests.exceptions.RequestException as e:
            print_error(f"Request failed: {e}")
            # Check if tracker crashed
            if self.tracker_process and self.tracker_process.poll() is not None:
                print_error(
                    f"Tracker terminated during request with code {self.tracker_process.returncode}")
                self.print_tracker_log()
            raise

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

        # Prepare environment variables for tracker
        env = os.environ.copy()
        env['TEE_MODE'] = self.tee_mode

        print_info(f"Setting TEE_MODE environment variable to: {self.tee_mode}")
        if self.tee_mode != 'disabled':
            print_info(f"Starting tracker with TEE mode: {self.tee_mode}")

        # Start tracker with logs written to file
        tracker_log_file = self.temp_dir / "tracker.log"
        self.tracker_log_file = tracker_log_file
        tracker_log_handle = open(tracker_log_file, 'w')

        print_info(f"Tracker logs: {tracker_log_file}")

        self.tracker_process = subprocess.Popen(
            ["python", "tracker.py"],
            stdout=tracker_log_handle,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout
            cwd=Path(__file__).parent.parent.parent,  # Project root
            env=env
        )

        # Wait for tracker to be ready
        print_info("Waiting for tracker to start...")
        for i in range(15):
            time.sleep(1)
            try:
                response = requests.get(
                    f"{self.tracker_url}/health", timeout=1)
                if response.status_code == 200:
                    print_success(
                        f"Tracker started on port {self.tracker_port}")
                    return
            except:
                continue

        raise Exception("Failed to start tracker")

    def fund_tee_account(self):
        """Fund TEE-derived account with ETH from Anvil's pre-funded account"""
        if self.tee_mode == 'disabled':
            return  # No need to fund in non-TEE mode

        print_header("Funding TEE-Derived Account")

        # Get tracker's account address
        response = requests.get(
            f"{self.tracker_url}/contract/status", timeout=2)
        if response.status_code != 200:
            raise Exception(f"Failed to get contract status: {response.text}")

        status = response.json()
        tracker_address = status.get('account_address')

        if not tracker_address:
            raise Exception("Tracker account address not found")

        print_info(f"TEE-derived account: {tracker_address}")

        # Connect to Anvil
        w3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{self.anvil_port}"))
        if not w3.is_connected():
            raise Exception("Failed to connect to Anvil")

        # Anvil's pre-funded account (first default account)
        anvil_account = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        anvil_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

        # Check current balance
        balance_before = w3.eth.get_balance(tracker_address)
        print_info(
            f"Current balance: {w3.from_wei(balance_before, 'ether')} ETH")

        # Transfer 10 ETH to tracker account
        amount_wei = w3.to_wei(10, 'ether')

        print_info(f"Transferring 10 ETH from Anvil account to TEE account...")

        tx = {
            'from': anvil_account,
            'to': tracker_address,
            'value': amount_wei,
            'gas': 21000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(anvil_account),
            'chainId': w3.eth.chain_id
        }

        signed_tx = w3.eth.account.sign_transaction(tx, anvil_private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        if receipt['status'] != 1:
            raise Exception("Failed to fund TEE account")

        balance_after = w3.eth.get_balance(tracker_address)
        print_success(
            f"Funded! New balance: {w3.from_wei(balance_after, 'ether')} ETH")

    def generate_user_keys(self):
        """Generate keypairs for Alice and Bob"""
        print_header("Generating User Keypairs")

        # Alice (seeder)
        self.alice_sk, self.alice_pk = generate_keypair()
        print_success(
            f"Alice public key: {base64.b64encode(self.alice_pk).decode()[:32]}...")

        # Save keys
        alice_keys_file = self.temp_dir / "alice_keys.json"
        with open(alice_keys_file, 'w') as f:
            json.dump({
                'private_key': base64.b64encode(self.alice_sk).decode(),
                'public_key': base64.b64encode(self.alice_pk).decode()
            }, f)

        # Bob (leecher)
        self.bob_sk, self.bob_pk = generate_keypair()
        print_success(
            f"Bob public key: {base64.b64encode(self.bob_pk).decode()[:32]}...")

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
            raise Exception(
                f"Failed to register Alice on contract: {response.text}")
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
            raise Exception(
                f"Failed to register Bob on contract: {response.text}")
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
        submitted = self.alice_client.submit_receipts_to_tracker(
            update_contract=True)
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

    def check_final_reputation(self):
        """Check and display final reputation from both tracker and contract"""
        print_header("Final Reputation Summary")

        # Get tracker stats
        print_info("Querying tracker in-memory state...")
        try:
            response = requests.get(f"{self.tracker_url}/stats", timeout=5)
            if response.status_code == 200:
                tracker_stats = response.json()
                print(f"\n{Colors.BOLD}Tracker Statistics:{Colors.ENDC}")
                print(
                    f"  Instance ID: {tracker_stats.get('instance_id', 'N/A')}")
                print(f"  Total users: {tracker_stats.get('total_users', 0)}")
                print(
                    f"  Total torrents: {tracker_stats.get('total_torrents', 0)}")
                print(f"  Total peers: {tracker_stats.get('total_peers', 0)}")
                print(f"  Min ratio: {tracker_stats.get('min_ratio', 0.0)}")
        except Exception as e:
            print_warning(f"Could not fetch tracker stats: {e}")

        # Get contract state for both users
        print(f"\n{Colors.BOLD}Smart Contract Reputation:{Colors.ENDC}")

        # Alice's final reputation
        try:
            response = requests.get(
                f"{self.tracker_url}/contract/user/alice", timeout=5)
            if response.status_code == 200:
                alice_stats = response.json()['user']
                print(f"\n  {Colors.OKGREEN}Alice (Seeder):{Colors.ENDC}")
                print(f"    Username: {alice_stats['username']}")
                print(f"    Upload: {alice_stats['uploadSize']:,} bytes")
                print(f"    Download: {alice_stats['downloadSize']:,} bytes")
                print(f"    Ratio: {alice_stats['ratio']:.4f}")

                # Calculate human-readable sizes
                upload_kb = alice_stats['uploadSize'] / 1024
                download_kb = alice_stats['downloadSize'] / 1024
                print(f"    Upload (KB): {upload_kb:.2f} KB")
                print(f"    Download (KB): {download_kb:.2f} KB")
            else:
                print_warning(
                    f"Could not fetch Alice's stats: {response.text}")
        except Exception as e:
            print_warning(f"Could not fetch Alice's stats: {e}")

        # Bob's final reputation
        try:
            response = requests.get(
                f"{self.tracker_url}/contract/user/bob", timeout=5)
            if response.status_code == 200:
                bob_stats = response.json()['user']
                print(f"\n  {Colors.OKCYAN}Bob (Leecher):{Colors.ENDC}")
                print(f"    Username: {bob_stats['username']}")
                print(f"    Upload: {bob_stats['uploadSize']:,} bytes")
                print(f"    Download: {bob_stats['downloadSize']:,} bytes")
                print(f"    Ratio: {bob_stats['ratio']:.4f}")

                # Calculate human-readable sizes
                upload_kb = bob_stats['uploadSize'] / 1024
                download_kb = bob_stats['downloadSize'] / 1024
                print(f"    Upload (KB): {upload_kb:.2f} KB")
                print(f"    Download (KB): {download_kb:.2f} KB")
            else:
                print_warning(f"Could not fetch Bob's stats: {response.text}")
        except Exception as e:
            print_warning(f"Could not fetch Bob's stats: {e}")

        # Summary
        print(f"\n{Colors.BOLD}Summary:{Colors.ENDC}")
        print(f"  ✅ Reputation successfully tracked on-chain")

    def run(self):
        """Run complete E2E test"""
        try:
            print(f"\n{Colors.BOLD}PBTS End-to-End Test{Colors.ENDC}")
            print(f"Tracker: {self.tracker_url}")
            print(f"TEE Mode: {self.tee_mode}")
            print(f"Temp dir: {self.temp_dir}")

            # Setup phase
            self.start_anvil()
            self.deploy_contracts()  # Deploy factory (writes FACTORY to .env)
            self.start_tracker()  # Start tracker so it loads FACTORY from .env
            self.fund_tee_account()  # Fund TEE-derived account if in TEE mode
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

            # Check final reputation (comprehensive summary)
            self.check_final_reputation()

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
    parser.add_argument(
        '--tee-mode',
        default='disabled',
        choices=['disabled', 'enabled', 'benchmark'],
        help='TEE mode (default: disabled)'
    )

    args = parser.parse_args()

    # Create orchestrator
    orchestrator = E2ETestOrchestrator(
        skip_anvil=args.skip_anvil,
        skip_contracts=args.skip_contracts,
        tracker_url=args.tracker_url,
        tee_mode=args.tee_mode
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
