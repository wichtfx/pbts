#!/usr/bin/env python3
"""
Smart Contract Gas Cost Benchmark

Measures gas consumption for all on-chain operations:
- createReputation (factory)
- addUser
- updateUser
- migrateUserData

Also computes annual cost projections at different reporting frequencies.

Requires:
- Foundry (forge, anvil) installed
- Smart contract project at ../smartcontract/
"""

import sys
import os
import time
import hashlib
import json
import subprocess
import re
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False


def check_command(cmd: str) -> bool:
    """Check if a command is available."""
    try:
        subprocess.run([cmd, "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def start_anvil() -> subprocess.Popen:
    """Start a local Anvil instance and return the process."""
    proc = subprocess.Popen(
        ["anvil", "--silent"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)  # Wait for Anvil to start
    return proc


def deploy_with_forge(
    contract_path: str,
    rpc_url: str,
    private_key: str,
    project_root: str,
    constructor_args: List[str] = None,
) -> Optional[str]:
    """Deploy a contract using forge create, return deployed address."""
    cmd = [
        "forge", "create", contract_path,
        "--rpc-url", rpc_url,
        "--private-key", private_key,
        "--root", project_root,
    ]
    if constructor_args:
        cmd.extend(["--constructor-args"] + constructor_args)

    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout + result.stderr

    if result.returncode != 0:
        print(f"  forge create failed: {output}")
        return None

    # Parse "Deployed to: 0x..."
    for line in output.splitlines():
        if "Deployed to:" in line:
            match = re.search(r'0x[0-9a-fA-F]{40}', line)
            if match:
                return match.group(0)

    print(f"  Could not parse address from: {output}")
    return None


@dataclass
class GasResult:
    operation: str
    gas_used: int
    latency_ms: float


@dataclass
class AnnualCostProjection:
    frequency: str
    users: int
    updates_per_year: int
    total_gas: int
    estimated_eth: float
    estimated_usd: float


@dataclass
class GasBenchmarkResults:
    create_reputation: GasResult
    add_user: GasResult
    update_user: GasResult
    migrate_user: GasResult
    batch_add_users: List[GasResult]
    batch_update_users: List[GasResult]
    annual_cost_projections: List[AnnualCostProjection]


# ABIs for contract interaction
FACTORY_ABI = [
    {
        "inputs": [
            {"name": "_referrerReputation", "type": "address"},
            {"name": "_attestation", "type": "bytes"},
        ],
        "name": "createReputation",
        "outputs": [{"name": "", "type": "address"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": False, "name": "newReputationAddress", "type": "address"},
            {"indexed": False, "name": "owner", "type": "address"},
            {"indexed": False, "name": "referrer", "type": "address"},
            {"indexed": False, "name": "attestation", "type": "bytes"},
        ],
        "name": "ReputationCreated",
        "type": "event",
    },
]

REPUTATION_ABI = [
    {
        "inputs": [
            {"name": "_username", "type": "string"},
            {"name": "_salt", "type": "string"},
            {"name": "_passwordHash", "type": "bytes32"},
            {"name": "_downloadSize", "type": "uint256"},
            {"name": "_uploadSize", "type": "uint256"},
        ],
        "name": "addUser",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "_username", "type": "string"},
            {"name": "_downloadSize", "type": "uint256"},
            {"name": "_uploadSize", "type": "uint256"},
        ],
        "name": "updateUser",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "_username", "type": "string"}],
        "name": "migrateUserData",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "_username", "type": "string"}],
        "name": "getUserData",
        "outputs": [
            {
                "components": [
                    {"name": "username", "type": "string"},
                    {"name": "salt", "type": "string"},
                    {"name": "passwordHash", "type": "bytes32"},
                    {"name": "downloadSize", "type": "uint256"},
                    {"name": "uploadSize", "type": "uint256"},
                ],
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
]


class GasBenchmark:
    """Benchmark for smart contract gas costs."""

    def __init__(
        self,
        num_users: int = 100,
        contract_project: str = None,
    ):
        self.num_users = num_users
        self.contract_project = contract_project or str(
            project_root / "smartcontract"
        )
        self.results = None

    def run_all(self) -> Dict:
        """Run all gas benchmarks. Returns results dict."""
        print("\n=== Smart Contract Gas Cost Benchmarks ===\n")

        if not WEB3_AVAILABLE:
            print("ERROR: web3 package not installed. Run: pip install web3")
            return {}

        if not check_command("anvil"):
            print("ERROR: Anvil not found. Install Foundry:")
            print("  curl -L https://foundry.paradigm.xyz | bash && foundryup")
            return {}

        if not check_command("forge"):
            print("ERROR: forge not found. Install Foundry.")
            return {}

        # Start Anvil
        print("Starting Anvil...")
        anvil_proc = start_anvil()
        rpc_url = "http://127.0.0.1:8545"
        # Anvil default account 0
        private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

        try:
            w3 = Web3(Web3.HTTPProvider(rpc_url))
            account = w3.eth.account.from_key(private_key)
            w3.eth.default_account = account.address

            # Deploy factory
            print("Deploying ReputationFactory via forge...")
            factory_addr = deploy_with_forge(
                "src/factory.sol:ReputationFactory",
                rpc_url, private_key, self.contract_project,
            )
            if not factory_addr:
                print("Failed to deploy factory")
                return {}
            print(f"  Factory deployed at: {factory_addr}")
            factory = w3.eth.contract(
                address=Web3.to_checksum_address(factory_addr),
                abi=FACTORY_ABI,
            )

            # Create Reputation contract
            print("Creating Reputation contract...")
            start = time.perf_counter()
            tx = factory.functions.createReputation(
                "0x0000000000000000000000000000000000000000", b""
            ).transact({"from": account.address})
            receipt = w3.eth.wait_for_transaction_receipt(tx)
            create_time = (time.perf_counter() - start) * 1000
            create_gas = receipt.gasUsed

            # Extract new contract address from event
            logs = factory.events.ReputationCreated().process_receipt(receipt)
            rep_addr = logs[0]['args']['newReputationAddress']
            print(f"  Reputation at: {rep_addr}, gas: {create_gas}")

            rep = w3.eth.contract(
                address=Web3.to_checksum_address(rep_addr),
                abi=REPUTATION_ABI,
            )

            create_reputation = GasResult("createReputation", create_gas, create_time)

            # Add user
            print("Adding user...")
            pw_hash = hashlib.sha256(b"password").digest()
            start = time.perf_counter()
            tx = rep.functions.addUser(
                "user0", "salt0", pw_hash, 0, 1024
            ).transact({"from": account.address})
            receipt = w3.eth.wait_for_transaction_receipt(tx)
            add_time = (time.perf_counter() - start) * 1000
            add_gas = receipt.gasUsed
            print(f"  addUser gas: {add_gas}")
            add_user = GasResult("addUser", add_gas, add_time)

            # Update user
            print("Updating user...")
            start = time.perf_counter()
            tx = rep.functions.updateUser(
                "user0", 1024, 2048
            ).transact({"from": account.address})
            receipt = w3.eth.wait_for_transaction_receipt(tx)
            update_time = (time.perf_counter() - start) * 1000
            update_gas = receipt.gasUsed
            print(f"  updateUser gas: {update_gas}")
            update_user = GasResult("updateUser", update_gas, update_time)

            # Migrate user
            print("Testing migration...")
            tx2 = factory.functions.createReputation(
                Web3.to_checksum_address(rep_addr), b""
            ).transact({"from": account.address})
            receipt2 = w3.eth.wait_for_transaction_receipt(tx2)
            logs2 = factory.events.ReputationCreated().process_receipt(receipt2)
            rep2_addr = logs2[0]['args']['newReputationAddress']
            rep2 = w3.eth.contract(
                address=Web3.to_checksum_address(rep2_addr),
                abi=REPUTATION_ABI,
            )

            start = time.perf_counter()
            tx = rep2.functions.migrateUserData("user0").transact(
                {"from": account.address}
            )
            receipt = w3.eth.wait_for_transaction_receipt(tx)
            migrate_time = (time.perf_counter() - start) * 1000
            migrate_gas = receipt.gasUsed
            print(f"  migrateUserData gas: {migrate_gas}")
            migrate_user = GasResult("migrateUserData", migrate_gas, migrate_time)

            # Batch operations
            print(f"\nBatch operations ({self.num_users} users)...")
            batch_add = []
            batch_update = []

            for i in range(1, self.num_users + 1):
                username = f"batchuser{i}"
                ph = hashlib.sha256(username.encode()).digest()

                start = time.perf_counter()
                tx = rep.functions.addUser(
                    username, f"salt{i}", ph, 0, 1024 * i
                ).transact({"from": account.address})
                r = w3.eth.wait_for_transaction_receipt(tx)
                t = (time.perf_counter() - start) * 1000
                batch_add.append(GasResult(f"addUser[{i}]", r.gasUsed, t))

                start = time.perf_counter()
                tx = rep.functions.updateUser(
                    username, 512 * i, 2048 * i
                ).transact({"from": account.address})
                r = w3.eth.wait_for_transaction_receipt(tx)
                t = (time.perf_counter() - start) * 1000
                batch_update.append(GasResult(f"updateUser[{i}]", r.gasUsed, t))

                if i % 20 == 0:
                    print(f"  Processed {i}/{self.num_users} users...")

            avg_add_gas = sum(g.gas_used for g in batch_add) // len(batch_add)
            avg_update_gas = sum(g.gas_used for g in batch_update) // len(batch_update)
            avg_add_ms = sum(g.latency_ms for g in batch_add) / len(batch_add)
            avg_update_ms = sum(g.latency_ms for g in batch_update) / len(batch_update)

            print(f"\n  Avg addUser:    gas={avg_add_gas}, latency={avg_add_ms:.2f} ms")
            print(f"  Avg updateUser: gas={avg_update_gas}, latency={avg_update_ms:.2f} ms")

            # Annual cost projections (30 gwei, $3000/ETH)
            gas_price_gwei = 30.0
            eth_price_usd = 3000.0

            projections = []
            for freq_name, updates_per_year_per_user in [
                ("per-transfer (10/day)", 3650),
                ("hourly", 8760),
                ("daily", 365),
                ("weekly", 52),
            ]:
                for user_count in [100, 1000, 10000]:
                    total_updates = updates_per_year_per_user * user_count
                    total_gas = total_updates * avg_update_gas
                    est_eth = total_gas * gas_price_gwei * 1e-9
                    est_usd = est_eth * eth_price_usd
                    projections.append(AnnualCostProjection(
                        frequency=freq_name,
                        users=user_count,
                        updates_per_year=total_updates,
                        total_gas=total_gas,
                        estimated_eth=est_eth,
                        estimated_usd=est_usd,
                    ))

            print(f"\n  Annual Cost Projections (30 gwei, $3000/ETH):")
            print(f"  {'Frequency':>25} {'Users':>8} {'Updates/yr':>14} {'ETH':>12} {'USD':>12}")
            for p in projections:
                print(f"  {p.frequency:>25} {p.users:>8} {p.updates_per_year:>14} "
                      f"{p.estimated_eth:>12.4f} ${p.estimated_usd:>10.2f}")

            bench_results = GasBenchmarkResults(
                create_reputation=create_reputation,
                add_user=add_user,
                update_user=update_user,
                migrate_user=migrate_user,
                batch_add_users=batch_add,
                batch_update_users=batch_update,
                annual_cost_projections=projections,
            )

            # Convert to JSON-serializable dict
            self.results = {
                'create_reputation': asdict(bench_results.create_reputation),
                'add_user': asdict(bench_results.add_user),
                'update_user': asdict(bench_results.update_user),
                'migrate_user': asdict(bench_results.migrate_user),
                'batch_add_users': [asdict(g) for g in bench_results.batch_add_users],
                'batch_update_users': [asdict(g) for g in bench_results.batch_update_users],
                'annual_cost_projections': [asdict(p) for p in bench_results.annual_cost_projections],
            }
            return self.results

        finally:
            anvil_proc.terminate()
            anvil_proc.wait()

    def print_results(self):
        """Print summary of results."""
        if not self.results:
            print("No results available.")
            return

        print("\n" + "=" * 80)
        print("GAS COST BENCHMARK RESULTS")
        print("=" * 80)

        for op in ['create_reputation', 'add_user', 'update_user', 'migrate_user']:
            r = self.results[op]
            print(f"  {r['operation']:<25} gas={r['gas_used']:>8}  latency={r['latency_ms']:.2f} ms")

        if self.results['batch_add_users']:
            avg_add = sum(g['gas_used'] for g in self.results['batch_add_users']) // len(self.results['batch_add_users'])
            avg_upd = sum(g['gas_used'] for g in self.results['batch_update_users']) // len(self.results['batch_update_users'])
            print(f"\n  Batch avg addUser:    {avg_add} gas")
            print(f"  Batch avg updateUser: {avg_upd} gas")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='PBTS Gas Cost Benchmark')
    parser.add_argument('--users', type=int, default=100,
                        help='Number of batch users to test (default: 100)')
    parser.add_argument('--contract-project', type=str,
                        default=str(project_root / "smartcontract"),
                        help='Path to Foundry smartcontract project')
    parser.add_argument('--output', type=str,
                        help='Output JSON file for results')

    args = parser.parse_args()

    benchmark = GasBenchmark(
        num_users=args.users,
        contract_project=args.contract_project,
    )
    results = benchmark.run_all()
    benchmark.print_results()

    if args.output and results:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
