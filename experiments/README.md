# PBTS Experiments

Benchmark and experiment scripts for measuring PBTS overhead. Available in both **Python** and **Rust** implementations.

## Benchmark Overview

| # | Benchmark | Measures | Requirements |
|---|-----------|----------|-------------|
| 1 | **Receipt Operations** | BLS12-381 keygen, sign, verify, aggregate | None |
| 2 | **TEE Operations** | TEE key derivation, attestation gen/verify | dstack-sdk, TEE environment |
| 3 | **Client Download** | Receipt overhead in download scenarios | None |
| 4 | **Tracker Overhead** | Component-by-component latency breakdown | Running tracker |
| 5 | **Scalability** | Concurrent report throughput + swarm scale | None |
| 6 | **Gas Cost** | Smart contract gas consumption + annual projections | Foundry (forge, anvil) |

## Python Experiments

### Prerequisites

```bash
cd pbts/
pip install -r requirements.txt  # py_ecc, flask, web3, etc.
```

For TEE benchmarks: run inside a TEE instance with `dstack_sdk` available.
For gas benchmarks: install [Foundry](https://book.getfoundry.sh/getting-started/installation).

### Run All

```bash
# Run everything (skips unavailable components automatically)
python experiments/run_all_experiments.py

# Skip specific benchmarks
python experiments/run_all_experiments.py --skip-tee --skip-gas --skip-tracker-overhead

# Custom output directory
python experiments/run_all_experiments.py --output-dir /tmp/pbts_results
```

### Run Individual Benchmarks

```bash
# 1. Receipt operations (BLS crypto)
python experiments/benchmark_receipts.py --iterations 1000 --batch-sizes 10 25 50 100 500
python experiments/benchmark_receipts.py --output receipts.json

# 2. TEE operations (requires TEE)
python experiments/benchmark_tee.py --iterations 100 --verify-iterations 5
python experiments/benchmark_tee.py --output tee.json

# 3. Client download simulation
python experiments/benchmark_client_download.py --output client_download.json

# 4. Tracker overhead (requires running tracker)
python experiments/benchmark_tracker_overhead.py --iterations 100

# 5. Scalability (NEW)
python experiments/benchmark_scalability.py --peer-counts 10 50 100 200 500 \
    --swarm-sizes 100 1000 5000 10000 --output scalability.json

# 6. Gas cost (NEW, requires Foundry)
python experiments/benchmark_gas.py --users 100 --output gas.json
```

### Key CLI Options for run_all_experiments.py

| Flag | Description |
|------|-------------|
| `--output-dir PATH` | Output directory (default: `/tmp/pbts_experiments`) |
| `--receipt-iterations N` | Iterations for receipt benchmarks (default: 10) |
| `--receipt-batch-sizes N...` | Aggregate batch sizes (default: 10 25 50) |
| `--tee-iterations N` | TEE benchmark iterations (default: 10) |
| `--skip-tee` | Skip TEE benchmarks |
| `--skip-client-download` | Skip download simulation |
| `--skip-tracker-overhead` | Skip tracker overhead |
| `--skip-scalability` | Skip scalability benchmarks |
| `--skip-gas` | Skip gas cost benchmarks |
| `--scalability-peers N...` | Peer counts for concurrency test |
| `--scalability-swarm-sizes N...` | Swarm sizes for scaling test |
| `--gas-users N` | Number of users for gas batch test (default: 100) |

---

## Rust Experiments

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Foundry (for gas benchmarks)
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Build
cd pbts/pbts-rs/
cargo build --release
```

### Run All

```bash
# Run all benchmarks (skips TEE and gas if unavailable)
cargo run --release -p pbts-bench -- all --output /tmp/pbts_results

# Skip TEE and gas
cargo run --release -p pbts-bench -- all --skip-tee --skip-gas --output /tmp/pbts_results
```

### Run Individual Benchmarks

```bash
# 1. Receipt operations (BLS crypto via blst)
cargo run --release -p pbts-bench -- receipts --iterations 1000 --batch-sizes 10,25,50,100,500
cargo run --release -p pbts-bench -- receipts --output receipts.json

# 2. TEE operations (requires TEE with dstack-sdk)
cargo run --release -p pbts-bench -- tee --iterations 100 --verify-iterations 5
cargo run --release -p pbts-bench -- tee --output tee.json

# 3. Client download simulation
cargo run --release -p pbts-bench -- download --speeds 1,5,10,25,50,100 --pieces 256,512,1024,2048
cargo run --release -p pbts-bench -- download --output client_download.json

# 5. Scalability
cargo run --release -p pbts-bench -- scalability --peers 10,50,100,200,500 \
    --swarm-sizes 100,1000,5000,10000 --output scalability.json

# 6. Gas cost (requires Foundry)
cargo run --release -p pbts-bench -- gas --users 100 --output gas.json
```

### Rust CLI Subcommands

| Subcommand | Description |
|------------|-------------|
| `receipts` | BLS receipt operation benchmarks |
| `download` | Client download overhead simulation |
| `tee` | TEE key generation and attestation benchmarks |
| `gas` | Smart contract gas cost measurement |
| `scalability` | Concurrent report throughput and swarm scaling |
| `all` | Run all benchmarks |

---

## Benchmark Details

### 1. Receipt Operations

Measures BLS12-381 cryptographic operations:
- **Keypair generation**: Time to generate a BLS key pair
- **Receipt creation**: Time to sign a receipt (attest_piece_transfer)
- **Receipt verification**: Time to verify a single receipt
- **Aggregate verification**: Time to verify N receipts using BLS aggregate signatures, compared to verifying them individually. Reports speedup factor.

Batch sizes tested: 10, 25, 50, 100, 500 (configurable)

### 2. TEE Operations

Requires running inside a TEE (Intel TDX) with dstack-sdk:
- **Regular vs TEE key generation**: Overhead of TEE-derived keys
- **Attestation generation**: Time to generate a TDX quote
- **Attestation verification**: Time to verify a quote (network-bound, slow)

### 3. Client Download Simulation

Simulates realistic download scenarios to measure receipt overhead:
- Speeds: 1, 5, 10, 25, 50, 100 MB/s
- Piece sizes: 256KB, 512KB, 1MB, 2MB
- Computes: overhead %, throughput reduction %, actual vs baseline time

### 4. Tracker Overhead Breakdown

Component-by-component latency analysis of the tracker:
- Baseline announce latency
- Receipt verification (individual + aggregate)
- On-chain operations

Requires a running tracker instance.

### 5. Scalability (NEW)

Two dimensions of scalability analysis:

**Concurrent Report Processing**:
- N peers submit reports simultaneously (N = 10, 50, 100, 200, 500)
- Each report contains M receipts with BLS aggregate verification
- Measures: throughput (reports/sec), mean latency, p50/p95/p99

**Swarm Size Impact**:
- Swarm sizes: 100, 1000, 5000, 10000 peers
- Measures announce lookup time and report processing time as swarm grows

### 6. Gas Cost (NEW)

Smart contract gas measurement using Anvil (local Ethereum testnet):

**Operations measured**:
| Operation | Description |
|-----------|-------------|
| `createReputation` | Deploy new Reputation contract via factory |
| `addUser` | Register a user on-chain |
| `updateUser` | Update user upload/download stats |
| `migrateUserData` | Migrate data from referrer contract |

**Annual cost projections** at different frequencies:
- Per-transfer (10/day), hourly, daily, weekly
- User counts: 100, 1,000, 10,000
- Reference: 30 gwei gas price, $3,000/ETH

---

## Output Format

All benchmarks output JSON files compatible with the paper's figure generation scripts. Results are saved to the specified output directory.

**Output files from `run_all_experiments.py`:**
```
output_dir/
├── receipts.json
├── tee.json
├── client_download.json
├── scalability.json
├── gas.json
├── all_results.json
├── SUMMARY.txt
└── COMPARISON.txt
```

**Output files from Rust `pbts-bench all`:**
```
output_dir/
├── receipts.json
├── tee.json
├── client_download.json
├── scalability.json
├── gas.json
└── all_results.json
```

## Running on TEE Instance

```bash
# 1. Clone the repo
git clone <repo-url> && cd paper-tracker/pbts

# 2. Python setup
pip install -r requirements.txt

# 3. Rust setup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 4. Foundry setup (for gas benchmarks)
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup

# 5. Build Rust
cd pbts-rs && cargo build --release && cd ..

# 6. Run Python experiments
python experiments/run_all_experiments.py --output-dir /tmp/pbts_py_results

# 7. Run Rust experiments
cargo run --release -p pbts-bench --manifest-path pbts-rs/Cargo.toml -- \
    all --output /tmp/pbts_rs_results
```
