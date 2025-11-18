# PBTS Tracker

A private BitTorrent tracker with portable reputation and cryptographic receipts.

## Quick Start

```bash
# Start tracker
docker-compose up -d

# Check status
curl http://localhost:8000/health
```

The tracker runs on port 8000.

## Features

### Standard BitTorrent (BEP 3, 23, 48)

- HTTP announce/scrape endpoints
- Compact and dictionary peer formats
- Private tracker with ratio enforcement

### PBTS Extensions

- User registration with BLS12-381 keypairs
- Cryptographic receipts for piece transfers (with signature aggregation)
- Double-spend prevention
- Portable reputation across tracker instances
- **BEP 10 Extension Protocol**: Peer-to-peer receipt exchange (see [docs/BEP10_IMPLEMENTATION.md](docs/BEP10_IMPLEMENTATION.md))

### Smart Contract Integration

- On-chain reputation storage using Ethereum smart contracts
- ReputationFactory for deploying new reputation contracts
- User data migration between contract versions
- Transparent and verifiable reputation history
- Support for contract chaining (referrer pattern)

## Usage

### As Standard Tracker

Add to your `.torrent` file:

```
http://localhost:8000/announce
```

Compatible with Transmission, qBittorrent, Deluge, rtorrent.

### With Cryptographic Features

```bash
# Generate keypair
curl -X POST http://localhost:8000/keygen

# Register user
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice", "public_key": "BASE64_PUBLIC_KEY"}'

# Enable verification
curl -X POST http://localhost:8000/config \
  -d '{"verify_signatures": true}'
```

## Smart Contract Setup

### Prerequisites

```bash
# Install Foundry (for smart contract deployment)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install Python dependencies with web3 support
pip install -r requirements.txt

# Start local blockchain (Anvil)
anvil
```

### Configuration

Create `smartcontract/.env` with minimal configuration:

```bash
RPC=http://127.0.0.1:8545
PK0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
A0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

### Deploy Smart Contracts

```bash
# Deploy ReputationFactory (automatically updates .env)
./deploy_factory.sh
```

This will deploy the factory and add `FACTORY=0x...` to your `.env` file.

### Start Tracker with Smart Contract Support

```bash
# Start the tracker
python tracker.py

# Check smart contract status
curl http://localhost:8000/contract/status
```

## Smart Contract Usage

### 1. Initialize Reputation Contract

```bash
# Create a new Reputation contract via factory
curl -X POST http://localhost:8000/contract/init
```

Response:

```json
{
  "success": true,
  "reputation_address": "0x...",
  "referrer_address": "0x0000000000000000000000000000000000000000"
}
```

### 2. Register User on Smart Contract

```bash
curl -X POST http://localhost:8000/contract/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "salt": "random_salt_123",
    "password_hash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    "download_size": 0,
    "upload_size": 0
  }'
```

### 3. Query User Reputation

```bash
curl http://localhost:8000/contract/user/alice
```

Response:

```json
{
  "success": true,
  "user": {
    "username": "alice",
    "salt": "random_salt_123",
    "passwordHash": "0xabcdef...",
    "downloadSize": 1024000,
    "uploadSize": 2048000,
    "ratio": 2.0
  }
}
```

### 4. Update User Statistics

```bash
curl -X POST http://localhost:8000/contract/update \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "download_size": 1024000,
    "upload_size": 2048000
  }'
```

### Example Workflow

```bash
# 1. Deploy factory
./deploy_factory.sh

# 2. Start tracker
python tracker.py &

# 3. Initialize reputation contract
curl -X POST http://localhost:8000/contract/init

# 4. Register users
curl -X POST http://localhost:8000/contract/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "salt": "salt123",
       "password_hash": "0x1234...", "download_size": 0, "upload_size": 0}'

curl -X POST http://localhost:8000/contract/register \
  -H "Content-Type: application/json" \
  -d '{"username": "bob", "salt": "salt456",
       "password_hash": "0x5678...", "download_size": 0, "upload_size": 0}'

# 5. Query reputation
curl http://localhost:8000/contract/user/alice
curl http://localhost:8000/contract/user/bob

# 6. Update stats as users download/upload
curl -X POST http://localhost:8000/contract/update \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "download_size": 500000, "upload_size": 1000000}'

# 7. Check updated ratio
curl http://localhost:8000/contract/user/alice
# Returns: ratio = 2.0 (1000000 / 500000)
```

## API Endpoints

### BitTorrent & PBTS Endpoints

| Endpoint    | Method   | Purpose                    |
| ----------- | -------- | -------------------------- |
| `/announce` | GET      | BitTorrent announce        |
| `/scrape`   | GET      | Torrent statistics         |
| `/register` | POST     | Register user              |
| `/report`   | POST     | Report stats with receipts |
| `/keygen`   | POST     | Generate keypair           |
| `/attest`   | POST     | Create receipt             |
| `/config`   | GET/POST | Configuration              |
| `/health`   | GET      | Health check               |

### Smart Contract Endpoints

| Endpoint                | Method | Purpose                        |
| ----------------------- | ------ | ------------------------------ |
| `/contract/status`      | GET    | Check contract configuration   |
| `/contract/init`        | POST   | Initialize Reputation contract |
| `/contract/register`    | POST   | Register user on contract      |
| `/contract/user/<name>` | GET    | Get user reputation            |
| `/contract/update`      | POST   | Update user statistics         |
| `/contract/migrate`     | POST   | Migrate user from referrer     |

## Configuration

Environment variables:

```bash
MIN_RATIO=0.5    # Minimum upload/download ratio
MAX_PEERS=50     # Maximum peers per announce
```

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
python tracker.py

# Run tests
python test_tracker.py

# Run smart contract tests
python test_smartcontract.py
```

## Project Structure

```
├── tracker.py                # Main tracker application
├── bep10_extension.py        # BEP 10 extension protocol implementation
├── test_tracker.py           # Tracker tests
├── test_bep10.py            # BEP 10 unit tests
├── test_bep10_integration.py # BEP 10 integration tests
├── test_smartcontract.py     # Smart contract tests
├── deploy_factory.sh         # Deploy factory script
├── requirements.txt          # Python dependencies
├── Dockerfile                # Container image
├── docker-compose.yml        # Docker setup
├── smartcontract/            # Solidity contracts
│   ├── src/
│   │   ├── Reputation.sol    # Reputation contract
│   │   └── factory.sol       # Factory contract
│   ├── test/                 # Contract tests
│   └── .env                  # Blockchain configuration
├── docs/
│   └── BEP10_IMPLEMENTATION.md   # BEP 10 protocol guide
├── tests/
│   └── example_bep10_client.py   # Example BitTorrent client with PBTS
└── README.md
```

## Requirements

- Python 3.11+
- Flask 3.0+
- bencoder 0.2.0
- py_ecc 8.0+
- web3.py 7.0+ (for smart contract integration)
- python-dotenv 1.0+ (for environment management)
- Foundry (for smart contract deployment)

## Docker

Pull from GitHub Container Registry:

```bash
docker pull ghcr.io/wichtfx/pbts-tracker:latest
docker run -p 8000:8000 ghcr.io/wichtfx/pbts-tracker:latest
```

## License

MIT

---

**Compatibility**: BitTorrent BEP 3, 10, 23, 48 compliant

## TEE Experiments (For Research Paper)

PBTS includes comprehensive benchmarks for evaluating TEE (Trusted Execution Environment) performance overhead:

### Quick Start

```bash
# Run all experiments (generates paper-ready LaTeX table)
python experiments/run_experiments.py --iterations 1000 --duration 60

# Results in experiments/results/
# - LaTeX table: results_table_*.tex (copy to paper)
# - CSV data: latency_*.csv
# - Text report: experiment_report_*.txt
```

### What's Measured

**Latency Benchmarks:**
- Key generation (BLS baseline vs TEE-derived)
- Attestation generation (TDX quote creation)
- End-to-end registration flow

**Throughput Benchmarks:**
- Operations per second (single and multi-threaded)
- Scaling efficiency (1, 2, 4, 8 threads)

### TEE Support

**With Phala TEE:**
```bash
pip install dstack-sdk
python experiments/run_experiments.py
```

**Without TEE (baseline only):**
```bash
# Skip dstack-sdk - still get baseline measurements
python experiments/run_experiments.py
```

### Documentation

- **[Quick Start](experiments/QUICKSTART.md)**: Get results for your paper fast
- **[Experiment Guide](experiments/README.md)**: Detailed experiment documentation
- **[TEE Integration](docs/TEE_INTEGRATION.md)**: Technical implementation guide
- **[Summary](EXPERIMENT_SUMMARY.md)**: Complete implementation overview

## Documentation

- **[BEP 10 Implementation Guide](docs/BEP10_IMPLEMENTATION.md)**: Peer-to-peer receipt exchange protocol
- **[TEE Integration Guide](docs/TEE_INTEGRATION.md)**: Trusted Execution Environment support
