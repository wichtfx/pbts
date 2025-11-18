# PBTS End-to-End Testing Guide

Complete guide for running E2E tests that validate the entire PBTS system.

## Overview

The E2E test simulates a complete BitTorrent swarm with PBTS extensions:

1. **Setup**: Deploy smart contracts, start tracker
2. **Users**: Register Alice (seeder) and Bob (leecher)
3. **Transfer**: Simulate piece downloads with receipt generation
4. **Verification**: Validate receipts and smart contract updates

## Quick Start

### Prerequisites

```bash
# Install dependencies
pip install -r requirements.txt

# Install Foundry (for smart contracts)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Configure smart contract environment
cat > smartcontract/.env << EOF
RPC=http://127.0.0.1:8545
PK0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
A0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
EOF
```

### Run Complete E2E Test

The simplest way to run the full E2E test:

```bash
# Run everything (Anvil, contracts, tracker, test)
python tests/e2e_test.py
```

This will:
- ✅ Start Anvil (local blockchain)
- ✅ Deploy ReputationFactory and Reputation contracts
- ✅ Start PBTS tracker
- ✅ Generate keypairs for Alice and Bob
- ✅ Register users on tracker and smart contract
- ✅ Create test torrent (100KB)
- ✅ Simulate 5 piece transfers with receipt generation
- ✅ Submit receipt batch to tracker
- ✅ Verify smart contract state updates
- ✅ Clean up all processes

**Expected output:**

```
======================================================================
  ✅ E2E TEST PASSED!
======================================================================

Alice:
  Upload: 81920 bytes
  Download: 0 bytes
  Ratio: inf

Bob:
  Upload: 0 bytes
  Download: 81920 bytes
  Ratio: 0.0
```

### Run with Existing Services

If you already have Anvil and tracker running:

```bash
# Terminal 1: Start Anvil
anvil

# Terminal 2: Deploy contracts and start tracker
./deploy_factory.sh
python tracker.py

# Terminal 3: Run E2E test
python tests/e2e_test.py --skip-anvil --skip-contracts
```

## Components

### 1. pbts_client.py

Simplified BitTorrent client with real PBTS receipt generation.

**Features:**
- BLS keypair management
- Torrent file parsing
- Tracker announce/scrape
- Simulated piece transfers (with sleep)
- **Real** BLS signature generation
- **Real** receipt creation and verification
- **Real** batch submission to tracker

**Usage:**

```bash
# Create client for seeder
python tests/pbts_client.py \
  --user-id alice \
  --keys /tmp/alice_keys.json \
  --torrent test.torrent \
  --mode seeder \
  --data test_data.dat

# Create client for leecher
python tests/pbts_client.py \
  --user-id bob \
  --keys /tmp/bob_keys.json \
  --torrent test.torrent \
  --mode leecher
```

**Key Methods:**

```python
from tests.pbts_client import PBTSClient

# Initialize client
client = PBTSClient(
    user_id="alice",
    private_key=alice_sk,
    public_key=alice_pk,
    mode="seeder"
)

# Load torrent
client.load_torrent(Path("test.torrent"))

# Announce to tracker
client.announce_to_tracker(event="started")

# Simulate upload (as seeder)
piece_data, piece_hash = client.simulate_upload_to_peer(
    peer_user_id="bob",
    peer_public_key=bob_pk,
    piece_index=0
)

# Simulate download (as leecher)
receipt = client.simulate_download_from_peer(
    peer_user_id="alice",
    peer_public_key=alice_pk,
    piece_index=0
)

# Receive receipt (as uploader)
client.receive_receipt_from_peer(receipt)

# Submit receipts to tracker
client.submit_receipts_to_tracker(update_contract=True)
```

### 2. torrent_generator.py

Create .torrent files for testing.

**Usage:**

```bash
# Generate test data and create torrent
python tests/torrent_generator.py \
  --generate 1048576 \
  --output test.torrent \
  --tracker http://localhost:8000/announce

# Create torrent from existing file
python tests/torrent_generator.py \
  --file myfile.dat \
  --output myfile.torrent

# Parse existing torrent
python tests/torrent_generator.py --parse test.torrent
```

**Output:**

```
Generating test data file (1048576 bytes)...
  ✓ Created: test.dat

Creating torrent for: test.dat
  Tracker: http://localhost:8000/announce
  Piece length: 16384 bytes
  File size: 1048576 bytes
  Number of pieces: 64
  Info hash: a3f5c8b2d9e1f0a7b4c3d8e2f1a0b9c8d7e6f5a4
  ✓ Created: test.torrent
```

### 3. e2e_test.py

Complete E2E test orchestrator.

**Features:**
- Process management (Anvil, tracker)
- Smart contract deployment
- User registration (tracker + contract)
- Piece transfer simulation
- Receipt generation and submission
- Contract state verification
- Automatic cleanup

**Command-line options:**

```bash
# Full test (recommended)
python tests/e2e_test.py

# Skip Anvil (if already running)
python tests/e2e_test.py --skip-anvil

# Skip contract deployment
python tests/e2e_test.py --skip-contracts

# Keep processes running after test
python tests/e2e_test.py --no-cleanup

# Custom tracker URL
python tests/e2e_test.py --tracker-url http://192.168.1.100:8000
```

## Test Scenarios

### Scenario 1: Basic Transfer

Test 5 pieces transferred from Alice to Bob:

```bash
python tests/e2e_test.py
```

**Validates:**
- ✅ Receipt generation with BLS signatures
- ✅ Receipt verification by tracker
- ✅ Upload stats for Alice
- ✅ Download stats for Bob
- ✅ Smart contract updates

### Scenario 2: Large Transfer

Test with larger file and more pieces:

```python
# Modify e2e_test.py
self.create_test_torrent(file_size=10_485_760)  # 10MB
self.simulate_piece_transfers(num_pieces=50)
```

### Scenario 3: Multiple Leechers

Test with multiple downloaders:

```python
# Create multiple leechers
bob_client = PBTSClient(...)
charlie_client = PBTSClient(...)
david_client = PBTSClient(...)

# Simulate transfers from Alice to all leechers
for leecher in [bob_client, charlie_client, david_client]:
    # Transfer pieces...
    # Generate receipts...
```

## Manual Testing

For manual testing and debugging:

### Step 1: Setup

```bash
# Terminal 1: Anvil
anvil

# Terminal 2: Deploy contracts
./deploy_factory.sh

# Terminal 3: Start tracker
python tracker.py
```

### Step 2: Create Test Data

```bash
# Generate test torrent
python tests/torrent_generator.py \
  --generate 102400 \
  --output /tmp/test.torrent
```

### Step 3: Generate Keys

```python
from tracker import generate_keypair
import json, base64

# Alice
alice_sk, alice_pk = generate_keypair()
with open('/tmp/alice_keys.json', 'w') as f:
    json.dump({
        'private_key': base64.b64encode(alice_sk).decode(),
        'public_key': base64.b64encode(alice_pk).decode()
    }, f)

# Bob
bob_sk, bob_pk = generate_keypair()
with open('/tmp/bob_keys.json', 'w') as f:
    json.dump({
        'private_key': base64.b64encode(bob_sk).decode(),
        'public_key': base64.b64encode(bob_pk).decode()
    }, f)
```

### Step 4: Register Users

```bash
# Register with tracker
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice", "public_key": "BASE64_PK"}'

# Register with contract
curl -X POST http://localhost:8000/contract/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "salt": "salt123",
    "password_hash": "0x1234...",
    "download_size": 0,
    "upload_size": 0
  }'
```

### Step 5: Test Transfer

```python
from tests.pbts_client import PBTSClient
from pathlib import Path

# Load keys
alice_sk, alice_pk = load_keys_from_file(Path('/tmp/alice_keys.json'))
bob_sk, bob_pk = load_keys_from_file(Path('/tmp/bob_keys.json'))

# Create clients
alice = PBTSClient("alice", alice_sk, alice_pk, mode="seeder")
bob = PBTSClient("bob", bob_sk, bob_pk, mode="leecher")

# Load torrent
alice.load_torrent(Path('/tmp/test.torrent'))
bob.load_torrent(Path('/tmp/test.torrent'))

# Announce
alice.announce_to_tracker(event="started")
bob.announce_to_tracker(event="started")

# Transfer piece
piece_data, piece_hash = alice.simulate_upload_to_peer("bob", bob_pk, 0)
receipt = bob.simulate_download_from_peer("alice", alice_pk, 0)
alice.receive_receipt_from_peer(receipt)

# Submit
alice.submit_receipts_to_tracker(update_contract=True)
```

### Step 6: Verify

```bash
# Check tracker stats
curl http://localhost:8000/stats

# Check contract state
curl http://localhost:8000/contract/user/alice
curl http://localhost:8000/contract/user/bob
```

## Troubleshooting

### Anvil not starting

```bash
# Check if already running
lsof -i :8545

# Kill existing instance
killall anvil

# Start fresh
anvil --port 8545
```

### Contract deployment fails

```bash
# Verify Foundry installation
forge --version

# Check environment
cat smartcontract/.env

# Re-deploy
cd smartcontract
forge create src/factory.sol:ReputationFactory \
  --rpc-url http://127.0.0.1:8545 \
  --private-key $PK0
```

### Tracker not responding

```bash
# Check if running
curl http://localhost:8000/health

# Check logs
python tracker.py

# Check dependencies
pip install -r requirements.txt
```

### Receipt verification fails

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Check signature:

```python
from tracker import verify_signature

is_valid = verify_signature(
    receipt.receiver_pk,
    receipt.get_message(),
    receipt.signature
)
print(f"Valid: {is_valid}")
```

## CI/CD Integration

Add to `.github/workflows/e2e-test.yml`:

```yaml
name: E2E Test

on: [push, pull_request]

jobs:
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run E2E test
        run: python tests/e2e_test.py
```

## Performance Testing

Benchmark receipt generation:

```python
import time
from tests.pbts_client import PBTSClient

# Measure 100 receipt generations
start = time.time()
for i in range(100):
    receipt = bob.simulate_download_from_peer("alice", alice_pk, i)
elapsed = time.time() - start

print(f"Receipts/sec: {100 / elapsed:.2f}")
```

Expected performance:
- Receipt generation: ~1000/sec
- Receipt verification: ~500/sec
- Batch verification (10 receipts): ~200 batches/sec

## Further Reading

- [BEP 10 Implementation Guide](../docs/BEP10_IMPLEMENTATION.md)
- [Smart Contract Integration](../docs/TEE_INTEGRATION.md)
- [Tracker API Documentation](../CLAUDE.md)
