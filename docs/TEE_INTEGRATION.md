# TEE Integration Guide for PBTS

This document describes the TEE (Trusted Execution Environment) integration in the PBTS tracker system.

## Overview

PBTS supports optional TEE-backed operations using Intel TDX via Phala's dstack SDK. This enables:

1. **Secure Key Derivation**: Keys derived from TEE's root of trust
2. **Attestation**: Cryptographic proof that tracker runs in genuine TEE
3. **Verifiable Execution**: Remote parties can verify tracker's code integrity

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   PBTS Tracker                           │
│                                                          │
│  ┌──────────────┐           ┌──────────────┐           │
│  │  Regular     │           │  TEE Mode    │           │
│  │  Operations  │           │  (Optional)  │           │
│  │              │           │              │           │
│  │ - BLS keygen │           │ - TEE keygen │           │
│  │ - Sign       │           │ - Attest     │           │
│  │ - Verify     │           │ - Verify     │           │
│  └──────────────┘           └──────┬───────┘           │
│                                    │                    │
│                          ┌─────────▼─────────┐          │
│                          │  tee_manager.py   │          │
│                          │                   │          │
│                          │ - TEEMode         │          │
│                          │ - KeyPair         │          │
│                          │ - Attestation     │          │
│                          └─────────┬─────────┘          │
│                                    │                    │
└────────────────────────────────────┼────────────────────┘
                                     │
                          ┌──────────▼──────────┐
                          │   dstack_sdk        │
                          │  (Phala TEE SDK)    │
                          │                     │
                          │ - DstackClient      │
                          │ - get_key()         │
                          │ - get_quote()       │
                          └─────────────────────┘
                                     │
                          ┌──────────▼──────────┐
                          │   Intel TDX / TEE   │
                          │   Hardware          │
                          └─────────────────────┘
```

## Components

### 1. TEE Manager (`tee_manager.py`)

Core module that abstracts TEE operations:

**Classes:**
- `TEEMode`: Enum for operation modes (DISABLED, ENABLED, BENCHMARK)
- `TEEKeyPair`: Container for TEE-derived or regular keypairs
- `AttestationReport`: TEE attestation quote with metadata
- `TEEManager`: Main manager class

**Key Methods:**
```python
# Initialize manager
manager = TEEManager(mode=TEEMode.ENABLED)

# Generate keypair
keypair = manager.generate_keypair(tee_enabled=True)
# Returns: TEEKeyPair(private_key, public_key, tee_derived, derivation_time_ms)

# Generate attestation
attestation = manager.generate_attestation(payload="user_registration")
# Returns: AttestationReport(quote, generation_time_ms, payload, quote_size_bytes)

# Verify attestation (STUB - implement yourself)
is_valid, time_ms = manager.verify_attestation(quote, expected_payload)
```

### 2. Tracker Endpoints (`tracker.py`)

New TEE-aware endpoints:

**`POST /keygen-tee`**
Generate TEE-derived BLS keypair
```bash
curl -X POST http://localhost:8000/keygen-tee
```
Response:
```json
{
  "success": true,
  "private_key": "base64...",
  "public_key": "base64...",
  "key_type": "BLS12-381 (TEE-derived)",
  "tee_derived": true,
  "derivation_time_ms": 12.5
}
```

**`POST /generate-attestation`**
Generate TDX attestation quote
```bash
curl -X POST http://localhost:8000/generate-attestation \
  -H "Content-Type: application/json" \
  -d '{"payload": "user_registration_data"}'
```
Response:
```json
{
  "success": true,
  "quote": "...",
  "generation_time_ms": 42.3,
  "payload": "user_registration_data",
  "quote_size_bytes": 1234
}
```

**`POST /verify-attestation`** ⚠️ STUB
Verify attestation report
```bash
curl -X POST http://localhost:8000/verify-attestation \
  -H "Content-Type: application/json" \
  -d '{"quote": "...", "expected_payload": "..."}'
```

**`GET /tee/status`**
Check TEE availability and statistics
```bash
curl http://localhost:8000/tee/status
```
Response:
```json
{
  "tee_available": true,
  "tee_mode": "enabled",
  "statistics": {
    "key_generations": 42,
    "attestations_generated": 10,
    "avg_key_gen_time_ms": 12.5,
    "avg_attestation_time_ms": 42.3
  }
}
```

**Updated: `POST /config`**
Configure TEE mode
```bash
curl -X POST http://localhost:8000/config \
  -H "Content-Type: application/json" \
  -d '{"tee_mode": "enabled"}'
```

## Installation

### Standard Installation (No TEE)
```bash
pip install -r requirements.txt
python tracker.py
```

Tracker runs normally with TEE features disabled.

### TEE-Enabled Installation

#### Option 1: Phala Cloud
```bash
# Install dstack SDK (DstackClient API)
pip install dstack-sdk==0.5.3

# Configure Phala Cloud credentials (if needed)
export PHALA_ENDPOINT="https://..."
export PHALA_API_KEY="..."

# Run tracker with TEE enabled
python tracker.py
```

#### Option 2: Local TDX Hardware
```bash
# Install dstack SDK (DstackClient API)
pip install dstack-sdk==0.5.3

# Ensure Intel TDX is enabled
# (requires compatible hardware and BIOS settings)

# Run tracker inside TDX VM
# DstackClient automatically connects to /var/run/dstack.sock
python tracker.py
```

## Usage

### Enabling TEE Mode

**At Startup:**
```python
from tee_manager import set_tee_mode, TEEMode

set_tee_mode(TEEMode.ENABLED)
```

**Via API:**
```bash
curl -X POST http://localhost:8000/config \
  -H "Content-Type: application/json" \
  -d '{"tee_mode": "enabled"}'
```

### Modes

**DISABLED** (default)
- TEE features unavailable
- Uses regular BLS12-381 crypto
- No performance overhead

**ENABLED**
- All operations use TEE
- Keys derived from TEE root of trust
- Attestation available

**BENCHMARK**
- TEE available but can measure both modes
- Used for performance experiments

### User Registration with TEE

**Client-side flow:**

1. Generate TEE-derived keypair
```bash
curl -X POST http://localhost:8000/keygen-tee
```

2. Generate attestation for registration message
```bash
curl -X POST http://localhost:8000/generate-attestation \
  -H "Content-Type: application/json" \
  -d '{"payload": "register||alice||tracker_instance_1"}'
```

3. Sign registration message with private key
```python
message = "register||alice||tracker_instance_1"
signature = bls.Sign(private_key, message.encode())
```

4. Submit registration with attestation
```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "alice",
    "public_key": "...",
    "signature": "...",
    "attestation": "..."  # Include TDX quote
  }'
```

**Server-side verification:**
```python
# Tracker verifies:
# 1. Signature is valid
# 2. Attestation is valid (proves client used TEE)
# 3. Public key in attestation matches public key in registration
```

## Attestation Verification with DCAP QVL

The implementation uses **dcap-qvl** (Phala Network's DCAP Quote Verification Library) for full cryptographic verification of TDX/SGX quotes.

**File:** [tee_manager.py](../tee_manager.py)
**Function:** `verify_attestation(quote, expected_payload, pccs_url=None)`

### Installation

```bash
pip install dcap-qvl
```

### How It Works

The verification process performs:

1. **Quote Structure Parsing** - Decodes TDX/SGX quote headers and report body
2. **Collateral Retrieval** - Fetches certificates and revocation lists from PCCS or Intel PCS
3. **Signature Chain Verification** - Validates Intel/AMD signature chains
4. **TCB Status Check** - Verifies Trusted Computing Base is up-to-date
5. **Payload Validation** - Confirms expected_payload is in quote's report_data field

### Usage Example

```python
from tee_manager import TEEManager, TEEMode

# Initialize manager with TEE enabled
manager = TEEManager(mode=TEEMode.ENABLED)

# Generate attestation
attestation = manager.generate_attestation(payload="user_id:alice")

# Verify attestation (uses Intel PCS by default)
is_valid, time_ms = manager.verify_attestation(
    quote=attestation.quote,
    expected_payload="user_id:alice"
)

# Or use custom PCCS
is_valid, time_ms = manager.verify_attestation(
    quote=attestation.quote,
    expected_payload="user_id:alice",
    pccs_url="https://my-pccs.example.com"
)

print(f"Valid: {is_valid}, Time: {time_ms:.2f}ms")
```

### API Endpoint Usage

```bash
curl -X POST http://localhost:8000/verify-attestation \
  -H "Content-Type: application/json" \
  -d '{
    "quote": "030002000000...",
    "expected_payload": "user_id:alice",
    "pccs_url": "https://my-pccs.example.com"
  }'
```

Response:
```json
{
  "success": true,
  "is_valid": true,
  "verification_time_ms": 150.5
}
```

### Quote Structure

Intel TDX quotes have this structure:
```
Quote = {
  header: {
    version: 4,
    attestation_key_type: 2,  // ECDSA
    tee_type: 0x81,            // TDX
    ...
  },
  report_body: {
    rtmr[0-3]: [48 bytes each],  // Runtime measurements
    report_data: [64 bytes],      // Custom data (payload hash)
    ...
  },
  signature: {...}                // Intel ECDSA signature
}
```

### Verification Status Codes

The library returns these status codes:
- **OK** - Quote is valid and TCB is up-to-date
- **SW_HARDENING_NEEDED** - Valid but software hardening recommended
- **CONFIGURATION_NEEDED** - Valid but configuration changes recommended
- **OUT_OF_DATE** - TCB is outdated, should update
- Other codes indicate verification failure

### Performance

Typical verification times:
- **First verification**: 150-300ms (includes collateral download)
- **Subsequent verifications**: 50-100ms (cached collateral)

### Additional RTMR Verification (Optional)

If you need to verify specific RTMR measurements (runtime measurements of code/data):

```python
# After dcap-qvl verification passes, extract RTMRs for additional checks
# Note: dcap-qvl already verifies the signature chain and TCB

# Expected measurements (calculated from source code)
EXPECTED_RTMR_2 = "..."  # Root filesystem (contains tracker code)
EXPECTED_RTMR_3 = "..."  # Application (Docker image hash)

# Parse quote to extract RTMRs
# TDX v4: RTMRs are at offsets 112, 160, 208, 256 (48 bytes each)
rtmr_2 = quote_bytes[208:256]
rtmr_3 = quote_bytes[256:304]

if rtmr_2 != bytes.fromhex(EXPECTED_RTMR_2):
    logger.warning("RTMR[2] mismatch - unexpected code version")
if rtmr_3 != bytes.fromhex(EXPECTED_RTMR_3):
    logger.warning("RTMR[3] mismatch - unexpected application")
```

**Resources:**
- **dcap-qvl**: https://github.com/Phala-Network/dcap-qvl
- **Intel DCAP**: https://github.com/intel/SGXDataCenterAttestationPrimitives
- **dcap-qvl Python Package**: https://pypi.org/project/dcap-qvl/

## Performance Experiments

See `experiments/README.md` for detailed benchmarking instructions.

**Quick Start:**
```bash
# Run all experiments
python experiments/run_experiments.py --iterations 1000 --duration 60

# Results in experiments/results/
```

**Expected Overhead:**
- Key generation: +50-200%
- Attestation generation: ~10-50ms
- End-to-end registration: +50-150%

## Security Considerations

### 1. Attestation Verification is Critical

**DO NOT** skip attestation verification in production!
- Without verification, anyone can claim to use TEE
- Implement full verification (signature + measurements + payload)

### 2. RTMR Measurement Management

**Track Expected Measurements:**
- Store expected RTMR values in configuration
- Update when tracker code changes
- Use code hashing to calculate expected values

**Example:**
```bash
# Calculate expected RTMR[3] from Docker image
docker save pbts-tracker:latest | sha256sum
# Use this hash as EXPECTED_RTMR_3
```

### 3. Key Derivation

**TEE-derived keys are deterministic:**
- Same salt → same key
- Use unique salts per user/purpose
- Store salts securely (on-chain or encrypted)

### 4. Attestation Freshness

**Prevent replay attacks:**
- Include timestamp or nonce in payload
- Verify attestation is recent (<5 minutes)
- Track used nonces to prevent reuse

## Troubleshooting

### TEE Not Available
```
Error: TEE not available - install dstack_sdk
```
**Solution:**
```bash
pip install dstack-sdk
```

### Import Error
```
ImportError: cannot import name 'DstackClient'
```
**Solution:** dstack-sdk not installed or wrong version
```bash
pip install dstack-sdk==0.5.3
```

### Migration from TappdClient
If you see deprecation warnings about `TappdClient`:
```
DeprecationWarning: TappdClient is deprecated, use DstackClient
```
**Solution:** The code has been updated to use `DstackClient`. If using an older version of the tracker:
1. Update to latest code
2. Install `dstack-sdk==0.5.3`
3. Verify `/var/run/dstack.sock` is available (not `/var/run/tappd.sock`)

### Verification Requires dcap-qvl
```
RuntimeError: dcap_qvl not available for attestation verification
```
**Solution:** Install dcap-qvl for full attestation verification:
```bash
pip install dcap-qvl
```
The implementation uses Phala's dcap-qvl library for full cryptographic verification of TDX/SGX quotes.

### Performance Issues
```
Key generation very slow with TEE enabled
```
**Expected:** TEE operations are 50-200% slower than baseline.
**Mitigation:** Generate keys in advance, cache when possible.

## API Reference

### TEEManager

```python
class TEEManager:
    def __init__(self, mode: TEEMode = TEEMode.DISABLED)
    def generate_keypair(self, tee_enabled: bool = None) -> TEEKeyPair
    def generate_attestation(self, payload: str) -> AttestationReport
    def verify_attestation(self, quote: str, expected_payload: str, pccs_url: Optional[str] = None) -> Tuple[bool, float]
    def get_statistics(self) -> Dict[str, Any]
    def reset_statistics(self)
```

### Tracker Endpoints

| Endpoint | Method | TEE Required | Description |
|----------|--------|--------------|-------------|
| `/keygen-tee` | POST | Yes | Generate TEE-derived keypair |
| `/generate-attestation` | POST | Yes | Create TDX quote |
| `/verify-attestation` | POST | Yes | Verify quote using DCAP QVL |
| `/tee/status` | GET | No | Check TEE availability |
| `/config` | POST | No | Configure TEE mode |

## References

- **Phala dstack SDK**: https://github.com/Phala-Network/dstack-sdk
- **Phala dcap-qvl**: https://github.com/Phala-Network/dcap-qvl (Quote verification library)
- **dcap-qvl PyPI**: https://pypi.org/project/dcap-qvl/
- **Intel TDX Documentation**: https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html
- **Intel DCAP**: https://github.com/intel/SGXDataCenterAttestationPrimitives
- **TEE Attestation Primer**: https://confidentialcomputing.io/wp-content/uploads/sites/10/2023/03/CCC-A-Technical-Analysis-of-Confidential-Computing-v1.3_unlocked.pdf
- **PBTS Paper**: (add link)

## Support

For implementation questions:
- Check `experiments/README.md` for benchmarking
- See `tee_manager.py` for code examples
- Review `docs/BEP10_IMPLEMENTATION.md` for protocol details
