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

## Implementing Attestation Verification

The current implementation has a **STUB** for verification. You must implement it yourself.

**File:** `tee_manager.py`
**Function:** `verify_attestation(quote, expected_payload)`

**Implementation Steps:**

### 1. Parse TDX Quote Structure

Intel TDX quotes have this structure:
```
Quote = {
  header: {...},
  report_body: {
    rtmr[0-3]: [48 bytes each],  // Runtime measurements
    report_data: [64 bytes],      // Custom data (payload hash)
    ...
  },
  signature: {...}                // Intel signature
}
```

### 2. Verify Signature Chain

Verify Intel's signature on the quote:
- Check certificate chain (Intel root CA → intermediate → quote signer)
- Verify ECDSA signature over quote body

**Resources:**
- Intel TDX Quote Verification Library: https://github.com/intel/SGXDataCenterAttestationPrimitives
- Phala verification service (if available)

### 3. Check RTMR Measurements

Verify the code running in TEE:
```python
# Expected measurements (calculated from source code)
EXPECTED_RTMR_0 = "..."  # TD firmware
EXPECTED_RTMR_1 = "..."  # OS loader
EXPECTED_RTMR_2 = "..."  # Root filesystem (contains tracker code)
EXPECTED_RTMR_3 = "..."  # Application (Docker image hash)

# Verify quote's RTMRs match expected
assert quote.report_body.rtmr[2] == EXPECTED_RTMR_2
assert quote.report_body.rtmr[3] == EXPECTED_RTMR_3
```

### 4. Verify Payload

Check that expected payload is in quote:
```python
payload_hash = hashlib.sha256(expected_payload.encode()).digest()

# report_data should contain payload hash
assert quote.report_body.report_data[:32] == payload_hash
```

### Complete Example

```python
def verify_attestation(self, quote: str, expected_payload: str) -> Tuple[bool, float]:
    start_time = time.perf_counter()

    try:
        # 1. Parse quote (use Intel's library or custom parser)
        quote_obj = parse_tdx_quote(quote)

        # 2. Verify signature chain
        if not verify_intel_signature_chain(quote_obj):
            return False, (time.perf_counter() - start_time) * 1000

        # 3. Check RTMR measurements
        expected_rtmrs = get_expected_rtmrs()  # From config
        if quote_obj.rtmr != expected_rtmrs:
            return False, (time.perf_counter() - start_time) * 1000

        # 4. Verify payload
        payload_hash = hashlib.sha256(expected_payload.encode()).digest()
        if quote_obj.report_data[:32] != payload_hash:
            return False, (time.perf_counter() - start_time) * 1000

        # All checks passed
        duration_ms = (time.perf_counter() - start_time) * 1000
        return True, duration_ms

    except Exception as e:
        self.logger.error(f"Attestation verification failed: {e}")
        duration_ms = (time.perf_counter() - start_time) * 1000
        return False, duration_ms
```

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

### Verification Always Returns True
```
WARNING: verify_attestation is a stub - implement actual verification
```
**Solution:** Implement verification in `tee_manager.py` (see above)

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
    def verify_attestation(self, quote: str, expected_payload: str) -> Tuple[bool, float]
    def get_statistics(self) -> Dict[str, Any]
    def reset_statistics(self)
```

### Tracker Endpoints

| Endpoint | Method | TEE Required | Description |
|----------|--------|--------------|-------------|
| `/keygen-tee` | POST | Yes | Generate TEE-derived keypair |
| `/generate-attestation` | POST | Yes | Create TDX quote |
| `/verify-attestation` | POST | Yes | Verify quote (stub) |
| `/tee/status` | GET | No | Check TEE availability |
| `/config` | POST | No | Configure TEE mode |

## References

- **Phala dstack SDK**: https://github.com/Phala-Network/dstack-sdk
- **Intel TDX Documentation**: https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html
- **TEE Attestation Primer**: https://confidentialcomputing.io/wp-content/uploads/sites/10/2023/03/CCC-A-Technical-Analysis-of-Confidential-Computing-v1.3_unlocked.pdf
- **PBTS Paper**: (add link)

## Support

For implementation questions:
- Check `experiments/README.md` for benchmarking
- See `tee_manager.py` for code examples
- Review `docs/BEP10_IMPLEMENTATION.md` for protocol details
