# BEP 10 Implementation for PBTS

This document describes the BitTorrent Extension Protocol (BEP 10) implementation for PBTS (Persistent BitTorrent Tracker System).

## Overview

BEP 10 enables peer-to-peer receipt exchange in PBTS, replacing the centralized HTTP API for receipt submission. This provides:

- **Decentralized receipt collection**: Peers exchange receipts directly during piece transfers
- **Reduced tracker load**: Only batch reports contact the tracker
- **Better privacy**: Less frequent tracker communication
- **Backward compatibility**: Standard BitTorrent clients continue to work

## Protocol Specification

### Extended Handshake

After the standard BitTorrent handshake (which sets bit 43 in reserved bytes to indicate extension support), peers exchange an extended handshake:

**Message Format:**
```
<length prefix><EXTENDED_ID><HANDSHAKE_ID><bencoded payload>
```

Where:
- `length prefix`: 4-byte big-endian message length
- `EXTENDED_ID`: 20 (BEP 10 extension message ID)
- `HANDSHAKE_ID`: 0 (extended handshake sub-message)
- `payload`: Bencoded dictionary

**Handshake Dictionary:**
```python
{
    "m": {
        "pbts": {
            "receipt": 1,           # Message ID for pbts_receipt
            "receipt_batch": 2,      # Message ID for pbts_receipt_batch
            "request_receipt": 3     # Message ID for pbts_request_receipt
        }
    },
    "v": "PBTS Client 0.1",  # Optional: client version
    "p": 6881                # Optional: listening port
}
```

### PBTS Extension Messages

#### 1. pbts_receipt

Send a single receipt for a piece transfer.

**Format:**
```
<length><EXTENDED_ID><msg_id><bencoded_receipt>
```

**Receipt Dictionary:**
```python
{
    "infohash": bytes,      # 20-byte torrent info hash
    "sender_pk": bytes,     # 48-byte BLS public key (uploader)
    "receiver_pk": bytes,   # 48-byte BLS public key (downloader)
    "piece_hash": bytes,    # 32-byte SHA-256 hash of piece
    "piece_index": int,     # Piece index in torrent
    "timestamp": int,       # Unix timestamp
    "t_epoch": int,         # Time epoch = floor(timestamp / window)
    "signature": bytes      # 96-byte BLS signature by receiver
}
```

**Signature Message:**
```
infohash || sender_pk || piece_hash || piece_index (4 bytes big-endian) || t_epoch (8 bytes big-endian)
```

The **downloader** (receiver) signs the receipt, proving they received the piece from the uploader.

#### 2. pbts_receipt_batch

Send multiple receipts in one message for efficiency.

**Format:**
```
<length><EXTENDED_ID><msg_id><bencoded_batch>
```

**Batch Dictionary:**
```python
{
    "receipts": [
        { /* receipt 1 */ },
        { /* receipt 2 */ },
        ...
    ]
}
```

#### 3. pbts_request_receipt

Request a receipt from peer for a piece you uploaded to them.

**Format:**
```
<length><EXTENDED_ID><msg_id><bencoded_request>
```

**Request Dictionary:**
```python
{
    "infohash": bytes,      # 20-byte torrent info hash
    "piece_index": int,     # Piece index
    "piece_hash": bytes     # 32-byte SHA-256 hash of piece
}
```

## Receipt Flow

### Typical Piece Transfer with PBTS

```
Uploader (A)                          Downloader (B)
    |                                      |
    |-- Standard BT: Piece Data --------->|
    |                                      |
    |                                      |-- Verify piece hash
    |                                      |-- Create receipt
    |                                      |-- Sign with private key
    |                                      |
    |<-- BEP 10: pbts_receipt -------------|
    |                                      |
    |-- Store receipt locally              |
    |                                      |
    |-- (After threshold reached) -------->|
    |   Submit batch to tracker            |
```

### Key Points

1. **Downloader signs**: The peer who receives the piece creates and signs the receipt
2. **Uploader collects**: The uploader stores receipts as proof of upload
3. **Batch submission**: Uploader submits accumulated receipts to tracker periodically
4. **Tracker verifies**: Tracker verifies BLS signatures and updates reputation

## Implementation Guide

### For BitTorrent Client Developers

#### Step 1: Add BEP 10 Support

In your BitTorrent handshake, set bit 43 in the reserved bytes:

```python
reserved = bytearray(8)
reserved[5] |= 0x10  # Bit 43 (0x10 in byte 5) = extension support
```

#### Step 2: Perform Extended Handshake

After standard handshake, send/receive extended handshake:

```python
from bep10_extension import BEP10Handler

handler = BEP10Handler(client_version="MyClient 1.0")
handshake_msg = handler.create_handshake(listening_port=6881)
peer_socket.send(handshake_msg)

# Receive peer's handshake
response = peer_socket.recv(4096)
supports_pbts = handler.parse_handshake(response[6:])  # Skip length + IDs
```

#### Step 3: Generate Receipt After Download

When you successfully download a piece:

```python
from bep10_extension import PBTSReceipt, compute_piece_hash, compute_time_epoch
from tracker import sign_message

# Verify piece hash first!
piece_hash = compute_piece_hash(piece_data)
if piece_hash != expected_piece_hash:
    raise ValueError("Piece hash mismatch!")

# Create receipt
timestamp = time.time()
t_epoch = compute_time_epoch(timestamp, window=3600)

message = (
    infohash +
    uploader_public_key +
    piece_hash +
    struct.pack(">I", piece_index) +
    struct.pack(">Q", t_epoch)
)

signature = sign_message(my_private_key, message)

receipt = PBTSReceipt(
    infohash=infohash,
    sender_pk=uploader_public_key,
    receiver_pk=my_public_key,
    piece_hash=piece_hash,
    piece_index=piece_index,
    timestamp=timestamp,
    t_epoch=t_epoch,
    signature=signature
)

# Send to uploader
receipt_msg = handler.create_receipt_message(receipt)
peer_socket.send(receipt_msg)
```

#### Step 4: Collect Receipts After Upload

When you receive a receipt:

```python
# Parse incoming message
message = peer_socket.recv(4096)
msg_id = message[5]  # After length (4) + ext_id (1)
payload = message[6:]

receipt = handler.parse_message(msg_id, payload)

if receipt:
    # Store receipt for later submission
    my_receipts.append(receipt)
```

#### Step 5: Submit Receipts to Tracker

When you've accumulated enough receipts (e.g., 10-50):

```python
import requests
import base64

receipts_data = []
for r in my_receipts:
    receipts_data.append({
        "infohash": r.infohash.hex(),
        "sender_pk": base64.b64encode(r.sender_pk).decode(),
        "receiver_pk": base64.b64encode(r.receiver_pk).decode(),
        "piece_hash": r.piece_hash.hex(),
        "piece_index": r.piece_index,
        "t_epoch": r.t_epoch,
        "signature": base64.b64encode(r.signature).decode()
    })

response = requests.post(
    "https://tracker.example.com/report",
    json={
        "user_id": my_user_id,
        "receipts": receipts_data
    }
)

if response.status_code == 200:
    # Clear submitted receipts
    my_receipts.clear()
```

## Security Considerations

### Receipt Forgery Prevention

1. **BLS Signatures**: Each receipt is signed with the downloader's BLS private key
2. **Piece Hash Verification**: Receipt includes SHA-256 hash of piece data
3. **Timestamp Window**: Receipts expire after acceptance window (default: 24 hours)
4. **Double-Spend Prevention**: Tracker tracks receipt IDs to prevent resubmission

### Attack Scenarios

#### 1. Fake Receipt Attack

**Attack**: Uploader creates fake receipts claiming they uploaded pieces.

**Defense**:
- Receipt must be signed by downloader's private key
- Tracker verifies BLS signature
- Only registered public keys accepted

#### 2. Receipt Replay Attack

**Attack**: Uploader submits same receipt multiple times.

**Defense**:
- Tracker maintains `recent_receipts` set with receipt IDs
- Receipt ID includes: `infohash:sender:receiver:piece_hash:index:epoch`
- Duplicate receipts rejected

#### 3. Timestamp Manipulation

**Attack**: Create receipts with future timestamps to extend validity.

**Defense**:
- Tracker only accepts receipts within `[t_now - ACCEPTANCE_WINDOW, t_now]`
- Default acceptance window: 24 epochs (24 hours with 1-hour windows)
- Future timestamps rejected

#### 4. Piece Data Modification

**Attack**: Claim credit for uploading corrupted data.

**Defense**:
- Receipt includes SHA-256 hash of piece data
- Downloader verifies piece hash before signing receipt
- Invalid pieces rejected before receipt creation

## Configuration

### Client Configuration

```python
# Receipt batching
RECEIPT_BATCH_THRESHOLD = 10  # Submit after collecting N receipts
RECEIPT_BATCH_TIMEOUT = 3600  # Submit after N seconds regardless

# Time windows
RECEIPT_WINDOW = 3600  # 1 hour epoch window
```

### Tracker Configuration

```python
# In tracker.py or environment variables
RECEIPT_WINDOW = 3600           # Time window for epochs (seconds)
RECEIPT_ACCEPTANCE_WINDOW = 24  # Accept receipts from last N epochs
MIN_RATIO = 0.5                 # Minimum upload/download ratio
```

## Testing

### Run Examples

```bash
# Test BEP 10 message encoding/decoding
python bep10_extension.py

# Test client simulation
python example_bep10_client.py
```

### Expected Output

The example client demonstrates:
1. Extended handshake negotiation
2. Receipt creation and signing
3. Receipt transmission via BEP 10
4. Batch submission to tracker

### Integration Testing

To test with a real BitTorrent client:

1. Start PBTS tracker:
   ```bash
   python tracker.py
   ```

2. Register test users:
   ```bash
   curl -X POST http://localhost:8000/keygen  # Get keypairs
   curl -X POST http://localhost:8000/register \
     -H "Content-Type: application/json" \
     -d '{"user_id": "alice", "public_key": "BASE64_KEY"}'
   ```

3. Modify your BitTorrent client to:
   - Include `bep10_extension.py`
   - Add extended handshake support
   - Generate receipts on piece completion
   - Submit batches to `/report` endpoint

## Performance Considerations

### Message Overhead

| Message Type | Size (bytes) | Notes |
|-------------|--------------|-------|
| Extended Handshake | ~150 | One-time per connection |
| pbts_receipt | ~300 | Per piece transfer |
| pbts_receipt_batch (10) | ~2500 | Amortized: ~250 bytes/receipt |

### Batch Size Recommendations

| Torrent Size | Pieces | Suggested Batch |
|-------------|--------|-----------------|
| Small (< 100 MB) | < 100 | 10 receipts |
| Medium (100 MB - 1 GB) | 100-1000 | 25 receipts |
| Large (> 1 GB) | > 1000 | 50 receipts |

### Network Impact

- **Standard BitTorrent**: ~0 bytes overhead
- **PBTS with batching**: ~250 bytes per piece (amortized)
- **PBTS overhead**: < 0.1% for typical piece sizes (256 KB - 16 MB)

## Backward Compatibility

### With Standard BitTorrent Clients

PBTS clients work seamlessly with standard clients:

1. **Extended handshake**: Standard clients ignore PBTS messages
2. **Piece transfer**: Standard protocol unchanged
3. **Receipt exchange**: Only happens between PBTS-enabled peers
4. **Tracker announce**: Standard clients use HTTP announce

### Fallback Behavior

If peer doesn't support PBTS:
- No receipt exchange occurs
- Uploader gets no reputation credit for that peer
- Standard BitTorrent functionality unaffected

## Future Enhancements

### Aggregate Signatures

Currently, each receipt has individual signature. Future optimization:

```python
# Batch multiple receipts with single aggregate signature
aggregate_sig = bls.Aggregate([r.signature for r in receipts])

# Tracker verifies in one operation
public_keys = [r.receiver_pk for r in receipts]
messages = [r.get_message() for r in receipts]
valid = bls.AggregateVerify(public_keys, messages, aggregate_sig)
```

This reduces signature size from `N * 96` bytes to `96` bytes for N receipts.

### Receipt Compression

For large batches, compress receipts:

```python
import zlib

receipts_encoded = bencoder.encode(receipts_data)
receipts_compressed = zlib.compress(receipts_encoded)

# Saves ~60% for typical receipt batches
```

## References

- **BEP 10**: [Extension Protocol](http://www.bittorrent.org/beps/bep_0010.html)
- **BEP 3**: [BitTorrent Protocol](http://www.bittorrent.org/beps/bep_0003.html)
- **BLS Signatures**: [py-ecc library](https://github.com/ethereum/py_ecc)
- **PBTS Paper**: See `implementation-plan.md` for paper references

## Support

For issues or questions:
- GitHub Issues: [pbts repository](https://github.com/yourusername/pbts)
- Documentation: [docs/](../docs/)
- Example Code: [example_bep10_client.py](../example_bep10_client.py)
