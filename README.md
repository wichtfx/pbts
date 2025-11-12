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

- User registration with ECDSA keypairs
- Cryptographic receipts for piece transfers
- Double-spend prevention
- Portable reputation across tracker instances

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

## API Endpoints

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
```

## Project Structure

```
├── tracker.py           # Main application
├── requirements.txt     # Python dependencies
├── Dockerfile          # Container image
├── docker-compose.yml  # Docker setup
└── README.md
```

## Requirements

- Python 3.11+
- Flask 3.0+
- bencoder 0.2.0
- py_ecc 8.0+

## Docker

Pull from GitHub Container Registry:

```bash
docker pull ghcr.io/wichtfx/pbts-tracker:latest
docker run -p 8000:8000 ghcr.io/wichtfx/pbts-tracker:latest
```

## License

MIT

---

**Compatibility**: BitTorrent BEP 3, 23, 48 compliant
