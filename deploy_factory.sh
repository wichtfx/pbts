#!/bin/bash
# Deploy ReputationFactory contract and update .env

set -e

echo "================================================"
echo "Deploying ReputationFactory Contract"
echo "================================================"

# Load environment variables
if [ -f "smartcontract/.env" ]; then
    source smartcontract/.env
else
    echo "ERROR: smartcontract/.env not found"
    exit 1
fi

# Check required variables
if [ -z "$RPC" ]; then
    echo "ERROR: RPC not set in .env"
    exit 1
fi

if [ -z "$PK0" ]; then
    echo "ERROR: PK0 not set in .env"
    exit 1
fi

echo "RPC: $RPC"
echo "Deploying with: $A0"
echo ""

# Deploy factory
echo "Deploying ReputationFactory..."
cd smartcontract

FACTORY=$(forge create src/factory.sol:ReputationFactory \
  --rpc-url "$RPC" \
  --private-key "$PK0" \
  --broadcast \
  --json | jq -r .deployedTo)

if [ -z "$FACTORY" ] || [ "$FACTORY" = "null" ]; then
    echo "ERROR: Deployment failed or could not extract contract address"
    exit 1
fi

echo "SUCCESS: Factory deployed: $FACTORY"
echo ""

# Update .env file
cd ..
echo "Updating smartcontract/.env..."

# Remove existing FACTORY line if it exists
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' '/^FACTORY=/d' smartcontract/.env
else
    sed -i '/^FACTORY=/d' smartcontract/.env
fi

# Add new FACTORY
echo "" >> smartcontract/.env
echo "# Auto-generated - Factory contract address" >> smartcontract/.env
echo "FACTORY=$FACTORY" >> smartcontract/.env

echo "   Updated FACTORY=$FACTORY"
echo ""
echo "================================================"
echo "Deployment Complete!"
echo "================================================"
echo "Factory Address: $FACTORY"
echo ""
echo "Next steps:"
echo "1. Restart your tracker: python tracker.py"
echo "2. Initialize Reputation contract: curl -X POST http://localhost:8000/contract/init"
echo "3. Or run tests: python test_smartcontract.py"
echo ""
