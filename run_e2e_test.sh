#!/bin/bash
#
# PBTS End-to-End Test Runner
#
# This script runs the complete E2E test including:
# - Anvil blockchain
# - Smart contract deployment
# - Tracker startup
# - User registration
# - Piece transfer simulation
# - Receipt verification
# - Contract state validation
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           PBTS End-to-End Test Runner                         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo

# Check dependencies
echo -e "${YELLOW}Checking dependencies...${NC}"

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 not found${NC}"
    exit 1
fi

if ! command -v anvil &> /dev/null; then
    echo -e "${RED}❌ Anvil not found. Install Foundry: curl -L https://foundry.paradigm.xyz | bash${NC}"
    exit 1
fi

if ! command -v forge &> /dev/null; then
    echo -e "${RED}❌ Forge not found. Run: foundryup${NC}"
    exit 1
fi

# Check if smartcontract/.env exists
if [ ! -f smartcontract/.env ]; then
    echo -e "${YELLOW}Creating smartcontract/.env...${NC}"
    cat > smartcontract/.env << EOF
RPC=http://127.0.0.1:8545
PK0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
A0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
EOF
    echo -e "${GREEN}✅ Created smartcontract/.env${NC}"
fi

# Parse command-line arguments
SKIP_ANVIL=false
SKIP_CONTRACTS=false
NO_CLEANUP=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-anvil)
            SKIP_ANVIL=true
            shift
            ;;
        --skip-contracts)
            SKIP_CONTRACTS=true
            shift
            ;;
        --no-cleanup)
            NO_CLEANUP=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --skip-anvil       Skip starting Anvil (assume already running)"
            echo "  --skip-contracts   Skip contract deployment"
            echo "  --no-cleanup       Keep processes running after test"
            echo "  --help             Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Build command (use uv run to ensure dependencies are available)
CMD="python tests/e2e/e2e_test.py"

if [ "$SKIP_ANVIL" = true ]; then
    CMD="$CMD --skip-anvil"
fi

if [ "$SKIP_CONTRACTS" = true ]; then
    CMD="$CMD --skip-contracts"
fi

if [ "$NO_CLEANUP" = true ]; then
    CMD="$CMD --no-cleanup"
fi

# Run the test
echo -e "${BLUE}Running E2E test...${NC}"
echo -e "${BLUE}Command: $CMD${NC}"
echo

$CMD

# Check exit code
if [ $? -eq 0 ]; then
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    ✅ E2E TEST PASSED!                         ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                    ❌ E2E TEST FAILED!                         ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi
