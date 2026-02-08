#!/bin/bash

# ==============================================================================
#  Pause Syscall Throttling Test
#  Description: Configures the kernel module to throttle the 'pause' syscall
#               and launches multiple background instances to trigger the limit.
# ==============================================================================

# --- Configuration ---
CLIENT="./client"
TARGET_PROG="$(pwd)/pause"
SYSCALL_PAUSE=34  # 34 is 'pause' on x86_64

# Number of threads to launch
NUM_THREADS=${1:-10}

# --- Colors for Logging ---
YELLOW='\033[1;33m'
NC='\033[0m'

# --- Helper Functions ---

# Function: log_test
# Purpose:  Prints formatted log messages with the yellow [TEST] tag
log_test() {
    local msg=$@
    local timestamp=$(date +"%H:%M:%S")
    echo -e "${YELLOW}[TEST]${NC} $timestamp - $msg"
}

# Function: cleanup
# Purpose:  Kills the background processes when the script exits
cleanup() {
    echo ""
    log_test "Cleaning up..."
    log_test "Terminating background 'pause' processes..."
    # Kill processes matching the target program name
    pkill -f "$TARGET_PROG" > /dev/null 2>&1 || true
    log_test "Cleanup completed."
}

# --- Checks ---

if [ ! -f "$CLIENT" ]; then
    echo "Error: Client binary '$CLIENT' not found."
    exit 1
fi

if [ ! -f "$TARGET_PROG" ]; then
    echo "Error: Target program '$TARGET_PROG' not found."
    echo "Please compile 'pause.c' first."
    exit 1
fi

# Register cleanup to run on exit or CTRL+C
trap cleanup EXIT

# ==============================================================================
#  MODULE SETUP
# ==============================================================================

log_test "Starting configuration phase..."

# Disable monitoring temporarily
log_test "Disabling monitoring temporarily..."
sudo $CLIENT status --val 0 > /dev/null

# Add Syscall
log_test "Adding monitoring for Syscall $SYSCALL_PAUSE..."
sudo $CLIENT add --sys $SYSCALL_PAUSE > /dev/null

# Add Program Path
log_test "Adding monitoring for Program: $TARGET_PROG"
sudo $CLIENT add --prog "$TARGET_PROG" > /dev/null

# Set Limit
# We set the limit to half the number of threads to ensure some get throttled
LIMIT=$((NUM_THREADS / 2))
if [ "$LIMIT" -lt 1 ]; then LIMIT=1; fi

log_test "Setting execution limit to $LIMIT (for $NUM_THREADS threads)..."
sudo $CLIENT limit --val $LIMIT > /dev/null

# Enable monitoring
log_test "Re-enabling monitoring..."
sudo $CLIENT status --val 1 > /dev/null

# ==============================================================================
#  EXECUTION PHASE
# ==============================================================================

echo ""
log_test "Starting execution phase..."
log_test "Launching $NUM_THREADS instances of '$TARGET_PROG' in background..."

for i in $(seq 1 $NUM_THREADS); do
    # Launch program in background, silence stdout/stderr
    $TARGET_PROG > /dev/null 2>&1 &
    PID=$!
    echo "  -> Thread $i launched (PID: $PID)"
done

echo ""
log_test "All instances launched."
log_test "Waiting 3 seconds to gather statistics..."
sleep 3

# ==============================================================================
#  VERIFICATION PHASE
# ==============================================================================

echo ""
log_test "Verifying current statistics..."
echo "----------------------------------------"
sudo $CLIENT get-stats
echo "----------------------------------------"

echo ""
log_test "Verifying monitor status..."
echo "----------------------------------------"
sudo $CLIENT get-status
echo "----------------------------------------"

echo ""
log_test "Test sequence finished. Press ENTER to cleanup and exit."
read -p ""