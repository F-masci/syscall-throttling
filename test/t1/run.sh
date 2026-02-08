#!/bin/bash

# --- CONFIGURATION ---
RCLIENT="../../client/client"
CLIENT=$(realpath "$RCLIENT")
REXEC="./stress_test"
EXEC=$(realpath "$REXEC")

DNODE="/dev/sct-monitor"
SYSCALL_NR=110          # 110 = getppid (x86_64)

THREADS=${1:-50}        # Number of threads (default 50)
DURATION=${2:-20}       # Duration in seconds (default 20)

# Check file existence
if [ ! -f "$CLIENT" ]; then
    echo "ERROR: $CLIENT not found. Please compile it first."
    exit 1
fi

if [ ! -f "$EXEC" ]; then
    echo "ERROR: $EXEC not found."
    exit 1
fi

# Disable monitoring
sudo $CLIENT status --val 0

# Set limit
sudo $CLIENT limit --val 20

# Add monitoring
sudo $CLIENT add --sys $SYSCALL_NR
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to add syscall."
    exit 1
fi

# Add monitoring
sudo $CLIENT add --prog $EXEC
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to add program."
    exit 1
fi

cat $DNODE

# Normal execution
echo "===================== NORMAL ======================"

$EXEC "$THREADS" "$DURATION"

echo "===================================================="

# Enable monitoring
sudo $CLIENT status --val 1

# Throttle execution
echo "===================== THROTTLE ====================="

$EXEC "$THREADS" "$DURATION"

echo "===================================================="

$CLIENT get-status

sudo $CLIENT status --val 0

# Retrieve statistics
$CLIENT get-stats
$CLIENT get-delay

sudo $CLIENT remove --sys $SYSCALL_NR
sudo $CLIENT remove --prog $EXEC

cat $DNODE

echo "Done."