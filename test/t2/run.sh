#!/bin/bash

# --- CONFIGURATION ---
RCLIENT="../../client/client"
CLIENT=$(realpath "$RCLIENT")

RMON_PROG="./mon_prog_test"
RMON_EUID="./mon_euid_test"
RUMON_PROG="./unmon_prog_test"
RUMON_EUID="./unmon_euid_test"

MON_PROG=$(realpath "$RMON_PROG")
MON_EUID=$(realpath "$RMON_EUID")
UNMON_PROG=$(realpath "$RUMON_PROG")
UNMON_EUID=$(realpath "$RUMON_EUID")

TARGET_UID=1000

DNODE="/dev/sct-monitor"
SYSCALL_NR=110          # 110 = getppid (x86_64)

THREADS=${1:-10}        # Number of threads (default 10)
DURATION=${2:-5}        # Duration in seconds (default 5)

# Check file existence
if [ ! -f "$CLIENT" ]; then
    echo "ERROR: $CLIENT not found. Please compile it first."
    exit 1
fi

# Check file existence
if [ ! -f "$MON_PROG" ]; then
    echo "ERROR: $MON_PROG not found."
    exit 1
fi

# Check file existence
if [ ! -f "$MON_EUID" ]; then
    echo "ERROR: $MON_EUID not found."
    exit 1
fi

# Check file existence
if [ ! -f "$UNMON_PROG" ]; then
    echo "ERROR: $UNMON_PROG not found."
    exit 1
fi

# Check file existence
if [ ! -f "$UNMON_EUID" ]; then
    echo "ERROR: $UNMON_EUID not found."
    exit 1
fi

# Disable monitoring
sudo $CLIENT status --val 0

# Set limit
sudo $CLIENT limit --val 5

# Add monitoring
sudo $CLIENT add --sys $SYSCALL_NR
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to add syscall."
    exit 1
fi

# Add monitoring
sudo $CLIENT add --prog $MON_PROG
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to add program."
    exit 1
fi

# Enable monitoring
sudo $CLIENT status --val 1

echo ""
echo ""

cat $DNODE

echo ""
echo ""

echo "==================== PROG MON ======================"

echo "Executing: $MON_PROG $THREADS $DURATION"
$MON_PROG "$THREADS" "$DURATION"

echo ""
echo ""

echo "Executing: $UNMON_PROG $THREADS $DURATION"
$UNMON_PROG "$THREADS" "$DURATION"

echo "===================================================="

echo ""
echo ""

# Add monitoring
sudo $CLIENT add --uid $TARGET_UID
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to add program."
    exit 1
fi

echo ""
echo ""

echo "==================== EUID MON ======================"

echo "Executing: $MON_EUID $THREADS $DURATION"
$MON_EUID "$THREADS" "$DURATION"

echo ""
echo ""

echo "Executing: $UNMON_EUID $THREADS $DURATION"
sudo $UNMON_EUID "$THREADS" "$DURATION"

echo "===================================================="

echo ""
echo ""

$CLIENT get-status

# Retrieve statistics
$CLIENT get-stats
$CLIENT get-delay

sudo $CLIENT remove --sys $SYSCALL_NR
sudo $CLIENT remove --prog $MON_PROG
sudo $CLIENT remove --uid $TARGET_UID

sudo $CLIENT status --val 0

echo ""
echo ""

cat $DNODE

echo ""
echo ""

echo "Done."