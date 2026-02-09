#!/bin/bash

# --- CONFIGURATION ---
RCLIENT="../../client/client"
CLIENT=$(realpath "$RCLIENT")

RPAUSE="./pause"
PAUSE=$(realpath "$RPAUSE")

DNODE="/dev/sct-monitor"
SYSCALL_NR=34          # 34 = pause (x86_64)

TIMEOUT="10s"          # Max wait time (seconds)
INTERVAL=0.1           # Check interval (100ms)
MAX_CHECK_LOOPS=50     # Max check loops

COUNTER=0
BLOCKED=0

setup_monitoring() {
    local fastUnload="${1:-1}"
    local limit="${2:-0}"

    # Check file existence
    if [ ! -f "$CLIENT" ]; then
        echo "ERROR: $CLIENT not found. Please compile it first."
        exit 1
    fi

    # Check file existence
    if [ ! -f "$PAUSE" ]; then
        echo "ERROR: $PAUSE not found."
        exit 1
    fi

    # Add monitoring
    sudo $CLIENT add --sys $SYSCALL_NR
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to add syscall."
        exit 1
    fi

    # Add monitoring
    sudo $CLIENT add --prog $PAUSE
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to add program."
        exit 1
    fi

    # Enable monitoring
    sudo $CLIENT status --val 1

    # Enable fast unloading
    sudo $CLIENT fast-unload --val "$fastUnload"

    # Set limit
    sudo $CLIENT limit --val "$limit"

    echo ""
    echo ""

    cat $DNODE

    echo ""
    echo ""
}

setup_monitoring 1 0

echo "==================== ENABLED ======================"

timeout --preserve-status $TIMEOUT $PAUSE &
PID_PAUSE_TIMEOUT=$!

sleep 0.1
PID_PAUSE_REAL=$(pgrep -P $PID_PAUSE_TIMEOUT -n)
echo "Pause timeout PID: $PID_PAUSE_TIMEOUT"
echo "Pause PID: $PID_PAUSE_REAL"

sleep 1

echo "Unloading module..."
sudo make unload -f ../../Makefile &
PID_UNLOAD_TIMEOUT=$!

sleep 0.1
PID_UNLOAD_REAL=$(pgrep -P $PID_UNLOAD_TIMEOUT -n)
echo "Unload timeout PID: $PID_UNLOAD_TIMEOUT"
echo "Unload PID: $PID_UNLOAD_REAL"

sleep 1

timeout --preserve-status 3 $PAUSE

wait $PID_PAUSE_TIMEOUT
wait $PID_UNLOAD_TIMEOUT

RET=$?
if [ $RET -eq 124 ]; then
    echo "Timeout reached. Process was killed."
else
    echo "Process finished manually with code $RET."
fi

echo "===================================================="

echo ""
echo ""

echo "Loading module..."
sudo make load -f ../../Makefile

setup_monitoring 0 0

echo "=================== DISABLED ======================="

timeout --preserve-status $TIMEOUT $PAUSE &
PID_PAUSE_TIMEOUT=$!

sleep 0.1
PID_PAUSE_REAL=$(pgrep -P $PID_PAUSE_TIMEOUT -n)
echo "Pause timeout PID: $PID_PAUSE_TIMEOUT"
echo "Pause PID: $PID_PAUSE_REAL"

sleep 1

echo "Unloading module..."
sudo make unload -f ../../Makefile &
PID_UNLOAD_TIMEOUT=$!

sleep 0.1
PID_UNLOAD_REAL=$(pgrep -P $PID_UNLOAD_TIMEOUT -n)
echo "Unload timeout PID: $PID_UNLOAD_TIMEOUT"
echo "Unload PID: $PID_UNLOAD_REAL"

sleep 1

timeout --preserve-status 3 $PAUSE

wait $PID_PAUSE_TIMEOUT
wait $PID_UNLOAD_TIMEOUT

RET=$?
if [ $RET -eq 124 ]; then
    echo "Timeout reached. Process was killed."
else
    echo "Process finished manually with code $RET."
fi

echo "===================================================="

echo ""
echo ""

echo "Loading module..."
sudo make load -f ../../Makefile

echo ""
echo ""

echo "Done."