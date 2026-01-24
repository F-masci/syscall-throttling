#!/bin/bash

# Configuration
CLIENT="./client"
NUM_ENTRIES=${1:-5}  # Default to 5 entries if not provided

# Common Linux program names for random selection
PROG_NAMES=("vim" "nano" "cat" "grep" "find" "ls" "cp" "mv" "rm" "mkdir" "touch" "python3" "gcc" "make" "tar" "ssh" "bash" "git" "docker" "curl")

# Check if client exists
if [ ! -f "$CLIENT" ]; then
    echo "Error: Client binary '$CLIENT' not found."
    echo "Please compile the client first."
    exit 1
fi

echo "[Script] Starting random population of the monitor..."

# --- Add Random Syscalls ---
echo "[Script] Adding $NUM_ENTRIES random Syscalls..."
for i in $(seq 1 $NUM_ENTRIES); do
    # Generate random syscall between 0 and 330 (typical x86_64 range)
    RAND_SYS=$((RANDOM % 330))
    echo "  -> Adding syscall $RAND_SYS"
    sudo $CLIENT add --sys $RAND_SYS > /dev/null
done

# --- Add Random UIDs ---
echo "[Script] Adding $NUM_ENTRIES random UIDs..."
for i in $(seq 1 $NUM_ENTRIES); do
    # Generate random UID between 1000 and 5000
    RAND_UID=$((1000 + RANDOM % 4000))
    echo "  -> Adding UID $RAND_UID"
    sudo $CLIENT add --uid $RAND_UID > /dev/null
done

# --- Add Random Programs ---
echo "[Script] Adding $NUM_ENTRIES random Program names..."
# Get the number of items in the array
NUM_PROGS=${#PROG_NAMES[@]}

for i in $(seq 1 $NUM_ENTRIES); do
    # Pick a random index
    RAND_IDX=$((RANDOM % NUM_PROGS))
    # Extract element
    PROG=${PROG_NAMES[$RAND_IDX]}
    
    echo "  -> Adding program '$PROG'"
    sudo $CLIENT add --prog "$PROG" > /dev/null
done

# --- Set Random Limit ---
RAND_LIMIT=$((5 + RANDOM % 50))
echo "[Script] Setting random limit to $RAND_LIMIT..."
sudo $CLIENT limit --val $RAND_LIMIT > /dev/null

echo "[Script] Population complete."
echo ""
echo "[Script] Verifying current configuration..."
echo "----------------------------------------"

# Verify results
sudo $CLIENT get-list --sys 0
echo ""
sudo $CLIENT get-list --uid 0
echo ""
sudo $CLIENT get-list --prog ""

echo "----------------------------------------"