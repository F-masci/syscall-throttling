#!/bin/bash

# ==============================================================================
#  Vagrant Test Runner Script
#  Description: Automates the deployment, compilation, and testing of the 
#               kernel module and client within the Vagrant VM.
# ==============================================================================

# --- Configuration ---
VM_HOME="/home/vagrant"
SYNC_MODULE_DIR="$VM_HOME/module"
VM_TEST_DIR="$VM_HOME/test"
VM_CLIENT_DIR="$VM_TEST_DIR/client"

TIMEOUT_PAUSE="40s"
TIMEOUT_TEST="20s"

# --- Colors for Logging ---
COLOR_HOST='\033[1;32m' # Bold Green for HOST
COLOR_VM='\033[1;33m'   # Bold Yellow for VM
COLOR_ERR='\033[1;31m'  # Bold Red for ERROR
NC='\033[0m'           # No Color

# --- Helper Functions ---

# Function: log_host
# Purpose:  Prints messages from the HOST perspective (Green)
log_host() {
    local msg=$@
    local timestamp=$(date +"%H:%M:%S")
    echo -e "${COLOR_HOST}[HOST]${NC} $timestamp - $msg"
}

# Function: log_error
# Purpose:  Prints error messages (Red)
log_error() {
    local msg=$@
    local timestamp=$(date +"%H:%M:%S")
    echo -e "${COLOR_ERR}[ERROR]${NC} $timestamp - $msg" >&2
}

# Function: prefix_vm_output
# Purpose:  Reads output from stdin (pipe) and prepends the [VM] tag in yellow
#           to every single line.
prefix_vm_output() {
    local timestamp
    while IFS= read -r line; do
        timestamp=$(date +"%H:%M:%S")
        echo -e "${COLOR_VM}[VM]${NC}   $timestamp - $line"
    done
}

# Function: run_in_vm
# Purpose:  Executes a command inside the VM via SSH.
#           Pipes the output to prefix_vm_output to ensure consistent formatting.
run_in_vm() {
    local cmd=$1
    local description=$2
    
    if [ -n "$description" ]; then
        # Manually print the description line using the VM format
        echo -e "${COLOR_VM}[VM]${NC}   $(date +"%H:%M:%S") - $description"
    fi

    # Use pipefail to catch errors even when piping output
    set -o pipefail
    
    # Execute command, redirect stderr to stdout (2>&1), and pipe to formatter
    vagrant ssh -c "$cmd" 2>&1 | prefix_vm_output
    
    local status=$?
    set +o pipefail
    
    # Check execution status
    if [ $status -ne 0 ]; then
        log_error "Command failed in VM (Exit code: $status)"
        return $status
    fi
}

# Function: cleanup
# Purpose:  Ensures the module is unloaded when the script exits.
cleanup() {
    log_host "Cleanup: Unloading module..."
    
    # We also pipe cleanup output to keep the formatting consistent
    set -o pipefail
    vagrant ssh -c "cd $VM_TEST_DIR && sudo make unload" 2>&1 | prefix_vm_output || true
    set +o pipefail
    
    log_host "Cleanup completed. Exiting."
}


# --- Main Execution Flow ---

# Exit immediately if a command exits with a non-zero status
set -e

# Register the cleanup function
trap cleanup EXIT

log_host "=== Starting Test in Vagrant VM ==="

# Preparation & Compilation
run_in_vm "
    echo 'Preparing test environment...'
    mkdir -p $VM_TEST_DIR && \
    sudo cp -R $SYNC_MODULE_DIR/* $VM_TEST_DIR && \
    sudo chown -R vagrant:vagrant $VM_TEST_DIR && \
    cd $VM_TEST_DIR && \
    echo 'Cleaning build environment...' && \
    sudo make clean && \
    echo 'Compiling kernel module...' && \
    sudo make ENABLE_FTRACE=1 && \
    echo 'Loading module...' && \
    sudo make load && \
    echo 'Compiling client...' && \
    cd client && sudo make
" "Environment setup, compilation, and module loading"

# Client Setup
run_in_vm "
    cd $VM_CLIENT_DIR && \
    ./setup.sh && \
    sudo ./client get-list --prog && \
    echo 'Client setup completed.'
" "Setting up client test environment"

# Test Execution
log_host "Running Client Tests..."

run_in_vm "
    cd $VM_CLIENT_DIR && \
    echo 'Starting background pause process...' && \
    timeout $TIMEOUT_PAUSE $VM_CLIENT_DIR/pause & \
    PAUSE_PID=\$! && \
    echo 'Running test script...' && \
    
    # We capture the exit code of the timeout command
    timeout $TIMEOUT_TEST $VM_CLIENT_DIR/test.sh
    TEST_RESULT=\$?
    
    # Analyze the result
    if [ \$TEST_RESULT -eq 124 ]; then
        echo 'SUCCESS: Test ran for the full duration.'
    elif [ \$TEST_RESULT -eq 0 ]; then
        echo 'FAILURE: Test finished too early !!!'
        exit 1
    else
        echo \"FAILURE: Test crashed or failed with exit code \$TEST_RESULT !!!\"
        exit 1
    fi

    cat /dev/sct-monitor
    cd $VM_CLIENT_DIR && $VM_CLIENT_DIR/clean.sh


" "Executing Test Logic"

log_host "=== Test Suite Completed Successfully ==="