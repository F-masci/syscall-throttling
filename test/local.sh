#!/bin/bash

# ================================================================================
#  Host Test Runner
#  Description: Compile the module and client, then run the tests on the HOST.
#
#  Usage:       ./run_host_test.sh [--reload] <test_name_1> <test_name_2> ...
# ================================================================================

# --- Configuration ---
MODULE_NAME="sct"                   # Module name
WORK_DIR="$(pwd)/.."                # Working directory (parent of current)
CLIENT_DIR="$WORK_DIR/client"       # Client directory
TEST_DIR="$WORK_DIR/test"           # Test directory

# --- Colors ---
COLOR_HOST='\033[1;32m' # Green
COLOR_VM='\033[1;33m'   # Yellow (Kept variable name for consistency)
COLOR_ERR='\033[1;31m'  # Red
NC='\033[0m'            # Reset

# --- Parsing Arguments ---
RELOAD_MODULE=false
TEST_SUITE=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --reload)
            RELOAD_MODULE=true
            shift
            ;;
        *)
            TEST_SUITE+=("$1")
            shift
            ;;
    esac
done

if [ ${#TEST_SUITE[@]} -eq 0 ]; then
    echo -e "${COLOR_ERR}[ERROR]${NC} No tests specified!"
    echo "Usage: $0 [--reload] test1 test2 ..."
    exit 1
fi

# --- Funzioni Helper ---

log_host() {
    echo -e "${COLOR_HOST}[HOST]${NC} $(date +"%H:%M:%S") - $@"
}

log_error() {
    echo -e "${COLOR_ERR}[ERROR]${NC} $(date +"%H:%M:%S") - $@" >&2
}

prefix_output() {
    local prefix="${1:-HOST}"
    while IFS= read -r line; do
        echo -e "${COLOR_VM}[${prefix}]${NC}   $line"
    done
}

run_on_host() {
    local cmd=$1
    local prefix=$2

    bash -c "set -o pipefail; $cmd" 2>&1 | prefix_output "$prefix"
    
    local status=${PIPESTATUS[0]} 
    if [ $status -ne 0 ]; then
        log_error "Command failed on HOST: $status"
        exit $status
    fi
}

# --- Main Execution ---

if [ "$RELOAD_MODULE" = "true" ]; then
    log_host "Enabled Reload Module"
fi

log_host "=== Setup Module ==="

HOST_SCRIPT="
    cd $WORK_DIR

    # Check if module is loaded
    IS_LOADED=\$(lsmod | grep -w \"^$MODULE_NAME\" || true)

    # Check if reload is needed
    if [ \"$RELOAD_MODULE\" = \"true\" ] || [ -z \"\$IS_LOADED\" ]; then

        # If it was loaded, unload it first
        if [ -n \"\$IS_LOADED\" ]; then
            echo '>>> Unloading module...'
            sudo make unload || exit 1
        fi

        echo '>>> Compiling module...'
        sudo make || exit 1

        echo '>>> Loading module...'
        sudo make load || exit 1
    else
        echo '>>> Module already loaded. Skipping build.'
    fi
"

run_on_host "$HOST_SCRIPT" "SETUP"

log_host "=== Setup Client ==="

HOST_SCRIPT="
    cd $CLIENT_DIR
    echo '>>> Compiling client...'
    make || exit 1
"

run_on_host "$HOST_SCRIPT" "CLIENT"

log_host "=== Start Test Suite: ${TEST_SUITE[*]} ==="

for TEST_NAME in "${TEST_SUITE[@]}"; do

    PREFIX="${TEST_NAME^^}"

    log_host "=== Starting Test '$TEST_NAME' ==="

    HOST_SCRIPT="
        # Check if test directory exists
        cd $TEST_DIR
        if [ ! -d \"$TEST_NAME\" ]; then
            echo \"ERROR: Test directory '$TEST_NAME' not found!\"
            exit 1
        fi

        # Run test
        TARGET_RUN_SCRIPT=\"$TEST_DIR/$TEST_NAME/run.sh\"
        if [ ! -f \"\$TARGET_RUN_SCRIPT\" ]; then
            echo \"ERROR: Script 'run' not found (\$TARGET_RUN_SCRIPT)\"
            exit 1
        fi

        # Enter the specific test directory
        cd \"$TEST_DIR/$TEST_NAME\"

        # Test compilation
        echo '>>> Compiling test...'
        make

        # Run the test
        echo '>>> Running test...'
        chmod +x run.sh
        ./run.sh
    "

    run_on_host "$HOST_SCRIPT" "$PREFIX"

    log_host "=== Test Completed ==="

done

log_host "=== End of Test Suite ==="