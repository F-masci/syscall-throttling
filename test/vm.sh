#!/bin/bash

# ================================================================================
#  Vagrant Test Runner
#  Description: Compile the module and client, then run the tests in a Vagrant VM.
#
#  Usage:       ./run_vm_test.sh [--reload] <test_name_1> <test_name_2> ...
# ================================================================================

# --- Configuration ---
MODULE_NAME="sct"                   # Module name (without .ko)
VM_SRC_DIR="/home/vagrant/module"   # Path defined in Vagrantfile (synced folder)
VM_WORK_DIR="/home/vagrant/work"    # Path defined in Vagrantfile (work folder)
VM_CLIENT_DIR="$VM_WORK_DIR/client" # Path defined in Vagrantfile (client folder)
VM_TEST_DIR="$VM_WORK_DIR/test"     # Path defined in Vagrantfile (tests folder)

# --- Colors ---
COLOR_HOST='\033[1;32m' # Green
COLOR_VM='\033[1;36m'   # Cyan
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

TAG_WIDTH=8

log_host() {
    printf "${COLOR_HOST}%-${TAG_WIDTH}s${NC} %s | %s\n" "[HOST]" "$(date +"%H:%M:%S")" "$*"
}

log_error() {
    printf "${COLOR_ERR}%-${TAG_WIDTH}s${NC} %s | %s\n" "[ERROR]" "$(date +"%H:%M:%S")" "$*" >&2
}

prefix_vm_output() {
    local prefix="${1:-VM}"
    local tag="[$prefix]"
    
    while IFS= read -r line; do
        printf "${COLOR_VM}%-${TAG_WIDTH}s${NC} %s | %s\n" "$tag" "$(date +"%H:%M:%S")" "$line"
    done
}

run_in_vm() {
    local cmd=$1
    local prefix=$2

    vagrant ssh -c "set -o pipefail; $cmd" 2>&1 | prefix_vm_output "$prefix"
    
    local status=${PIPESTATUS[0]} 
    if [ $status -ne 0 ]; then
        log_error "Command failed in VM: $status"
        exit $status
    fi
}

# --- Main Execution ---

if [ "$RELOAD_MODULE" = "true" ]; then
    log_host "Enabled Reload Module"
fi

log_host "=== Setup Module ==="

VM_SCRIPT="

    # Copy files
    echo '>>> Copying files...'
    mkdir -p $VM_WORK_DIR
    cp -r $VM_SRC_DIR/* $VM_WORK_DIR/

    cd $VM_WORK_DIR

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
        sudo make ENABLE_FTRACE=1 || exit 1

        echo '>>> Loading module...'
        sudo make load || exit 1
    else
        echo '>>> Module already loaded. Skipping build.'
    fi
"

run_in_vm "$VM_SCRIPT"

log_host "=== Setup Client ==="

VM_SCRIPT="
    cd $VM_CLIENT_DIR
    echo '>>> Compiling client...'
    make || exit 1
"

run_in_vm "$VM_SCRIPT"

log_host "=== Start Test Suite: ${TEST_SUITE[*]} ==="

for TEST_NAME in "${TEST_SUITE[@]}"; do

    PREFIX="${TEST_NAME^^}"

    log_host "=== Starting Test '$TEST_NAME' ==="

    VM_SCRIPT="
        # Check if test directory exists
        cd $VM_TEST_DIR
        if [ ! -d \"$TEST_NAME\" ]; then
            echo \"ERROR: Test directory '$TEST_NAME' not found!\"
            exit 1
        fi

        # Run test
        TARGET_RUN_SCRIPT=\"$VM_TEST_DIR/$TEST_NAME/run.sh\"
        if [ ! -f \"\$TARGET_RUN_SCRIPT\" ]; then
            echo \"ERROR: Script 'run' not found (\$TARGET_RUN_SCRIPT)\"
            exit 1
        fi

        # Enter the specific test directory
        cd \"$VM_TEST_DIR/$TEST_NAME\"

        # Test compilation
        echo '>>> Compiling test...'
        make

        # Run the test
        echo '>>> Running test...'
        chmod +x run.sh
        ./run.sh
    "

    run_in_vm "$VM_SCRIPT" "$PREFIX"

    log_host "=== Test Completed ==="

done

log_host "=== End of Test Suite ==="