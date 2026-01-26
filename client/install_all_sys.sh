#!/bin/bash

SYSCALLS_NUM=${1:-450}  # Default to 450 syscalls if not provided

for i in $(seq 1 $SYSCALLS_NUM); do
    echo "  -> Adding syscall $i"
    sudo ./client add --sys $i
done