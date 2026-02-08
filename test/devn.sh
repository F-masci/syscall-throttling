#!/bin/bash

# Check args
if [ -z "$1" ]; then
    echo "Usage: $0 <path_to_file>" >&2
    exit 1
fi

TARGET="$1"

# Check if file exists
if [ ! -e "$TARGET" ]; then
    echo "Error: File $TARGET not found" >&2
    exit 1
fi

# Get Inode
INODE=$(stat -c "%i" "$TARGET")

# Get Device in User Space
DEV_USER=$(stat -c "%d" "$TARGET")

# Compute dev number in kernel format (Major << 20 | Minor)
#
# Major is the high 12 bits, Minor is the low 8 bits
KERNEL_DEV=$(( ( (DEV_USER / 256) << 20 ) | (DEV_USER % 256) ))

# Print ONLY the final string so it can be captured
echo "$INODE:$KERNEL_DEV"