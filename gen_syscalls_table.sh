#!/bin/bash

OUTPUT="syscall_table.h"
HEADER_FILE="/usr/include/asm/unistd_64.h"

echo "Generating $OUTPUT..."

# Header of H file
cat <<EOF > $OUTPUT
#pragma once

#include <linux/kernel.h>

/* Automatically generated table */
static const char *syscall_names[] = {
EOF

if command -v ausyscall &> /dev/null; then
    # Use ausyscall (part of audit) if available
    echo "// Generated via ausyscall" >> $OUTPUT
    ausyscall --dump | awk 'NR>1 { printf("\t[%s] = \"%s\",\n", $1, $2) }' >> $OUTPUT
else
    # Fallback to grep parsing
    echo "// Generated via grep parsing (ausyscall not found)" >> $OUTPUT
    grep -r "__NR_" $HEADER_FILE \
    | awk '{print $2, $3}' | sed 's/__NR_//' \
    | awk '{ printf("\t[%s] = \"%s\",\n", $2, $1) }' >> $OUTPUT
fi

# Closing the H file
cat <<EOF >> $OUTPUT
};

#define SYSCALL_TABLE_SIZE (sizeof(syscall_names) / sizeof(syscall_names[0]))

EOF

echo "Done! $OUTPUT is ready."