#pragma once

#include "sct.h"

int setup_syscall_hooks(size_t);
void cleanup_syscall_hooks(void);

int install_syscall_hook(scidx_t);
unsigned long get_original_syscall_address(scidx_t);
int uninstall_syscall_hook(scidx_t);

int install_monitored_syscalls_hooks(void);
int uninstall_active_syscalls_hooks(void);