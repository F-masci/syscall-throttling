#pragma once

#include "sct.h"

#ifdef _FTRACE_HOOKING
#include "hook/ftrace/fhook.h"
#elif defined(_DISCOVER_HOOKING)
#include "hook/discover/disc.h"
#include "hook/discover/dhook.h"
#endif

int setup_syscall_hooks(size_t syscalls_num);
void cleanup_syscall_hooks(void);

int install_syscall_hook(int syscall_idx);
unsigned long get_original_syscall_address(int syscall_idx);
int uninstall_syscall_hook(int syscall_idx);

int install_monitored_syscalls_hooks(void);
int uninstall_active_syscalls_hooks(void);
