#ifndef _DISCOVER_HOOKING
#define _DISCOVER_HOOKING
#endif

#include "../../types.h"

int init_syscall_dhook(hook_syscall_t *);
int install_syscall_dhook(hook_syscall_t *);
int uninstall_syscall_dhook(hook_syscall_t *);