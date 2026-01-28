#ifndef _FTRACE_HOOKING
#define _FTRACE_HOOKING
#endif

#include "../../types.h"

int load_sys_ni_syscall_address(void);
int set_syscall_address(struct hook_syscall_t * hook);