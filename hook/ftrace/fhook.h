#include <linux/ftrace.h>

#ifndef _FTRACE_HOOKING
#define _FTRACE_HOOKING
#endif

#include "../../types.h"

int setup_ftrace_hook(void);
void cleanup_ftrace_hook(void);

int init_syscall_fhook(hook_syscall_t *);
int install_syscall_fhook(hook_syscall_t *);
int uninstall_syscall_fhook(hook_syscall_t *);