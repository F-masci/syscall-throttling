#pragma once

#ifndef _FTRACE_HOOKING
#define _FTRACE_HOOKING
#endif

#include <linux/ftrace.h>

#include "../../sct.h"

int setup_ftrace_hook(void);
void cleanup_ftrace_hook(void);

int init_syscall_fhook(struct hook_syscall_t *hook);
int install_syscall_fhook(struct hook_syscall_t *hook);
int uninstall_syscall_fhook(struct hook_syscall_t *hook);
