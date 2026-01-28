#pragma once

#ifndef _DISCOVER_HOOKING
#define _DISCOVER_HOOKING
#endif

#include "../../sct.h"

int init_syscall_dhook(struct hook_syscall_t *hook);
int install_syscall_dhook(struct hook_syscall_t *hook);
int uninstall_syscall_dhook(struct hook_syscall_t *hook);
