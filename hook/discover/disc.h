#pragma once

#ifndef _DISCOVER_HOOKING
#define _DISCOVER_HOOKING
#endif

int setup_discover_hook(void);
void cleanup_discover_hook(void);

unsigned long **get_syscall_table_addr(void);
unsigned long *get_original_syscall_addrs(void);
