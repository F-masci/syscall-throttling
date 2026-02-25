#pragma once

#ifndef _DISCOVER_HOOKING
#define _DISCOVER_HOOKING
#endif

void begin_syscall_table_hack(void);
void end_syscall_table_hack(void);

void set_memory_executable(unsigned long addr, int numpages);