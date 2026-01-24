#include <linux/ftrace.h>

#include "../../types.h"

unsigned long install_syscall_fhook(scidx_t, unsigned long, struct ftrace_ops *);
unsigned long uninstall_syscall_fhook(scidx_t, struct ftrace_ops *);