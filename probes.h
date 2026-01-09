#pragma once

#include <linux/kprobes.h>

int install_syscall_name_probe(const char *, struct kprobe **);
int install_syscall_idx_probe(int, struct kprobe **);