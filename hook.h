int setup_syscall_hooks(int);
int install_syscall_hook(int);
int uninstall_syscall_hook(int syscall_idx);
void cleanup_syscall_hooks(void);